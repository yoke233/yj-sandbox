use crate::acl::add_allow_ace;
use crate::acl::add_deny_write_ace;
use crate::acl::allow_null_device;
use crate::allow::AllowDenyPaths;
use crate::allow::compute_allow_paths_for_permissions;
use crate::cap::load_or_create_cap_sids;
use crate::cap::workspace_write_cap_sid_for_root;
use crate::cap::workspace_write_root_contains_path;
use crate::cap::workspace_write_root_overlaps_path;
use crate::cap::workspace_write_root_specificity;
use crate::env::apply_no_network_to_env;
use crate::env::ensure_non_interactive_pager;
use crate::env::inherit_path_env;
use crate::env::normalize_null_device_env;
use crate::logging::log_start;
use crate::path_normalization::canonicalize_path;
use crate::resolved_permissions::ResolvedWindowsSandboxPermissions;
use crate::resolved_permissions::effective_write_roots_for_permissions;
use crate::sandbox_utils::ensure_codex_home_exists;
use crate::sandbox_utils::inject_git_safe_directory;
use crate::token::LocalSid;
use crate::token::create_readonly_token_with_cap;
use crate::token::create_workspace_write_token_with_caps_from;
use crate::token::get_current_token_for_restriction;
use crate::token::get_logon_sid_bytes;
use crate::workspace_acl::is_command_cwd_root;
use crate::workspace_acl::protect_workspace_agents_dir;
use crate::workspace_acl::protect_workspace_codex_dir;
use anyhow::Context;
use anyhow::Result;
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::HANDLE;

pub(crate) struct SpawnContext {
    pub(crate) permissions: ResolvedWindowsSandboxPermissions,
    pub(crate) current_dir: PathBuf,
    pub(crate) logs_base_dir: Option<PathBuf>,
    pub(crate) uses_write_capabilities: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SpawnPrepOptions {
    pub(crate) inherit_path: bool,
    pub(crate) add_git_safe_directory: bool,
}

pub(crate) struct LegacySessionSecurity {
    pub(crate) h_token: HANDLE,
    pub(crate) readonly_sid: Option<LocalSid>,
    pub(crate) write_root_sids: Vec<RootCapabilitySid>,
}

pub(crate) struct RootCapabilitySid {
    pub(crate) root: PathBuf,
    pub(crate) sid: LocalSid,
    // Retained for parity with upstream (used by the elevated/deny-read paths).
    #[allow(dead_code)]
    pub(crate) sid_str: String,
}

pub(crate) struct LegacyAclSids<'a> {
    pub(crate) readonly_sid: Option<&'a LocalSid>,
    pub(crate) write_root_sids: &'a [RootCapabilitySid],
}

fn prepare_spawn_context_common(
    permissions: &ResolvedWindowsSandboxPermissions,
    codex_home: &Path,
    cwd: &Path,
    env_map: &mut HashMap<String, String>,
    command: &[String],
    options: SpawnPrepOptions,
) -> Result<SpawnContext> {
    let permissions = permissions.clone();

    normalize_null_device_env(env_map);
    ensure_non_interactive_pager(env_map);
    if options.inherit_path {
        inherit_path_env(env_map);
    }
    if options.add_git_safe_directory {
        inject_git_safe_directory(env_map, cwd);
    }

    ensure_codex_home_exists(codex_home)?;
    let sandbox_base = codex_home.join(".sandbox");
    std::fs::create_dir_all(&sandbox_base)?;
    let logs_base_dir = Some(sandbox_base);
    log_start(command, logs_base_dir.as_deref());

    let uses_write_capabilities = permissions.uses_write_capabilities_for_cwd(cwd, env_map);

    Ok(SpawnContext {
        permissions,
        current_dir: cwd.to_path_buf(),
        logs_base_dir,
        uses_write_capabilities,
    })
}

pub(crate) fn prepare_legacy_spawn_context(
    permissions: &ResolvedWindowsSandboxPermissions,
    codex_home: &Path,
    cwd: &Path,
    env_map: &mut HashMap<String, String>,
    command: &[String],
    options: SpawnPrepOptions,
) -> Result<SpawnContext> {
    let common = prepare_spawn_context_common(
        permissions,
        codex_home,
        cwd,
        env_map,
        command,
        options,
    )?;
    if common.permissions.should_apply_network_block() {
        apply_no_network_to_env(env_map)?;
    }
    Ok(common)
}

pub(crate) fn prepare_legacy_session_security(
    uses_write_capabilities: bool,
    codex_home: &Path,
    cwd: &Path,
    capability_roots: impl IntoIterator<Item = PathBuf>,
) -> Result<LegacySessionSecurity> {
    let caps = load_or_create_cap_sids(codex_home)?;
    let (h_token, readonly_sid, write_root_sids) = unsafe {
        if uses_write_capabilities {
            let write_root_sids = root_capability_sids(codex_home, cwd, capability_roots)?;
            if write_root_sids.is_empty() {
                anyhow::bail!("workspace-write sandbox has no writable root capability SIDs");
            }
            let base = get_current_token_for_restriction()?;
            let cap_ptrs: Vec<*mut c_void> = write_root_sids
                .iter()
                .map(|root| root.sid.as_ptr())
                .collect();
            let h_token = create_workspace_write_token_with_caps_from(base, cap_ptrs.as_slice());
            CloseHandle(base);
            let h_token = h_token?;
            (h_token, None, write_root_sids)
        } else {
            let psid = LocalSid::from_string(&caps.readonly)?;
            let (h_token, _psid) = create_readonly_token_with_cap(psid.as_ptr())?;
            (h_token, Some(psid), Vec::new())
        }
    };

    Ok(LegacySessionSecurity {
        h_token,
        readonly_sid,
        write_root_sids,
    })
}

pub(crate) fn legacy_session_capability_roots(
    permissions: &ResolvedWindowsSandboxPermissions,
    current_dir: &Path,
    env_map: &HashMap<String, String>,
    codex_home: &Path,
) -> Vec<PathBuf> {
    let allow_paths = compute_allow_paths_for_permissions(permissions, current_dir, env_map)
        .allow
        .into_iter()
        .collect::<Vec<_>>();
    if permissions.uses_write_capabilities_for_cwd(current_dir, env_map) {
        effective_write_roots_for_permissions(
            permissions,
            current_dir,
            env_map,
            codex_home,
            Some(allow_paths.as_slice()),
        )
    } else {
        allow_paths
    }
}

pub(crate) fn root_capability_sids(
    codex_home: &Path,
    cwd: &Path,
    allow_paths: impl IntoIterator<Item = PathBuf>,
) -> Result<Vec<RootCapabilitySid>> {
    let mut roots: Vec<PathBuf> = allow_paths.into_iter().collect();
    roots.sort_by_key(|root| canonicalize_path(root.as_path()));
    roots.dedup_by(|a, b| canonicalize_path(a.as_path()) == canonicalize_path(b.as_path()));

    let mut out = Vec::with_capacity(roots.len());
    for root in roots {
        let sid_str = workspace_write_cap_sid_for_root(codex_home, cwd, &root)?;
        let sid = LocalSid::from_string(&sid_str)?;
        out.push(RootCapabilitySid { root, sid, sid_str });
    }
    Ok(out)
}

fn matching_root_capability<'a>(
    path: &Path,
    root_sids: &'a [RootCapabilitySid],
) -> Option<&'a RootCapabilitySid> {
    root_sids
        .iter()
        .filter(|root_sid| workspace_write_root_contains_path(&root_sid.root, path))
        .max_by_key(|root_sid| workspace_write_root_specificity(&root_sid.root))
}

fn deny_root_capabilities_for_path<'a>(
    path: &Path,
    root_sids: &'a [RootCapabilitySid],
) -> Vec<&'a RootCapabilitySid> {
    let matching_root_sids = root_sids
        .iter()
        .filter(|root_sid| workspace_write_root_overlaps_path(&root_sid.root, path))
        .collect::<Vec<_>>();
    if matching_root_sids.is_empty() {
        root_sids.iter().collect()
    } else {
        matching_root_sids
    }
}

pub(crate) fn allow_null_device_for_workspace_write(is_workspace_write: bool) {
    if !is_workspace_write {
        return;
    }

    unsafe {
        if let Ok(base) = get_current_token_for_restriction() {
            if let Ok(bytes) = get_logon_sid_bytes(base) {
                let mut tmp = bytes;
                let psid = tmp.as_mut_ptr() as *mut c_void;
                allow_null_device(psid);
            }
            CloseHandle(base);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_legacy_session_acl_rules(
    permissions: &ResolvedWindowsSandboxPermissions,
    _codex_home: &Path,
    current_dir: &Path,
    env_map: &HashMap<String, String>,
    additional_deny_write_paths: &[PathBuf],
    acl_sids: LegacyAclSids<'_>,
) -> Result<()> {
    let AllowDenyPaths { allow, mut deny } =
        compute_allow_paths_for_permissions(permissions, current_dir, env_map);
    unsafe {
        for path in additional_deny_write_paths {
            // Explicit carveouts must exist before the command starts so the
            // sandbox cannot create them under a writable parent first.
            if !path.exists() {
                std::fs::create_dir_all(path)
                    .with_context(|| format!("create deny-write path {}", path.display()))?;
            }
            deny.insert(path.clone());
        }
        if let Some(readonly_sid) = acl_sids.readonly_sid {
            for p in &allow {
                let _ = add_allow_ace(p, readonly_sid.as_ptr());
            }
        } else {
            for p in &allow {
                let Some(root_sid) = matching_root_capability(p, acl_sids.write_root_sids) else {
                    continue;
                };
                let _ = add_allow_ace(p, root_sid.sid.as_ptr());
            }
        }
        for p in &deny {
            for root_sid in deny_root_capabilities_for_path(p, acl_sids.write_root_sids) {
                let _ = add_deny_write_ace(p, root_sid.sid.as_ptr());
            }
        }
        for root_sid in acl_sids.write_root_sids {
            allow_null_device(root_sid.sid.as_ptr());
        }
        if let Some(readonly_sid) = acl_sids.readonly_sid {
            allow_null_device(readonly_sid.as_ptr());
        }
        if !acl_sids.write_root_sids.is_empty()
            && let Some(workspace_sid) =
                matching_root_capability(current_dir, acl_sids.write_root_sids)
        {
            let canonical_cwd = canonicalize_path(current_dir);
            if is_command_cwd_root(&workspace_sid.root, &canonical_cwd) {
                let _ = protect_workspace_codex_dir(current_dir, workspace_sid.sid.as_ptr());
                let _ = protect_workspace_agents_dir(current_dir, workspace_sid.sid.as_ptr());
            }
        }
    }
    Ok(())
}
