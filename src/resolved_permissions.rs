//! Resolved sandbox permissions (decoupled from `codex_protocol`).
//!
//! Upstream Codex builds this from a `PermissionProfile` / `FileSystemSandboxPolicy`.
//! This crate has no dependency on those types, so the same public surface
//! (`ResolvedSandboxPermissions`, `WindowsWritableRoot`, the
//! `*_for_cwd` accessors) is reproduced over a small self-contained
//! representation. Windows behaviour matches Codex's non-elevated path:
//!
//! * full-disk **read**; only **writes** are constrained,
//! * `:workspace_roots` are resolved *cwd-aware* — only the workspace root that
//!   contains the command's cwd is made writable,
//! * extra writable roots and (optionally) `TEMP`/`TMP` are always writable,
//! * `.git` / `.codex` / `.agents` inside any writable root stay read-only.

use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;

use crate::path_normalization::canonicalize_path;
#[cfg(target_os = "macos")]
use crate::{
    absolute_path::AbsolutePathBuf,
    macos_permissions::{
        FileSystemSandboxPolicy, NetworkSandboxPolicy, WritableRoot as MacosWritableRoot,
    },
};

/// Subdirectories denied write inside every writable root, matching Codex.
const PROTECTED_SUBDIRS: &[&str] = &[".git", ".codex", ".agents"];

/// A writable root plus the subpaths beneath it that must stay read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsWritableRoot {
    pub root: PathBuf,
    pub read_only_subpaths: Vec<PathBuf>,
}

/// Windows-local view of the runtime permission profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSandboxPermissions {
    /// Workspace/project roots; only the one containing the cwd becomes writable.
    workspace_roots: Vec<PathBuf>,
    /// Roots that are writable regardless of cwd.
    extra_writable_roots: Vec<PathBuf>,
    /// Treat `TEMP`/`TMP` as writable.
    include_temp: bool,
    /// Block network access (env-based soft block).
    block_network: bool,
}

/// Backwards-compatible name for the originally Windows-only public API.
pub type ResolvedWindowsSandboxPermissions = ResolvedSandboxPermissions;

impl ResolvedSandboxPermissions {
    /// Full-disk read, no writes anywhere.
    pub fn read_only(block_network: bool) -> Self {
        Self {
            workspace_roots: Vec::new(),
            extra_writable_roots: Vec::new(),
            include_temp: false,
            block_network,
        }
    }

    /// Full-disk read; writes limited to the workspace root containing the cwd,
    /// plus `extra_writable_roots` and (when `include_temp`) the temp dirs.
    pub fn workspace_write(
        workspace_roots: Vec<PathBuf>,
        extra_writable_roots: Vec<PathBuf>,
        include_temp: bool,
        block_network: bool,
    ) -> Self {
        Self {
            workspace_roots,
            extra_writable_roots,
            include_temp,
            block_network,
        }
    }

    /// The restricted token grants full-disk read in every supported profile.
    pub fn has_full_disk_read_access(&self) -> bool {
        true
    }

    /// Whether to apply the env-based network block.
    pub fn should_apply_network_block(&self) -> bool {
        self.block_network
    }

    /// Whether any write capability is in effect for this invocation.
    pub fn uses_write_capabilities_for_cwd(
        &self,
        cwd: &Path,
        env_map: &HashMap<String, String>,
    ) -> bool {
        !self.writable_roots_for_cwd(cwd, env_map).is_empty()
    }

    /// Effective writable roots for `cwd`, each annotated with read-only subpaths.
    ///
    /// Workspace roots are filtered to those containing `cwd`; extra roots and
    /// temp dirs are always included. Deduped by canonical path.
    pub fn writable_roots_for_cwd(
        &self,
        cwd: &Path,
        env_map: &HashMap<String, String>,
    ) -> Vec<WindowsWritableRoot> {
        let canonical_cwd = canonicalize_path(cwd);
        let mut out: Vec<WindowsWritableRoot> = Vec::new();

        for root in &self.workspace_roots {
            let canonical = canonicalize_path(root);
            if canonical_cwd.starts_with(&canonical) {
                self.push_root(&mut out, canonical);
            }
        }
        for root in &self.extra_writable_roots {
            self.push_root(&mut out, canonicalize_path(root));
        }
        if self.include_temp {
            for temp_root in windows_temp_env_roots(env_map) {
                self.push_root(&mut out, temp_root);
            }
        }

        out
    }

    fn push_root(&self, out: &mut Vec<WindowsWritableRoot>, root: PathBuf) {
        if out.iter().any(|existing| existing.root == root) {
            return;
        }
        let read_only_subpaths = protected_subpaths(&root);
        out.push(WindowsWritableRoot {
            root,
            read_only_subpaths,
        });
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn macos_file_system_policy_for_cwd(
        &self,
        cwd: &Path,
        env_map: &HashMap<String, String>,
    ) -> FileSystemSandboxPolicy {
        let writable_roots = self.macos_writable_roots_for_cwd(cwd, env_map);
        if writable_roots.is_empty() {
            FileSystemSandboxPolicy::read_only_full_disk()
        } else {
            FileSystemSandboxPolicy::workspace_write_full_read(writable_roots)
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn macos_network_policy(&self) -> NetworkSandboxPolicy {
        if self.block_network {
            NetworkSandboxPolicy::Restricted
        } else {
            NetworkSandboxPolicy::Enabled
        }
    }

    #[cfg(target_os = "macos")]
    fn macos_writable_roots_for_cwd(
        &self,
        cwd: &Path,
        env_map: &HashMap<String, String>,
    ) -> Vec<MacosWritableRoot> {
        let cwd_abs = absolute_cwd(cwd);
        let canonical_cwd = canonicalize_path(&cwd_abs);
        let mut out = Vec::new();

        for root in &self.workspace_roots {
            let root = absolute_for_cwd(root, &canonical_cwd);
            let canonical = canonicalize_path(&root);
            if canonical_cwd.starts_with(&canonical) {
                push_macos_root(&mut out, canonical);
            }
        }
        for root in &self.extra_writable_roots {
            let root = absolute_for_cwd(root, &canonical_cwd);
            push_macos_root(&mut out, canonicalize_path(&root));
        }
        if self.include_temp {
            for temp_root in macos_temp_env_roots(env_map) {
                push_macos_root(&mut out, canonicalize_path(&temp_root));
            }
        }

        out
    }
}

/// `.git` / `.codex` / `.agents` under `root`, when they exist on disk.
fn protected_subpaths(root: &Path) -> Vec<PathBuf> {
    PROTECTED_SUBDIRS
        .iter()
        .map(|name| root.join(name))
        .filter(|path| path.exists())
        .collect()
}

/// Resolve absolute `TEMP`/`TMP` directories from the child env (falling back to
/// the parent process env).
fn windows_temp_env_roots(env_map: &HashMap<String, String>) -> Vec<PathBuf> {
    ["TEMP", "TMP"]
        .into_iter()
        .filter_map(|key| {
            env_map
                .get(key)
                .map(|value| PathBuf::from(value.as_str()))
                .or_else(|| std::env::var_os(key).map(PathBuf::from))
        })
        .filter(|path| path.is_absolute())
        .collect()
}

#[cfg(target_os = "macos")]
fn macos_temp_env_roots(env_map: &HashMap<String, String>) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(tmpdir) = env_map
        .get("TMPDIR")
        .map(|value| PathBuf::from(value.as_str()))
        .or_else(|| std::env::var_os("TMPDIR").map(PathBuf::from))
        .filter(|path| path.is_absolute())
    {
        roots.push(tmpdir);
    }
    roots.push(PathBuf::from("/tmp"));
    roots
}

#[cfg(target_os = "macos")]
fn absolute_cwd(cwd: &Path) -> PathBuf {
    if cwd.is_absolute() {
        cwd.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(cwd)
    }
}

#[cfg(target_os = "macos")]
fn absolute_for_cwd(path: &Path, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

#[cfg(target_os = "macos")]
fn push_macos_root(out: &mut Vec<MacosWritableRoot>, root: PathBuf) {
    if out.iter().any(|existing| existing.root.as_path() == root) {
        return;
    }
    let Ok(root) = AbsolutePathBuf::from_absolute_path(root) else {
        return;
    };
    let read_only_subpaths = protected_subpaths(root.as_path())
        .into_iter()
        .filter_map(|path| AbsolutePathBuf::from_absolute_path(path).ok())
        .collect();
    out.push(MacosWritableRoot {
        root,
        read_only_subpaths,
        protected_metadata_names: PROTECTED_SUBDIRS
            .iter()
            .map(|name| (*name).to_string())
            .collect(),
    });
}

/// Writable roots that should receive capability ACLs.
///
/// Mirrors Codex's `setup::effective_write_roots_for_permissions` for the
/// non-elevated path: when `write_roots_override` is supplied (the capture path
/// passes the allow-set it already computed) those roots are used; otherwise the
/// roots come from `permissions`. Roots are canonicalized, filtered to existing
/// paths, deduped, and the sandbox state directory is never made writable.
#[cfg(windows)]
pub(crate) fn effective_write_roots_for_permissions(
    permissions: &ResolvedSandboxPermissions,
    command_cwd: &Path,
    env_map: &HashMap<String, String>,
    state_dir: &Path,
    write_roots_override: Option<&[PathBuf]>,
) -> Vec<PathBuf> {
    let roots = match write_roots_override {
        Some(roots) => canonical_existing(roots.iter().cloned()),
        None => canonical_existing(
            permissions
                .writable_roots_for_cwd(command_cwd, env_map)
                .into_iter()
                .map(|root| root.root),
        ),
    };
    let canonical_state = canonicalize_path(state_dir);
    roots
        .into_iter()
        .filter(|root| !root.starts_with(&canonical_state))
        .collect()
}

#[cfg(windows)]
fn canonical_existing(roots: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut seen: Vec<PathBuf> = Vec::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        let canonical = canonicalize_path(&root);
        if !seen.iter().any(|existing| existing == &canonical) {
            seen.push(canonical);
        }
    }
    seen
}
