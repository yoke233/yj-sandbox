//! macOS Seatbelt command generation.
//!
//! Ported from openai/codex `codex-rs/sandboxing/src/seatbelt.rs` (Apache-2.0)
//! and decoupled from `codex_protocol`, `codex_network_proxy`, and
//! `codex_utils_absolute_path`. Keep the policy-generation functions close to
//! upstream when syncing.

use crate::absolute_path::AbsolutePathBuf;
use crate::macos_permissions::FileSystemSandboxPolicy;
use crate::macos_permissions::NetworkSandboxPolicy;
use crate::macos_permissions::PROTECTED_METADATA_PATH_NAMES;
use crate::macos_permissions::WritableRoot;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::path::Path;
use std::path::PathBuf;
use tracing::warn;
use url::Url;

const MACOS_SEATBELT_BASE_POLICY: &str = include_str!("seatbelt_base_policy.sbpl");
const MACOS_SEATBELT_NETWORK_POLICY: &str = include_str!("seatbelt_network_policy.sbpl");
const MACOS_SEATBELT_PREFERENCES_POLICY: &str = include_str!("seatbelt_preferences_policy.sbpl");
const MACOS_RESTRICTED_READ_ONLY_PLATFORM_DEFAULTS: &str =
    include_str!("seatbelt_read_only_platform_defaults.sbpl");
// Ordinary processes need system scratch directories for compatibility, but filesystem helpers
// must not inherit scratch access beyond the paths their permission profile explicitly grants.
const MACOS_PROCESS_PLATFORM_DEFAULTS: &str = r#"
(allow file-read* (subpath "/Applications"))
(allow file-read* file-test-existence file-write* (subpath "/tmp"))
(allow file-read* file-write* (subpath "/private/tmp"))
(allow file-read* file-write* (subpath "/var/tmp"))
(allow file-read* file-write* (subpath "/private/var/tmp"))
"#;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum MacosSeatbeltProfile {
    #[default]
    Process,
    FileSystemHelper,
}

#[derive(Debug)]
pub(crate) enum SeatbeltPreparationError {
    FileSystem(String),
    EnvironmentNetworkProxy(String),
}

impl std::fmt::Display for SeatbeltPreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileSystem(message) | Self::EnvironmentNetworkProxy(message) => {
                f.write_str(message)
            }
        }
    }
}

/// When working with `sandbox-exec`, only consider `sandbox-exec` in `/usr/bin`
/// to defend against an attacker trying to inject a malicious version on the
/// PATH. If /usr/bin/sandbox-exec has been tampered with, then the attacker
/// already has root access.
pub const MACOS_PATH_TO_SEATBELT_EXECUTABLE: &str = "/usr/bin/sandbox-exec";

const PROXY_URL_ENV_KEYS: &[&str] = &[
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
];

#[derive(Debug)]
pub(crate) struct NetworkProxy {
    _private: (),
}

impl NetworkProxy {
    fn apply_to_env(&self, _env: &mut HashMap<String, String>) {}
    fn dangerously_allow_all_unix_sockets(&self) -> bool {
        false
    }
    fn allow_unix_sockets(&self) -> &[String] {
        &[]
    }
    fn allow_local_binding(&self) -> bool {
        false
    }
}

fn proxy_url_env_value<'a>(env: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    env.get(key).map(String::as_str)
}

fn has_proxy_url_env_vars(env: &HashMap<String, String>) -> bool {
    PROXY_URL_ENV_KEYS
        .iter()
        .any(|key| env.get(*key).is_some_and(|value| !value.trim().is_empty()))
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn proxy_scheme_default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "socks5" | "socks5h" | "socks4" | "socks4a" => 1080,
        _ => 80,
    }
}

fn proxy_loopback_ports_from_env(env: &HashMap<String, String>) -> Vec<u16> {
    let mut ports = BTreeSet::new();
    for key in PROXY_URL_ENV_KEYS {
        let Some(proxy_url) = proxy_url_env_value(env, key) else {
            continue;
        };
        let trimmed = proxy_url.trim();
        if trimmed.is_empty() {
            continue;
        }

        let candidate = if trimmed.contains("://") {
            trimmed.to_string()
        } else {
            format!("http://{trimmed}")
        };
        let Ok(parsed) = Url::parse(&candidate) else {
            continue;
        };
        let Some(host) = parsed.host_str() else {
            continue;
        };
        if !is_loopback_host(host) {
            continue;
        }

        let scheme = parsed.scheme().to_ascii_lowercase();
        let port = parsed
            .port()
            .unwrap_or_else(|| proxy_scheme_default_port(scheme.as_str()));
        ports.insert(port);
    }
    ports.into_iter().collect()
}

#[derive(Debug, Default)]
struct ProxyPolicyInputs {
    ports: Vec<u16>,
    has_proxy_config: bool,
    allow_local_binding: bool,
    unix_domain_socket_policy: UnixDomainSocketPolicy,
}

#[derive(Debug, Clone)]
// Keep allow-all and allowlist modes disjoint so we don't carry ignored state.
enum UnixDomainSocketPolicy {
    AllowAll,
    Restricted { allowed: Vec<AbsolutePathBuf> },
}

impl Default for UnixDomainSocketPolicy {
    fn default() -> Self {
        Self::Restricted { allowed: vec![] }
    }
}

#[derive(Debug, Clone)]
struct UnixSocketPathParam {
    index: usize,
    path: AbsolutePathBuf,
}

fn proxy_policy_inputs(
    network: Option<&NetworkProxy>,
    extra_allow_unix_sockets: &[AbsolutePathBuf],
) -> ProxyPolicyInputs {
    let extra_allowed = extra_allow_unix_sockets
        .iter()
        .filter_map(|socket_path| normalize_path_for_sandbox(socket_path.as_path()))
        .collect::<Vec<_>>();

    match network {
        Some(network) => {
            let mut env = HashMap::new();
            network.apply_to_env(&mut env);
            let unix_domain_socket_policy = if network.dangerously_allow_all_unix_sockets() {
                UnixDomainSocketPolicy::AllowAll
            } else {
                let mut allowed = network
                    .allow_unix_sockets()
                    .iter()
                    .filter_map(|socket_path| match normalize_path_for_sandbox(Path::new(socket_path)) {
                        Some(path) => Some(path),
                        None => {
                            warn!(
                                "ignoring network.allow_unix_sockets entry because it could not be normalized: {socket_path}"
                            );
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                allowed.extend(extra_allowed);
                UnixDomainSocketPolicy::Restricted { allowed }
            };
            ProxyPolicyInputs {
                ports: proxy_loopback_ports_from_env(&env),
                has_proxy_config: has_proxy_url_env_vars(&env),
                allow_local_binding: network.allow_local_binding(),
                unix_domain_socket_policy,
            }
        }
        None => ProxyPolicyInputs {
            unix_domain_socket_policy: UnixDomainSocketPolicy::Restricted {
                allowed: extra_allowed,
            },
            ..Default::default()
        },
    }
}

fn normalize_path_for_sandbox(path: &Path) -> Option<AbsolutePathBuf> {
    if !path.is_absolute() {
        return None;
    }

    let absolute_path = AbsolutePathBuf::from_absolute_path(path).ok()?;
    let normalized_path = absolute_path
        .as_path()
        .canonicalize()
        .ok()
        .and_then(|canonical_path| AbsolutePathBuf::from_absolute_path(canonical_path).ok());
    normalized_path.or(Some(absolute_path))
}

fn unix_socket_path_params(proxy: &ProxyPolicyInputs) -> Vec<UnixSocketPathParam> {
    let mut deduped_paths: BTreeMap<String, AbsolutePathBuf> = BTreeMap::new();
    let UnixDomainSocketPolicy::Restricted { allowed } = &proxy.unix_domain_socket_policy else {
        return vec![];
    };
    for path in allowed {
        deduped_paths
            .entry(path.to_string_lossy().to_string())
            .or_insert_with(|| path.clone());
    }

    deduped_paths
        .into_values()
        .enumerate()
        .map(|(index, path)| UnixSocketPathParam { index, path })
        .collect()
}

fn unix_socket_path_param_key(index: usize) -> String {
    format!("UNIX_SOCKET_PATH_{index}")
}

fn unix_socket_dir_params(proxy: &ProxyPolicyInputs) -> Vec<(String, PathBuf)> {
    unix_socket_path_params(proxy)
        .into_iter()
        .map(|param| {
            (
                unix_socket_path_param_key(param.index),
                param.path.into_path_buf(),
            )
        })
        .collect()
}

/// Returns zero or more complete Seatbelt policy lines for unix socket rules.
/// When non-empty, the returned string is newline-terminated so callers can
/// append it directly to larger policy blocks.
fn unix_socket_policy(proxy: &ProxyPolicyInputs) -> String {
    let socket_params = unix_socket_path_params(proxy);
    let has_unix_socket_access = matches!(
        proxy.unix_domain_socket_policy,
        UnixDomainSocketPolicy::AllowAll
    ) || !socket_params.is_empty();
    if !has_unix_socket_access {
        return String::new();
    }

    let mut policy = String::new();
    policy.push_str("(allow system-socket (socket-domain AF_UNIX))\n");
    if matches!(
        proxy.unix_domain_socket_policy,
        UnixDomainSocketPolicy::AllowAll
    ) {
        policy.push_str("(allow network-bind (local unix-socket))\n");
        policy.push_str("(allow network-outbound (remote unix-socket))\n");
        return policy;
    }

    for param in socket_params {
        let key = unix_socket_path_param_key(param.index);
        policy.push_str(&format!(
            "(allow network-bind (local unix-socket (subpath (param \"{key}\"))))\n"
        ));
        policy.push_str(&format!(
            "(allow network-outbound (remote unix-socket (subpath (param \"{key}\"))))\n"
        ));
    }
    policy
}

fn dynamic_network_policy_for_network(
    network_policy: NetworkSandboxPolicy,
    enforce_managed_network: bool,
    proxy: &ProxyPolicyInputs,
) -> String {
    let has_some_unix_socket_access = match &proxy.unix_domain_socket_policy {
        UnixDomainSocketPolicy::AllowAll => true,
        UnixDomainSocketPolicy::Restricted { allowed } => !allowed.is_empty(),
    };
    let should_use_restricted_network_policy = !proxy.ports.is_empty()
        || proxy.has_proxy_config
        || enforce_managed_network
        || (!network_policy.is_enabled() && has_some_unix_socket_access);
    if should_use_restricted_network_policy {
        let mut policy = String::new();
        if proxy.allow_local_binding {
            policy.push_str("; allow local binding and loopback traffic\n");
            policy.push_str("(allow network-bind (local ip \"*:*\"))\n");
            policy.push_str("(allow network-inbound (local ip \"localhost:*\"))\n");
            policy.push_str("(allow network-outbound (remote ip \"localhost:*\"))\n");
        }
        if proxy.allow_local_binding && !proxy.ports.is_empty() {
            policy.push_str("; allow DNS lookups while application traffic remains proxy-routed\n");
            policy.push_str("(allow network-outbound (remote ip \"*:53\"))\n");
        }
        for port in &proxy.ports {
            policy.push_str(&format!(
                "(allow network-outbound (remote ip \"localhost:{port}\"))\n"
            ));
        }
        let unix_socket_policy = unix_socket_policy(proxy);
        if !unix_socket_policy.is_empty() {
            policy.push_str("; allow unix domain sockets for local IPC\n");
            policy.push_str(&unix_socket_policy);
        }
        return format!("{policy}{MACOS_SEATBELT_NETWORK_POLICY}");
    }

    if proxy.has_proxy_config {
        // Proxy configuration is present but we could not infer any valid loopback endpoints.
        // Fail closed to avoid silently widening network access in proxy-enforced sessions.
        return String::new();
    }

    if enforce_managed_network {
        // Managed network requirements are active but no usable proxy endpoints
        // are available. Fail closed for network access.
        return String::new();
    }

    if network_policy.is_enabled() {
        // No proxy env is configured: retain the existing full-network behavior.
        let mut policy = String::from("(allow network-outbound)\n(allow network-inbound)\n");
        let unix_socket_policy = unix_socket_policy(proxy);
        if !unix_socket_policy.is_empty() {
            policy.push_str("; allow unix domain sockets for local IPC\n");
            policy.push_str(&unix_socket_policy);
        }
        format!("{policy}{MACOS_SEATBELT_NETWORK_POLICY}")
    } else {
        String::new()
    }
}

fn root_absolute_path() -> AbsolutePathBuf {
    match AbsolutePathBuf::from_absolute_path(Path::new("/")) {
        Ok(path) => path,
        Err(err) => panic!("root path must be absolute: {err}"),
    }
}

#[derive(Debug, Clone)]
struct SeatbeltAccessRoot {
    root: AbsolutePathBuf,
    excluded_subpaths: Vec<AbsolutePathBuf>,
    protected_metadata_names: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SeatbeltAccessKind {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SeatbeltPathMatch {
    Literal,
    Subpath,
}

#[derive(Debug)]
enum NormalizedWritableRoot {
    Subpath(AbsolutePathBuf),
    Literal(AbsolutePathBuf),
}

fn nested_symlink_component(path: &Path) -> Option<&Path> {
    // Keep top-level macOS aliases such as `/tmp -> /private/tmp` compatible,
    // but reject symlinks in user-controlled path components.
    path.ancestors().find(|ancestor| {
        let Ok(metadata) = std::fs::symlink_metadata(ancestor) else {
            return false;
        };
        metadata.file_type().is_symlink() && ancestor.parent().and_then(Path::parent).is_some()
    })
}

fn normalize_top_level_alias_for_sandbox(
    path: AbsolutePathBuf,
) -> Result<AbsolutePathBuf, SeatbeltPreparationError> {
    let Some(top_level) = path.as_path().ancestors().find(|ancestor| {
        ancestor.parent().is_some() && ancestor.parent().and_then(Path::parent).is_none()
    }) else {
        return Ok(path);
    };
    if !std::fs::symlink_metadata(top_level).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Ok(path);
    }

    let canonical_top_level = top_level.canonicalize().map_err(|err| {
        SeatbeltPreparationError::FileSystem(format!(
            "failed to normalize top-level alias {} for Seatbelt: {err}",
            top_level.display()
        ))
    })?;
    let suffix = path.as_path().strip_prefix(top_level).map_err(|err| {
        SeatbeltPreparationError::FileSystem(format!(
            "failed to preserve path {} after normalizing {}: {err}",
            path.display(),
            top_level.display()
        ))
    })?;
    AbsolutePathBuf::from_absolute_path(canonical_top_level.join(suffix)).map_err(|err| {
        SeatbeltPreparationError::FileSystem(format!(
            "failed to normalize top-level alias for path {}: {err}",
            path.display()
        ))
    })
}

fn normalize_writable_root_for_sandbox(
    root: AbsolutePathBuf,
) -> Result<NormalizedWritableRoot, SeatbeltPreparationError> {
    if let Some(symlink) = nested_symlink_component(root.as_path()) {
        return Err(SeatbeltPreparationError::FileSystem(format!(
            "writable root {} contains symlink component {}; symlinked writable roots are not supported",
            root.display(),
            symlink.display()
        )));
    }

    // Resolve only top-level system aliases such as `/tmp -> /private/tmp`.
    // Deeper components can be mutated by an already-running sandboxed process,
    // so following them here would turn a path check into a new authority grant.
    let normalized = normalize_top_level_alias_for_sandbox(root)?;

    let metadata = match std::fs::symlink_metadata(normalized.as_path()) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(NormalizedWritableRoot::Subpath(normalized));
        }
        Err(err) => {
            return Err(SeatbeltPreparationError::FileSystem(format!(
                "failed to inspect Seatbelt writable root {}: {err}",
                normalized.display()
            )));
        }
    };
    if metadata.is_dir() {
        return Ok(NormalizedWritableRoot::Subpath(normalized));
    }

    Ok(NormalizedWritableRoot::Literal(normalized))
}

fn build_seatbelt_access_policy(
    access_kind: SeatbeltAccessKind,
    roots: Vec<SeatbeltAccessRoot>,
) -> Result<(String, Vec<(String, PathBuf)>), SeatbeltPreparationError> {
    let mut policy_components = Vec::new();
    let mut root_anchor_denies = Vec::new();
    let mut params = Vec::new();
    let (action, param_prefix) = match access_kind {
        SeatbeltAccessKind::Read => ("file-read*", "READABLE_ROOT"),
        SeatbeltAccessKind::Write => ("file-write*", "WRITABLE_ROOT"),
    };

    for (index, access_root) in roots.into_iter().enumerate() {
        let (root, path_match) = match access_kind {
            SeatbeltAccessKind::Read => {
                let root = normalize_path_for_sandbox(access_root.root.as_path())
                    .unwrap_or(access_root.root);
                (root, SeatbeltPathMatch::Subpath)
            }
            SeatbeltAccessKind::Write => {
                match normalize_writable_root_for_sandbox(access_root.root)? {
                    NormalizedWritableRoot::Subpath(root) => (root, SeatbeltPathMatch::Subpath),
                    NormalizedWritableRoot::Literal(root) => (root, SeatbeltPathMatch::Literal),
                }
            }
        };
        let root_param = format!("{param_prefix}_{index}");
        params.push((root_param.clone(), root.clone().into_path_buf()));
        if access_kind == SeatbeltAccessKind::Write {
            // A sandboxed process must not be able to replace an authority
            // boundary that will be reused to build the next sandbox policy.
            root_anchor_denies.push(format!(
                "(deny file-write-unlink (require-all (literal (param \"{root_param}\")) (vnode-type DIRECTORY)))"
            ));
        }
        let root_filter = match path_match {
            SeatbeltPathMatch::Literal => format!("(literal (param \"{root_param}\"))"),
            SeatbeltPathMatch::Subpath => format!("(subpath (param \"{root_param}\"))"),
        };

        if access_root.excluded_subpaths.is_empty()
            && access_root.protected_metadata_names.is_empty()
        {
            policy_components.push(root_filter);
            continue;
        }

        let mut require_parts = vec![root_filter];
        for (excluded_index, excluded_subpath) in
            access_root.excluded_subpaths.into_iter().enumerate()
        {
            let excluded_param = format!("{param_prefix}_{index}_EXCLUDED_{excluded_index}");
            let excluded_subpaths = match access_kind {
                SeatbeltAccessKind::Read => vec![(
                    excluded_param.clone(),
                    normalize_path_for_sandbox(excluded_subpath.as_path())
                        .unwrap_or(excluded_subpath),
                )],
                SeatbeltAccessKind::Write => {
                    let logical = normalize_top_level_alias_for_sandbox(excluded_subpath)?;
                    let resolved = normalize_path_for_sandbox(logical.as_path())
                        .filter(|resolved| resolved != &logical);
                    let mut paths = vec![(excluded_param.clone(), logical)];
                    if let Some(resolved) = resolved {
                        paths.push((format!("{excluded_param}_RESOLVED"), resolved));
                    }
                    paths
                }
            };
            for (excluded_param, excluded_subpath) in excluded_subpaths {
                params.push((excluded_param.clone(), excluded_subpath.into_path_buf()));
                // Exclude both the exact protected path and anything beneath it.
                // `subpath` alone leaves a gap for first-time creation of the
                // protected directory itself, such as `mkdir .codex`.
                require_parts.push(format!(
                    "(require-not (literal (param \"{excluded_param}\")))"
                ));
                require_parts.push(format!(
                    "(require-not (subpath (param \"{excluded_param}\")))"
                ));
            }
        }
        for metadata_name in access_root.protected_metadata_names {
            let regex =
                seatbelt_protected_metadata_name_regex(&root, &metadata_name).replace('"', "\\\"");
            require_parts.push(format!(r#"(require-not (regex #"{regex}"))"#));
        }
        policy_components.push(format!("(require-all {} )", require_parts.join(" ")));
    }

    if policy_components.is_empty() {
        Ok((String::new(), Vec::new()))
    } else {
        let mut policies = vec![format!(
            "(allow {action}\n{}\n)",
            policy_components.join(" ")
        )];
        policies.extend(root_anchor_denies);
        Ok((policies.join("\n"), params))
    }
}

fn seatbelt_protected_metadata_name_regex(root: &AbsolutePathBuf, name: &str) -> String {
    let mut root = root.to_string_lossy().to_string();
    while root.len() > 1 && root.ends_with('/') {
        root.pop();
    }
    let root = regex_lite::escape(&root);
    let name = regex_lite::escape(name);
    if root == "/" {
        format!(r#"^/{name}(/.*)?$"#)
    } else {
        format!(r#"^{root}/{name}(/.*)?$"#)
    }
}

fn protected_metadata_names_for_writable_root(
    file_system_sandbox_policy: &FileSystemSandboxPolicy,
    writable_root: &WritableRoot,
    cwd: &Path,
) -> Vec<String> {
    let mut names = writable_root.protected_metadata_names.clone();
    for name in PROTECTED_METADATA_PATH_NAMES {
        if names.iter().any(|existing| existing == name) {
            continue;
        }
        let path = writable_root.root.join(*name);
        if !file_system_sandbox_policy.can_write_local_path_with_cwd(path.as_path(), cwd) {
            names.push((*name).to_string());
        }
    }
    names
}

fn build_seatbelt_unreadable_glob_policy(
    file_system_sandbox_policy: &FileSystemSandboxPolicy,
    cwd: &Path,
) -> String {
    // Seatbelt does not understand the filesystem policy's glob syntax directly.
    // Convert each unreadable pattern into anchored read/write denies. Also deny
    // renaming directories that could contain matches so the protected files
    // cannot be moved beyond the path where the glob applies.
    let unreadable_globs = file_system_sandbox_policy.get_unreadable_globs_with_cwd(cwd);
    if unreadable_globs.is_empty() {
        return String::new();
    }
    let mut policy_components = Vec::new();
    for pattern in unreadable_globs {
        let mut patterns = BTreeSet::from([pattern.clone()]);
        if let Some(pattern) = canonicalize_glob_static_prefix_for_sandbox(&pattern) {
            patterns.insert(pattern);
        }
        for pattern in patterns {
            let Some(regex) = seatbelt_regex_for_unreadable_glob(&pattern) else {
                continue;
            };
            let regex = regex.replace('"', "\\\"");
            policy_components.push(format!(r#"(deny file-read* (regex #"{regex}"))"#));
            policy_components.push(format!(r#"(deny file-write* (regex #"{regex}"))"#));
            for ancestor in Path::new(&pattern).ancestors().skip(1) {
                let Some(regex) = ancestor
                    .to_str()
                    .and_then(|path| seatbelt_regex_for_glob(path, GlobMatch::Exact))
                else {
                    continue;
                };
                let regex = regex.replace('"', "\\\"");
                policy_components.push(format!(
                    r#"(deny file-write-unlink (require-all (vnode-type DIRECTORY) (regex #"{regex}")))"#
                ));
            }
        }
    }

    policy_components.join("\n")
}

fn canonicalize_glob_static_prefix_for_sandbox(pattern: &str) -> Option<String> {
    let first_glob_index = pattern
        .char_indices()
        .find_map(|(index, ch)| matches!(ch, '*' | '?' | '[' | ']' | '{' | '\\').then_some(index));
    let Some(first_glob_index) = first_glob_index else {
        return normalize_path_for_sandbox(Path::new(pattern))
            .map(|path| path.to_string_lossy().to_string());
    };

    let static_prefix = &pattern[..first_glob_index];
    let prefix_end = if static_prefix.ends_with('/') {
        static_prefix.len() - 1
    } else {
        static_prefix.rfind('/').unwrap_or(0)
    };
    if prefix_end == 0 {
        return None;
    }

    let root = normalize_path_for_sandbox(Path::new(&pattern[..prefix_end]))?;
    let root = root.to_string_lossy();
    let suffix = &pattern[prefix_end..];
    let normalized_pattern = format!("{root}{suffix}");
    (normalized_pattern != pattern).then_some(normalized_pattern)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GlobMatch {
    Exact,
    Subtree,
}

fn seatbelt_regex_for_unreadable_glob(pattern: &str) -> Option<String> {
    seatbelt_regex_for_glob(pattern, GlobMatch::Subtree)
}

fn seatbelt_regex_for_glob(pattern: &str, glob_match: GlobMatch) -> Option<String> {
    if pattern.is_empty() {
        return None;
    }

    // Translate the supported git-style glob subset into a Seatbelt regex:
    // `*` and `?` stay within one path component, `**/` can consume zero or
    // more components, closed character classes remain character classes,
    // brace groups become alternations, and backslashes escape metacharacters.
    // Literal patterns also match descendants unless exact matching is requested.
    let mut regex = String::from("^");
    let mut chars = pattern.chars().collect::<VecDeque<_>>();
    let mut saw_glob = false;
    let mut alternate_depth = 0;

    while let Some(ch) = chars.pop_front() {
        match ch {
            '*' => {
                saw_glob = true;
                if chars.front() == Some(&'*') {
                    chars.pop_front();
                    if chars.front() == Some(&'/') {
                        chars.pop_front();
                        regex.push_str("(.*/)?");
                    } else {
                        regex.push_str(".*");
                    }
                } else {
                    regex.push_str("[^/]*");
                }
            }
            '?' => {
                saw_glob = true;
                regex.push_str("[^/]");
            }
            '\\' => {
                if let Some(escaped) = chars.pop_front() {
                    regex.push_str(&regex_lite::escape(&escaped.to_string()));
                } else {
                    regex.push_str("\\\\");
                }
            }
            '{' => {
                saw_glob = true;
                alternate_depth += 1;
                regex.push('(');
            }
            '}' if alternate_depth > 0 => {
                alternate_depth -= 1;
                regex.push(')');
            }
            ',' if alternate_depth > 0 => regex.push('|'),
            '[' => {
                saw_glob = true;
                let mut class = Vec::new();
                let mut closed = false;
                while let Some(class_ch) = chars.pop_front() {
                    if class_ch == ']' {
                        closed = true;
                        break;
                    }
                    class.push(class_ch);
                }
                if !closed {
                    regex.push_str("\\[");
                    for class_ch in class.into_iter().rev() {
                        chars.push_front(class_ch);
                    }
                    continue;
                }

                regex.push('[');
                let mut class_chars = class.into_iter();
                if let Some(first) = class_chars.next() {
                    match first {
                        '!' => regex.push('^'),
                        '^' => regex.push_str("\\^"),
                        _ => regex.push(first),
                    }
                }
                for class_ch in class_chars {
                    match class_ch {
                        '\\' => regex.push_str("\\\\"),
                        _ => regex.push(class_ch),
                    }
                }
                regex.push(']');
            }
            ']' => {
                saw_glob = true;
                regex.push_str("\\]");
            }
            _ => regex.push_str(&regex_lite::escape(&ch.to_string())),
        }
    }

    // Path ancestors can end inside a brace alternative when a branch contains
    // a separator, such as `/repo/{private/nested,other}` -> `/repo/{private`.
    // Close those partial groups so their directory prefixes remain protected.
    for _ in 0..alternate_depth {
        regex.push(')');
    }

    if !saw_glob && glob_match == GlobMatch::Subtree {
        regex.push_str("(/.*)?");
    }
    regex.push('$');
    Some(regex)
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
pub struct CreateSeatbeltCommandArgsParams<'a> {
    pub command: Vec<String>,
    pub file_system_sandbox_policy: &'a FileSystemSandboxPolicy,
    pub network_sandbox_policy: NetworkSandboxPolicy,
    pub sandbox_policy_cwd: &'a Path,
    pub enforce_managed_network: bool,
    pub network: Option<&'a NetworkProxy>,
    pub extra_allow_unix_sockets: &'a [AbsolutePathBuf],
}

pub fn create_seatbelt_command_args(
    args: CreateSeatbeltCommandArgsParams<'_>,
) -> Result<Vec<String>, String> {
    create_seatbelt_command_args_with_profile(args, MacosSeatbeltProfile::Process)
        .map_err(|err| err.to_string())
}

pub(crate) fn create_seatbelt_command_args_with_profile(
    args: CreateSeatbeltCommandArgsParams<'_>,
    profile: MacosSeatbeltProfile,
) -> Result<Vec<String>, SeatbeltPreparationError> {
    let CreateSeatbeltCommandArgsParams {
        command,
        file_system_sandbox_policy,
        network_sandbox_policy,
        sandbox_policy_cwd,
        enforce_managed_network,
        network,
        extra_allow_unix_sockets,
    } = args;

    let unreadable_roots =
        file_system_sandbox_policy.get_unreadable_roots_with_cwd(sandbox_policy_cwd);
    let writable_roots = file_system_sandbox_policy
        .get_writable_roots_with_cwd_preserving_mutable_paths(sandbox_policy_cwd);
    // Protect ancestors of read-only paths so renaming a writable directory
    // cannot move its descendants outside their policy carveouts.
    let mut protected_ancestors = BTreeSet::new();
    for writable_root in &writable_roots {
        let root = normalize_path_for_sandbox(writable_root.root.as_path())
            .unwrap_or_else(|| writable_root.root.clone());
        for protected_directory in writable_root.read_only_subpaths.iter().filter_map(|path| {
            let normalized =
                normalize_path_for_sandbox(path.as_path()).unwrap_or_else(|| path.clone());
            normalized.as_path().parent().map(Path::to_path_buf)
        }) {
            for ancestor in protected_directory.ancestors() {
                if !ancestor.starts_with(root.as_path()) {
                    break;
                }
                protected_ancestors.insert(ancestor.to_path_buf());
            }
        }
    }
    let protected_ancestor_params: Vec<(String, PathBuf)> = protected_ancestors
        .into_iter()
        .enumerate()
        .map(|(index, path)| (format!("PROTECTED_ANCESTOR_{index}"), path))
        .collect();
    let (file_write_policy, file_write_dir_params) =
        if file_system_sandbox_policy.has_full_disk_write_access() {
            if unreadable_roots.is_empty() {
                // Allegedly, this is more permissive than `(allow file-write*)`.
                (
                    r#"(allow file-write* (regex #"^/"))"#.to_string(),
                    Vec::new(),
                )
            } else {
                build_seatbelt_access_policy(
                    SeatbeltAccessKind::Write,
                    vec![SeatbeltAccessRoot {
                        root: root_absolute_path(),
                        excluded_subpaths: unreadable_roots.clone(),
                        protected_metadata_names: Vec::new(),
                    }],
                )?
            }
        } else {
            build_seatbelt_access_policy(
                SeatbeltAccessKind::Write,
                writable_roots
                    .into_iter()
                    .map(|root| SeatbeltAccessRoot {
                        protected_metadata_names: protected_metadata_names_for_writable_root(
                            file_system_sandbox_policy,
                            &root,
                            sandbox_policy_cwd,
                        ),
                        root: root.root,
                        excluded_subpaths: root.read_only_subpaths,
                    })
                    .collect(),
            )?
        };

    let (file_read_policy, file_read_dir_params) =
        if file_system_sandbox_policy.has_full_disk_read_access() {
            if unreadable_roots.is_empty() {
                (
                    "; allow read-only file operations\n(allow file-read*)".to_string(),
                    Vec::new(),
                )
            } else {
                let (policy, params) = build_seatbelt_access_policy(
                    SeatbeltAccessKind::Read,
                    vec![SeatbeltAccessRoot {
                        root: root_absolute_path(),
                        excluded_subpaths: unreadable_roots,
                        protected_metadata_names: Vec::new(),
                    }],
                )?;
                (
                    format!("; allow read-only file operations\n{policy}"),
                    params,
                )
            }
        } else {
            let (policy, params) = build_seatbelt_access_policy(
                SeatbeltAccessKind::Read,
                file_system_sandbox_policy
                    .get_readable_roots_with_cwd(sandbox_policy_cwd)
                    .into_iter()
                    .map(|root| SeatbeltAccessRoot {
                        excluded_subpaths: unreadable_roots
                            .iter()
                            .filter(|path| path.as_path().starts_with(root.as_path()))
                            .cloned()
                            .collect(),
                        protected_metadata_names: Vec::new(),
                        root,
                    })
                    .collect(),
            )?;
            if policy.is_empty() {
                (String::new(), params)
            } else {
                (
                    format!("; allow read-only file operations\n{policy}"),
                    params,
                )
            }
        };

    let proxy = proxy_policy_inputs(network, extra_allow_unix_sockets);
    let network_policy =
        dynamic_network_policy_for_network(network_sandbox_policy, enforce_managed_network, &proxy);

    let include_platform_defaults = file_system_sandbox_policy.include_platform_defaults();
    let deny_read_policy =
        build_seatbelt_unreadable_glob_policy(file_system_sandbox_policy, sandbox_policy_cwd);
    let mut policy_sections = vec![
        MACOS_SEATBELT_BASE_POLICY.to_string(),
        file_read_policy,
        file_write_policy,
        network_policy,
    ];
    if file_system_sandbox_policy.has_full_disk_read_access() {
        policy_sections.push(MACOS_SEATBELT_PREFERENCES_POLICY.to_string());
    }
    if include_platform_defaults {
        policy_sections.push(MACOS_RESTRICTED_READ_ONLY_PLATFORM_DEFAULTS.to_string());
        if profile == MacosSeatbeltProfile::Process {
            policy_sections.push(MACOS_PROCESS_PLATFORM_DEFAULTS.to_string());
        }
    }
    policy_sections.push(deny_read_policy);
    // Renaming an allowed ancestor relocates its protected descendants past
    // their pathname carveouts. Keep these denies last so no broader allowance
    // can reopen the unlink operation used by rename.
    policy_sections.extend(
        protected_ancestor_params.iter().map(|(key, _)| {
            format!(
                "(deny file-write-unlink (require-all (vnode-type DIRECTORY) (literal (param \"{key}\"))))"
            )
        }),
    );

    let full_policy = policy_sections.join("\n");

    let dir_params = [
        file_read_dir_params,
        file_write_dir_params,
        protected_ancestor_params,
        unix_socket_dir_params(&proxy),
    ]
    .concat();

    let mut seatbelt_args: Vec<String> = vec!["-p".to_string(), full_policy];
    let definition_args = dir_params
        .into_iter()
        .map(|(key, value): (String, PathBuf)| {
            format!("-D{key}={value}", value = value.to_string_lossy())
        });
    seatbelt_args.extend(definition_args);
    seatbelt_args.push("--".to_string());
    seatbelt_args.extend(command);
    Ok(seatbelt_args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos_permissions::WritableRoot;

    #[test]
    fn workspace_write_profile_protects_metadata_names() {
        let cwd = std::env::current_dir().expect("cwd");
        let root = AbsolutePathBuf::from_absolute_path(&cwd).expect("absolute cwd");
        let policy = FileSystemSandboxPolicy::workspace_write_full_read(vec![WritableRoot {
            root,
            read_only_subpaths: Vec::new(),
            protected_metadata_names: vec![".git".to_string()],
        }]);

        let args = create_seatbelt_command_args(CreateSeatbeltCommandArgsParams {
            command: vec!["sh".to_string(), "-lc".to_string(), "true".to_string()],
            file_system_sandbox_policy: &policy,
            network_sandbox_policy: NetworkSandboxPolicy::Restricted,
            sandbox_policy_cwd: &cwd,
            enforce_managed_network: false,
            network: None,
            extra_allow_unix_sockets: &[],
        })
        .expect("build Seatbelt arguments");

        assert_eq!(args.first().map(String::as_str), Some("-p"));
        let profile = args.get(1).expect("profile");
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(allow file-write*"));
        assert!(profile.contains(".git"));
        assert!(args.iter().any(|arg| arg == "--"));
    }

    #[test]
    fn writable_root_policy_denies_renaming_authority_boundary() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path();
        let root = AbsolutePathBuf::from_absolute_path(cwd).expect("absolute root");
        let policy = FileSystemSandboxPolicy::workspace_write_full_read(vec![WritableRoot {
            root,
            read_only_subpaths: Vec::new(),
            protected_metadata_names: Vec::new(),
        }]);

        let args = create_seatbelt_command_args(CreateSeatbeltCommandArgsParams {
            command: vec!["true".to_string()],
            file_system_sandbox_policy: &policy,
            network_sandbox_policy: NetworkSandboxPolicy::Restricted,
            sandbox_policy_cwd: cwd,
            enforce_managed_network: false,
            network: None,
            extra_allow_unix_sockets: &[],
        })
        .expect("build Seatbelt arguments");

        assert!(args[1].contains(
            "(deny file-write-unlink (require-all (literal (param \"WRITABLE_ROOT_0\")) (vnode-type DIRECTORY)))"
        ));
    }

    #[test]
    fn protected_subpath_ancestors_cannot_be_renamed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path();
        std::fs::create_dir_all(cwd.join("parent/protected")).expect("create protected directory");
        let protected = AbsolutePathBuf::from_absolute_path(cwd.join("parent/protected"))
            .expect("absolute protected path");
        let policy = FileSystemSandboxPolicy::workspace_write_full_read(vec![WritableRoot {
            root: AbsolutePathBuf::from_absolute_path(cwd).expect("absolute root"),
            read_only_subpaths: vec![protected],
            protected_metadata_names: Vec::new(),
        }]);

        let args = create_seatbelt_command_args(CreateSeatbeltCommandArgsParams {
            command: vec!["true".to_string()],
            file_system_sandbox_policy: &policy,
            network_sandbox_policy: NetworkSandboxPolicy::Restricted,
            sandbox_policy_cwd: cwd,
            enforce_managed_network: false,
            network: None,
            extra_allow_unix_sockets: &[],
        })
        .expect("build Seatbelt arguments");

        assert!(args[1].contains(
            "(deny file-write-unlink (require-all (vnode-type DIRECTORY) (literal (param \"PROTECTED_ANCESTOR_"
        ));
    }

    #[test]
    fn filesystem_helper_profile_does_not_inherit_process_scratch_access() {
        let cwd = std::env::current_dir().expect("cwd");
        let policy = FileSystemSandboxPolicy::read_only_full_disk();
        let params = || CreateSeatbeltCommandArgsParams {
            command: vec!["true".to_string()],
            file_system_sandbox_policy: &policy,
            network_sandbox_policy: NetworkSandboxPolicy::Restricted,
            sandbox_policy_cwd: &cwd,
            enforce_managed_network: false,
            network: None,
            extra_allow_unix_sockets: &[],
        };

        let process =
            create_seatbelt_command_args_with_profile(params(), MacosSeatbeltProfile::Process)
                .expect("build process profile");
        let helper = create_seatbelt_command_args_with_profile(
            params(),
            MacosSeatbeltProfile::FileSystemHelper,
        )
        .expect("build helper profile");
        let scratch_rule = "(allow file-read* file-test-existence file-write* (subpath \"/tmp\"))";

        assert!(process[1].contains(scratch_rule));
        assert!(!helper[1].contains(scratch_rule));
    }
}
