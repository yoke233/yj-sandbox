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
const MACOS_RESTRICTED_READ_ONLY_PLATFORM_DEFAULTS: &str =
    include_str!("restricted_read_only_platform_defaults.sbpl");

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

/// Minimal local stand-in for Codex's managed network proxy.
///
/// yj-sandbox currently does not construct this type; it remains in the
/// signature so future Codex syncs keep the same shape around proxy-specific
/// Seatbelt policy.
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
enum UnixDomainSocketPolicy {
    AllowAll,
    Restricted { allowed: Vec<AbsolutePathBuf> },
}

impl Default for UnixDomainSocketPolicy {
    fn default() -> Self {
        Self::Restricted {
            allowed: Vec::new(),
        }
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

    if proxy.has_proxy_config || enforce_managed_network {
        return String::new();
    }

    if network_policy.is_enabled() {
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

fn build_seatbelt_access_policy(
    action: &str,
    param_prefix: &str,
    roots: Vec<SeatbeltAccessRoot>,
) -> (String, Vec<(String, PathBuf)>) {
    let mut policy_components = Vec::new();
    let mut params = Vec::new();

    for (index, access_root) in roots.into_iter().enumerate() {
        let root =
            normalize_path_for_sandbox(access_root.root.as_path()).unwrap_or(access_root.root);
        let root_param = format!("{param_prefix}_{index}");
        params.push((root_param.clone(), root.clone().into_path_buf()));

        if access_root.excluded_subpaths.is_empty()
            && access_root.protected_metadata_names.is_empty()
        {
            policy_components.push(format!("(subpath (param \"{root_param}\"))"));
            continue;
        }

        let mut require_parts = vec![format!("(subpath (param \"{root_param}\"))")];
        for (excluded_index, excluded_subpath) in
            access_root.excluded_subpaths.into_iter().enumerate()
        {
            let excluded_subpath =
                normalize_path_for_sandbox(excluded_subpath.as_path()).unwrap_or(excluded_subpath);
            let excluded_param = format!("{param_prefix}_{index}_EXCLUDED_{excluded_index}");
            params.push((excluded_param.clone(), excluded_subpath.into_path_buf()));
            require_parts.push(format!(
                "(require-not (literal (param \"{excluded_param}\")))"
            ));
            require_parts.push(format!(
                "(require-not (subpath (param \"{excluded_param}\")))"
            ));
        }
        for metadata_name in access_root.protected_metadata_names {
            let regex =
                seatbelt_protected_metadata_name_regex(&root, &metadata_name).replace('"', "\\\"");
            require_parts.push(format!(r#"(require-not (regex #"{regex}"))"#));
        }
        policy_components.push(format!("(require-all {} )", require_parts.join(" ")));
    }

    if policy_components.is_empty() {
        (String::new(), Vec::new())
    } else {
        (
            format!("(allow {action}\n{}\n)", policy_components.join(" ")),
            params,
        )
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
        if !file_system_sandbox_policy.can_write_path_with_cwd(path.as_path(), cwd) {
            names.push((*name).to_string());
        }
    }
    names
}

fn build_seatbelt_unreadable_glob_policy(
    file_system_sandbox_policy: &FileSystemSandboxPolicy,
    cwd: &Path,
) -> String {
    let unreadable_globs = file_system_sandbox_policy.get_unreadable_globs_with_cwd(cwd);
    if unreadable_globs.is_empty() {
        return String::new();
    }

    let mut policy_components = Vec::new();
    for pattern in unreadable_globs {
        let mut regexes = BTreeSet::new();
        if let Some(regex) = seatbelt_regex_for_unreadable_glob(&pattern) {
            regexes.insert(regex);
        }
        if let Some(pattern) = canonicalize_glob_static_prefix_for_sandbox(&pattern)
            && let Some(regex) = seatbelt_regex_for_unreadable_glob(&pattern)
        {
            regexes.insert(regex);
        }
        for regex in regexes {
            let regex = regex.replace('"', "\\\"");
            policy_components.push(format!(r#"(deny file-read* (regex #"{regex}"))"#));
            policy_components.push(format!(r#"(deny file-write-unlink (regex #"{regex}"))"#));
        }
    }

    policy_components.join("\n")
}

fn canonicalize_glob_static_prefix_for_sandbox(pattern: &str) -> Option<String> {
    let first_glob_index = pattern
        .char_indices()
        .find_map(|(index, ch)| matches!(ch, '*' | '?' | '[' | ']').then_some(index));
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

fn seatbelt_regex_for_unreadable_glob(pattern: &str) -> Option<String> {
    if pattern.is_empty() {
        return None;
    }

    let mut regex = String::from("^");
    let mut chars = pattern.chars().collect::<VecDeque<_>>();
    let mut saw_glob = false;

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

    if !saw_glob {
        regex.push_str("(/.*)?");
    }
    regex.push('$');
    Some(regex)
}

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

pub fn create_seatbelt_command_args(args: CreateSeatbeltCommandArgsParams<'_>) -> Vec<String> {
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
    let (file_write_policy, file_write_dir_params) =
        if file_system_sandbox_policy.has_full_disk_write_access() {
            if unreadable_roots.is_empty() {
                (
                    r#"(allow file-write* (regex #"^/"))"#.to_string(),
                    Vec::new(),
                )
            } else {
                build_seatbelt_access_policy(
                    "file-write*",
                    "WRITABLE_ROOT",
                    vec![SeatbeltAccessRoot {
                        root: root_absolute_path(),
                        excluded_subpaths: unreadable_roots.clone(),
                        protected_metadata_names: Vec::new(),
                    }],
                )
            }
        } else {
            build_seatbelt_access_policy(
                "file-write*",
                "WRITABLE_ROOT",
                file_system_sandbox_policy
                    .get_writable_roots_with_cwd(sandbox_policy_cwd)
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
            )
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
                    "file-read*",
                    "READABLE_ROOT",
                    vec![SeatbeltAccessRoot {
                        root: root_absolute_path(),
                        excluded_subpaths: unreadable_roots,
                        protected_metadata_names: Vec::new(),
                    }],
                );
                (
                    format!("; allow read-only file operations\n{policy}"),
                    params,
                )
            }
        } else {
            let unreadable_roots =
                file_system_sandbox_policy.get_unreadable_roots_with_cwd(sandbox_policy_cwd);
            let (policy, params) = build_seatbelt_access_policy(
                "file-read*",
                "READABLE_ROOT",
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
            );
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
        deny_read_policy,
        network_policy,
    ];
    if include_platform_defaults {
        policy_sections.push(MACOS_RESTRICTED_READ_ONLY_PLATFORM_DEFAULTS.to_string());
    }

    let full_policy = policy_sections.join("\n");

    let dir_params = [
        file_read_dir_params,
        file_write_dir_params,
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
    seatbelt_args
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
        });

        assert_eq!(args.first().map(String::as_str), Some("-p"));
        let profile = args.get(1).expect("profile");
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(allow file-write*"));
        assert!(profile.contains(".git"));
        assert!(args.iter().any(|arg| arg == "--"));
    }
}
