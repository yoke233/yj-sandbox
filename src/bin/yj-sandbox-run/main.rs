use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgAction, ArgGroup, Args, Parser};
use yj_sandbox::{ResolvedWindowsSandboxPermissions, run_sandbox_capture};

#[derive(Debug, Default, Args)]
struct SandboxStateArgs {
    /// JSON value from `codex/sandbox-state-meta` to apply directly.
    #[arg(
        long = "sandbox-state-json",
        value_name = "JSON",
        conflicts_with_all = ["permissions_profile", "cwd", "include_managed_config"]
    )]
    sandbox_state_json: Option<String>,

    /// Add a readable root to the supplied sandbox state. Repeat for multiple roots.
    #[arg(long, requires = "sandbox_state_json", value_parser = absolute_path)]
    sandbox_state_readable_root: Vec<PathBuf>,

    /// Request disabled network in the supplied state; Gemini allows direct network.
    #[arg(long, requires = "sandbox_state_json", default_value_t = false)]
    sandbox_state_disable_network: bool,
}

#[derive(Debug, Parser)]
#[command(name = "yj-sandbox-run")]
struct WindowsCommand {
    #[command(flatten)]
    sandbox_state: SandboxStateArgs,

    /// Named permissions profile to apply from the active configuration stack.
    #[arg(long = "permissions-profile", short = 'P', value_name = "NAME")]
    permissions_profile: Option<String>,

    /// Layer $CODEX_HOME/<name>.config.toml on top of the base user config.
    #[arg(long = "profile", short = 'p', value_parser = profile_name)]
    config_profile: Option<String>,

    /// Working directory used for profile resolution and command execution.
    #[arg(
        short = 'C',
        long = "cd",
        value_name = "DIR",
        requires = "permissions_profile",
        value_parser = absolute_path
    )]
    cwd: Option<PathBuf>,

    /// Additional directories that should be writable alongside the primary workspace.
    #[arg(long = "add-dir", value_name = "DIR", value_hint = clap::ValueHint::DirPath)]
    add_dir: Vec<PathBuf>,

    /// Include managed requirements while resolving an explicit permissions profile.
    #[arg(
        long = "include-managed-config",
        default_value_t = false,
        requires = "permissions_profile"
    )]
    include_managed_config: bool,

    /// Override `windows.sandbox`, matching Codex's root `-c key=value` syntax.
    #[arg(short = 'c', long = "config", value_name = "key=value", action = ArgAction::Append)]
    config_overrides: Vec<String>,

    /// Full command args to run under the Windows sandbox.
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Parser)]
#[command(group(
    ArgGroup::new("sandbox_user")
        .required(true)
        .args(["user", "current_user"])
))]
struct SandboxSetupCommand {
    /// Set up the elevated Windows sandbox.
    #[arg(long = "elevated", action = ArgAction::SetTrue)]
    elevated_sandbox_level: bool,

    /// Windows user that will run the sandbox after managed deployment.
    #[arg(
        long = "user",
        value_name = "USER",
        conflicts_with = "current_user",
        requires = "codex_home"
    )]
    user: Option<String>,

    /// Use the current Windows user as the sandbox user.
    #[arg(
        long = "current-user",
        default_value_t = false,
        conflicts_with = "user"
    )]
    current_user: bool,

    /// CODEX_HOME for the sandbox user. Required with --user.
    #[arg(long = "codex-home", value_name = "DIR")]
    codex_home: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowsSandboxLevel {
    RestrictedToken,
    Gemini,
    Elevated,
}

fn absolute_path(raw: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(raw);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|err| format!("invalid path {raw}: {err}"))?
            .join(path)
    };
    Ok(path)
}

fn profile_name(raw: &str) -> Result<String, String> {
    if !raw.is_empty()
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Ok(raw.to_string());
    }
    Err(format!(
        "invalid --profile value `{raw}`; pass a plain name such as `work`"
    ))
}

fn codex_home() -> Result<PathBuf, String> {
    if let Some(value) = std::env::var_os("CODEX_HOME") {
        let path = PathBuf::from(value);
        let canonical = dunce::canonicalize(&path).map_err(|err| {
            format!(
                "CODEX_HOME must point to an existing directory ({}): {err}",
                path.display()
            )
        })?;
        if !canonical.is_dir() {
            return Err(format!(
                "CODEX_HOME must point to a directory: {}",
                canonical.display()
            ));
        }
        return Ok(canonical);
    }
    dirs_next::home_dir()
        .map(|home| home.join(".codex"))
        .ok_or_else(|| "failed to resolve CODEX_HOME".to_string())
}

fn config_sandbox_value(path: &Path) -> Result<Option<String>, String> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    let document = contents
        .parse::<toml_edit::DocumentMut>()
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
    let Some(item) = document
        .get("windows")
        .and_then(toml_edit::Item::as_table)
        .and_then(|windows| windows.get("sandbox"))
    else {
        return Ok(None);
    };
    item.as_str()
        .map(|value| Some(value.to_owned()))
        .ok_or_else(|| {
            format!(
                "invalid windows.sandbox value in {}; expected `gemini`, `elevated`, or `unelevated`",
                path.display()
            )
        })
}

fn parse_sandbox_override(raw: &str) -> Result<Option<String>, String> {
    let Some((key, value)) = raw.split_once('=') else {
        return Err(format!(
            "invalid config override `{raw}`; expected key=value"
        ));
    };
    if key.trim() != "windows.sandbox" {
        return Err(format!(
            "unsupported config override `{}`; this standalone build only accepts `windows.sandbox`",
            key.trim()
        ));
    }
    Ok(Some(value.trim().trim_matches(['\'', '"']).to_string()))
}

fn resolve_windows_sandbox_level(
    command: &WindowsCommand,
    home: &Path,
) -> Result<WindowsSandboxLevel, String> {
    let mut value = config_sandbox_value(&home.join("config.toml"))?;
    if let Some(profile) = command.config_profile.as_deref() {
        value = config_sandbox_value(&home.join(format!("{profile}.config.toml")))?.or(value);
    }
    for override_value in &command.config_overrides {
        if let Some(parsed) = parse_sandbox_override(override_value)? {
            value = Some(parsed);
        }
    }
    match value.as_deref().unwrap_or("gemini") {
        "unelevated" => Ok(WindowsSandboxLevel::RestrictedToken),
        "gemini" => Ok(WindowsSandboxLevel::Gemini),
        "elevated" => Ok(WindowsSandboxLevel::Elevated),
        other => Err(format!(
            "invalid windows.sandbox value `{other}`; expected `gemini`, `elevated`, or `unelevated`"
        )),
    }
}

fn native_path(raw: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        return Ok(path);
    }
    if let Ok(uri) = url::Url::parse(raw) {
        if uri.scheme() != "file" {
            return Err(format!(
                "sandbox state path is not native to this host: {raw}"
            ));
        }
        return uri
            .to_file_path()
            .map_err(|_| format!("sandbox state path is not native to this host: {raw}"));
    }
    Err(format!("sandbox state path is not absolute: {raw}"))
}

fn resolve_add_dirs(add_dirs: &[PathBuf], cwd: &Path) -> Vec<PathBuf> {
    let mut resolved = Vec::with_capacity(add_dirs.len());
    for path in add_dirs {
        let path = if path.is_absolute() {
            path.clone()
        } else {
            cwd.join(path)
        };
        let path = dunce::canonicalize(&path).unwrap_or(path);
        if !resolved.contains(&path) {
            resolved.push(path);
        }
    }
    resolved
}

fn warn_ignored_add_dirs(add_dirs: &[PathBuf]) {
    if add_dirs.is_empty() {
        return;
    }
    let joined = add_dirs
        .iter()
        .map(|path| path.to_string_lossy())
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!(
        "warning: ignoring --add-dir ({joined}) because the effective permissions do not allow additional writable roots"
    );
}

fn resolve_permissions(
    command: &WindowsCommand,
    cwd: &Path,
) -> Result<ResolvedWindowsSandboxPermissions, String> {
    let profile = command
        .permissions_profile
        .as_deref()
        .unwrap_or(":workspace");
    let block_network = true;
    match profile {
        ":read-only" => {
            warn_ignored_add_dirs(&command.add_dir);
            Ok(ResolvedWindowsSandboxPermissions::read_only(block_network))
        }
        ":workspace" => Ok(ResolvedWindowsSandboxPermissions::workspace_write(
            vec![cwd.to_path_buf()],
            resolve_add_dirs(&command.add_dir, cwd),
            true,
            block_network,
        )),
        ":danger-full-access" => Err(
            "`:danger-full-access` does not create a Windows sandbox; run the command directly"
                .to_string(),
        ),
        other => Err(format!(
            "permission profile `{other}` is not available in this standalone build; use `:read-only` or `:workspace`"
        )),
    }
}

struct ResolvedCommandState {
    cwd: PathBuf,
    permissions: ResolvedWindowsSandboxPermissions,
    deny_read_paths: Vec<PathBuf>,
    deny_write_paths: Vec<PathBuf>,
}

fn resolve_sandbox_state(
    raw: &str,
    additional_readable_roots: &[PathBuf],
    disable_network: bool,
    add_dirs: &[PathBuf],
) -> Result<ResolvedCommandState, String> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|err| format!("invalid --sandbox-state-json value: {err}"))?;
    let cwd_raw = value
        .get("sandboxCwd")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "--sandbox-state-json is missing sandboxCwd".to_string())?;
    let cwd = native_path(cwd_raw)?;
    let profile = value
        .get("permissionProfile")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "--sandbox-state-json is missing permissionProfile".to_string())?;
    let profile_type = profile
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "sandbox state permission_profile is missing type".to_string())?;
    if profile_type == "disabled" {
        return Err("sandbox state contains a disabled permission profile".to_string());
    }
    if profile_type == "external" {
        match profile.get("network").and_then(serde_json::Value::as_str) {
            Some("enabled" | "restricted") => {}
            Some(other) => {
                return Err(format!(
                    "unsupported sandbox state network policy `{other}`"
                ));
            }
            None => return Err("external permission profile is missing network".to_string()),
        }
        warn_ignored_add_dirs(add_dirs);
        return Ok(ResolvedCommandState {
            cwd,
            permissions: ResolvedWindowsSandboxPermissions::read_only(true),
            deny_read_paths: Vec::new(),
            deny_write_paths: Vec::new(),
        });
    }
    if profile_type != "managed" {
        return Err(format!(
            "unsupported sandbox state permission profile type `{profile_type}`"
        ));
    }

    let mut readable_roots = additional_readable_roots.to_vec();
    let mut workspace_write = false;
    let mut extra_writable_roots = Vec::new();
    let mut deny_read_paths = Vec::new();
    let mut deny_write_paths = Vec::new();
    let mut include_temp = false;
    let mut include_platform_defaults = false;
    let mut full_disk_read = false;
    let file_system = profile
        .get("file_system")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "managed permission profile is missing file_system".to_string())?;
    let file_system_type = file_system
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "managed file_system is missing type".to_string())?;
    match file_system_type {
        "restricted" => {}
        "unrestricted" => {
            return Err("unrestricted filesystem permissions do not create a sandbox".to_string());
        }
        other => {
            return Err(format!("unsupported managed file_system type `{other}`"));
        }
    }
    let entries = file_system
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "restricted managed file_system is missing entries".to_string())?;
    for (index, entry) in entries.iter().enumerate() {
        let access = entry
            .get("access")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("filesystem entry {index} is missing access"))?;
        if !matches!(access, "read" | "write" | "deny" | "none") {
            return Err(format!(
                "filesystem entry {index} has unsupported access `{access}`"
            ));
        }
        let Some(path) = entry.get("path").and_then(serde_json::Value::as_object) else {
            return Err(format!("filesystem entry {index} is missing path"));
        };
        match path.get("type").and_then(serde_json::Value::as_str) {
            Some("path") => {
                let Some(raw_path) = path.get("path").and_then(serde_json::Value::as_str) else {
                    return Err(format!("filesystem entry {index} path is missing path"));
                };
                let path = native_path(raw_path)?;
                match access {
                    "read" => readable_roots.push(path),
                    "write" => extra_writable_roots.push(path),
                    "deny" | "none" => {
                        deny_read_paths.push(path.clone());
                        deny_write_paths.push(path);
                    }
                    _ => unreachable!("access validated above"),
                }
            }
            Some("special") => {
                let special_value = path
                    .get("value")
                    .and_then(serde_json::Value::as_object)
                    .ok_or_else(|| {
                        format!("filesystem entry {index} special path is missing value")
                    })?;
                let special = special_value
                    .get("kind")
                    .and_then(serde_json::Value::as_str);
                let subpath = match special_value.get("subpath") {
                    Some(value) => Some(value.as_str().ok_or_else(|| {
                        format!("filesystem entry {index} special subpath must be a string")
                    })?),
                    None => None,
                };
                match (special, access) {
                    (Some("root"), "read") => full_disk_read = true,
                    (Some("project_roots" | "current_working_directory"), "read") => {
                        readable_roots
                            .push(subpath.map_or_else(|| cwd.clone(), |subpath| cwd.join(subpath)));
                    }
                    (Some("project_roots" | "current_working_directory"), "write")
                        if subpath.is_none() =>
                    {
                        workspace_write = true
                    }
                    (Some("project_roots" | "current_working_directory"), "write") => {
                        extra_writable_roots
                            .push(cwd.join(subpath.expect("guarded by previous arm")));
                    }
                    (Some("project_roots" | "current_working_directory"), "deny" | "none") => {
                        let denied_path =
                            subpath.map_or_else(|| cwd.clone(), |subpath| cwd.join(subpath));
                        deny_read_paths.push(denied_path.clone());
                        deny_write_paths.push(denied_path);
                    }
                    (Some("tmpdir" | "slash_tmp"), "write") => include_temp = true,
                    (Some("minimal"), "read") => include_platform_defaults = true,
                    (Some("root"), "write") => {
                        return Err(
                            "unrestricted filesystem permissions do not create a sandbox"
                                .to_string(),
                        );
                    }
                    (Some("unknown"), _) => {}
                    (Some(kind), _) => {
                        return Err(format!(
                            "filesystem entry {index} uses unsupported `{kind}` special-path access"
                        ));
                    }
                    (None, _) => {
                        return Err(format!(
                            "filesystem entry {index} special path is missing kind"
                        ));
                    }
                }
            }
            Some("glob_pattern") => {
                return Err(
                    "glob filesystem permissions are not supported by this standalone build"
                        .to_string(),
                );
            }
            Some(other) => {
                return Err(format!(
                    "filesystem entry {index} has unsupported path type `{other}`"
                ));
            }
            None => return Err(format!("filesystem entry {index} path is missing type")),
        }
    }
    let network_enabled = match profile.get("network").and_then(serde_json::Value::as_str) {
        Some("enabled") => true,
        Some("restricted") => false,
        Some(other) => {
            return Err(format!(
                "unsupported sandbox state network policy `{other}`"
            ));
        }
        None => return Err("managed permission profile is missing network".to_string()),
    };
    let block_network = disable_network || !network_enabled;
    let workspace_roots = workspace_write
        .then(|| vec![cwd.clone()])
        .unwrap_or_default();
    if workspace_write || !extra_writable_roots.is_empty() || include_temp {
        for root in resolve_add_dirs(add_dirs, &cwd) {
            if !extra_writable_roots.contains(&root) {
                extra_writable_roots.push(root);
            }
        }
    } else {
        warn_ignored_add_dirs(add_dirs);
    }
    let permissions = if full_disk_read {
        if workspace_roots.is_empty() && extra_writable_roots.is_empty() && !include_temp {
            ResolvedWindowsSandboxPermissions::read_only(block_network)
        } else {
            ResolvedWindowsSandboxPermissions::workspace_write(
                workspace_roots,
                extra_writable_roots,
                include_temp,
                block_network,
            )
        }
    } else {
        ResolvedWindowsSandboxPermissions::restricted(
            readable_roots,
            workspace_roots,
            extra_writable_roots,
            include_temp,
            block_network,
            include_platform_defaults,
        )
    };
    Ok(ResolvedCommandState {
        cwd,
        permissions,
        deny_read_paths,
        deny_write_paths,
    })
}

#[cfg(windows)]
fn run_setup(command: &WindowsCommand, home: &Path) -> Result<Option<i32>, String> {
    if command.command.first().map(String::as_str) != Some("setup") {
        return Ok(None);
    }
    let setup =
        match SandboxSetupCommand::try_parse_from(command.command.iter().map(String::as_str)) {
            Ok(setup) => setup,
            Err(err) => err.exit(),
        };
    if !setup.elevated_sandbox_level {
        return Err("`yj-sandbox-run setup` currently requires --elevated".to_string());
    }
    let real_user = if setup.current_user {
        std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .map_err(|err| format!("failed to determine current user: {err}"))?
    } else {
        setup
            .user
            .ok_or_else(|| "--user or --current-user is required".to_string())?
    };
    let target_home = setup.codex_home.unwrap_or_else(|| home.to_path_buf());
    yj_sandbox::run_elevated_provisioning_setup(
        &target_home,
        &real_user,
        yj_sandbox::WindowsSandboxProvisioningSettings::default(),
    )
    .map_err(|err| format!("elevated sandbox setup failed: {err:#}"))?;
    persist_elevated_mode(&target_home).map_err(|err| {
        format!(
            "sandbox provisioning succeeded, but failed to persist elevated sandbox config: {err}"
        )
    })?;
    println!(
        "Windows elevated sandbox setup completed for {real_user} at {}.",
        target_home.display()
    );
    Ok(Some(0))
}

#[cfg(not(windows))]
fn run_setup(_command: &WindowsCommand, _home: &Path) -> Result<Option<i32>, String> {
    Ok(None)
}

#[cfg(windows)]
fn persist_elevated_mode(home: &Path) -> Result<(), String> {
    std::fs::create_dir_all(home)
        .map_err(|err| format!("failed to create {}: {err}", home.display()))?;
    let path = home.join("config.toml");
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    let mut document = contents
        .parse::<toml_edit::DocumentMut>()
        .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
    document["windows"]["sandbox"] = toml_edit::value("elevated");
    let mut temporary = tempfile::NamedTempFile::new_in(home).map_err(|err| {
        format!(
            "failed to create temporary config in {}: {err}",
            home.display()
        )
    })?;
    use std::io::Write as _;
    temporary
        .write_all(document.to_string().as_bytes())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|err| {
            format!(
                "failed to write temporary config for {}: {err}",
                path.display()
            )
        })?;
    temporary
        .persist(&path)
        .map_err(|err| format!("failed to replace {}: {}", path.display(), err.error))?;
    Ok(())
}

fn run() -> Result<i32, String> {
    let command = WindowsCommand::parse();
    let home = codex_home()?;
    if let Some(exit_code) = run_setup(&command, &home)? {
        return Ok(exit_code);
    }
    if command.include_managed_config {
        return Err(
            "--include-managed-config requires Codex's managed configuration loader and is not available in this standalone build"
                .to_string(),
        );
    }
    let state = match command.sandbox_state.sandbox_state_json.as_deref() {
        Some(raw) => resolve_sandbox_state(
            raw,
            &command.sandbox_state.sandbox_state_readable_root,
            command.sandbox_state.sandbox_state_disable_network,
            &command.add_dir,
        )?,
        None => {
            let cwd = command.cwd.clone().unwrap_or(
                std::env::current_dir().map_err(|err| format!("cannot resolve cwd: {err}"))?,
            );
            ResolvedCommandState {
                permissions: resolve_permissions(&command, &cwd)?,
                cwd,
                deny_read_paths: Vec::new(),
                deny_write_paths: Vec::new(),
            }
        }
    };
    let cwd = state.cwd;
    let permissions = state.permissions;
    let env_map: HashMap<String, String> = std::env::vars().collect();

    #[cfg(windows)]
    let sandbox_level = resolve_windows_sandbox_level(&command, &home)?;

    #[cfg(windows)]
    if sandbox_level == WindowsSandboxLevel::Elevated {
        let result = yj_sandbox::run_windows_sandbox_capture_elevated(
            yj_sandbox::ElevatedSandboxCaptureRequest {
                permissions: &permissions,
                codex_home: &home,
                command: command.command,
                cwd: &cwd,
                env_map,
                timeout_ms: None,
                cancellation: None,
                stream_output: true,
                capture_output: false,
                use_private_desktop: false,
                proxy_enforced: false,
                network_proxy_restricting_sid: None,
                read_roots_override: None,
                read_roots_include_platform_defaults: true,
                write_roots_override: None,
                deny_read_paths_override: &state.deny_read_paths,
                deny_write_paths_override: &state.deny_write_paths,
            },
        )
        .map_err(|err| format!("sandbox run failed: {err:#}"))?;
        return Ok(result.exit_code);
    }

    if !permissions.has_full_disk_read_access()
        || !state.deny_read_paths.is_empty()
        || !state.deny_write_paths.is_empty()
    {
        return Err(
            "restricted-read and explicit deny paths require windows.sandbox=\"elevated\""
                .to_string(),
        );
    }

    #[cfg(windows)]
    let result = match sandbox_level {
        WindowsSandboxLevel::Gemini => yj_sandbox::run_gemini_sandbox_capture(
            &permissions,
            &home,
            command.command,
            &cwd,
            env_map,
            None,
            None,
            false,
            true,
        ),
        WindowsSandboxLevel::RestrictedToken => run_sandbox_capture(
            &permissions,
            &home,
            command.command,
            &cwd,
            env_map,
            None,
            None,
            false,
            true,
        ),
        WindowsSandboxLevel::Elevated => unreachable!("elevated returned above"),
    }
    .map_err(|err| format!("sandbox run failed: {err:#}"))?;

    #[cfg(not(windows))]
    let result = run_sandbox_capture(
        &permissions,
        &home,
        command.command,
        &cwd,
        env_map,
        None,
        None,
        false,
        true,
    )
    .map_err(|err| format!("sandbox run failed: {err:#}"))?;
    Ok(result.exit_code)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(u8::try_from(code & 0xff).unwrap_or(1)),
        Err(message) => {
            eprintln!("yj-sandbox-run: {message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_upstream_windows_argument_names() {
        let parsed = WindowsCommand::try_parse_from([
            "yj-sandbox-run",
            "--permissions-profile",
            ":workspace",
            "-C",
            r"C:\workspace",
            "--add-dir",
            r"C:\cache",
            "--add-dir",
            r"D:\output",
            "--include-managed-config",
            "--",
            "cmd.exe",
            "/c",
            "ver",
        ])
        .expect("parse");
        assert_eq!(parsed.permissions_profile.as_deref(), Some(":workspace"));
        assert_eq!(
            parsed.add_dir,
            vec![PathBuf::from(r"C:\cache"), PathBuf::from(r"D:\output")]
        );
        assert_eq!(parsed.command[0], "cmd.exe");
    }

    #[test]
    fn add_dir_extends_workspace_roots_and_dedupes_relative_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("frontend");
        let backend = temp.path().join("backend");
        std::fs::create_dir_all(&cwd).expect("create frontend");
        std::fs::create_dir_all(&backend).expect("create backend");
        let command = WindowsCommand::try_parse_from([
            "yj-sandbox-run",
            "-P",
            ":workspace",
            "-C",
            cwd.to_str().expect("cwd utf8"),
            "--add-dir",
            "../backend",
            "--add-dir",
            backend.to_str().expect("backend utf8"),
            "--",
            "cmd.exe",
        ])
        .expect("parse");

        let permissions = resolve_permissions(&command, &cwd).expect("resolve permissions");
        let roots = permissions.writable_roots_for_cwd(&cwd, &HashMap::new());
        let canonical_cwd = dunce::canonicalize(&cwd).expect("canonical cwd");
        let canonical_backend = dunce::canonicalize(&backend).expect("canonical backend");
        assert_eq!(
            roots
                .iter()
                .filter(|root| root.root == canonical_cwd)
                .count(),
            1
        );
        assert_eq!(
            roots
                .iter()
                .filter(|root| root.root == canonical_backend)
                .count(),
            1
        );
    }

    #[test]
    fn parses_upstream_backend_override_values() {
        assert_eq!(
            parse_sandbox_override("windows.sandbox='elevated'").unwrap(),
            Some("elevated".to_string())
        );
        assert_eq!(
            parse_sandbox_override("windows.sandbox=\"unelevated\"").unwrap(),
            Some("unelevated".to_string())
        );
        assert_eq!(
            parse_sandbox_override("windows.sandbox='gemini'").unwrap(),
            Some("gemini".to_string())
        );
        assert!(parse_sandbox_override("default_permissions=':read-only'").is_err());
    }

    #[test]
    fn defaults_to_gemini_backend() {
        let home = tempfile::tempdir().expect("tempdir");
        let command = WindowsCommand::try_parse_from(["yj-sandbox-run", "cmd.exe", "/c", "ver"])
            .expect("parse");
        assert_eq!(
            resolve_windows_sandbox_level(&command, home.path()).expect("resolve"),
            WindowsSandboxLevel::Gemini
        );
    }

    #[test]
    fn setup_requires_elevated_flag() {
        let parsed =
            SandboxSetupCommand::try_parse_from(["setup", "--current-user"]).expect("parse");
        assert!(!parsed.elevated_sandbox_level);
    }

    #[test]
    fn resolves_upstream_sandbox_state_shape() {
        let cwd = std::env::current_dir().expect("cwd");
        let cwd_uri = url::Url::from_file_path(&cwd).expect("file uri");
        let state = serde_json::json!({
            "sandboxCwd": cwd_uri.as_str(),
            "permissionProfile": {
                "type": "managed",
                "file_system": {
                    "type": "restricted",
                    "entries": [
                        { "path": { "type": "special", "value": { "kind": "root" } }, "access": "read" },
                        { "path": { "type": "special", "value": { "kind": "project_roots" } }, "access": "write" },
                        { "path": { "type": "special", "value": { "kind": "project_roots", "subpath": ".git" } }, "access": "deny" }
                    ]
                },
                "network": "restricted"
            },
            "codexLinuxSandboxExe": null,
            "useLegacyLandlock": false
        });
        let resolved = resolve_sandbox_state(&state.to_string(), &[], false, &[]).expect("resolve");
        assert_eq!(resolved.cwd, cwd);
        assert!(resolved.permissions.has_full_disk_read_access());
        assert!(resolved.permissions.should_apply_network_block());
        assert_eq!(resolved.deny_read_paths, vec![resolved.cwd.join(".git")]);
        assert_eq!(resolved.deny_write_paths, resolved.deny_read_paths);
    }

    #[test]
    fn add_dir_extends_writable_sandbox_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path().join("workspace");
        let extra = temp.path().join("extra");
        std::fs::create_dir_all(&cwd).expect("create workspace");
        std::fs::create_dir_all(&extra).expect("create extra");
        let cwd_uri = url::Url::from_file_path(&cwd).expect("file uri");
        let state = serde_json::json!({
            "sandboxCwd": cwd_uri.as_str(),
            "permissionProfile": {
                "type": "managed",
                "file_system": {
                    "type": "restricted",
                    "entries": [
                        { "path": { "type": "special", "value": { "kind": "root" } }, "access": "read" },
                        { "path": { "type": "special", "value": { "kind": "project_roots" } }, "access": "write" }
                    ]
                },
                "network": "enabled"
            },
            "codexLinuxSandboxExe": null,
            "useLegacyLandlock": false
        });

        let resolved =
            resolve_sandbox_state(&state.to_string(), &[], false, &[PathBuf::from("../extra")])
                .expect("resolve");
        let roots = resolved
            .permissions
            .writable_roots_for_cwd(&cwd, &HashMap::new());
        let canonical_extra = dunce::canonicalize(extra).expect("canonical extra");
        assert!(roots.iter().any(|root| root.root == canonical_extra));
    }

    #[test]
    fn preserves_project_root_write_subpaths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cwd = temp.path();
        let docs = cwd.join("docs");
        std::fs::create_dir(&docs).expect("create docs");
        let cwd_uri = url::Url::from_file_path(cwd).expect("file uri");
        let state = serde_json::json!({
            "sandboxCwd": cwd_uri.as_str(),
            "permissionProfile": {
                "type": "managed",
                "file_system": {
                    "type": "restricted",
                    "entries": [
                        { "path": { "type": "special", "value": { "kind": "root" } }, "access": "read" },
                        { "path": { "type": "special", "value": { "kind": "project_roots", "subpath": "docs" } }, "access": "write" }
                    ]
                },
                "network": "restricted"
            },
            "codexLinuxSandboxExe": null,
            "useLegacyLandlock": false
        });
        let resolved = resolve_sandbox_state(&state.to_string(), &[], false, &[]).expect("resolve");
        let roots = resolved
            .permissions
            .writable_roots_for_cwd(cwd, &HashMap::new());
        assert_eq!(roots.len(), 1);
        assert_eq!(
            roots[0].root,
            dunce::canonicalize(docs).expect("canonical docs")
        );
    }

    #[test]
    fn rejects_non_native_sandbox_state_paths_and_malformed_entries() {
        assert!(native_path("https://example.com/repo").is_err());
        let cwd = std::env::current_dir().expect("cwd");
        let cwd_uri = url::Url::from_file_path(cwd).expect("file uri");
        let state = serde_json::json!({
            "sandboxCwd": cwd_uri.as_str(),
            "permissionProfile": {
                "type": "managed",
                "file_system": {
                    "type": "restricted",
                    "entries": [{ "path": { "type": "path" }, "access": "deny" }]
                },
                "network": "restricted"
            },
            "codexLinuxSandboxExe": null,
            "useLegacyLandlock": false
        });
        assert!(resolve_sandbox_state(&state.to_string(), &[], false, &[]).is_err());
    }

    #[test]
    fn validates_upstream_profile_name_contract() {
        assert_eq!(profile_name("work-2").unwrap(), "work-2");
        assert!(profile_name("").is_err());
        assert!(profile_name(r"..\outside").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn persists_elevated_mode_without_discarding_existing_config() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("config.toml");
        std::fs::write(&path, "model = \"gpt-test\"\n").expect("write config");
        persist_elevated_mode(temp.path()).expect("persist");
        let document = std::fs::read_to_string(path)
            .expect("read config")
            .parse::<toml_edit::DocumentMut>()
            .expect("parse config");
        assert_eq!(document["model"].as_str(), Some("gpt-test"));
        assert_eq!(document["windows"]["sandbox"].as_str(), Some("elevated"));
    }
}
