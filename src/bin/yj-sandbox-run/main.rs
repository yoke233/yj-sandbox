//! `yj-sandbox-run` — run a command under the non-elevated Windows sandbox.
//!
//! Writes are confined by the OS to the granted roots; reads are unrestricted
//! (full-disk read) and network is only soft-blocked via env vars. This is the
//! restricted-token (no UAC, no admin) backend; it defends against accidental or
//! destructive *writes*, not data exfiltration.
//!
//! Usage:
//!   yj-sandbox-run [OPTIONS] -- <command> [args...]
//!
//! Options:
//!   --workspace-root <DIR>   cwd-aware writable project root (repeatable)
//!   --writable <DIR>         always-writable extra root (repeatable)
//!   --temp                   also make TEMP/TMP writable
//!   --read-only              no writable roots (read-only sandbox)
//!   --no-network             apply the env-based soft network block
//!   --cwd <DIR>              working directory (default: current dir)
//!   --state-dir <DIR>        sandbox state/log dir (default: %LOCALAPPDATA%\yj-sandbox)
//!   --private-desktop        run on a private desktop/window station
//!   --timeout-ms <N>         terminate the command after N milliseconds
//!   -h, --help               print this help

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use yj_sandbox::ResolvedWindowsSandboxPermissions;
use yj_sandbox::run_sandbox_capture;

struct Args {
    workspace_roots: Vec<PathBuf>,
    writable_roots: Vec<PathBuf>,
    include_temp: bool,
    read_only: bool,
    block_network: bool,
    cwd: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    private_desktop: bool,
    timeout_ms: Option<u64>,
    command: Vec<String>,
}

const HELP: &str = "\
yj-sandbox-run — run a command under the non-elevated Windows sandbox

USAGE:
    yj-sandbox-run [OPTIONS] -- <command> [args...]

OPTIONS:
    --workspace-root <DIR>   cwd-aware writable project root (repeatable)
    --writable <DIR>         always-writable extra root (repeatable)
    --temp                   also make TEMP/TMP writable
    --read-only              no writable roots (read-only sandbox)
    --no-network             apply the env-based soft network block
    --cwd <DIR>              working directory (default: current dir)
    --state-dir <DIR>        sandbox state/log dir (default: %LOCALAPPDATA%\\yj-sandbox)
    --private-desktop        run on a private desktop/window station
    --timeout-ms <N>         terminate the command after N milliseconds
    -h, --help               print this help

NOTE: writes are OS-enforced to the granted roots; reads are NOT restricted and
network is only soft-blocked via env vars. Use the elevated backend for
deny-read or real network isolation.
";

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        workspace_roots: Vec::new(),
        writable_roots: Vec::new(),
        include_temp: false,
        read_only: false,
        block_network: false,
        cwd: None,
        state_dir: None,
        private_desktop: false,
        timeout_ms: None,
        command: Vec::new(),
    };

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--" => {
                args.command.extend(it.by_ref());
                break;
            }
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "--workspace-root" => {
                args.workspace_roots
                    .push(PathBuf::from(require_value(&mut it, &arg)?));
            }
            "--writable" => {
                args.writable_roots
                    .push(PathBuf::from(require_value(&mut it, &arg)?));
            }
            "--cwd" => args.cwd = Some(PathBuf::from(require_value(&mut it, &arg)?)),
            "--state-dir" => args.state_dir = Some(PathBuf::from(require_value(&mut it, &arg)?)),
            "--timeout-ms" => {
                let raw = require_value(&mut it, &arg)?;
                let ms = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --timeout-ms value: {raw}"))?;
                args.timeout_ms = Some(ms);
            }
            "--temp" => args.include_temp = true,
            "--read-only" => args.read_only = true,
            "--no-network" => args.block_network = true,
            "--private-desktop" => args.private_desktop = true,
            other => {
                return Err(format!(
                    "unexpected argument: {other}\n(use `-- <command>` to pass the command)"
                ));
            }
        }
    }

    if args.command.is_empty() {
        return Err("no command given; pass it after `--`".to_string());
    }
    Ok(args)
}

fn require_value(
    it: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}

fn default_state_dir() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local).join("yj-sandbox");
    }
    std::env::temp_dir().join("yj-sandbox")
}

fn run() -> Result<i32, String> {
    let args = parse_args()?;

    let cwd = match args.cwd {
        Some(cwd) => cwd,
        None => std::env::current_dir().map_err(|e| format!("cannot resolve cwd: {e}"))?,
    };

    let state_dir = args.state_dir.unwrap_or_else(default_state_dir);
    std::fs::create_dir_all(&state_dir)
        .map_err(|e| format!("cannot create state dir {}: {e}", state_dir.display()))?;

    let permissions = if args.read_only {
        ResolvedWindowsSandboxPermissions::read_only(args.block_network)
    } else {
        // Default the workspace root to the cwd when none was supplied, matching
        // Codex's workspace-write default.
        let mut workspace_roots = args.workspace_roots;
        if workspace_roots.is_empty() && args.writable_roots.is_empty() {
            workspace_roots.push(cwd.clone());
        }
        ResolvedWindowsSandboxPermissions::workspace_write(
            workspace_roots,
            args.writable_roots,
            args.include_temp,
            args.block_network,
        )
    };

    let env_map: HashMap<String, String> = std::env::vars().collect();

    // Output is streamed live by the capture backend; the child runs inside a
    // kill-on-close job, so killing this process tears down the whole sandboxed
    // process tree.
    let result = run_sandbox_capture(
        &permissions,
        &state_dir,
        args.command,
        &cwd,
        env_map,
        args.timeout_ms,
        None,
        args.private_desktop,
        true,
    )
    .map_err(|e| format!("sandbox run failed: {e:#}"))?;

    if result.timed_out {
        eprintln!("yj-sandbox-run: command timed out");
    }
    Ok(result.exit_code)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(u8::try_from(code & 0xff).unwrap_or(1)),
        Err(msg) => {
            eprintln!("yj-sandbox-run: {msg}");
            ExitCode::from(2)
        }
    }
}
