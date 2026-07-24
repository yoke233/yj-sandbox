use super::CaptureResult;
use super::ResolvedWindowsSandboxPermissions;
use super::WindowsSandboxCancellationToken;
use super::seatbelt::CreateSeatbeltCommandArgsParams;
use super::seatbelt::MACOS_PATH_TO_SEATBELT_EXECUTABLE;
use super::seatbelt::create_seatbelt_command_args;
use anyhow::Result;
use anyhow::bail;
use std::collections::HashMap;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

enum WaitOutcome {
    Exited(ExitStatus),
    TimedOut,
    Cancelled,
}

fn wait_for_child(
    child: &mut Child,
    timeout_ms: Option<u64>,
    cancellation: Option<&WindowsSandboxCancellationToken>,
) -> io::Result<WaitOutcome> {
    let deadline = timeout_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(WaitOutcome::Exited(status));
        }
        if cancellation.is_some_and(WindowsSandboxCancellationToken::is_cancelled) {
            return Ok(WaitOutcome::Cancelled);
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Ok(WaitOutcome::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn spawn_reader<R: Read + Send + 'static>(
    mut reader: R,
    stream_output: bool,
    is_stderr: bool,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut tmp = [0u8; 8192];
        loop {
            let read_bytes = match reader.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if stream_output {
                if is_stderr {
                    let mut err = io::stderr();
                    let _ = err.write_all(&tmp[..read_bytes]);
                    let _ = err.flush();
                } else {
                    let mut stdout = io::stdout();
                    let _ = stdout.write_all(&tmp[..read_bytes]);
                    let _ = stdout.flush();
                }
            }
            out.extend_from_slice(&tmp[..read_bytes]);
        }
        out
    })
}

/// Run `command` to completion under macOS Seatbelt (`sandbox-exec`).
///
/// The public signature matches the Windows backend. `state_dir` and
/// `use_private_desktop` are Windows-only knobs and are ignored here.
#[allow(clippy::too_many_arguments)]
pub fn run_sandbox_capture(
    permissions: &ResolvedWindowsSandboxPermissions,
    _state_dir: &Path,
    command: Vec<String>,
    cwd: &Path,
    env_map: HashMap<String, String>,
    timeout_ms: Option<u64>,
    cancellation: Option<WindowsSandboxCancellationToken>,
    _use_private_desktop: bool,
    stream_output: bool,
) -> Result<CaptureResult> {
    if command.is_empty() {
        bail!("no command given");
    }

    let file_system_sandbox_policy = permissions.macos_file_system_policy_for_cwd(cwd, &env_map);
    let network_sandbox_policy = permissions.macos_network_policy();
    let seatbelt_args = create_seatbelt_command_args(CreateSeatbeltCommandArgsParams {
        command,
        file_system_sandbox_policy: &file_system_sandbox_policy,
        network_sandbox_policy,
        sandbox_policy_cwd: cwd,
        enforce_managed_network: false,
        network: None,
        extra_allow_unix_sockets: &[],
    });

    let mut child = Command::new(MACOS_PATH_TO_SEATBELT_EXECUTABLE)
        .args(seatbelt_args)
        .current_dir(cwd)
        .env_clear()
        .envs(env_map)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "missing child stdout pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "missing child stderr pipe"))?;
    let stdout_reader = spawn_reader(stdout, stream_output, false);
    let stderr_reader = spawn_reader(stderr, stream_output, true);

    let wait_outcome = wait_for_child(&mut child, timeout_ms, cancellation.as_ref())?;
    let (exit_code, timed_out) = match wait_outcome {
        WaitOutcome::Exited(status) => (status.code().unwrap_or(1), false),
        WaitOutcome::TimedOut => {
            let _ = child.kill();
            let _ = child.wait();
            (128 + 64, true)
        }
        WaitOutcome::Cancelled => {
            let _ = child.kill();
            let _ = child.wait();
            (1, false)
        }
    };

    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();

    Ok(CaptureResult {
        exit_code,
        stdout,
        stderr,
        timed_out,
    })
}
