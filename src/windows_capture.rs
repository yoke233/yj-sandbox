use super::CaptureResult;
use super::ResolvedWindowsSandboxPermissions;
use super::WindowsSandboxCancellationToken;
use super::allow::compute_allow_paths_for_permissions;
use super::gemini::prepare_gemini_security;
use super::logging::log_failure;
use super::logging::log_success;
use super::process::ConsoleMode;
use super::process::StderrMode;
use super::process::StdinMode;
use super::process::spawn_process_with_pipes;
use super::resolved_permissions::windows_temp_env_roots;
use super::spawn_prep::LegacyAclSids;
use super::spawn_prep::SpawnPrepOptions;
use super::spawn_prep::allow_null_device_for_workspace_write;
use super::spawn_prep::apply_legacy_session_acl_rules;
use super::spawn_prep::legacy_session_capability_roots;
use super::spawn_prep::prepare_gemini_spawn_context;
use super::spawn_prep::prepare_legacy_session_security;
use super::spawn_prep::prepare_legacy_spawn_context;
use anyhow::Result;
use std::collections::HashMap;
use std::io;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use std::time::Instant;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::GetExitCodeProcess;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

enum WaitOutcome {
    Exited,
    TimedOut,
    Cancelled,
}

#[derive(Clone, Copy)]
enum UnelevatedBackend {
    CodexRestrictedToken,
    GeminiLowIntegrity,
}

fn wait_for_process(
    process: HANDLE,
    timeout_ms: Option<u64>,
    cancellation: Option<&WindowsSandboxCancellationToken>,
) -> WaitOutcome {
    let Some(cancellation) = cancellation else {
        let timeout = timeout_ms.map(|ms| ms as u32).unwrap_or(INFINITE);
        let res = unsafe { WaitForSingleObject(process, timeout) };
        return if res == 0x0000_0102 {
            WaitOutcome::TimedOut
        } else {
            WaitOutcome::Exited
        };
    };

    let deadline = timeout_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
    loop {
        if cancellation.is_cancelled() {
            return WaitOutcome::Cancelled;
        }
        let wait_ms = match deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return WaitOutcome::TimedOut;
                }
                remaining.min(Duration::from_millis(50)).as_millis() as u32
            }
            None => 50,
        };
        let res = unsafe { WaitForSingleObject(process, wait_ms) };
        if res == 0x0000_0102 {
            continue;
        }
        return WaitOutcome::Exited;
    }
}

/// Run `command` to completion under a restricted-token sandbox, capturing
/// stdout/stderr and the exit code.
///
/// `state_dir` holds the persisted capability-SID map and rolling logs (the
/// equivalent of Codex's `$CODEX_HOME`). `permissions` describes the writable
/// roots and network policy; reads are always unrestricted in this backend.
///
/// The child is placed in a kill-on-close job object, so the entire
/// sandboxed process tree is terminated when this function returns or when
/// the calling process dies. With `stream_output` the child's stdout/stderr
/// are additionally forwarded to this process's stdout/stderr as they
/// arrive (they are still captured in the returned `CaptureResult`).
#[allow(clippy::too_many_arguments)]
pub fn run_sandbox_capture(
    permissions: &ResolvedWindowsSandboxPermissions,
    state_dir: &Path,
    command: Vec<String>,
    cwd: &Path,
    env_map: HashMap<String, String>,
    timeout_ms: Option<u64>,
    cancellation: Option<WindowsSandboxCancellationToken>,
    use_private_desktop: bool,
    stream_output: bool,
) -> Result<CaptureResult> {
    run_sandbox_capture_impl(
        permissions,
        state_dir,
        command,
        cwd,
        env_map,
        timeout_ms,
        cancellation,
        use_private_desktop,
        stream_output,
        UnelevatedBackend::CodexRestrictedToken,
    )
}

/// Runs a command with Gemini's current-user Low Integrity token model. All
/// resolved writable roots receive inheritable Low Mandatory labels; network
/// environment variables are inherited unchanged.
#[allow(clippy::too_many_arguments)]
pub fn run_gemini_sandbox_capture(
    permissions: &ResolvedWindowsSandboxPermissions,
    state_dir: &Path,
    command: Vec<String>,
    cwd: &Path,
    env_map: HashMap<String, String>,
    timeout_ms: Option<u64>,
    cancellation: Option<WindowsSandboxCancellationToken>,
    use_private_desktop: bool,
    stream_output: bool,
) -> Result<CaptureResult> {
    run_sandbox_capture_impl(
        permissions,
        state_dir,
        command,
        cwd,
        env_map,
        timeout_ms,
        cancellation,
        use_private_desktop,
        stream_output,
        UnelevatedBackend::GeminiLowIntegrity,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_sandbox_capture_impl(
    permissions: &ResolvedWindowsSandboxPermissions,
    state_dir: &Path,
    command: Vec<String>,
    cwd: &Path,
    mut env_map: HashMap<String, String>,
    timeout_ms: Option<u64>,
    cancellation: Option<WindowsSandboxCancellationToken>,
    use_private_desktop: bool,
    stream_output: bool,
    backend: UnelevatedBackend,
) -> Result<CaptureResult> {
    let options = SpawnPrepOptions {
        inherit_path: true,
        add_git_safe_directory: matches!(backend, UnelevatedBackend::CodexRestrictedToken),
    };
    let common = match backend {
        UnelevatedBackend::CodexRestrictedToken => prepare_legacy_spawn_context(
            permissions,
            state_dir,
            cwd,
            &mut env_map,
            &command,
            options,
        ),
        UnelevatedBackend::GeminiLowIntegrity => prepare_gemini_spawn_context(
            permissions,
            state_dir,
            cwd,
            &mut env_map,
            &command,
            options,
        ),
    }?;
    let permissions = common.permissions;
    let current_dir = common.current_dir;
    let logs_base_dir = common.logs_base_dir.as_deref();
    let uses_write_capabilities = common.uses_write_capabilities;

    // Neither current-user backend enforces restricted reads. Deny-read therefore
    // requires the elevated backend; these backends always grant full-disk read.
    if !permissions.has_full_disk_read_access() {
        anyhow::bail!("restricted read-only access requires the elevated Windows sandbox backend");
    }

    let h_token = match backend {
        UnelevatedBackend::CodexRestrictedToken => {
            let writable_roots =
                legacy_session_capability_roots(&permissions, &current_dir, &env_map, state_dir);
            let security = prepare_legacy_session_security(
                uses_write_capabilities,
                state_dir,
                cwd,
                writable_roots,
            )?;
            allow_null_device_for_workspace_write(uses_write_capabilities);
            apply_legacy_session_acl_rules(
                &permissions,
                state_dir,
                &current_dir,
                &env_map,
                &[],
                LegacyAclSids {
                    readonly_sid: security.readonly_sid.as_ref(),
                    write_root_sids: &security.write_root_sids,
                },
            )?;
            security.h_token
        }
        UnelevatedBackend::GeminiLowIntegrity => {
            let writable_roots =
                compute_allow_paths_for_permissions(&permissions, &current_dir, &env_map).allow;
            let non_propagating_roots = windows_temp_env_roots(&env_map);
            prepare_gemini_security(writable_roots, &non_propagating_roots)?
        }
    };

    let spawn_result = spawn_process_with_pipes(
        h_token,
        &command,
        cwd,
        &env_map,
        StdinMode::Closed,
        StderrMode::Separate,
        ConsoleMode::Inherit,
        use_private_desktop,
        logs_base_dir,
    );
    unsafe {
        CloseHandle(h_token);
    }
    let pipe_handles = spawn_result?;
    let pi = pipe_handles.process;
    let job = pipe_handles.job();
    let out_r = pipe_handles.stdout_read;
    let err_r = pipe_handles
        .stderr_read
        .expect("separate stderr pipe must be present");

    let (tx_out, rx_out) = std::sync::mpsc::channel::<Vec<u8>>();
    let (tx_err, rx_err) = std::sync::mpsc::channel::<Vec<u8>>();
    let t_out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        let stdout = io::stdout();
        let mut streamed = stream_output.then(|| stdout.lock());
        loop {
            let mut read_bytes: u32 = 0;
            let ok = unsafe {
                windows_sys::Win32::Storage::FileSystem::ReadFile(
                    out_r,
                    tmp.as_mut_ptr(),
                    tmp.len() as u32,
                    &mut read_bytes,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || read_bytes == 0 {
                break;
            }
            if let Some(out) = streamed.as_mut() {
                let _ = out.write_all(&tmp[..read_bytes as usize]);
            }
            buf.extend_from_slice(&tmp[..read_bytes as usize]);
        }
        if let Some(out) = streamed.as_mut() {
            let _ = out.flush();
        }
        unsafe {
            CloseHandle(out_r);
        }
        let _ = tx_out.send(buf);
    });
    let t_err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        let stderr = io::stderr();
        let mut streamed = stream_output.then(|| stderr.lock());
        loop {
            let mut read_bytes: u32 = 0;
            let ok = unsafe {
                windows_sys::Win32::Storage::FileSystem::ReadFile(
                    err_r,
                    tmp.as_mut_ptr(),
                    tmp.len() as u32,
                    &mut read_bytes,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || read_bytes == 0 {
                break;
            }
            if let Some(err) = streamed.as_mut() {
                let _ = err.write_all(&tmp[..read_bytes as usize]);
            }
            buf.extend_from_slice(&tmp[..read_bytes as usize]);
        }
        if let Some(err) = streamed.as_mut() {
            let _ = err.flush();
        }
        unsafe {
            CloseHandle(err_r);
        }
        let _ = tx_err.send(buf);
    });

    let wait_outcome = wait_for_process(pi.hProcess, timeout_ms, cancellation.as_ref());
    let timed_out = matches!(wait_outcome, WaitOutcome::TimedOut);
    let cancelled = matches!(wait_outcome, WaitOutcome::Cancelled);
    let mut exit_code_u32: u32 = 1;
    if !timed_out && !cancelled {
        unsafe {
            GetExitCodeProcess(pi.hProcess, &mut exit_code_u32);
        }
    }
    if timed_out || cancelled {
        if job.terminate().is_err() {
            unsafe {
                windows_sys::Win32::System::Threading::TerminateProcess(pi.hProcess, 1);
            }
        }
    }

    unsafe {
        if pi.hThread != 0 {
            CloseHandle(pi.hThread);
        }
        if pi.hProcess != 0 {
            CloseHandle(pi.hProcess);
        }
    }
    // Closing the last Job handle terminates descendants that outlived the
    // root process and closes inherited pipe writers before reader joins.
    drop(pipe_handles);
    drop(job);
    let _ = t_out.join();
    let _ = t_err.join();
    let stdout = rx_out.recv().unwrap_or_default();
    let stderr = rx_err.recv().unwrap_or_default();
    let exit_code = if timed_out {
        128 + 64
    } else {
        exit_code_u32 as i32
    };

    if exit_code == 0 {
        log_success(&command, logs_base_dir);
    } else {
        log_failure(&command, &format!("exit code {exit_code}"), logs_base_dir);
    }

    Ok(CaptureResult {
        exit_code,
        stdout,
        stderr,
        timed_out,
    })
}
