// Ported from openai/codex `codex-rs/windows-sandbox-rs` (Apache-2.0), reduced
// to the non-elevated (restricted-token) capture path and decoupled from the
// `codex_protocol` / `codex_otel` / `codex_utils_*` crates. See NOTICE.
//
// Security model (non-elevated): writes are constrained by the OS to the
// granted capability roots; reads are NOT constrained (full-disk read); network
// is only soft-blocked via environment variables. Use the elevated backend if
// you need deny-read or kernel-level network isolation.

#![allow(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::sync::Arc;

/// Cancellation hook used by the capture backend to abort a running command.
#[derive(Clone)]
pub struct WindowsSandboxCancellationToken {
    is_cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl WindowsSandboxCancellationToken {
    pub fn new(is_cancelled: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self {
            is_cancelled: Arc::new(is_cancelled),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        (self.is_cancelled)()
    }
}

impl fmt::Debug for WindowsSandboxCancellationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsSandboxCancellationToken")
            .finish_non_exhaustive()
    }
}

mod resolved_permissions;
pub use resolved_permissions::ResolvedWindowsSandboxPermissions;
pub use resolved_permissions::WindowsWritableRoot;

// Vendored Win32 modules. Some carry helper APIs used only by Codex's elevated
// backend (dropped here); they are kept intact to ease future upstream sync, so
// dead-code is allowed on the vendored set.
#[cfg(windows)]
#[allow(dead_code)]
mod acl;
#[cfg(windows)]
mod allow;
#[cfg(windows)]
#[allow(dead_code)]
mod cap;
#[cfg(windows)]
#[allow(dead_code)]
mod desktop;
#[cfg(windows)]
#[allow(dead_code)]
mod env;
#[cfg(windows)]
#[allow(dead_code)]
mod logging;
#[cfg(windows)]
mod path_normalization;
#[cfg(windows)]
#[allow(dead_code)]
mod proc_thread_attr;
#[cfg(windows)]
#[allow(dead_code)]
mod process;
#[cfg(windows)]
mod sandbox_utils;
#[cfg(windows)]
mod spawn_prep;
#[cfg(windows)]
#[allow(dead_code)]
mod token;
#[cfg(windows)]
#[allow(dead_code)]
mod winutil;
#[cfg(windows)]
mod workspace_acl;

// `path_normalization` is portable (used by `resolved_permissions`).
#[cfg(not(windows))]
#[path = "path_normalization.rs"]
mod path_normalization;

/// Result of running a command to completion inside the sandbox.
#[derive(Debug, Default)]
pub struct CaptureResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

#[cfg(windows)]
pub use windows_impl::run_sandbox_capture;

#[cfg(windows)]
mod windows_impl {
    use super::CaptureResult;
    use super::ResolvedWindowsSandboxPermissions;
    use super::WindowsSandboxCancellationToken;
    use super::logging::log_failure;
    use super::logging::log_success;
    use super::process::create_process_as_user;
    use super::spawn_prep::LegacyAclSids;
    use super::spawn_prep::SpawnPrepOptions;
    use super::spawn_prep::allow_null_device_for_workspace_write;
    use super::spawn_prep::apply_legacy_session_acl_rules;
    use super::spawn_prep::legacy_session_capability_roots;
    use super::spawn_prep::prepare_legacy_session_security;
    use super::spawn_prep::prepare_legacy_spawn_context;
    use anyhow::Result;
    use std::collections::HashMap;
    use std::io;
    use std::path::Path;
    use std::ptr;
    use std::time::Duration;
    use std::time::Instant;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT;
    use windows_sys::Win32::Foundation::SetHandleInformation;
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::GetExitCodeProcess;
    use windows_sys::Win32::System::Threading::INFINITE;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    type PipeHandles = ((HANDLE, HANDLE), (HANDLE, HANDLE), (HANDLE, HANDLE));

    enum WaitOutcome {
        Exited,
        TimedOut,
        Cancelled,
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

    unsafe fn setup_stdio_pipes() -> io::Result<PipeHandles> {
        let mut in_r: HANDLE = 0;
        let mut in_w: HANDLE = 0;
        let mut out_r: HANDLE = 0;
        let mut out_w: HANDLE = 0;
        let mut err_r: HANDLE = 0;
        let mut err_w: HANDLE = 0;
        if CreatePipe(&mut in_r, &mut in_w, ptr::null_mut(), 0) == 0 {
            return Err(io::Error::from_raw_os_error(GetLastError() as i32));
        }
        if CreatePipe(&mut out_r, &mut out_w, ptr::null_mut(), 0) == 0 {
            return Err(io::Error::from_raw_os_error(GetLastError() as i32));
        }
        if CreatePipe(&mut err_r, &mut err_w, ptr::null_mut(), 0) == 0 {
            return Err(io::Error::from_raw_os_error(GetLastError() as i32));
        }
        if SetHandleInformation(in_r, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
            return Err(io::Error::from_raw_os_error(GetLastError() as i32));
        }
        if SetHandleInformation(out_w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
            return Err(io::Error::from_raw_os_error(GetLastError() as i32));
        }
        if SetHandleInformation(err_w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 {
            return Err(io::Error::from_raw_os_error(GetLastError() as i32));
        }
        Ok(((in_r, in_w), (out_r, out_w), (err_r, err_w)))
    }

    /// Run `command` to completion under a restricted-token sandbox, capturing
    /// stdout/stderr and the exit code.
    ///
    /// `state_dir` holds the persisted capability-SID map and rolling logs (the
    /// equivalent of Codex's `$CODEX_HOME`). `permissions` describes the writable
    /// roots and network policy; reads are always unrestricted in this backend.
    #[allow(clippy::too_many_arguments)]
    pub fn run_sandbox_capture(
        permissions: &ResolvedWindowsSandboxPermissions,
        state_dir: &Path,
        command: Vec<String>,
        cwd: &Path,
        mut env_map: HashMap<String, String>,
        timeout_ms: Option<u64>,
        cancellation: Option<WindowsSandboxCancellationToken>,
        use_private_desktop: bool,
    ) -> Result<CaptureResult> {
        let common = prepare_legacy_spawn_context(
            permissions,
            state_dir,
            cwd,
            &mut env_map,
            &command,
            SpawnPrepOptions {
                inherit_path: true,
                add_git_safe_directory: true,
            },
        )?;
        let permissions = common.permissions;
        let current_dir = common.current_dir;
        let logs_base_dir = common.logs_base_dir.as_deref();
        let uses_write_capabilities = common.uses_write_capabilities;

        // The restricted-token backend cannot enforce restricted reads: WRITE_RESTRICTED
        // tokens only consult restricting SIDs for writes. Deny-read therefore requires
        // the elevated backend; this backend always grants full-disk read.
        if !permissions.has_full_disk_read_access() {
            anyhow::bail!(
                "restricted read-only access requires the elevated Windows sandbox backend"
            );
        }

        let capability_roots =
            legacy_session_capability_roots(&permissions, &current_dir, &env_map, state_dir);
        let security = prepare_legacy_session_security(
            uses_write_capabilities,
            state_dir,
            cwd,
            capability_roots,
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

        let (stdin_pair, stdout_pair, stderr_pair) = unsafe { setup_stdio_pipes()? };
        let ((in_r, in_w), (out_r, out_w), (err_r, err_w)) = (stdin_pair, stdout_pair, stderr_pair);
        let spawn_res = unsafe {
            create_process_as_user(
                security.h_token,
                &command,
                cwd,
                &env_map,
                logs_base_dir,
                Some((in_r, out_w, err_w)),
                use_private_desktop,
            )
        };
        let created = match spawn_res {
            Ok(v) => v,
            Err(err) => {
                unsafe {
                    CloseHandle(in_r);
                    CloseHandle(in_w);
                    CloseHandle(out_r);
                    CloseHandle(out_w);
                    CloseHandle(err_r);
                    CloseHandle(err_w);
                    CloseHandle(security.h_token);
                }
                return Err(err);
            }
        };
        let pi = created.process_info;
        let _desktop = created;

        unsafe {
            CloseHandle(in_r);
            // Close the parent's stdin write end so the child sees EOF immediately.
            CloseHandle(in_w);
            CloseHandle(out_w);
            CloseHandle(err_w);
        }

        let (tx_out, rx_out) = std::sync::mpsc::channel::<Vec<u8>>();
        let (tx_err, rx_err) = std::sync::mpsc::channel::<Vec<u8>>();
        let t_out = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
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
                buf.extend_from_slice(&tmp[..read_bytes as usize]);
            }
            let _ = tx_out.send(buf);
        });
        let t_err = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
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
                buf.extend_from_slice(&tmp[..read_bytes as usize]);
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
        } else {
            unsafe {
                windows_sys::Win32::System::Threading::TerminateProcess(pi.hProcess, 1);
            }
        }

        unsafe {
            if pi.hThread != 0 {
                CloseHandle(pi.hThread);
            }
            if pi.hProcess != 0 {
                CloseHandle(pi.hProcess);
            }
            CloseHandle(security.h_token);
        }
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
}

#[cfg(not(windows))]
pub use stub::run_sandbox_capture;

#[cfg(not(windows))]
mod stub {
    use super::CaptureResult;
    use super::ResolvedWindowsSandboxPermissions;
    use super::WindowsSandboxCancellationToken;
    use anyhow::Result;
    use anyhow::bail;
    use std::collections::HashMap;
    use std::path::Path;

    #[allow(clippy::too_many_arguments)]
    pub fn run_sandbox_capture(
        _permissions: &ResolvedWindowsSandboxPermissions,
        _state_dir: &Path,
        _command: Vec<String>,
        _cwd: &Path,
        _env_map: HashMap<String, String>,
        _timeout_ms: Option<u64>,
        _cancellation: Option<WindowsSandboxCancellationToken>,
        _use_private_desktop: bool,
    ) -> Result<CaptureResult> {
        bail!("the Windows sandbox is only available on Windows")
    }
}
