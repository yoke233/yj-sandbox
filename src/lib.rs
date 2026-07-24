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

#[allow(dead_code)]
mod absolute_path;
#[allow(dead_code)]
mod macos_permissions;
mod resolved_permissions;
#[allow(dead_code)]
mod seatbelt;
pub use resolved_permissions::ResolvedSandboxPermissions;
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
mod job;
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
mod windows_capture;
#[cfg(windows)]
pub use windows_capture::run_sandbox_capture;

#[cfg(target_os = "macos")]
mod macos_capture;
#[cfg(target_os = "macos")]
pub use macos_capture::run_sandbox_capture;

#[cfg(not(any(windows, target_os = "macos")))]
mod unsupported_capture;
#[cfg(not(any(windows, target_os = "macos")))]
pub use unsupported_capture::run_sandbox_capture;
