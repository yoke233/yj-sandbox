// Ported from openai/codex `codex-rs/windows-sandbox-rs` (Apache-2.0) and kept
// structurally close to upstream. Codex-wide config and telemetry types are
// represented by a deliberately small local adapter. See NOTICE.

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
#[cfg(windows)]
pub use resolved_permissions::WindowsSandboxTokenMode;
pub use resolved_permissions::WindowsWritableRoot;

/// Network settings installed during managed elevated-sandbox provisioning.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowsSandboxProvisioningSettings {
    pub proxy_ports: Vec<u16>,
    pub allow_local_binding: bool,
}

/// How setup reconciles proxy settings with an existing elevated installation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WindowsSandboxProxySettingsMode {
    #[default]
    Reconcile,
    Preserve,
}

// Vendored Win32 modules. Some carry helper APIs used only by Codex's elevated
// backend (dropped here); they are kept intact to ease future upstream sync, so
// dead-code is allowed on the vendored set.
#[cfg(windows)]
#[allow(dead_code)]
mod acl;
#[cfg(windows)]
mod allow;
#[cfg(windows)]
mod audit;
#[cfg(windows)]
#[allow(dead_code)]
mod cap;
#[cfg(windows)]
mod deny_read_acl;
#[cfg(windows)]
mod deny_read_state;
#[cfg(windows)]
#[allow(dead_code)]
mod desktop;
#[cfg(windows)]
mod dpapi;
#[cfg(windows)]
#[allow(dead_code)]
mod env;
#[cfg(windows)]
mod file_write;
#[cfg(windows)]
mod framed_io;
#[cfg(windows)]
mod gemini;
#[cfg(windows)]
mod helper_materialization;
#[cfg(windows)]
mod hide_users;
#[cfg(windows)]
mod identity;
#[cfg(windows)]
mod job;
#[cfg(windows)]
#[allow(dead_code)]
mod logging;
#[cfg(windows)]
mod no_reparse_dir;
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
mod setup;
#[cfg(windows)]
mod setup_error;
#[cfg(windows)]
mod setup_launch;
#[cfg(windows)]
mod setup_mutex;
#[cfg(windows)]
mod spawn_prep;
#[cfg(any(windows, test))]
mod ssh_config_dependencies;
#[cfg(windows)]
#[allow(dead_code)]
mod token;
#[cfg(windows)]
mod wfp;
#[cfg(windows)]
mod wfp_setup;
#[cfg(windows)]
#[allow(dead_code)]
mod winutil;
#[cfg(windows)]
mod workspace_acl;

#[cfg(windows)]
mod conpty;
#[cfg(windows)]
mod elevated;
#[cfg(windows)]
mod elevated_impl;

#[cfg(windows)]
pub(crate) use elevated::ipc_framed;
#[cfg(windows)]
pub(crate) use elevated::runner_client;
#[cfg(windows)]
pub(crate) use elevated::runner_pipe;

#[cfg(windows)]
pub use acl::{
    add_deny_read_ace, add_deny_write_ace, allow_null_device, ensure_allow_mask_aces,
    ensure_allow_mask_aces_with_inheritance, ensure_allow_write_aces, path_mask_allows,
    path_write_aces_need_refresh,
};
#[cfg(windows)]
pub use audit::apply_world_writable_scan_and_denies_for_permissions;
#[cfg(windows)]
pub use cap::{
    load_or_create_cap_sids, workspace_write_cap_sid_for_root, workspace_write_root_overlaps_path,
};
#[cfg(windows)]
pub use conpty::{ConptyInstance, spawn_conpty_process_as_user};
#[cfg(windows)]
pub use deny_read_state::sync_persistent_deny_read_acls;
#[cfg(windows)]
pub use dpapi::protect as dpapi_protect;
#[cfg(windows)]
pub use elevated_impl::{ElevatedSandboxCaptureRequest, run_windows_sandbox_capture_elevated};
#[cfg(windows)]
pub use file_write::write_file_atomically;
#[cfg(windows)]
pub use helper_materialization::{resolve_current_exe_for_launch, resolve_exe_for_launch};
#[cfg(windows)]
pub use hide_users::{hide_current_user_profile_dir, hide_newly_created_users};
#[cfg(windows)]
pub use ipc_framed::{
    ErrorPayload, ErrorStage, ExitPayload, FramedMessage, IPC_PROTOCOL_VERSION, Message,
    OutputPayload, OutputStream, ResizePayload, SpawnReady, SpawnRequest, decode_bytes,
    encode_bytes, read_frame, write_frame,
};
#[cfg(windows)]
pub use job::JobObject;
#[cfg(windows)]
pub use logging::{log_note, log_writer, setup_log_writer};
#[cfg(windows)]
pub use no_reparse_dir::{
    DirectoryOpenDisposition, create_directory_guard, open_directory_no_reparse,
    validate_local_directory_path,
};
#[cfg(windows)]
pub use process::{
    ConsoleMode, PipeSpawnHandles, StderrMode, StdinMode, read_handle_loop,
    spawn_process_with_pipes,
};
#[cfg(windows)]
pub use setup::{
    SETUP_VERSION, SandboxSetupRequest, SetupRootOverrides, run_elevated_provisioning_setup,
    run_elevated_provisioning_setup_with_retained_handles, run_elevated_setup, run_setup_refresh,
    run_setup_refresh_with_extra_read_roots, sandbox_bin_dir, sandbox_dir, sandbox_secrets_dir,
};
#[cfg(windows)]
pub use setup_error::{
    SetupErrorCode, SetupErrorReport, SetupFailure, extract_failure as extract_setup_failure,
    setup_error_path, write_setup_error_report,
};
#[cfg(windows)]
pub use setup_mutex::acquire_sandbox_setup_lock;
#[cfg(windows)]
pub use token::{
    LocalSid, convert_string_sid_to_sid, create_readonly_token_with_caps_and_user_from,
    create_workspace_write_token_with_caps_and_user_from, get_current_token_for_restriction,
};
#[cfg(windows)]
pub use wfp::install_wfp_filters_for_account;
#[cfg(windows)]
pub use wfp_setup::install_wfp_filters;
#[cfg(windows)]
pub use winutil::{
    SANDBOX_USERS_GROUP, ensure_sandbox_users_group, local_user_flags, resolve_sid,
    set_local_user_flags, string_from_sid_bytes, to_wide,
};

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
pub use windows_capture::{run_gemini_sandbox_capture, run_sandbox_capture};

#[cfg(target_os = "macos")]
mod macos_capture;
#[cfg(target_os = "macos")]
pub use macos_capture::run_sandbox_capture;

#[cfg(not(any(windows, target_os = "macos")))]
mod unsupported_capture;
#[cfg(not(any(windows, target_os = "macos")))]
pub use unsupported_capture::run_sandbox_capture;
