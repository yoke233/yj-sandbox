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
    _stream_output: bool,
) -> Result<CaptureResult> {
    bail!("sandbox capture is only available on Windows and macOS")
}
