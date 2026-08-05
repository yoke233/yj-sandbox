use crate::install_wfp_filters_for_account;
use std::path::Path;

fn panic_payload_to_string(panic_payload: Box<dyn std::any::Any + Send>) -> String {
    match panic_payload.downcast::<String>() {
        Ok(message) => *message,
        Err(panic_payload) => match panic_payload.downcast::<&'static str>() {
            Ok(message) => (*message).to_string(),
            Err(_) => "unknown panic payload".to_string(),
        },
    }
}

/// Installs the same upstream WFP rules. The standalone crate intentionally
/// omits Codex's Statsig/OTEL reporting dependency.
pub fn install_wfp_filters<F>(_state_dir: &Path, offline_username: &str, mut log: F)
where
    F: FnMut(&str),
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        install_wfp_filters_for_account(offline_username)
    })) {
        Ok(Ok(installed_filter_count)) => log(&format!(
            "WFP setup succeeded for {offline_username} with {installed_filter_count} installed filters"
        )),
        Ok(Err(err)) => log(&format!(
            "WFP setup failed for {offline_username}: {err}; continuing elevated setup"
        )),
        Err(payload) => log(&format!(
            "WFP setup panicked for {offline_username}: {}; continuing elevated setup",
            panic_payload_to_string(payload)
        )),
    }
}
