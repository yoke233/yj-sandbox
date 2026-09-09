#![cfg(target_os = "macos")]

use std::io;
use std::path::Path;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

fn wait_for_path(path: &Path, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("timed out waiting for {}", path.display()),
    ))
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "timed out waiting for yj-sandbox-run to exit",
    ))
}

#[test]
fn sigterm_kills_delayed_grandchild_before_it_can_write() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let ready = temp.path().join("ready");
    let leaked = temp.path().join("leaked");
    let script = r#"(sleep 2; printf leaked > "$1") & printf ready > "$2"; wait"#;

    let mut sidecar = Command::new(env!("CARGO_BIN_EXE_yj-sandbox-run"))
        .args(["-P", ":workspace", "-C"])
        .arg(temp.path())
        .arg("--")
        .args(["/bin/sh", "-c", script, "sh"])
        .arg(&leaked)
        .arg(&ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    wait_for_path(&ready, Duration::from_secs(5))?;
    let signal_result = unsafe { libc::kill(sidecar.id() as libc::pid_t, libc::SIGTERM) };
    if signal_result != 0 {
        return Err(io::Error::last_os_error().into());
    }

    let status = wait_for_exit(&mut sidecar, Duration::from_secs(5))?;
    assert!(
        !status.success(),
        "SIGTERM cancellation should not report success"
    );
    thread::sleep(Duration::from_millis(2200));
    assert!(
        !leaked.exists(),
        "sandbox descendant survived sidecar termination and wrote {}",
        leaked.display()
    );

    Ok(())
}
