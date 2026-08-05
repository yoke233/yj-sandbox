# Syncing from upstream Codex

This repository is a manifest-driven vendor of:

- `codex-rs/windows-sandbox-rs`
- the macOS Seatbelt source and SBPL profiles from `codex-rs/sandboxing/src`

The goal is to keep the Windows sandbox structure and helper protocol close to
upstream while isolating standalone differences in a small set of adapters.
`tools/codex-vendor.json` is the authoritative path map.

## Vendor baseline

| | |
|---|---|
| Upstream repo | `https://github.com/openai/codex` (`main`) |
| Vendored/reviewed at commit | `5d89ab65dc9d4d0c55796c11df112b54157922b4` |
| Windows subtree | `codex-rs/windows-sandbox-rs/` |
| macOS sources | `codex-rs/sandboxing/src/seatbelt.rs` and its three SBPL files |

The SHA above, `NOTICE`, and `tools/codex-vendor.json` must always agree.

## Sync boundaries

### Verbatim

Most Win32 implementation modules remain byte-for-byte upstream, including ACL,
token, DPAPI, sandbox identities, WFP, helper materialization, the elevated
runner transport, and the two helper entry points. The sync tool can safely
overwrite these only when the local blob is the recorded baseline or requested
target blob.

### Thin adapters requiring review

| Area | Local difference |
|---|---|
| `resolved_permissions.rs` | Serializable local equivalent of the resolved Codex permission profile. |
| `lib.rs` | Standalone public API and cross-platform dispatch. |
| `windows_capture.rs` / `spawn_prep.rs` | Existing synchronous unelevated capture API plus a small dispatch seam for the local Gemini backend. |
| `elevated_impl.rs` / `elevated/ipc_framed.rs` | Send resolved local permissions instead of `codex_protocol` types. |
| `process.rs` / `job.rs` / `conpty/mod.rs` | Small `windows-sys` replacements for `codex-utils-pty` ownership types. |
| `setup.rs` / `setup_error.rs` / `wfp_setup.rs` | Remove Codex config/OTEL dependencies; keep setup, ACL, firewall, and WFP behavior. |
| helper `win.rs` files | Import `yj_sandbox`; OTEL payload fields are omitted. |
| `src/bin/yj-sandbox-run/main.rs` | Standalone CLI adapter; argument names and upstream backend values follow Codex, with local `gemini` selection. |

### Local Gemini extension

`src/gemini.rs` is not vendored from Codex and must never be overwritten by the
Codex sync tool. It is an isolated Rust port of Gemini CLI's current-user Low
Integrity token and writable-root labeling flow. `windows.sandbox="gemini"` is
the standalone default; explicit `unelevated` and `elevated` continue to select
the upstream-compatible paths.

### Intentionally omitted

The Tokio `unified_exec`/stdio bridge, Codex internal wrapper, and
`deny_read_resolver` are not compiled. They are Codex integration layers rather
than the Windows enforcement primitives. Elevated synchronous capture, ConPTY
inside the command runner, deny-read ACL application, WFP, and both helpers are
included.

## Workflow

Use PowerShell 7 and a local Codex checkout:

```powershell
.\tools\sync-codex.ps1 `
  -CodexPath D:\project\openai-codex `
  -Fetch

.\tools\sync-codex.ps1 `
  -CodexPath D:\project\openai-codex `
  -TargetRef origin/main `
  -ApplyVerbatim

.\tools\sync-codex.ps1 `
  -CodexPath D:\project\openai-codex `
  -TargetRef origin/main `
  -Json
```

Exit codes:

- `0`: no mapped upstream change
- `1`: changes require review or baseline advancement
- `2`: manifest, ancestry, local drift, or dependency invariant failed
- `3`: Git/archive/filesystem tooling failed

After copying verbatim files:

1. Review every `modified/review` and `rewritten/semantic` diff.
2. Keep standalone changes inside the adapter seams listed above.
3. Run the test, release build, CLI parsing, helper lookup, and sandbox smoke checks.
4. Advance the baseline SHA only after review succeeds.

The syncer's isolated contract test is:

```powershell
.\tools\test-sync-codex.ps1
```

## Dependency invariant

The compiled crate must not depend on `codex_protocol`, `codex_otel`,
`codex_utils_pty`, `codex_utils_absolute_path`, `codex_utils_string`,
`codex_network_proxy`, or `codex_core`. Disabled upstream-only fixture modules
are ignored by the textual check; `cargo check --all-targets` is the final
compiled dependency check.

## Windows release and smoke checks

```powershell
cargo test --all-targets
cargo build --release --bins
& .\tools\test-gemini-e2e.ps1

$bin = '.\target\release\yj-sandbox-run.exe'
$cwd = (Resolve-Path .).Path

& $bin -c 'windows.sandbox="unelevated"' -P :read-only -C $cwd -- `
  cmd.exe /d /s /c 'echo sandbox-ok'

# Elevated setup changes local users, protected state, ACLs, firewall, and WFP.
# Run it manually from an administrator shell only when that integration test is intended.
& $bin setup --elevated --current-user
& $bin -c 'windows.sandbox="elevated"' -P :workspace -C $cwd -- `
  cmd.exe /d /s /c 'echo elevated-ok'
```

The Windows release archive must contain:

```text
bin/yj-sandbox-run.exe
codex-resources/codex-command-runner.exe
codex-resources/codex-windows-sandbox-setup.exe
```
