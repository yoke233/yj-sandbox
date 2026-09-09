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

## Upstream review log

### 2026-09-04

`codex-rs/windows-sandbox-rs` has 29 commits between the baseline `5d89ab6`
and upstream `ea2046f`. They cover provisioning, deny-read resolution, private
desktops, uninstall, ACL hardening, and helper lookup. None of them touches
TLS, Schannel, or credential handling.

`src/token.rs` changed by one line in that range: `get_user_sid_bytes` became
`pub(crate)`. Restricted-token construction is unchanged
(`DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED`, restricting SIDs =
capabilities, logon SID, Everyone), and the unelevated path still omits the
caller user SID that the elevated path adds. That omission is where the
Schannel write check fails, so the `unelevated` HTTPS failure is unchanged
upstream: `SEC_E_NO_CREDENTIALS` via Schannel is `openai/codex#17459` (open,
no maintainer reply, no linked PR), and `openai/codex#42621` reports the same
error for private Git under `elevated`. Upstream `sandbox_smoketests.py` only
asserts that curl HTTPS is *blocked*, so a working-HTTPS case is not covered
by upstream CI at all.

Gemini CLI's Windows sandbox sources were reviewed on the same day and are
byte-identical to the studied baseline; see
`docs/gemini-windows-native-sandbox-study.md`, section 9.

This review did not advance the baseline SHA.

### 2026-09-09

Selective hardening was ported against reviewed Codex commit `ea2046f36d5ee12d39c8e168fc3e5129301afa2b`, plus the isolated proxy-marker optimization from `38cbebaf3fe3e81a94bf462079e7cf9659fc9e50`.

Windows now includes bounded framed I/O, no-reparse directory guards, handle-relative atomic state replacement, retained setup handles, machine-wide setup serialization, protected setup logs/markers/error reports, account-repair safeguards, and the reviewed ACL/helper lifecycle fixes. Standalone adapters still omit Codex protocol, service, and OTEL dependencies.

macOS now includes writable-root alias validation, literal-versus-subpath binding, protected-ancestor rename denies, expanded unreadable-glob enforcement, and process-only shared scratch grants. The obsolete `restricted_read_only_platform_defaults.sbpl` mapping was replaced by the upstream preferences and read-only policy fragments.

The recorded vendor baseline remains `5d89ab65dc9d4d0c55796c11df112b54157922b4`: this was a selective semantic port, not a complete subtree sync. `NOTICE` and the manifest baseline therefore remain unchanged.

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
