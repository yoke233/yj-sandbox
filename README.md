# yj-sandbox

A standalone Rust sandbox runner derived from the sandbox implementation in
[`openai/codex`](https://github.com/openai/codex) (Apache-2.0).

- **Windows** keeps both Codex backends and adds a lightweight `gemini` backend.
  `unelevated` uses Codex's current-user restricted token; `elevated` uses
  dedicated sandbox accounts, deny-read ACLs, Windows Filtering Platform rules,
  and the Codex setup/command-runner helpers. `gemini` uses the current user at
  Low Integrity and is the standalone default.
- **macOS** uses Seatbelt through `/usr/bin/sandbox-exec`.

The Windows source layout, helper names, setup protocol, upstream backend
values, and CLI option names intentionally stay close to Codex. The local
`gemini` adapter is isolated from vendored modules. Codex-wide config,
telemetry, UI, and API dependencies are replaced by a small standalone adapter.
See [`SYNCING.md`](./SYNCING.md) and [`NOTICE`](./NOTICE).

## Windows security model

| Backend | Writes | Reads | Network | Setup |
|---|---|---|---|---|
| `gemini` (default) | Low Integrity labels on every resolved writable root | Full disk | Direct/inherited | None |
| `unelevated` | Restricted-token + capability ACLs | Full disk | Environment-based soft block | None |
| `elevated` | Dedicated sandbox identity + ACLs | Supports deny-read policy | WFP/firewall rules | Administrator setup once |

`gemini` follows Gemini CLI's narrow Windows contract: it calls
`CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`, lowers the token to Low
Integrity, applies inheritable Low labels to the workspace, extra writable
roots, and configured temporary roots, and uses the existing kill-on-close Job
Object. Reads and direct network access are intentionally unrestricted. Labels
remain on those roots; this is intended for disposable client workspaces.
Like Gemini CLI itself, ACL/label failures are reported as warnings and launch
continues. The caller must own the writable roots strongly enough to change
their labels.

Low Integrity is the write boundary, not a session-specific path allowlist. A
Gemini child can also write another object that was already labeled Low when
the current user's DACL permits it. Consequently `:read-only` and
`--sandbox-state-disable-network` are not strict enforcement controls in the
`gemini` backend. Select `unelevated` or `elevated` for a restricted-token
read-only contract; only `elevated` provides the WFP-backed network boundary.

The original Schannel `curl` failure remains reproducible under upstream-style
`unelevated`, but `gemini` retains the current user's Schannel context and passes
the native curl, Git HTTPS, and npm HTTPS E2E checks. Upstream has not fixed the
Schannel path as of 2026-09-04 (`openai/codex#17459` is still open); see
`SYNCING.md` for the review log.

## Windows package layout

The release layout follows upstream Codex. Windows has three executable roles,
but only the main CLI belongs on `PATH`:

```text
yj-sandbox-v0.5.0-windows-x86_64/
├── bin/
│   └── yj-sandbox-run.exe
└── codex-resources/
    ├── codex-command-runner.exe
    └── codex-windows-sandbox-setup.exe
```

The main process locates helpers next to the package and copies the command
runner into the versioned sandbox state directory when needed. The helpers are
separate binaries, so their code does not inflate `yj-sandbox-run.exe`; the
Windows archive is larger because it contains all three files.

## CLI

The public option names and validation follow current `codex sandbox windows`,
with Codex's shared repeatable `--add-dir` option exposed for standalone use:

```text
yj-sandbox-run [OPTIONS] [COMMAND]...

  --sandbox-state-json <JSON>
  --sandbox-state-readable-root <PATH>   repeatable; requires state JSON
  --sandbox-state-disable-network        requires state JSON
  -P, --permissions-profile <NAME>
  -p, --profile <NAME>
  -C, --cd <DIR>                          requires --permissions-profile
      --add-dir <DIR>                     repeatable; relative to the command cwd
      --include-managed-config            requires --permissions-profile
  -c, --config <key=value>                windows.sandbox override in Codex form
```

This standalone build exposes the two upstream built-in managed profiles:
`:workspace` (default) and `:read-only`. Backend selection uses the upstream
configuration key. `elevated` and `unelevated` retain their upstream meanings;
`gemini` is the local default. Like Codex, `--add-dir` extends a writable
workspace profile and is ignored with a warning for `:read-only`.

Named permission profiles and Codex's managed-requirements loader are not linked
into this standalone crate. `--include-managed-config`, non-built-in permission
profiles, and `-c` keys other than `windows.sandbox` therefore fail explicitly
instead of being silently ignored.

```powershell
# Gemini-compatible Low Integrity backend (default)
& .\bin\yj-sandbox-run.exe `
  -P :workspace -C C:\work\app -- cmd.exe /c "npm test"

# Add multiple writable directories using the upstream repeatable flag
& .\bin\yj-sandbox-run.exe `
  -P :workspace -C C:\work\app `
  --add-dir D:\cache `
  --add-dir D:\output `
  -- cmd.exe /c "npm test"

# Upstream-compatible unelevated restricted-token backend
& .\bin\yj-sandbox-run.exe `
  -c 'windows.sandbox="unelevated"' `
  -P :workspace -C C:\work\app -- cmd.exe /c "npm test"

# Elevated backend after setup
& .\bin\yj-sandbox-run.exe `
  -c 'windows.sandbox="elevated"' `
  -P :workspace -C C:\work\app -- cmd.exe /c "npm test"
```

The same value may be stored in `$CODEX_HOME/config.toml` (or
`$HOME/.codex/config.toml`):

```toml
[windows]
sandbox = "gemini" # or "unelevated" / "elevated"
```

`-p NAME` layers `$CODEX_HOME/NAME.config.toml` over the base file for backend
selection, matching the upstream file naming convention. A later `-c` override
wins.

## Elevated setup

Run setup from an administrator PowerShell. The command name and arguments
match current Codex:

```powershell
& .\bin\yj-sandbox-run.exe setup --elevated --current-user
```

Managed deployment may specify the target identity explicitly:

```powershell
& .\bin\yj-sandbox-run.exe setup --elevated `
  --user 'DOMAIN\alice' `
  --codex-home 'C:\Users\alice\.codex'
```

Successful setup persists `windows.sandbox = "elevated"`. Setup creates local
sandbox identities, writes protected credentials/state, configures ACLs, and
installs Windows network restrictions. Review this operation before running it;
building or testing the crate does not execute setup.

## Library

The existing standalone capture API remains available:

```rust
use yj_sandbox::{ResolvedSandboxPermissions, run_sandbox_capture};

let permissions = ResolvedSandboxPermissions::workspace_write(
    vec![workspace_root],
    vec![],
    true,
    true,
);
let result = run_sandbox_capture(
    &permissions,
    &state_dir,
    command,
    &cwd,
    env,
    None,
    None,
    false,
    false,
)?;
```

On Windows, `ElevatedSandboxCaptureRequest` and
`run_windows_sandbox_capture_elevated` select the elevated capture path without
going through the CLI.

## Build

```powershell
cargo build --release --bins
```

Windows produces:

```text
target/release/yj-sandbox-run.exe
target/release/codex-command-runner.exe
target/release/codex-windows-sandbox-setup.exe
```

Run the Windows Gemini E2E suite after building. It verifies the default mode,
native Schannel curl, Low Integrity, multiple writable roots, outside-write
denial, Git/npm HTTPS, nested processes, and exit-code propagation:

```powershell
& .\tools\test-gemini-e2e.ps1
```

On macOS, build only the main binary. The helper binaries are Windows-only:

```text
cargo build --release --bin yj-sandbox-run
```

## License

Apache-2.0. Derived from `openai/codex` with a Windows Low Integrity backend
ported from Google Gemini CLI; see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
