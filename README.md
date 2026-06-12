# yj-sandbox

A small Rust sandbox runner for untrusted commands:

- **Windows**: non-elevated restricted-token sandbox. Writes are confined to
  granted directories using a `WRITE_RESTRICTED` token plus per-root capability
  SIDs, with no admin rights, UAC prompt, driver, or separate user account.
- **macOS**: Seatbelt sandbox via `/usr/bin/sandbox-exec`. The same writable
  root model is translated into an SBPL profile. This supports both
  `x86_64-apple-darwin` and `aarch64-apple-darwin` builds.

This is a vendored and slimmed subset of
[`openai/codex`](https://github.com/openai/codex)'s Windows and macOS sandbox
code (Apache-2.0), reduced to the standalone capture path and decoupled from
the Codex crates. See [`NOTICE`](./NOTICE). For how upstream changes are pulled
in, see [`SYNCING.md`](./SYNCING.md).

## Security model — read this first

| Capability | Enforced? | Notes |
|---|---|---|
| **Write** outside granted roots | ✅ kernel-enforced | Windows ACL/restricted-token checks; macOS Seatbelt `file-write*` policy. |
| **Read** any file | ❌ **not** restricted | Default profiles grant full-disk read. `~/.ssh`, tokens, cookies are all readable. |
| **Network** | Platform-specific | Windows is env-based soft blocking. macOS uses Seatbelt default deny unless network is enabled. |

**Use this when your threat model is "prevent damage / fat-finger", not
"prevent data exfiltration".** Blocking reads requires stricter split
filesystem policies from upstream Codex that this fork has not exposed yet.
On Windows, real network isolation requires the elevated backend (WFP), which
this fork intentionally does not include.

## How it works

### Windows

1. A random **capability SID** (`S-1-5-21-…`, backed by no real account) is
   generated per writable root and persisted under the state dir.
2. A `CreateRestrictedToken(WRITE_RESTRICTED | LUA_TOKEN | DISABLE_MAX_PRIVILEGE)`
   token is built with those capability SIDs as *restricting* SIDs.
3. An allow-write ACE for the capability SID is added to each writable root;
   `.git` / `.codex` / `.agents` inside a root get deny-write ACEs.
4. The command is launched with `CreateProcessAsUserW` under that token; writes
   only succeed where an ACE grants the capability SID. Reads are unaffected.

Writable roots are **cwd-aware**: of the declared `--workspace-root`s, only the
one containing the working directory is made writable (least privilege); extra
`--writable` roots and `--temp` are always writable.

### macOS

1. The same resolved writable roots are converted to Seatbelt `file-write*`
   allow rules.
2. The base profile starts with `(deny default)`, then allows process basics,
   read access, PTYs, readonly preferences, and platform services needed by
   common tools.
3. `.git`, `.codex`, and `.agents` under writable roots stay read-only via
   Seatbelt path exclusions, even if they do not exist yet.
4. The command is launched as `/usr/bin/sandbox-exec -p <profile> -- <command>`.

## Usage

```
yj-sandbox-run [OPTIONS] -- <command> [args...]

  --workspace-root <DIR>   cwd-aware writable project root (repeatable)
  --writable <DIR>         always-writable extra root (repeatable)
  --temp                   also make TEMP/TMP or TMPDIR writable
  --read-only              no writable roots (read-only sandbox)
  --no-network             apply the env-based soft network block
  --cwd <DIR>              working directory (default: current dir)
  --state-dir <DIR>        capability-SID + log dir (default: %LOCALAPPDATA%\yj-sandbox)
  --private-desktop        run on a private desktop/window station (Windows)
  --timeout-ms <N>         terminate the command after N ms
```

Examples:

```powershell
# Confine writes to a project; run a build
yj-sandbox-run --workspace-root C:\proj\app --cwd C:\proj\app -- cmd /c "npm run build"

# Read-only: command can read anything but write nothing
yj-sandbox-run --read-only --cwd C:\proj\app -- cmd /c "npm test"
```

Exit code is the child's exit code (`192` on timeout, `2` on argument error).
Child stdout/stderr are streamed live to this process's stdout/stderr. On
Windows, the child runs inside a kill-on-close job object so killing
`yj-sandbox-run` tears down the sandboxed process tree.

## Library

```rust
use yj_sandbox::{ResolvedSandboxPermissions, run_sandbox_capture};

let perms = ResolvedSandboxPermissions::workspace_write(
    vec![workspace_root],   // cwd-aware workspace roots
    vec![],                 // extra always-writable roots
    true,                   // include TEMP/TMP or TMPDIR
    false,                  // block_network (soft)
);
// Last two flags: use_private_desktop, stream_output (tee child output live).
let result = run_sandbox_capture(&perms, &state_dir, command, &cwd, env, None, None, false, false)?;
```

## Build

```
cargo build --release
```

Windows builds produce `yj-sandbox-run.exe`. macOS builds use the same binary
name and require `/usr/bin/sandbox-exec` at runtime. Build separately for Intel
and Apple Silicon with `x86_64-apple-darwin` and `aarch64-apple-darwin`, or
combine them into a universal binary outside Cargo.

## License

Apache-2.0. Derived from `openai/codex`; see [`LICENSE`](./LICENSE) and
[`NOTICE`](./NOTICE).
