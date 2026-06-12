# yj-sandbox

A **non-elevated Windows restricted-token sandbox** for running untrusted
commands. It confines a command's **writes** to a set of granted directories
using a `WRITE_RESTRICTED` token plus per-root capability SIDs — enforced by the
Windows kernel, with **no admin rights, no UAC prompt, no driver, and no
separate user account**.

This is a vendored and slimmed subset of
[`openai/codex`](https://github.com/openai/codex)'s `windows-sandbox-rs`
(Apache-2.0), reduced to the non-elevated capture path and decoupled from the
Codex crates. See [`NOTICE`](./NOTICE). For how upstream changes are pulled in,
see [`SYNCING.md`](./SYNCING.md).

## Security model — read this first

| Capability | Enforced? | Notes |
|---|---|---|
| **Write** outside granted roots | ✅ kernel-enforced | The whole point. Blocks accidental/destructive writes to the system, other projects, user files. |
| **Read** any file | ❌ **not** restricted | Full-disk read. `WRITE_RESTRICTED` tokens only consult capability SIDs for *writes*. `~/.ssh`, tokens, cookies are all readable. |
| **Network** | ⚠️ soft only | Injects `HTTP_PROXY` → dead port, `CARGO_NET_OFFLINE`, ssh/scp stub shims, etc. Native sockets bypass it. Existing proxy env vars are **not** overridden. |

**Use this when your threat model is "prevent damage / fat-finger", not
"prevent data exfiltration".** Blocking reads or doing real network isolation
requires the elevated backend (separate sandbox account + deny-read ACLs + WFP),
which this fork intentionally does not include.

## How it works

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

## Usage

```
yj-sandbox-run [OPTIONS] -- <command> [args...]

  --workspace-root <DIR>   cwd-aware writable project root (repeatable)
  --writable <DIR>         always-writable extra root (repeatable)
  --temp                   also make TEMP/TMP writable
  --read-only              no writable roots (read-only sandbox)
  --no-network             apply the env-based soft network block
  --cwd <DIR>              working directory (default: current dir)
  --state-dir <DIR>        capability-SID + log dir (default: %LOCALAPPDATA%\yj-sandbox)
  --private-desktop        run on a private desktop/window station
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
Child stdout/stderr are streamed live to this process's stdout/stderr. The
child runs inside a kill-on-close job object: killing `yj-sandbox-run` (or
its normal exit) tears down the entire sandboxed process tree, including
backgrounded grandchildren.

## Library

```rust
use yj_sandbox::{ResolvedWindowsSandboxPermissions, run_sandbox_capture};

let perms = ResolvedWindowsSandboxPermissions::workspace_write(
    vec![workspace_root],   // cwd-aware workspace roots
    vec![],                 // extra always-writable roots
    true,                   // include TEMP/TMP
    false,                  // block_network (soft)
);
// Last two flags: use_private_desktop, stream_output (tee child output live).
let result = run_sandbox_capture(&perms, &state_dir, command, &cwd, env, None, None, false, false)?;
```

## Build

```
cargo build --release   # -> target/release/yj-sandbox-run.exe
```

Windows host with the MSVC toolchain. The crate compiles on non-Windows (the
runner is a stub that errors at call time) so it can be referenced from
cross-platform workspaces.

## License

Apache-2.0. Derived from `openai/codex`; see [`LICENSE`](./LICENSE) and
[`NOTICE`](./NOTICE).
