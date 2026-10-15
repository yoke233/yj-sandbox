# yj-sandbox

A standalone Rust sandbox runner derived from the sandbox implementation in
[`openai/codex`](https://github.com/openai/codex) (Apache-2.0).

- **Windows** keeps both Codex backends and adds a lightweight `gemini` backend.
  `unelevated` uses Codex's current-user restricted token; `elevated` uses
  dedicated sandbox accounts, deny-read ACLs, Windows Filtering Platform rules,
  and the Codex setup/command-runner helpers. `gemini` uses the current user at
  Low Integrity and is the standalone default.
- **macOS** uses Seatbelt through `/usr/bin/sandbox-exec`.
- **OHOS ARM64** uses a pure-ptrace per-run directory guard against accidental
  file access. It is not a hostile-code sandbox or a network isolation boundary.

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
yj-sandbox-v0.6.1-windows-x86_64/
├── bin/
│   └── yj-sandbox-run.exe
└── codex-resources/
    ├── codex-command-runner.exe
    └── codex-windows-sandbox-setup.exe
```

Releases publish this layout for both `windows-x86_64` and `windows-aarch64`.

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

## OHOS ARM64 directory control

The `aarch64-unknown-linux-ohos` main binary implements an independent
`ohos-ptrace` backend. Rust identifies this target as `target_os = "linux"` and
`target_env = "ohos"`; generic Linux builds do not select it. Windows/macOS
backend behavior and CLI state parsing are unchanged.

### Contract and policy

First run `yj-sandbox-run --ohos-check`. Success prints only:

```json
{"available":true,"backend":"ohos-ptrace","protection":"accidental-file-access","protocol":1}
```

This is an active disposable-child probe, not an OS-name check. It verifies
TRACEME, syscall stops, required ptrace options, GET/SETREGSET `NT_PRSTATUS`
and `NT_ARM_SYSTEM_CALL`, remote memory read/write, a real write with a changed
byte, and a skipped write returning EACCES without producing output. A failed
probe exits nonzero. Each command repeats the mechanism probe before launching
user code, then installs tracing before its first exec; there is no native retry.
Neither GET_SYSCALL_INFO, seccomp, namespaces, nor Landlock is used.

Use the existing invocation:

```text
yj-sandbox-run --sandbox-state-json <JSON> -- <absolute-private-HNP-bash> -c <command>
```

The state must contain `sandboxCwd` and a managed, network-enabled,
restricted `permissionProfile.file_system` with explicit absolute native
`path` entries. `read`, `write`, `deny`, and `none` are consumed. Special/glob
roots, implicit profiles, writable whole-filesystem roots, disabled-network
requests, and unrelated Windows configuration switches fail explicitly on OHOS.
A filesystem-root `read` entry is supported; it does not grant any OS permission.
Additional `--sandbox-state-readable-root` entries are explicit read-only roots,
not invisible loader exceptions.

Outside all declared roots, content reads, directory listing and writes are denied.
The client supplies a filesystem-root **read-only** entry so ordinary
`workspace_write` commands can read any directory already readable by the App
and the executing HNP. OS DAC, signature permissions and other kernel checks
still apply: neither this entry nor the picker escalates them. The App directory
picker only changes application OS access; its RO/RW result is not an Agent
write grant or a per-Agent read restriction.

The most specific matching read/write root wins; an exact read/write tie is
read-only. Workspace and explicitly declared managed runtime/scratch write
children can override the root read default. Explicit user `readOnlyPaths`
protect their descendants: the client downgrades overlapping declared writable
children to read-only. `deny`/`none` always wins, including against more-specific
writable entries. Protected settings remain denied. Both lexical and resolved
paths must permit the operation.
The cwd must already be readable; it never receives an implicit grant.
The client requires an explicit temporary directory inside declared writable
roots, outside explicit RO/deny subtrees; no implicit `/tmp`, app userData or
filesystem-wide writable root is added. `/dev/null` retains its write exception
for standard I/O.
Metadata-only stat/access/readlink queries may inspect ancestors of declared
read/write roots (both lexical and resolved), even when a narrower caller policy
does not permit parent-directory content reads. Explicit denies still win.
`O_PATH` can acquire such a metadata handle; fstat/empty-path metadata queries
remain metadata-only, while every later FD read, getdents, write, mapping or
directory change still requires the ordinary data policy. Permission queries
report OS permissions, not a sandbox grant for a later operation.


Policy checks both the requested spelling and the resolved existing ancestors,
including relative cwd/dirfd paths, symlinks, missing creation targets,
component boundaries, and `..` in kernel pathname order. `/proc/self` and
`/proc/thread-self` roots remain symbolic and refer to each tracee, not to
the tracer. Proc FD/executable magic links still require permission for their
resolved target. Explicit RO/deny subtrees also prevent renaming or removing
an ancestor out of the protected namespace.

### Operations and lifecycle

The guard covers openat/openat2, fd reads/writes and vectored/positioned I/O,
truncate/ftruncate/fallocate, getdents/stat/access/readlink/xattrs, mkdir,
unlink, rename, hardlinks/symlinks, chmod/chown/timestamps, chdir/fchdir,
sendfile/splice/copy_file_range and file-backed mmap. Hardlink sources require
write access so a writable alias cannot defeat a read-only inode. ELF
PT_INTERP and shebang interpreter reads are checked before exec as well.
File-backed shared mappings require RW permission when writable or when their
FD is not read-only, including initially read-only mappings that could later be
promoted with mprotect. A PROT_READ shared mapping of a kernel-confirmed
O_RDONLY FD requires only read access; kernel FD permissions prevent later
write promotion. Missing or malformed proc fdinfo fails closed. Private read
mappings and anonymous mappings remain available.

Pathnames are copied into the guard's existing fixed buffer with
`process_vm_readv` (ARM64 syscall 270), bounded by the actual remote page
boundary and the 4096-byte pathname limit. Only successfully returned bytes
are searched for NUL; short reads continue from the next unread byte. A failed
or zero-length bulk read switches that pathname to the existing aligned
`PTRACE_PEEKDATA` reader. Protected pages are not assumed to be ptrace-readable.
ENOSYS/EPERM/EACCES disable bulk reads for the remaining run instead of
retrying an unsupported interface for every pathname.
This is only an internal memory-read fallback: both readers feed the same
path/symlink/FD policy, and neither retries a command outside the guard.
No pathname permission or symlink-resolution result is cached. The active
startup capability probe still runs before every command; `--ohos-check`
remains available as a standalone diagnostic.

On the tested commercial device, a bulk request crossing into `PROT_NONE`
fails with EFAULT rather than returning the readable prefix. Both private and
shared protected mappings also reject PEEKDATA with EPERM. Page-bounded
requests avoid the unnecessary cross-page failure; an unreadable pathname
still fails closed if the old reader cannot inspect it either.

Unsupported alternate filesystem pathways (kernel AIO, handle-based open,
mount/namespace changes, privileged device creation, external-process
memory/FD acquisition, and unhandled filesystem/device ioctls) fail closed
with `YJ_OHOS_DIRECTORY_DENIED` diagnostics. io_uring and clone3 return ENOSYS,
allowing ordinary libuv/libc fallback to traced synchronous I/O/clone; this
does not grant an untraced retry. Unknown modern syscall interfaces also
return ENOSYS. Ordinary threads and fork/vfork/clone/exec descendants remain
traced. FICLONE/FICLONERANGE check both source-read and destination-write
permission; other unsupported disk ioctls return ENOTTY for normal fallbacks.
`openat2 RESOLVE_IN_ROOT` is rejected because it changes pathname semantics.

The CLI inherits stdout/stderr directly, so flushed child output is streamed,
not held until exit. Normal root exit status is preserved (signals use
128 + signal); startup/internal errors exit nonzero. All inherited FDs above
stdio are closed before exec. SIGINT/SIGTERM/SIGHUP trigger owned process-group
and descendant cleanup/reaping; root exit also ends its background descendants.
Every tracee has EXITKILL, and the root has a parent-death signal. Fork children
start at syscall entry; exec events retain their matching syscall exit.
The library capture API can capture output or stream it, and supports its
existing timeout/cancellation hooks; use this backend in a dedicated runner
process, not concurrently inside an application that also owns child waiters.

### Diagnosing executable compatibility

`--ohos-check` verifies tracing mechanics, not whether the platform permits
every executable image to run while traced. To separate image compatibility
from the production syscall policy/state machine, run the diagnostic-only
`tools/ohos-exec-probe.py` under the application's signed Python HNP and UID,
**outside** the directory-control runner:

```text
<signed-python> <probe-path> --bash <absolute-private-bash-path> --timeout 8
```

It emits one JSON object comparing untraced, minimal TRACEME+CONT (no ptrace
options), and TRACEME+SYSCALL execution of private Bash, direct system toybox,
and system ls. It does not inspect user data, change policy, mutate tracee
registers, detach, or retry commands outside a sandbox. Each case has a deadline,
bounded captured output, and cleanup/wait restricted to its own child PID.
Run it separately from the application process's other child waiters.

If an image succeeds untraced but its `execve` returns EPERM even under minimal
CONT, the production policy and syscall-phase handling cannot be the cause of
that rejection. If minimal tracing succeeds but the runner fails, investigate
the runner's event handling and explicit `YJ_OHOS_DIRECTORY_DENIED` markers.
Do not infer a particular kernel security mechanism from EPERM alone, broaden
directory grants, or implement an untraced fallback.

The formal-client mechanism experiment (application UID 20020182) observed
private signed Bash succeed in all three modes. Direct system toybox succeeded
untraced, but both toybox and system ls returned `execve` EPERM/exit 126 under
minimal CONT with **no ptrace options or register writes**. SYSCALL tracing
gave the same rejection, before an exec event. Untraced system ls did enter
its image, then independently failed its system-symlink metadata read with
EACCES. These observations establish an image/platform tracing compatibility
limit, not a production syscall-phase bug; they do not identify a particular
security module or kernel hook.

The compatible integration route is a source-built OHOS utility collection
signed into the existing private Bash HNP and resolved through its existing
PATH. Those commands must remain under the same directory policy and tracing
for their entire lifetime. Do not copy and redistribute the device's system
binary, redirect absolute system executable paths invisibly, grant additional
directory access, detach, or suppress the platform's original exec error.

The client's `apps/shell/scripts/build-harmonyos-toybox.mjs` builds pinned upstream Toybox
0.8.13 source with the official OHOS SDK26 toolchain/sysroot. Its unsigned
`apps/harmonyos/toybox/build/dist/` output includes the single ELF, original
LICENSE, explicit applet configuration, and a source/toolchain/file-hash
manifest. The applet allowlist excludes setuid support and network, power, and
system-administration commands. Signing, HNP packaging, command entrypoints,
and formal-UID protection regression checks remain client integration steps.

### Deliberate limitations

This is an **accidental-file-access guard for non-adversarial commands**, not
hostile-code isolation. Native app directory grants remain the app-scoped
upper bound. A separate writer can change a MAP_SHARED pathname after the
check and before resume; mutable path buffers, FD replacement, symlinks,
renames, inode aliases/hardlinks that predate a run, and namespace changes by
another process likewise retain check/continue races. There is no atomic
path-to-inode capability or snapshot of a changing directory tree. Kernel
implicit activity beyond inspected ELF/shebang interpreters is not a complete
filesystem mediation boundary. Original intended stdio, pipes, sockets and
anonymous memory descriptors are available, and normal network access remains
enabled. Do not run hostile code or remove unrelated business/network approval
on the strength of this guard.

### Build and package

Build only the main binary with a compatible Rust OHOS ARM64 standard library
and the OHOS API26 native SDK. With the standard library already prepared:

```powershell
$native = Join-Path $env:DEVECO_SDK_HOME 'default/openharmony/native'
$env:CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_LINKER = "$native/llvm/bin/clang.exe"
$env:CARGO_ENCODED_RUSTFLAGS = @(
  '-C', 'link-arg=--target=aarch64-linux-ohos',
  '-C', "link-arg=--sysroot=$native/sysroot"
) -join [char]0x1f
cargo build --release --target aarch64-unknown-linux-ohos --bin yj-sandbox-run
```

The unsigned result is
`target/aarch64-unknown-linux-ohos/release/yj-sandbox-run`. Client packaging
signs it with the normal OHOS profile/API26 permission section and places it
at `bin/yj-sandbox-run` inside the existing `bash.org/bash_5.3` private HNP;
there is no seventh runtime package. It must use the platform
`/lib/ld-musl-aarch64.so.1` and platform C libraries, not a C++ runtime.
Policy and stop-phase regressions live in `ohos_policy.rs`; native FD,
mapping, thread/fallback, interpreter and active-probe regressions live in
`ohos.rs`. Its owned-child pathname regression exercises both bulk and forced
PEEKDATA reads: empty/non-UTF8 and unaligned paths, a NUL at the last readable
page byte, a 4095-byte path plus NUL, a 4096-byte unterminated path,
readable-to-PROT_NONE continuation with the same success/denial as the old
reader, and invalid pointers after a successful read (no stale buffer
acceptance). The diagnostic-only
`tools/ohos-memory-read-probe.py` records raw interface behavior under the app
UID; SDK declarations alone do not establish kernel support. Real-client
Bash/Python/Node/OfficeCLI and cancellation validation must be performed under
the formal app UID and its signed HNP payload, including the existing
RO/deny, FD, symlink and protected-ancestor rename cases.

## License

Apache-2.0. Derived from `openai/codex` with a Windows Low Integrity backend
ported from Google Gemini CLI; see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
