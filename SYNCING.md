# Syncing from upstream Codex

This crate is a **manifest-driven manual vendor** (not a git fork or submodule)
of subsets of `openai/codex`:

- Windows: `codex-rs/windows-sandbox-rs`
- macOS: `codex-rs/sandboxing/src/seatbelt.rs` and its SBPL profiles

Upstream occasionally ships sandbox security fixes. The canonical path map and
sync policy live in `tools/codex-vendor.json`; `tools/sync-codex.ps1` compares
that map with an exact upstream commit and only auto-copies files proven to be
verbatim.

## Vendor baseline (update after every sync)

| | |
|---|---|
| Upstream repo | `https://github.com/openai/codex` (branch `main`) |
| Vendored/reviewed at commit | `81da9deb065d7adb283816b19b40f89bcc484276` |
| `windows-sandbox-rs/src` last touched before that head | `b115de97d` (2026-07-23) |
| Windows upstream subtree | `codex-rs/windows-sandbox-rs/src/` |
| macOS upstream files | `codex-rs/sandboxing/src/seatbelt.rs`, `seatbelt_base_policy.sbpl`, `seatbelt_network_policy.sbpl`, `restricted_read_only_platform_defaults.sbpl` |

> When you finish a sync, bump the SHA in `tools/codex-vendor.json`, this table,
> and `NOTICE`. The checker refuses to run if these mirrors disagree.

## File map

`tools/codex-vendor.json` is authoritative. Every entry declares the local and
upstream paths, platform, classification, sync strategy, and the local behavior
that must be preserved.

### Verbatim vendor — codex-free, safe to overwrite then re-check

These have **no** local edits or dependency on Codex crates. The sync tool
hashes the local file against the recorded baseline before overwriting it, then
hashes the result against the target commit.

```
cap.rs  env.rs  desktop.rs  winutil.rs  sandbox_utils.rs  workspace_acl.rs
```

### Modified — review the upstream diff and re-apply our changes by hand

| File | What we changed (must be preserved) |
|---|---|
| `token.rs` | Drops the elevated-only additional-restricting-SID parameters and upstream tests. |
| `path_normalization.rs` | Adds a non-Windows dead-code allowance so the portable crate remains warning-free. |
| `logging.rs` | Inlined `codex_utils_string::take_bytes_at_char_boundary`; deleted `current_log_file_path_for_codex_home` (used `crate::sandbox_dir`) and the test module. |
| `allow.rs` | `compute_allow_paths_for_permissions` takes our `ResolvedWindowsSandboxPermissions`; deleted the codex-typed test module. |
| `spawn_prep.rs` | Dropped the elevated path (`prepare_elevated_spawn_context_for_permissions`, `ElevatedSpawnContext`), the deny-read branch, `readonly_sid_str`, and the codex-typed tests. `prepare_*` take a ready `&ResolvedWindowsSandboxPermissions` instead of `(PermissionProfile, workspace_roots)`. |
| `acl.rs` | Keeps the standalone legacy helpers, but carries upstream explicit-vs-inherited ACE refresh and safe `DELETE`-without-`FILE_DELETE_CHILD` semantics. The local legacy application path treats ACL mutation failures as fatal. |
| `proc_thread_attr.rs` | Carries upstream handle-list and atomic Job-list attributes plus a local Windows test. |
| `process.rs` | Uses the local `job::JobObject` instead of `codex_utils_pty::JobObject`; keeps the standalone capture signature and no `ConsoleMode` parameter. |
| `windows_capture.rs` | Rewritten from upstream `lib.rs::windows_impl`. Preserves the standalone, non-elevated API, atomic Job assignment, full-tree cleanup on completion/timeout/cancellation, and `stream_output`. Unlike upstream Codex, this bounded runner does not preserve background descendants after the root exits. |

### macOS Seatbelt vendor

`OURS = src/<file>` ← `UP = codex-rs/sandboxing/src/<file>`.

| File | Sync notes |
|---|---|
| `seatbelt_base_policy.sbpl` | Verbatim upstream profile; safe to overwrite, then smoke test on macOS. |
| `seatbelt_network_policy.sbpl` | Verbatim upstream profile; safe to overwrite, then smoke test on macOS. |
| `restricted_read_only_platform_defaults.sbpl` | Verbatim upstream profile; safe to overwrite, then smoke test on macOS. |
| `seatbelt.rs` | Modified. Keep upstream policy generation structure, but preserve local imports, the local `NetworkProxy` shim, and local permission types from `macos_permissions.rs` / `absolute_path.rs`. |

### Rewritten — no longer tracks upstream line-for-line

| File | Notes |
|---|---|
| `src/lib.rs` | Stable public interface and platform dispatch. Upstream capture changes belong in the platform supervisor, not here. |
| `windows_capture.rs` | Windows capture supervisor described above; semantically review upstream `windows-sandbox-rs/src/lib.rs`. |
| `resolved_permissions.rs` | Upstream wraps `codex_protocol::FileSystemSandboxPolicy`. Ours is self-contained (cwd-aware workspace roots + extra writable roots + temp; always deny `.git`/`.codex`/`.agents`). It also absorbs Windows `setup.rs::effective_write_roots_for_permissions` and exposes macOS conversion helpers for Seatbelt. If upstream changes **writable-root resolution or the protected-subdir set**, port the behavior by hand. |
| `absolute_path.rs` | Local subset of `codex_utils_absolute_path::AbsolutePathBuf` used by the Seatbelt vendor code. |
| `macos_permissions.rs` | Local subset of Codex filesystem/network policy types used by the Seatbelt vendor code. |

### Added — no upstream counterpart

```
src/bin/yj-sandbox-run/main.rs     # the CLI sidecar
src/job.rs                         # local windows-sys port of upstream JobObject
src/macos_capture.rs               # local bounded macOS capture supervisor
src/unsupported_capture.rs         # unsupported-platform adapter
```

### Intentionally NOT vendored (upstream has these; we dropped them)

`setup.rs` `setup_error.rs` `identity.rs` `deny_read_acl.rs` `deny_read_state.rs`
`deny_read_resolver.rs` `elevated*` `elevated_impl.rs` `conpty/` `unified_exec/`
`wfp*` `audit.rs` `hide_users.rs` `dpapi.rs` `helper_materialization.rs`
`ssh_config_dependencies.rs` `proc_thread_attr` elevated bits, and the
`bin/setup_main` + `bin/command_runner` binaries. These belong to the elevated
backend (separate sandbox accounts, WFP network filtering, deny-read, ConPTY,
OTEL) which this fork does not include.

## Sync workflow

Assumes a local checkout of Codex at `D:\project\openai-codex`.

```powershell
# Fetch explicitly, compare the manifest baseline with origin/main, and report.
.\tools\sync-codex.ps1 `
  -CodexPath D:\project\openai-codex `
  -Fetch

# After reviewing the report, copy only changed verbatim files from the exact
# target commit. Modified and rewritten files are never overwritten.
.\tools\sync-codex.ps1 `
  -CodexPath D:\project\openai-codex `
  -TargetRef origin/main `
  -ApplyVerbatim

# Machine-readable output for CI or other tooling.
.\tools\sync-codex.ps1 `
  -CodexPath D:\project\openai-codex `
  -TargetRef origin/main `
  -Json
```

Exit codes are part of the tool contract:

- `0`: no mapped upstream change.
- `1`: changes found (including after safe verbatim copies); review and baseline
  advancement are still required.
- `2`: manifest, path, ancestry, local-drift, or decoupling invariant failed;
  nothing is copied.
- `3`: Git/archive/filesystem tooling failed.

Then:

1. Review every `modified/review` and `rewritten/semantic` item in the report
   and port relevant behavior by hand.
2. For macOS, smoke-test copied SBPL profiles and hand-ported `seatbelt.rs`
   changes on macOS.
3. Rebuild and run the checks below.
4. Only after the review passes, advance the baseline SHA in
   `tools/codex-vendor.json`, this file, and `NOTICE`.

The syncer's own isolated-repository test is:

```powershell
# PowerShell 7+ is required.
.\tools\test-sync-codex.ps1
```

## Decoupling invariants (must hold after every sync)

- No dependency on `codex_protocol`, `codex_otel`, `codex_utils_pty`,
  `codex_utils_absolute_path`, `codex_utils_string`, `codex_network_proxy`,
  `codex_core`.
  Check: `rg -n "codex_" src` returns only comments.
- A `verbatim/overwrite` local file must match either the recorded baseline or
  the requested target blob exactly. Any third state is local drift and blocks
  all copying.
- Before applying multiple verbatim updates, every source is validated and
  every destination is backed up. A failed application restores the complete
  batch.
- Manifest destinations may not cross symlinks or junctions.
- The recorded baseline must exist and be an ancestor of the requested target.
- Non-elevated path only — do not pull in elevated/WFP/deny-read/ConPTY code.
- Security model unchanged: OS-enforced **write** isolation and full-disk
  **read** by default. Windows network block remains soft; macOS network block
  is Seatbelt-enforced when `--no-network` is used.

## Smoke check (run in PowerShell, not git-bash — MSYS mangles `/c`)

```powershell
$bin = ".\target\release\yj-sandbox-run.exe"
$ws  = "C:\some\workspace"
# write inside -> ok
& $bin --workspace-root $ws --cwd $ws -- cmd /c "echo hi> in.txt"          # exit 0, file created
# write outside -> denied
& $bin --workspace-root $ws --cwd $ws -- cmd /c "echo x> C:\Windows\x.txt" # 'Access is denied', exit 1
# read outside -> allowed (by design)
& $bin --workspace-root $ws --cwd $ws -- cmd /c "type C:\Windows\win.ini"  # prints content
```

## macOS smoke check

Build on both Intel and Apple Silicon targets when available:

```bash
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
```

Then run on macOS:

```bash
bin=./target/release/yj-sandbox-run
ws=/tmp/yj-sandbox-smoke
mkdir -p "$ws"
"$bin" --workspace-root "$ws" --cwd "$ws" -- sh -lc 'echo hi > in.txt'
"$bin" --workspace-root "$ws" --cwd "$ws" -- sh -lc 'echo no > /tmp/yj-sandbox-denied.txt'
"$bin" --read-only --cwd "$ws" -- sh -lc 'cat /etc/passwd >/dev/null'
```

Expected: writing inside `ws` succeeds, writing outside fails, read-only reads
still succeed by design.
