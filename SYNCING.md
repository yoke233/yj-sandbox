# Syncing from upstream Codex

This crate is a **manual vendor** (not a git fork or submodule) of subsets of
`openai/codex`:

- Windows: `codex-rs/windows-sandbox-rs`
- macOS: `codex-rs/sandboxing/src/seatbelt.rs` and its SBPL profiles

Upstream occasionally ships sandbox security fixes; this doc is how you pull
them in without re-doing the analysis each time.

## Vendor baseline (update after every sync)

| | |
|---|---|
| Upstream repo | `https://github.com/openai/codex` (branch `main`) |
| Vendored at commit | `be338ee9a28ce5a1c75455343e9712aded82c70f` |
| `windows-sandbox-rs/src` last touched | `0b2e7b5eb1cfa74e5807a84b291e6c900eeb197d` (2026-06-04) |
| Windows upstream subtree | `codex-rs/windows-sandbox-rs/src/` |
| macOS upstream files | `codex-rs/sandboxing/src/seatbelt.rs`, `seatbelt_base_policy.sbpl`, `seatbelt_network_policy.sbpl`, `restricted_read_only_platform_defaults.sbpl` |

> When you finish a sync, bump the "Vendored at commit" SHA above to the new
> upstream HEAD you synced against.

## File map

`OURS = src/<file>` ← `UP = codex-rs/windows-sandbox-rs/src/<file>` unless noted.

### Verbatim vendor — codex-free, safe to overwrite then re-check

These have **no** dependency on Codex crates. If upstream changes them, you can
usually copy the new version over and rebuild.

```
token.rs  acl.rs  cap.rs  env.rs  process.rs  desktop.rs
proc_thread_attr.rs  winutil.rs  path_normalization.rs
sandbox_utils.rs  workspace_acl.rs
```

### Modified — review the upstream diff and re-apply our changes by hand

| File | What we changed (must be preserved) |
|---|---|
| `logging.rs` | Inlined `codex_utils_string::take_bytes_at_char_boundary`; deleted `current_log_file_path_for_codex_home` (used `crate::sandbox_dir`) and the test module. |
| `allow.rs` | `compute_allow_paths_for_permissions` takes our `ResolvedWindowsSandboxPermissions`; deleted the codex-typed test module. |
| `spawn_prep.rs` | Dropped the elevated path (`prepare_elevated_spawn_context_for_permissions`, `ElevatedSpawnContext`), the deny-read branch, `readonly_sid_str`, and the codex-typed tests. `prepare_*` take a ready `&ResolvedWindowsSandboxPermissions` instead of `(PermissionProfile, workspace_roots)`. |
| `lib.rs` | Rewritten. Our Windows `run_sandbox_capture` ≈ upstream `windows_impl::run_windows_sandbox_capture_with_filesystem_overrides`, minus elevated/deny-read; plus a kill-on-close job object and `stream_output`. Our macOS `run_sandbox_capture` is a local capture wrapper around `seatbelt::create_seatbelt_command_args`. |

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
| `resolved_permissions.rs` | Upstream wraps `codex_protocol::FileSystemSandboxPolicy`. Ours is self-contained (cwd-aware workspace roots + extra writable roots + temp; always deny `.git`/`.codex`/`.agents`). It also absorbs Windows `setup.rs::effective_write_roots_for_permissions` and exposes macOS conversion helpers for Seatbelt. If upstream changes **writable-root resolution or the protected-subdir set**, port the behavior by hand. |
| `absolute_path.rs` | Local subset of `codex_utils_absolute_path::AbsolutePathBuf` used by the Seatbelt vendor code. |
| `macos_permissions.rs` | Local subset of Codex filesystem/network policy types used by the Seatbelt vendor code. |

### Added — no upstream counterpart

```
src/bin/yj-sandbox-run/main.rs     # the CLI sidecar
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

Assumes a local checkout of codex at `D:\project\openai-codex`.

```bash
OLD=be338ee9a28ce5a1c75455343e9712aded82c70f   # from the baseline table above
CODEX=D:/project/openai-codex

git -C "$CODEX" fetch origin
NEW=$(git -C "$CODEX" rev-parse origin/main)

# 1. Did anything in the subtree change since our baseline?
git -C "$CODEX" log --oneline "$OLD..$NEW" -- codex-rs/windows-sandbox-rs/src/

# 2. Per-file upstream diff (focus on the files we actually vendor)
git -C "$CODEX" diff "$OLD..$NEW" -- codex-rs/windows-sandbox-rs/src/token.rs
# ...repeat for each file in the map above.
```

Then:

1. **Verbatim files**: if changed and still codex-free, copy over and rebuild.
   Re-run `rg -n "codex_protocol|codex_utils|codex_otel|codex_network_proxy" src` — must only show comments/docs.
2. **Modified files**: read the upstream hunks, apply the relevant ones by hand,
   keeping the "must be preserved" changes from the table.
3. **macOS Seatbelt**: copy SBPL files verbatim. For `seatbelt.rs`, compare
   against upstream and port policy-generation changes while keeping local type
   shims.
4. **Rewritten files**: only touch `resolved_permissions.rs`,
   `absolute_path.rs`, or `macos_permissions.rs` if upstream changed the
   semantics they emulate.
5. Rebuild + re-run the smoke checks below.
6. Bump the baseline SHA in this file and in `NOTICE`; commit.

## Decoupling invariants (must hold after every sync)

- No dependency on `codex_protocol`, `codex_otel`, `codex_utils_pty`,
  `codex_utils_absolute_path`, `codex_utils_string`, `codex_network_proxy`,
  `codex_core`.
  Check: `rg -n "codex_" src` returns only comments.
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
