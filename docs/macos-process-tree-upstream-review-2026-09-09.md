# macOS 进程树与 Codex 上游生命周期复核（2026-09-09）

## 结论

**报告中关于 yj-sandbox v0.6.0 的核心诊断成立：它只杀死被跟踪的 `/usr/bin/sandbox-exec` 进程，没有建立和持有一个独立进程组，也没有对整个组发信号；后代进程可以继续运行并持有 stdout/stderr 管道，使同步 reader `join()` 无限等待。**

OpenAI Codex 已经修复了这个问题的**通用主体**：shell 子进程在独立 session/process group 中启动，timeout、取消和 Ctrl-C 都针对进程组，取消还先发 `SIGTERM`、短暂等待，再以 `SIGKILL` 清理幸存后代。因此不能把当前 yj-sandbox 行为解释成“`sandbox-exec` 自身会递归清理后代”；上游并不依赖这种假设。

但“上游已完整修复所有 macOS 信号边界”也不准确：

- Codex shell/Seatbelt 路径仍使用通用 `killpg`；
- macOS 上 `killpg` 返回 `EPERM` 后枚举并逐个信号后代的修复，仅接入 MCP stdio 和 PTY/pipe 路径，**没有接入 core shell/sandbox-exec 的 `consume_output`**；
- core 的直接 Ctrl-C 分支发的是进程组 `SIGKILL`，不是向子进程转发 `SIGINT`；优雅 `SIGTERM` 只属于 cancellation-token 分支；
- Linux 的 parent-death `prctl(PR_SET_PDEATHSIG)` 没有 macOS 等价实现。

所以答案是：**上游已修复“只杀 leader、后代持管道导致超时/取消挂死”的等价生命周期缺口；macOS `EPERM` fallback 和父进程被 `SIGKILL` 时的 orphan 清理并未完整覆盖 Seatbelt shell 路径。**

## 核对版本与同步边界

| 项目 | 固定点 | 含义 |
|---|---|---|
| yj-sandbox v0.6.0 tag | [`1fdf898a077bcd2934106a4d8e1484414531540e`](https://github.com/yoke233/yj-sandbox/commit/1fdf898a077bcd2934106a4d8e1484414531540e) | `v0.6.0^{commit}`；本报告比较的发布代码（功能发布提交为 [`9a2cdfb`](https://github.com/yoke233/yj-sandbox/commit/9a2cdfb734a8ef3f9c655271c89f418cc1162fb2)） |
| Codex 声明 baseline | [`5d89ab65dc9d4d0c55796c11df112b54157922b4`](https://github.com/openai/codex/commit/5d89ab65dc9d4d0c55796c11df112b54157922b4) | `tools/codex-vendor.json` 的权威 baseline |
| v0.6.0 评审参考点 | [`38cbebaf3fe3e81a94bf462079e7cf9659fc9e50`](https://github.com/openai/codex/commit/38cbebaf3fe3e81a94bf462079e7cf9659fc9e50) | 既有同步报告记录的上游参考点 |
| 本次上游 HEAD | [`634ebc1865c6ac840ed3ba118f040d527bf4b55d`](https://github.com/openai/codex/commit/634ebc1865c6ac840ed3ba118f040d527bf4b55d) | 2026-09-09 fetch 后的 `origin/main` |

`tools/codex-vendor.json` 明确把 `src/macos_capture.rs` 标成 `local` / `syncStrategy: never`，而 `seatbelt.rs` 和 SBPL 才映射到 Codex sandboxing crate。也就是说，升级 Seatbelt policy 不会自动带入 core 的 spawn/cancellation owner。

从 `38cbeba..634ebc1` 检查 `core/src/exec.rs`、`core/src/spawn.rs`、`utils/pty/src/process_group.rs`、`sandboxing/src/manager.rs` 和 `sandboxing/src/seatbelt.rs`，没有新的相关生命周期提交。当前结论不是由本次 HEAD 之后的一笔新修复造成的。

## v0.6.0 的实际所有权和失败路径

v0.6.0 的 [`src/macos_capture.rs`](https://github.com/yoke233/yj-sandbox/blob/1fdf898a077bcd2934106a4d8e1484414531540e/src/macos_capture.rs) 做了以下事情：

1. `Command::new("/usr/bin/sandbox-exec")` 直接 `spawn()`，没有 `process_group(0)`、`setpgid()` 或 `setsid()`；
2. timeout 和 cancellation 都调用 `std::process::Child::kill()`，然后只 `wait()` 这个直接 child；
3. 两个 reader thread 一直读 stdout/stderr 到 EOF，最后无 deadline 地 `join()`；
4. 普通退出也直接进入 reader `join()`，不处理仍继承管道的后代。

Rust 官方文档说明 [`Child::kill()` 在 Unix 上等价于向该 child 发 `SIGKILL`](https://doc.rust-lang.org/stable/std/process/struct.Child.html#method.kill)，而不是递归结束进程树；`Child` 本身也没有自动管理后代的语义。

因此有两条具体泄漏/挂死路径：

- timeout/cancellation 杀掉 sandbox leader 后，同组或另建组的后代仍然存活；
- 任一存活后代继承了 stdout/stderr 写端时，reader 看不到 EOF，`join()` 永远不返回。

v0.6.0 CLI 在 macOS 调用 capture 时把 cancellation 传为 `None`，也没有安装 `SIGTERM`/`SIGINT` handler。客户端终止 sidecar 时，默认信号动作直接结束 sidecar；capture 根本没有机会清理 child 或后代。因此“yj-sandbox 没有把终止信号转化为沙箱进程树清理”成立。

这不是 Seatbelt policy 生成器能解决的问题。Codex 当前 [`SandboxManager::transform`](https://github.com/openai/codex/blob/634ebc1865c6ac840ed3ba118f040d527bf4b55d/codex-rs/sandboxing/src/manager.rs#L389-L431) 只把 `/usr/bin/sandbox-exec` 和 policy 参数放到 argv 前面；进程所有权由后面的通用 spawn/exec 层承担。

## 当前 Codex 的完整调用链

Seatbelt 命令的主路径是：

`process_exec_tool_call` → `build_exec_request` → `SandboxManager::transform` → `execute_exec_request` → `get_raw_output_result` → `exec` → `spawn_child_async` → `consume_output`。

关键职责分布如下：

### 1. 建立独立 session/process group

[`core/src/spawn.rs::spawn_child_async`](https://github.com/openai/codex/blob/634ebc1865c6ac840ed3ba118f040d527bf4b55d/codex-rs/core/src/spawn.rs#L90-L116) 对 `RedirectForShellTool` 在 Unix `pre_exec` 中调用 `detach_from_tty()`；[`utils/pty/src/process_group.rs::detach_from_tty`](https://github.com/openai/codex/blob/634ebc1865c6ac840ed3ba118f040d527bf4b55d/codex-rs/utils/pty/src/process_group.rs#L47-L78) 使用 `setsid()`，失败为 `EPERM` 时退回 `setpgid(0, 0)`。

POSIX 对 [`setsid()`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/setsid.html) 的定义是：调用者成为新 session leader 和新 process-group leader，PGID 等于其 PID，并失去 controlling terminal。这正是 Codex 后续把 `child.id()` 当 PGID 使用的前提。

### 2. timeout、cancellation 和 Ctrl-C

[`core/src/exec.rs::consume_output`](https://github.com/openai/codex/blob/634ebc1865c6ac840ed3ba118f040d527bf4b55d/codex-rs/core/src/exec.rs#L949-L1050) 在 spawn 后持有 child：

- **timeout**：`kill_child_process_group()` 对组发 `SIGKILL`，再 `child.start_kill()` 兜底；
- **cancellation token**：先向 PGID 发 `SIGTERM`，等待 50 ms；leader 退出后仍以 PGID 发 `SIGKILL` 清理残余成员，或在 grace timeout 后组杀加 direct-child kill；
- **`tokio::signal::ctrl_c()`**：立即进程组 `SIGKILL`，没有 `SIGINT` 转发。

[`utils/pty/src/process_group.rs`](https://github.com/openai/codex/blob/634ebc1865c6ac840ed3ba118f040d527bf4b55d/codex-rs/utils/pty/src/process_group.rs#L86-L133) 最终使用 `killpg`。POSIX [`kill()`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/kill.html) 规定负 PID 针对整个 PGID，且允许实现施加额外安全控制并返回 `EPERM`；这同时解释了为什么组杀能覆盖普通后代，以及为什么 macOS fallback 是独立问题。

对应回归证据在 [`core/src/exec_tests.rs`](https://github.com/openai/codex/blob/634ebc1865c6ac840ed3ba118f040d527bf4b55d/codex-rs/core/src/exec_tests.rs#L1240-L1463)：

- `kill_child_process_group_kills_grandchildren_on_timeout` 验证 timeout 后 grandchild 不再存在；
- `process_exec_tool_call_respects_cancellation_token` 验证取消能及时返回且不伪装成 timeout；
- `process_exec_tool_call_cancellation_allows_sigterm_cleanup` 验证 parent 的 TERM trap 能执行，同时 TERM-resistant descendant 最终被杀。

### 3. 输出管道 deadline

普通 shell capture 在 leader 结束后只给 stdout/stderr drain 2 秒；超时会 abort reader task，见 [`consume_output`](https://github.com/openai/codex/blob/634ebc1865c6ac840ed3ba118f040d527bf4b55d/codex-rs/core/src/exec.rs#L1052-L1073)。这避免“后代持管道让调用永不返回”，但普通 `ShellTool` leader 自然退出时不保证把所有后代都杀掉。

[`808b3411fdd0dd05d7a9f1c221a5bc87934943ac`](https://github.com/openai/codex/commit/808b3411fdd0dd05d7a9f1c221a5bc87934943ac) 又为带 expiration 的 full-buffer/sensitive capture 保持 timeout/cancellation 直到 drain 完成，并在 drain 失败时杀进程组；当前实现见 [`exec.rs#L1078-L1149`](https://github.com/openai/codex/blob/634ebc1865c6ac840ed3ba118f040d527bf4b55d/codex-rs/core/src/exec.rs#L1078-L1149)。它是管道收尾加固，不是最初的进程组 ownership 修复。

### 4. macOS `EPERM` fallback 的真实覆盖范围

[`f2d825533c9423728f319a6dbcbb31c21768aa69`](https://github.com/openai/codex/commit/f2d825533c9423728f319a6dbcbb31c21768aa69) 明确记录：macOS 对 MCP server process group 发信号可能返回 `EPERM`。该提交新增 `proc_listpgrppids` 枚举、逐 PID 发信号，并在发信号前用 `getpgid` 复核成员仍属于预期组；测试覆盖 leader 存活/退出、TERM-resistant descendant、SIGKILL escalation 和非法 PGID，见 [`process_group_tests.rs`](https://github.com/openai/codex/blob/634ebc1865c6ac840ed3ba118f040d527bf4b55d/codex-rs/utils/pty/src/process_group_tests.rs#L17-L93)。

但是当前 fallback wrapper 只由 MCP stdio 和 PTY/pipe 使用；core `consume_output` 仍调用 `terminate_process_group`、`kill_child_process_group`，没有调用 `*_with_member_fallback`。因此这笔提交证明 macOS 的 `EPERM` 风险真实存在，但不能用来声称 Seatbelt shell 路径已覆盖它。

## 精确历史

| 提交 | 行为 | 相对本地同步点 |
|---|---|---|
| [`a2fdfce02a870773b3b037954b0fad6222020389`](https://github.com/openai/codex/commit/a2fdfce02a870773b3b037954b0fad6222020389), 2025-11-07, “Kill shell tool process groups on timeout” | 原始 bug 描述正是“只杀 direct child、grandchildren 持 PTY 导致永久挂死”；增加独立 process group，并在 timeout/ctrl-c 组杀。 | 早于 `5d89ab6` baseline，也早于 yj-sandbox 的 macOS adapter。 |
| [`dc1b62acbd890370c431d757ced1b02edf51ab82`](https://github.com/openai/codex/commit/dc1b62acbd890370c431d757ced1b02edf51ab82), 2026-01-19, “feat: detach non-tty childs” | 非 TTY shell 改用 `setsid()`/独立 session，巩固 PGID ownership。 | 早于 baseline。 |
| [`9152ebd289f2d9103ffc41c2fec69f6c623a6eab`](https://github.com/openai/codex/commit/9152ebd289f2d9103ffc41c2fec69f6c623a6eab), 2026-05-27, “preserve shell cleanup on interruption” | 把 turn cancellation 接入 `ExecExpiration`；取消时先组 `SIGTERM`，短暂等待，再组 `SIGKILL`；同时把 `ESRCH` 当作已清理。 | 早于 baseline；也早于本地 [`33758eaf`](https://github.com/yoke233/yj-sandbox/commit/33758eaf7d6fc550da5f6d1d217b2d1fcbe749e2) 引入当前 capture adapter。 |
| [`f2969f36e8b6aa2aefcd625d2a9fc8425bb2a519`](https://github.com/openai/codex/commit/f2969f36e8b6aa2aefcd625d2a9fc8425bb2a519), 2026-06-09, “Handle Ctrl-C for non-TTY unified exec” | 统一已知 PGID 的 `SIGINT`/`SIGTERM`/`SIGKILL` helper；当前 core 直接 Ctrl-C 仍选择硬杀。 | 早于 baseline。 |
| [`f2d825533c9423728f319a6dbcbb31c21768aa69`](https://github.com/openai/codex/commit/f2d825533c9423728f319a6dbcbb31c21768aa69), 2026-08-05 09:37Z | macOS MCP group-signal `EPERM` 时逐成员 fallback。 | 晚于 `5d89ab6`（同日 01:19Z），但早于 v0.6.0 的 `38cbeba` 评审参考点；未进入本地 `macos_capture.rs`。 |
| [`808b3411fdd0dd05d7a9f1c221a5bc87934943ac`](https://github.com/openai/codex/commit/808b3411fdd0dd05d7a9f1c221a5bc87934943ac), 2026-09-09 00:33Z | 加固 full-buffer capture 的 expiration、pipe drain 和 descendant cleanup。 | 晚于 baseline、早于 `38cbeba`；本地同步未覆盖。 |

“这些修复是否在本地 selective sync 之后”必须区分两个点回答：

- 相对 manifest baseline `5d89ab6`：核心进程组、timeout 和 cancellation 修复都已经存在；`f2d8255` 与 `808b341` 在其后。
- 相对 v0.6.0 实际评审参考点 `38cbeba`：上述提交都已在上游；不是 2026-09-09 05:55Z 之后的新修复。它们仍缺失，是因为 `macos_capture.rs` 是 local/never、选择性同步只移植了 Seatbelt policy enforcement，而不是因为评审参考点太旧。

## 逐项判断

| 主张 | 判断 | 依据/限定 |
|---|---|---|
| v0.6.0 只杀 `sandbox-exec` leader | **成立** | timeout/cancel 均为 `Child::kill()`。 |
| 后代可存活并持有 pipes，导致返回挂死 | **成立** | 没有 PGID ownership/group kill；reader thread 无 deadline 地 `join()`。 |
| `sandbox-exec` 会替调用方清理完整进程树 | **不成立** | Codex 自己建立 session/group 并显式 group kill；Seatbelt 层只构造 argv/policy。 |
| SIGINT/SIGTERM 会原样转发给 child | **不成立** | 本地把两者都折叠成 cancellation，随后 direct-child `SIGKILL`。 |
| 当前 Codex 已解决 timeout/cancel 的普通 descendant cleanup | **成立** | 独立 group；timeout group KILL；cancel TERM→grace→KILL；有 grandchild/TERM-trap 测试。 |
| 当前 Codex 所有 Ctrl-C 都转发 SIGINT | **不成立** | core capture 的 Ctrl-C 分支直接 group `SIGKILL`；PTY/pipe API 才提供 `interrupt_process_group`。 |
| 当前 Codex 保证父进程遭 `SIGKILL` 后 macOS child 自动死亡 | **不成立** | `PDEATHSIG` 是 Linux-only；macOS 没有对应 owner primitive。 |
| macOS `killpg` 的 `EPERM` 已对 Seatbelt shell 完整兜底 | **不成立** | fallback 存在但当前 core shell 路径未调用。 |

## 最低风险同步建议

不要整体 cherry-pick Codex core，也不要把完整 `codex-utils-pty` 或 MCP lifecycle 引入这个独立同步 crate。`src/macos_capture.rs` 的接口是同步的，本地已有 `libc` 和 signal-hook，最低风险是把上游已验证的两个窄语义组合移植到本地 owner，而不是复制上游架构：

1. spawn 前为 `/usr/bin/sandbox-exec` 建立独立 PGID/session，并立即保存 PGID；
2. 用小型 RAII owner 保证所有 error/early-return 路径最终对该 PGID 执行 hard kill；
3. cancellation（包括 CLI 捕获的 SIGINT/SIGTERM）先对组发 `SIGTERM`，给一个有界 grace period，再组 `SIGKILL`；timeout 可直接组 `SIGKILL`，与 Codex core 对齐；
4. 杀组并 reap leader 后再 join reader；另外给 reader drain 明确 deadline，避免 detached/re-grouped 后代仍持 pipe 时无限等待；
5. 保留 direct-child kill 作为组清理完全失败时的兜底，但不能把它当作完整清理；
6. 一并窄移植 `f2d8255` 的 macOS `EPERM` member fallback：先尝试 group signal，只有 `EPERM` 才用 `proc_listpgrppids` 枚举，并在逐 PID 发信号前用 `getpgid` 复核成员仍属于原 PGID。不要做无条件 descendant 遍历，也不要引入 MCP 类型。虽然 Codex core Seatbelt 尚未接入这层 fallback，但上游提交和 macOS 回归测试已经证明这一平台失败模式；在独立 owner 中加入同构兜底比等待生产复现后再修改终止路径风险更低。

应以真实 macOS 行为验收：命令启动 TERM-aware leader、TERM-resistant child 和继承 stdout/stderr 的 grandchild；分别触发 cancellation、timeout 和 CLI SIGINT/SIGTERM，确认 leader cleanup trap、幸存者 hard-kill、reader 有界返回及无残留 PID。Windows job-object 和 Seatbelt policy 文件不需要因本问题改动。
