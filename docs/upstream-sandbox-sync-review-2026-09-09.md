# yj-sandbox 上游沙箱同步评估（2026-09-09）

## 结论

需要同步 **Codex 的安全与正确性改动**，但不能整体覆盖或直接 cherry-pick；应按 `tools/codex-vendor.json` 的边界逐项移植和验证。

- **Windows / Codex：需要定向同步。** 本地基线仍是 `5d89ab65dc9d4d0c55796c11df112b54157922b4`；本次 `sync-codex.ps1 -Fetch -TargetRef origin/main -Json` 解析到 Codex `38cbebaf3fe3e81a94bf462079e7cf9659fc9e50`。基线后已有 ACL、reparse point、helper/provisioning、runner 生命周期和 deny-read 修复。本地多个 `verbatim` 文件仍处于 baseline 状态。
- **macOS / Codex Seatbelt：需要优先同步三组 enforcement 修复。** 它们直接修复 rename、symlink/rebind 和共享临时目录边界。
- **Gemini 原生 Windows 后端：暂不需要同步源码。** 本地 `src/gemini.rs` 移植的是 `GeminiSandbox.cs` 原生执行层；从本地基线 `ac42fb0a24fe7349e9968e2359ef5232f1cb6e72` 到当前相关历史，`GeminiSandbox.cs` 没有新的改动。2026-09-04 的安全修复位于 JS `PolicyEngine` / `commandSafety` 层，不属于当前 crate 的职责。
- **不要为了“追最新”引入 Codex MXC、provisioning service 或 Gemini command-approval 层。** 这些是新的产品/架构边界，不是现有模块的补丁同步。

## 实施结果

已按本报告建议完成定向同步：

- Windows portable security primitives and setup/helper hardening were ported from reviewed Codex `ea2046f36d5ee12d39c8e168fc3e5129301afa2b`, including no-reparse directory guards, handle-relative atomic state replacement, retained setup handles, bounded IPC framing, protected setup state, setup serialization, and account-repair safeguards.
- macOS Seatbelt received the three ordered enforcement fixes: writable-root path binding, protected-path rename denial, and process-only scratch defaults.
- Managed deny-read remains driven by the local serialized sandbox state and continues through refresh overrides; the upstream CLI layer was not copied.
- The `allow_local_binding=true` marker optimization from `38cbebaf3fe3e81a94bf462079e7cf9659fc9e50` was ported because the local firewall semantics match the optimized condition.
- Gemini native execution remains unchanged.

This is still a selective semantic port. The authoritative baseline SHA remains `5d89ab65dc9d4d0c55796c11df112b54157922b4`; advancing it would falsely claim review of omitted Codex service, protocol, uninstall, and MXC changes.

### 验证

- `cargo test --all-targets`: 90 passed, 1 ignored.
- `tools/test-sync-codex.ps1`: passed all manifest, mirror, drift, rollback, and no-copy contract checks.
- `cargo build --release --bins`: x64 Windows release binaries built.
- `cargo build --release --bins --target aarch64-pc-windows-msvc`: ARM64 Windows release binaries built.
- Default Gemini and explicit `unelevated` CLI smoke commands returned `gemini-ok` and `sandbox-ok`.

The broader Gemini E2E progressed through HTTPS, Low Integrity token, and extra writable-root checks, then stopped because Windows returned sharing violation 32 while labeling the process-wide `%TEMP%` directory; the Low Integrity child consequently could not create the test file there. This behavior is in the untouched Gemini backend path, outside the Codex hardening port, and `src/gemini.rs` was intentionally unchanged.

## 已核对基线

| 来源 | 本地基线 | 本次上游参考点 | 结果 |
|---|---|---|---|
| OpenAI Codex | [`5d89ab6`](https://github.com/openai/codex/commit/5d89ab65dc9d4d0c55796c11df112b54157922b4) | [`38cbeba`](https://github.com/openai/codex/commit/38cbebaf3fe3e81a94bf462079e7cf9659fc9e50) | 映射文件存在大量变更，需定向同步 |
| Google Gemini CLI | [`ac42fb0`](https://github.com/google-gemini/gemini-cli/commit/ac42fb0a24fe7349e9968e2359ef5232f1cb6e72) | Windows sandbox 路径最新相关提交 [`567afbb`](https://github.com/google-gemini/gemini-cli/commit/567afbbe8fc7927e38bd40733bf09cafc227ede4) | 原生 C# helper 未变；JS 策略层有安全修复 |

Codex 的权威路径映射和同步分类仍由 `tools/codex-vendor.json` 管理。上游路径历史可从官方 [Windows sandbox commits](https://github.com/openai/codex/commits/main/codex-rs/windows-sandbox-rs) 和 [sandboxing commits](https://github.com/openai/codex/commits/main/codex-rs/sandboxing) 复核。

## Codex：应移植的改动

### P0：Windows provisioning 文件与 reparse-point 加固

[`add870a4bf226d87e0201b4e28ee6a159a49aed1`](https://github.com/openai/codex/commit/add870a4bf226d87e0201b4e28ee6a159a49aed1) 对 setup/provisioning 路径增加 no-reparse 目录句柄、路径与 ancestor 校验、handle-relative 原子替换，并保护 setup log、credentials、marker 与 error report。它是明确的 TOCTOU / reparse-point 安全加固。

本项目不包含完整 Codex provisioning service，因此不能整提交复制。应只移植落在现有 `setup.rs`、`identity.rs`、setup helper 和持久状态文件路径上的原语，并保留本地无 `codex_protocol`、无 OTEL 的依赖边界。

同一批次应一起复核较早的 Windows 加固：

- [`a4f37a5b7`](https://github.com/openai/codex/commit/a4f37a5b7)：provisioning reparse-point 防护；
- [`3a211471d`](https://github.com/openai/codex/commit/3a211471d)：更新 ACL 时请求 `READ_CONTROL`；
- [`21c58c90f`](https://github.com/openai/codex/commit/21c58c90f)：helper 清理加固；
- [`88c39c457`](https://github.com/openai/codex/commit/88c39c457)：传播 Windows ACL 更新失败，避免静默降级。

### P0：macOS Seatbelt enforcement

按依赖顺序移植并一起验证：

1. [`02de49f7183d30cc72bdb83b64816392c29a908c`](https://github.com/openai/codex/commit/02de49f7183d30cc72bdb83b64816392c29a908c)：防止 writable-root 在 Seatbelt 路径绑定前被 symlink/rebind；区分文件 literal 与目录/subpath，并保护解析元数据路径。
2. [`52e387dacaf5375d9fe5a77f7fc5f6fe31d2f610`](https://github.com/openai/codex/commit/52e387dacaf5375d9fe5a77f7fc5f6fe31d2f610)：修复 protected-path rename bypass；强化 file-write/unlink deny，并调整 policy 顺序。
3. [`7f823973633472ec75b9ab86342e01561f78dd42`](https://github.com/openai/codex/commit/7f823973633472ec75b9ab86342e01561f78dd42)：把 `/tmp`、`/var/tmp` 及 `/private` aliases 从共享 restricted defaults 移到 process-only defaults，避免 filesystem helper 继承 scratch 权限。

本地 `seatbelt.rs` 是 modified adapter，SBPL 文件部分为 verbatim；需要语义移植，不能只覆盖单个 policy 文件。

### P1：managed deny-read 语义对齐

[`a482e65b8643509f2217b3a34453f3c4a1968228`](https://github.com/openai/codex/commit/a482e65b8643509f2217b3a34453f3c4a1968228) 修复 sandbox CLI 启动时未保留 managed deny-read paths、导致持久 deny ACL 被错误清理的问题。

本地 CLI 已从 sandbox state 解析 `deny_read_paths`，并在 elevated setup override 中传递；因此这里应做 **语义差异复核和回归场景验证**，而不是直接复制 Codex CLI 文件。确认本地连续两次启动时，第二次不会清掉第一次仍受管理的 deny-read ACL。

### P2：按实际配置选择性移植

[`5e3f0ee94b0719ab3d0d05cffaa75163e87668f6`](https://github.com/openai/codex/commit/5e3f0ee94b0719ab3d0d05cffaa75163e87668f6) 在 `allow_local_binding=true` 时忽略无关 proxy port 变化，避免重复触发 elevated setup，同时仍刷新 ACL。只有本地 firewall/WFP 与 proxy marker 语义一致时才移植。

## Codex：默认不移植的改动

| 改动 | 判断 |
|---|---|
| [`60888d086`](https://github.com/openai/codex/commit/60888d08685f3caa8ad4979518924d373d7477cf) native MXC adapter | 新 crate、SDK 与策略模型；不是现有 `windows-sandbox-rs` enforcement 补丁。除非明确新增 MXC 后端，否则不引入。 |
| [`7e45bdb5f`](https://github.com/openai/codex/commit/7e45bdb5fd0e6cae3aeb14330deed7861bb516da) authenticated provisioning | 依赖 Codex service/protocol 生命周期。只抽取现有本地路径需要的安全原语。 |
| [`665e5f45a`](https://github.com/openai/codex/commit/665e5f45ab91d43ec3a49487fb9be90109dd2875) app uninstall cleanup | 属于 Codex 应用卸载生命周期；yj-sandbox 当前没有等价 owner/uninstall service 契约。 |
| [`4fd2c460d`](https://github.com/openai/codex/commit/4fd2c460dd3e02495c1d0aae8bce4ccbd59915a9) deny-read planner 移入 protocol | 主要是 `codex_protocol` 共享重构；本项目明确禁止该依赖。只比较算法语义。 |
| [`89a4eec6d`](https://github.com/openai/codex/commit/89a4eec6dafce21486c5a56e6599095e7517c4b1) 隐藏 runner 窗口 | UX/打包行为；可独立评估，但不作为安全同步。 |
| [`f1aac1e88`](https://github.com/openai/codex/commit/f1aac1e885f676a1129f2da0c46a3dba86392fc6) wrapper setup 保留 `SYSTEMROOT` | 只适用于相同 wrapper 环境白名单路径；本地直接 setup 路径无同构 seam 时不移植。 |
| [`d13aeb77e`](https://github.com/openai/codex/commit/d13aeb77ea0eb72a994324143e6cdffcba650963) trusted symlinked `CODEX_HOME` | 跨 config/app-server/CLI/runtime 传播，且是显式放宽信任边界；有产品需求再单独设计。 |

## Gemini：为何当前不需要同步原生后端

[`567afbbe8fc7927e38bd40733bf09cafc227ede4`](https://github.com/google-gemini/gemini-cli/commit/567afbbe8fc7927e38bd40733bf09cafc227ede4) 是基线后的有效安全改动：它让 command safety 接收 effective cwd/workspace，阻止已知“安全”读取命令通过路径穿越或 symlink 越界，并把 `ln -s` 视为危险操作。对应的是 Gemini CLI 的审批/提示防绕过层。

但该提交没有修改 `packages/core/src/sandbox/windows/GeminiSandbox.cs`。yj-sandbox 不包含 Gemini 的 `PolicyEngine`、`commandSafety` 或交互审批模型，因此：

- 不应把该 JS 策略层塞进 Rust 原生 sandbox crate；
- `src/gemini.rs` 当前没有可同步的原生 delta；
- 如果调用方也提供命令审批，应在调用方独立复核等价的 cwd、workspace、symlink 和命令参数边界。

本地基线已经晚于 Gemini 2026-04-10 的 native ACL 优化和 2026-04-16 的 manager governance 变更；这些不是本轮新增 delta。Gemini 原生模型的既有限制仍然存在：Low Integrity 标签持久化、没有 restricting SID、网络限速不是严格断网、forbidden read 不能作为可靠机密隔离。详见 `docs/gemini-windows-native-sandbox-study.md`。

## 建议执行顺序

1. 先同步 Windows setup/provisioning 的 portable 安全原语，并验证 reparse-point/原子替换失败路径。
2. 独立同步 macOS 三组 Seatbelt enforcement 改动；不要与 Windows 改动混成一次审查。
3. 对本地 elevated 连续启动做 managed deny-read 持久性回归验证；只有发现语义缺口才改代码。
4. 再评估 `allow_local_binding` setup marker 优化。
5. 完成 Windows 与 macOS 验证后，才推进 `tools/codex-vendor.json`、`SYNCING.md`、`NOTICE` 的 baseline SHA；不能只改 SHA。
6. Gemini 保持当前 native baseline；后续定期比较 `GeminiSandbox.cs` blob，并单独跟踪 JS command-safety 变化供上层调用方参考。
