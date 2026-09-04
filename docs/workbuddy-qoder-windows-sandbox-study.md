# WorkBuddy 与 Qoder 的 Windows 沙箱实现学习笔记

## 结论

两者虽然都把功能称为“Windows 沙箱”或“安全工作区”，实际采用的是两种不同的安全边界：

```text
WorkBuddy
宿主 Agent → sandbox-cli.exe → 挂起创建 Windows 子进程 → 注入 tsbx.dll → 用户态 API Hook

Qoder
宿主 Agent → hvkit.exe → Windows 命名管道 → Hyper-V Linux VM → 在客体中执行 Bash
```

- WorkBuddy 是宿主机上的进程级策略沙箱，强调 Windows 原生命令兼容性、低启动成本和细粒度规则。
- Qoder 是 Hyper-V 支撑的 Linux 虚拟机沙箱，重点隔离 Shell 命令，但 Agent Loop 和文件工具仍有一部分运行在宿主机上。
- 对不可信 Shell 命令而言，Qoder 的虚拟化边界明显强于 WorkBuddy 的用户态 Hook。
- Qoder 不是 Windows 自带的 Windows Sandbox 应用；WorkBuddy 也没有使用 Windows Sandbox、WSL 或 Hyper-V。

## 一、WorkBuddy 的实现

### 1. 组成

CLI 声明了以下沙箱依赖：

- `@anthropic-ai/sandbox-runtime`，主要用于其他平台或旧实现。
- `@tencent-ai/sandbox-cli-win32-x64` 版本 `5.3.3`，Windows 上的原生实现。

证据位置：

- `D:\project\workbuddy-study\recovered-workbuddy\as-packaged\cli\package.json:15`
- `D:\project\workbuddy-study\recovered-workbuddy\as-packaged\cli\package.json:108`

恢复后的项目主要保留了 JS bundle 和规则文件。完整 Windows 原生组件位于：

`D:\project\workbuddy-study\artifacts\asar-unpacked\cli\vendor\sandbox\5.3.3`

其中包括：

- `sandbox-cli.exe`
- `sandbox-cli-gc.exe`
- `sandbox_ffi.dll`
- `tsbx_sdk.dll`
- `tsbx.dll`
- `tsbx_rules.json`

### 2. 命令执行链路

WorkBuddy CLI 启动 `sandbox-cli.exe`，建立沙箱会话，然后通过 IPC 发送命令和规则。bundle 中可见的协议包括：

- `OpenSession`
- `RunExecutable`
- `SetFileRules`
- `SetNetworkRules`
- `QueryFileChanges`
- `CommitFileChanges`
- `KillProcess`

证据位置：

- `D:\project\workbuddy-study\recovered-workbuddy\as-packaged\cli\dist\codebuddy.js:497`
- `D:\project\workbuddy-study\recovered-workbuddy\as-packaged\cli\dist\codebuddy.js:860`

原生二进制的导入表和内嵌日志表明，其进程隔离流程大致如下：

1. 以挂起状态创建目标 Windows 进程。
2. 使用 `VirtualAllocEx` 和 `WriteProcessMemory` 准备注入数据。
3. 将 `tsbx.dll` 注入目标进程。
4. 注入成功后恢复进程运行；失败时终止目标进程。
5. Hook `CreateProcessInternalW`，使后续子进程继续受到注入和规则约束。

它还处理 x64、ARM64 和 WoW64 等目标架构，跨架构场景会采用 APC 或 `rundll32` 桥接注入。

### 3. 文件系统策略

默认规则位于：

`D:\project\workbuddy-study\recovered-workbuddy\as-packaged\cli\vendor\sandbox\5.3.3\tsbx_rules.json`

关键配置：

- `default_action: deny_write`，默认禁止写入。
- `recyclebin_backup: true`，删除或修改前支持回收站备份。
- `auto_grant: true`，对符合条件的新路径可自动添加授权规则。
- `.ssh` 和 `.gnupg` 使用 `no_access`，禁止读取和写入。
- Temp、npm、pnpm、Yarn 等缓存目录使用 `inherit_user`，继承宿主用户权限。

规则主要包含以下动作：

- `no_access`：禁止访问。
- `read_only`：只读。
- `inherit_user`：按当前 Windows 用户权限访问。
- `modify_backup`：允许修改，但要求先创建备份。

文件工具本身也会先查询规则。对于 `no_access`、`read_only` 或需要备份的路径，CLI 可以阻止操作、申请用户授权或要求原生沙箱完成备份。

### 4. 网络和进程 Hook

`tsbx.dll` 的内嵌日志显示它会 Hook：

- `ws2_32` 的 `connect`、`send`、`sendto`
- DNS 查询相关 API
- `WinHttpConnect`
- `CreateProcessInternalW`
- 文件打开、写入、删除、重命名等 API

规则文件中的网络策略虽然启用了 Hook，但当前默认动作是 `allow`，且拒绝 IP、拒绝域名列表为空。因此“具备网络限制能力”不等于“这个默认配置禁止联网”。

证据位置：

- `D:\project\workbuddy-study\recovered-workbuddy\as-packaged\cli\vendor\sandbox\5.3.3\tsbx_rules.json:87`

### 5. 安全边界和绕过路径

WorkBuddy 沙箱中的进程仍然：

- 使用宿主 Windows 内核。
- 使用当前宿主用户身份。
- 看到宿主文件系统路径。
- 依赖用户态 DLL 注入和 API Hook 的完整性。

因此它不是强制访问控制意义上的内核安全边界。以下情况都会削弱或绕开隔离：

- 沙箱配置未启用。
- 命令被列入排除列表。
- 低风险执行策略决定直接在本地运行。
- 用户批准 `dangerouslyDisableSandbox` 或批准无沙箱重跑。
- DLL 注入或某项 Hook 安装不完整。
- 被列入白名单的进程跳过部分或全部 Hook。

产品配置中的 `Sandbox: true` 表示功能可用，并不证明每一条命令都强制进入沙箱：

- `D:\project\workbuddy-study\recovered-workbuddy\as-packaged\cli\product.json:1870`
- `D:\project\workbuddy-study\recovered-workbuddy\as-packaged\cli\dist\codebuddy.js:176`

## 二、Qoder 的实现

### 1. Hyper-V 前置条件

Qoder 在 Windows 上检查：

- Hyper-V 可选功能是否启用。
- `vmcompute`、`HvHost`、`vmms` 等系统服务是否存在。
- `QoderWorkVM` 服务是否安装。
- Windows 服务的二进制路径是否指向当前 `hvkit.exe`。

证据位置：

- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:96489`
- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:96700`
- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:98440`

它要求支持 Hyper-V 的 Windows 版本，一般是 Pro、Enterprise 或 Education，而不是 Windows Home。

### 2. Windows 服务和 VM 文件

安装脚本创建 `QoderWorkVM` 服务：

```text
"<virtualhost>\hvkit.exe" --service
```

该服务依赖 `vmcompute`，采用手动启动，并设置预关机超时和允许交互用户启动服务的 SDDL。

证据位置：

- `D:\project\qoder-study\recovered-qoder\resources\install-service.ps1:133`
- `D:\project\qoder-study\recovered-qoder\resources\install-service.ps1:147`
- `D:\project\qoder-study\recovered-qoder\resources\install-service.ps1:159`
- `D:\project\qoder-study\recovered-qoder\resources\install-service.ps1:205`

Windows VM 的关键文件包括：

- `hvkit.exe`
- `disk.vhdx`
- `vmlinuz`
- `initrd`

当前代码中的 VM 基础版本为 `0.1.4`，应用通过 CDN manifest 检查和下载 VM 资源。

证据位置：

- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:34426`
- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:176841`

### 3. 宿主与 VM 的通信

Windows 上使用三个命名管道：

- `\\.\pipe\qoderwork-mcp`
- `\\.\pipe\qoderwork-exec`
- `\\.\pipe\qoderwork-serial`

启动参数把这些管道交给 `hvkit.exe`，同时指定服务名 `QoderWorkVM`。

证据位置：

- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:456`
- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:98556`

### 4. Bash 执行链路

Qoder 只在 VM 模式下暴露 `mcp__workspace__bash`。每次调用都是无状态的，工作目录和环境变量不会自动保留。

典型执行形式为：

```text
hvkit.exe exec
  --socket <exec-pipe>
  --timeout <seconds>
  --cwd /sessions/<session-id>/mnt
  --session-id <session-id>
  <bash-command>
```

证据位置：

- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:75065`
- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:98977`

这意味着 Windows 宿主路径不能直接传给 Bash。命令必须使用 VM 内的挂载路径。

### 5. 目录挂载

每个工作区使用 `md5(cwd)` 的前 16 位生成 session id，主目录挂载到：

```text
/sessions/<session-id>/mnt
```

Qoder 全局资源目录以只读方式挂载到同一 session 下的专用路径。动态挂载通过 VM 内的 `/usr/local/bin/qoder-mount` 完成，输入包含：

```json
{
  "cwd": "宿主工作目录",
  "additionalDirectories": ["额外目录"]
}
```

证据位置：

- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:74084`
- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:74110`

客体安装脚本还管理 `qoder-9p-proxy`，说明宿主目录共享通道至少包含一层 9P 代理：

- `D:\project\qoder-study\recovered-qoder\resources\vm-boot\install.sh:148`

### 6. 客体服务

Linux VM 中启用了以下 systemd 服务：

- `qoder-run`
- `qoder-mcp`
- `qoder-portfwd`
- `qoder-exec`
- `qoder-netcfg`
- `qoder-netcfg-verify`

证据位置：

- `D:\project\qoder-study\recovered-qoder\resources\vm-boot\install.sh:96`
- `D:\project\qoder-study\recovered-qoder\resources\vm-boot\install.sh:115`

### 7. Qoder 不是整机全隔离

Qoder 的实际信任边界是混合的：

- Agent Loop 运行在宿主机。
- Bash 运行在 Linux VM。
- `Read`、`Write`、`Edit` 等文件工具直接使用宿主路径操作文件。
- 工作目录会被挂载给 VM。
- 额外目录通常需要用户确认后挂载。

系统提示词直接说明了文件工具与 Bash 的边界：

- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:145076`
- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:145901`

目录申请流程还有一个值得审计的分支：无法解析运行上下文时，代码会记录“proceeding without confirmation”并继续。后续仍要求能够解析工作区和 session，但这是明显的 fail-open 设计点。

- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:99312`

## 三、对比

| 维度 | WorkBuddy | Qoder |
|---|---|---|
| 核心隔离 | 用户态 DLL 注入和 API Hook | Hyper-V Linux VM |
| 是否共享宿主内核 | 是 | 否 |
| Shell 环境 | 原生 Windows | Linux Bash |
| 宿主文件访问 | 同一文件系统命名空间，靠规则拦截 | Bash 只见挂载目录，文件工具仍直接访问宿主 |
| 网络控制 | Windows Socket、DNS、WinHTTP Hook | VM 网络服务和转发层 |
| 子进程控制 | Hook `CreateProcessInternalW` 并继续注入 | 子进程自然留在 Linux 客体中 |
| 启动成本 | 低 | 较高，需要服务、VHDX 和 VM 启动 |
| Windows 工具兼容性 | 高 | Bash 中较低 |
| 对恶意 Shell 的隔离强度 | 较弱 | 较强 |
| 主要失败风险 | 注入失败、Hook 不完整、白名单或本地绕过 | 挂载面过大、宿主文件工具越权、Hyper-V 或服务配置错误 |

## 四、容易混淆的 Chromium 沙箱

两款产品都在 Windows 上关闭了 Electron/Chromium 自身的沙箱：

- WorkBuddy 添加 `no-sandbox`。
- Qoder 添加 `no-sandbox` 和 `disable-gpu-sandbox`。

证据位置：

- `D:\project\workbuddy-study\recovered-workbuddy\apps\desktop\src\main\index.ts:157`
- `D:\project\qoder-study\recovered-qoder\formatted\apps\desktop\out\main\main.js:1969`

Chromium 沙箱保护的是 Electron renderer、GPU 等进程；WorkBuddy 的命令 Hook 沙箱和 Qoder 的 VM Shell 沙箱保护的是 Agent 执行命令。它们不是同一个机制。关闭 Chromium 沙箱不会关闭后两者，但会削弱桌面应用处理不可信网页或渲染内容时的隔离。

## 五、设计启示

如果要为当前项目设计 Windows 命令沙箱，可以从目标倒推：

1. 需要运行原生 Windows 工具且追求低延迟时，可以考虑 WorkBuddy 一类受控进程启动器，但不应把用户态 Hook 当作强安全边界。
2. 需要承载高风险、来源不可信的 Shell 命令时，应优先选择独立内核边界，例如 Hyper-V utility VM。
3. 即使 Shell 已进入 VM，宿主侧文件工具、目录授权、挂载管理和 IPC 仍必须纳入同一威胁模型。
4. 默认策略比能力本身更重要。具备网络拦截代码但默认允许外连，不能视为网络隔离。
5. 沙箱降级或绕过必须是显式、可观察、可审计的，不能静默回退到宿主执行。
6. 应分别测试正常路径和失败路径，包括注入失败、Hook 不完整、VM 未启动、管道断开、挂载失败、审批上下文缺失、超时和子进程逃逸。

## 六、后续可继续验证的问题

- WorkBuddy 六个文件 Hook 对应的准确 Windows API 列表。
- WorkBuddy 注册表规则在 5.3.3 中是否实际执行，还是仅解析配置。
- WorkBuddy 白名单进程是否跳过全部 Hook，浏览器是否因此成为逃逸通道。
- Qoder 的 `qoder-mount` 和 `qoder-9p-proxy` 如何限制路径穿越、符号链接和重解析点。
- Qoder VM 的出站网络默认策略、DNS 策略和端口转发规则。
- Qoder 下载的 VHDX、内核和 initrd 是否完整执行签名或哈希校验。
- 宿主文件工具的权限判定是否与 VM 目录审批使用同一套授权状态。
- 两款产品关闭 Chromium 沙箱后，如何限制 renderer 到主进程的 IPC 能力。

## 七、GitHub 上的开源替代方案

以下筛选以 2026 年 8 月 5 日的仓库主分支为准，目标是寻找能够运行原生 Windows 命令、可被其他应用调用、文件和网络策略可配置，并且不需要调用方继续维护一份 Windows 安全底层代码的项目。

### 1. Anthropic Sandbox Runtime

仓库：[`anthropic-experimental/sandbox-runtime`](https://github.com/anthropic-experimental/sandbox-runtime)

这是与 `yj-sandbox` 目标最接近的候选。当前主分支已经加入 Windows Alpha 支持，npm 包名为 `@anthropic-ai/sandbox-runtime`，许可证为 Apache-2.0。它既提供 `srt` CLI，也导出 `SandboxManager` 供 Node.js 调用。

Windows 实现采用：

- 独立本地用户 `srt-sandbox`。
- 受限 Token 和 Job Object。
- 按沙箱用户 SID 建立的 WFP 出站网络围栏。
- 按会话给指定目录添加和回收 NTFS ACE。
- 宿主侧 HTTP 和 SOCKS5 代理执行域名白名单。

调用方可以通过 `--settings` 指定任意配置文件，并在 `filesystem.allowRead`、`filesystem.allowWrite`、`denyRead` 和 `denyWrite` 中配置实际工作目录，不需要采用 WorkBuddy 的 `Workspace\sessions\...` 目录布局。Windows helper 的位置也可通过 `windows.srtWin.path` 指定。

它仍有少量固定的内部状态：首次安装会创建固定名称的本地用户和组，凭据状态默认保存在 `%LOCALAPPDATA%\sandbox-runtime\state.db`。因此它解决的是“业务工作区和会话目录被产品写死”的问题，并不是所有内部路径都可改。

首次使用需要执行一次会触发 UAC 的安装：

```powershell
npx @anthropic-ai/sandbox-runtime windows-install
```

当前 Windows 支持仍标记为 Alpha。官方列出的 Schannel 已知问题是证书吊销查询被 WFP 拦截后产生 `CRYPT_E_REVOCATION_OFFLINE`，建议对 curl 使用 `--ssl-no-revoke`。这与当前 `yj-sandbox` 出现的 `SEC_E_NO_CREDENTIALS` 不是同一个错误。由于它同样切换到独立本地用户，不能仅凭文档断言原下载命令一定成功，接入前必须用同一条 `System32\curl.exe` 命令实测。

结论：优先做 PoC。它最有可能让调用方直接依赖上游，而不再维护 `yj-sandbox` 的 Codex vendor 分支。

资料：

- [Windows Alpha 的安装和隔离模型](https://github.com/anthropic-experimental/sandbox-runtime#windows-alpha)
- [Windows 配置与已知限制](https://github.com/anthropic-experimental/sandbox-runtime#known-limitations)
- [CLI 和 Library 调用方式](https://github.com/anthropic-experimental/sandbox-runtime#usage)
- [当前 package.json](https://github.com/anthropic-experimental/sandbox-runtime/blob/main/package.json)

### 2. Sandboxie Plus

仓库：[`sandboxie-plus/Sandboxie`](https://github.com/sandboxie-plus/Sandboxie)

Sandboxie Plus 是成熟的 Windows 专用项目，许可证为 GPL-3.0。它依靠驱动和服务实现文件、注册表虚拟化以及进程隔离，比用户态 Hook 或单纯受限 Token 更接近一个完整的 Windows 应用沙箱。

它适合调用方集成的几个能力：

- 可以通过 `Start.exe /box:<name> /wait <command>` 启动任意 Windows 命令并取得退出码。
- 每个 box 都能单独设置 `FileRootPath`，例如 `FileRootPath=D:\AppData\Sandboxes\%SANDBOX%`，不存在 WorkBuddy 那种不可配置的根目录问题。
- 可以启用基于 WFP 的 per-box 入站和出站网络策略。
- 文件和注册表修改默认落入虚拟化容器，便于丢弃或恢复。

代价是客户端必须安装 Sandboxie 的驱动和服务，初次部署需要管理员权限，升级、杀软兼容和驱动签名都会进入产品运维范围。GPL-3.0 对分发、修改或链接方式也需要单独做许可证评估。它不是一个复制单个 exe 就能使用的轻量库。

结论：如果可以接受安装系统级组件，并且更重视成熟度和 Windows 软件兼容性，它是第二候选；如果产品要求免安装、单文件随应用分发，则不合适。

资料：

- [`Start.exe` 命令行调用](https://sandboxie-plus.github.io/sandboxie-docs/Content/StartCommandLine/)
- [`FileRootPath` 可按 box 配置](https://sandboxie-plus.github.io/sandboxie-docs/Content/FileRootPath/)
- [per-box WFP 网络策略](https://sandboxie-plus.com/wfpsupport/)

### 3. Gemini CLI 的 Windows Native Sandbox

仓库：[`google-gemini/gemini-cli`](https://github.com/google-gemini/gemini-cli)

Gemini CLI 主分支包含 Apache-2.0 的 Windows 沙箱源码。它复制当前用户 Token，调用 `CreateRestrictedToken`，降到 Low Integrity，再使用 Job Object 约束整个进程树；TypeScript 管理层为允许和禁止路径生成临时 manifest。

详细源码核查和本机实测见 [`gemini-windows-native-sandbox-study.md`](./gemini-windows-native-sandbox-study.md)。在不评价网络隔离、只要求限制写入的前提下，原 GitHub ZIP 下载命令成功，工作区外写入被 Low Integrity 阻止，普通子进程也能由 Job Object 回收。

它可以作为“同一用户、无需管理员安装的写沙箱”实现基线，但不适合作为调用方的现成依赖：

- Windows helper 是 Gemini CLI 内部组件，没有独立、稳定的 sandbox 包或第三方接口承诺。
- Low Integrity 标签会持久写入文件系统，官方文档提示结束后可能需要用 `icacls` 手动恢复。
- 当前 forbidden-path DACL 在本机没有阻止外部命令读取目标文件，不能宣称它具备可靠的读隔离。
- 禁止网络的实现只是把 Job Object 最大带宽设为每秒 1 字节；设置失败时仅打印警告并继续，不是严格的网络阻断。
- 如果复制这部分代码到自己的项目，维护责任仍会回到本项目。

结论：如果产品契约明确为“允许读取当前用户环境，只限制写入范围”，优先基于 Gemini 的 Restricted Token、写入范围控制和 Job Object 做小型 PoC；不要直接依赖整个 Gemini core 包，也不要原样照搬其 ACL 生命周期和 forbidden-path 实现。

资料：

- [Gemini CLI 沙箱文档](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/sandbox.md#windows-native-sandbox-windows-only)
- [WindowsSandboxManager.ts](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/sandbox/windows/WindowsSandboxManager.ts)
- [GeminiSandbox.cs](https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/sandbox/windows/GeminiSandbox.cs)

### 4. Microsoft hcsshim

仓库：[`microsoft/hcsshim`](https://github.com/microsoft/hcsshim)

这是微软维护的 MIT 许可 Go 库，用于调用 Host Compute Service 启动和管理 Windows Containers，也是 Moby 和 containerd 在 Windows 上的底层组件之一。它能够提供 Windows 容器或 Hyper-V 容器级隔离，安全边界强于前面几种进程级方案。

它的问题是接入成本远高于当前需求。调用方需要 Windows 容器镜像、layer、containerd 或自建 HCS 编排，并处理宿主目录映射和镜像内工具链。它不是 `sandbox-cli.exe command` 这种可直接替换的进程包装器。

结论：只有在决定把产品架构升级为 Windows 容器或 Hyper-V 容器时再选，不应当为了解决当前 Schannel 和固定目录问题而引入。

### 5. 没有列入候选的项目

- `openai/codex`：当前 `yj-sandbox` 已明确从 `codex-rs/windows-sandbox-rs` vendor 并解耦。直接回到上游不会改变受限用户、ACL、WFP 和 Schannel 这组核心约束，也不能让调用方获得一个稳定的独立 sandbox 产品接口。2026-09-04 复核确认上游仍未修 Schannel，`openai/codex#17459` 保持 open，详见 `SYNCING.md` 的复核记录。
- `microsoft/Windows-Sandbox`：GitHub 仓库主要是文档和问题跟踪，不是 Windows Sandbox 系统组件的可复用开源实现。
- `microsoft/win32-app-isolation`：仓库主要提供 AppContainer/Win32 隔离相关文档和示例，不是可直接调用的通用命令沙箱运行时。
- Linux 或云端 sandbox 项目：即便提供统一 API，也不能直接运行用户机器现有的原生 Windows 工具，不满足当前替换目标。

## 八、建议的选型顺序

1. 如果产品契约是“同一用户环境、无需管理员安装、只限制写入”，先做 Gemini 式最小 PoC，检查允许目录、拒绝目录、子进程、超时、并发、临时目录和 ACL 回收。
2. 如果还需要更完整的策略层，再对 Anthropic Sandbox Runtime 做最小 PoC；若 Windows Alpha 稳定性或 Schannel 兼容性不合格，再评估 Sandboxie Plus。
3. 如果威胁模型要求隐藏当前用户秘密或防御主动恶意代码，不再接受共享当前用户和宿主内核的进程级边界，则直接进入独立账户、`hcsshim`/containerd 或 Hyper-V 容器方案评估。

短期内可以抽取 Gemini 的核心原语做独立 PoC，但不要把上游两份文件原样产品化。这个方向能显著缩小 `yj-sandbox` 的维护范围，不能把维护责任完全转移给 Gemini。
