# Gemini CLI Windows Native Sandbox 学习与实测

## 结论

Gemini 的方案可以作为“无需管理员安装、保留当前用户 Windows 兼容性”的实现基线，但不能原样作为安全沙箱交付。

它最适合的准确定位是“同一用户下的写入约束器”：

- 不创建本地用户，不安装服务、驱动或 WFP，不需要 UAC。
- 目标进程仍使用当前用户身份和当前用户 Profile，因此 `System32\curl.exe` 的 Schannel 兼容性明显好于 Codex 独立用户模式。
- Low Integrity 能有效阻止目标进程写入普通 Medium Integrity 目录。
- Job Object 能约束正常创建的子进程，并在 runner 退出时清理剩余进程。
- 默认不能阻止读取当前用户的其他文件和注册表数据。
- 当前上游的 forbidden-path DACL 实现在本机实测没有阻止外部命令读取目标文件。
- 对允许目录所做的 DACL 和 Mandatory Label 修改会持久留在宿主文件系统，runner 没有回滚。

如果当前产品目标是“允许读取用户环境，只限制写入工作区以外目录”，这个方向值得继续。如果目标还包括隐藏 `.ssh`、`.env`、浏览器凭据或其他当前用户秘密，现有代码不够。

## 一、研究基线

- GitHub 仓库：[`google-gemini/gemini-cli`](https://github.com/google-gemini/gemini-cli)
- 核查提交：`ac42fb0a24fe7349e9968e2359ef5232f1cb6e72`，2026 年 8 月 3 日的主分支提交。
- npm 稳定包：`@google/gemini-cli-core@0.53.1`，Apache-2.0，Node.js 20 及以上。
- npm 包已经导出 `WindowsSandboxManager` 和 `SandboxManager` 类型，但整个 core 包压缩包约 21.7 MB，解包约 54.9 MB，并不是一个专门的轻量 sandbox 包。
- 稳定包包含 `GeminiSandbox.cs`，没有包含预编译的 `GeminiSandbox.exe`。首次运行由 JS 尝试调用系统 `csc.exe`，把 exe 写到包自身目录。

主分支核心文件：

- [`WindowsSandboxManager.ts`](https://github.com/google-gemini/gemini-cli/blob/ac42fb0a24fe7349e9968e2359ef5232f1cb6e72/packages/core/src/sandbox/windows/WindowsSandboxManager.ts)
- [`GeminiSandbox.cs`](https://github.com/google-gemini/gemini-cli/blob/ac42fb0a24fe7349e9968e2359ef5232f1cb6e72/packages/core/src/sandbox/windows/GeminiSandbox.cs)
- [`WindowsSandboxManager.test.ts`](https://github.com/google-gemini/gemini-cli/blob/ac42fb0a24fe7349e9968e2359ef5232f1cb6e72/packages/core/src/sandbox/windows/WindowsSandboxManager.test.ts)
- [`compile-windows-sandbox.js`](https://github.com/google-gemini/gemini-cli/blob/ac42fb0a24fe7349e9968e2359ef5232f1cb6e72/packages/core/scripts/compile-windows-sandbox.js)

## 二、执行链路

```text
调用方
  │ command / args / cwd / env / permissions
  ▼
WindowsSandboxManager.ts
  ├─ 清理敏感环境变量
  ├─ 解析 workspace、allowed、forbidden 和额外写路径
  ├─ 扫描 .env / .env.*
  ├─ 创建临时 allowed.txt / forbidden.txt
  └─ 启动 GeminiSandbox.exe
        │
        ├─ 修改允许、拒绝路径的 DACL / Mandatory Label
        ├─ OpenProcessToken 当前用户 Token
        ├─ CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)
        ├─ SetTokenInformation → Low Integrity
        ├─ CreateJobObject(KILL_ON_JOB_CLOSE)
        ├─ CreateProcessAsUser(CREATE_SUSPENDED)
        ├─ AssignProcessToJobObject
        ├─ ResumeThread
        └─ 等待主进程并返回退出码
```

runner 的命令行契约很小：

```text
GeminiSandbox.exe <network:0|1> <cwd>
  --forbidden-manifest <file>
  --allowed-manifest <file>
  <program> [args...]
```

本机使用系统 .NET Framework C# 编译器直接编译成功，生成的 `GeminiSandbox.exe` 为 17,408 字节。

## 三、为什么不需要管理员权限

它没有切换 Windows 用户。runner 复制的是调用方自己的 Token，再通过 `CreateRestrictedToken` 删除除 `SeChangeNotifyPrivilege` 外的大部分权限。微软文档明确允许普通应用使用自身 Token 的受限版本调用 `CreateProcessAsUser`，不要求 `SE_ASSIGNPRIMARYTOKEN_NAME`。[1]

当前代码调用：

```text
CreateRestrictedToken(
  currentToken,
  DISABLE_MAX_PRIVILEGE,
  DisableSidCount = 0,
  RestrictedSidCount = 0
)
```

这意味着：

- 管理员组等 SID 没有被代码额外删除或改成 deny-only；非提权 UAC Token 中原本为 deny-only 的组仍保持原状。
- 没有添加 restricting SID，文件访问没有进行第二次“限制 SID”检查。
- 真正限制普通文件写入的主要机制是 Low Integrity，而不是 Restricted Token 的 SID 收缩。

## 四、文件系统模型

### 1. 默认写入拒绝

Windows Mandatory Integrity Control 默认执行 No-Write-Up。Low Integrity 进程不能写入没有标签或标记为 Medium Integrity 的对象，即使当前用户的普通 DACL 允许写入。[2]

这条行为本机验证有效：专用工作区之外的 Medium Integrity 临时目录无法创建文件，PowerShell 返回 `UnauthorizedAccessException`。

### 2. 允许目录

对 allowed manifest 中已经存在的文件或目录，helper：

1. 给 Low Mandatory Level SID 添加 `Modify` DACL ACE。
2. 把目录或文件的 Mandatory Label 设置为 Low，并设置 `No Write Up`。

目标进程仍具有当前用户 SID。目录降为 Low 后，MIC 不再阻止它写入；当前用户原有 DACL 同时允许写入。因此工作区写入成功。

允许路径必须已经存在。不存在的单文件写入只有在其父目录已经属于允许根时才会被接受。

### 3. 默认读取不受限

MIC 默认只设置 `NO_WRITE_UP`，并不设置 `NO_READ_UP`。Low Integrity 进程仍然可以读取当前用户有权读取的 Medium Integrity 文件。[2]

本机实测中，沙箱进程成功读取工作区之外的 `D:\project\yj-sandbox\README.md`。同理，当前用户 Profile、HKCU 注册表、证书存储以及其他可读文件没有天然的读取隔离。

### 4. forbidden manifest 的问题

helper 对 forbidden 路径添加的是普通 DACL：

```text
DENY FullControl to S-1-16-4096
```

本机实际 Token 的 `S-1-16-4096` 显示为 `Label`，没有 Enabled Group 属性。虽然文件 SDDL 中已经出现 `(D;;FA;;;LW)`，外部 PowerShell 仍能成功读取该文件，退出码为 0。

内部命令 `__read` 会先用字符串路径执行 `CheckForbidden`，因此能走到拒绝分支；但当前实现让 `UnauthorizedAccessException` 逃出 `Main`，最终得到 CLR 未处理异常退出码 `-532462766`，没有返回稳定的业务错误码。

结论：不能把当前 forbidden DACL 当成能够约束任意 Shell 命令的读取边界。现有 TypeScript 测试只验证路径是否写入 manifest，没有启动原生 helper 验证真实 AccessCheck。[3]

### 5. ACL 修改没有回滚

JS 返回的 `cleanup()` 只删除临时 manifest 目录。C# helper 不记录原始 DACL/SACL，也不删除新增 ACE 或恢复原 Mandatory Label。

影响包括：

- 允许目录会长期保持 Low Mandatory Label。
- 当前用户下的其他 Low Integrity 进程也可能写入这些被降级的目录。
- forbidden 和 allowed ACE 会反复留在目标对象上。
- runner 崩溃、调用方被杀或机器断电后没有恢复机制。

Gemini 官方文档只明确提醒 Low Integrity 修改会持久存在并可能需要手动 `icacls ... /setintegritylevel Medium`，源码中的普通 DACL ACE 同样没有清理。[4]

## 五、进程和兼容性

### 1. 子进程

目标进程先以挂起状态创建，成功加入 Job Object 后才恢复，不存在“先运行再加入 Job”的窗口。Job 设置 `KILL_ON_JOB_CLOSE`，微软文档说明最后一个 Job handle 关闭时会终止其中所有进程。[5]

本机验证中，主进程启动一个 60 秒 PowerShell 子进程后立即退出；helper 返回后子进程已经被终止。

Job 没有设置 `BREAKAWAY_OK` 或 `SILENT_BREAKAWAY_OK`，正常 `CreateProcess` 子进程会继承 Job。通过 WMI `Win32_Process.Create` 的一次逃逸测试在本机被 Low Integrity/RPC 权限拒绝，但这不能证明所有 COM、任务计划、BITS 和系统 broker 路径都不可用。

### 2. 退出码和超时

主进程退出码能够原样传回，`cmd.exe /c exit 7` 的 helper 退出码为 7。

helper 自己使用无限等待，没有 timeout 参数。调用方必须在超时时终止 helper；helper 退出导致 Job handle 关闭，随后由 Job 清理目标进程树。

### 3. Schannel

它没有创建新用户，也没有加载独立 Profile，目标仍在当前用户安全上下文中。环境变量经过清理，但 Windows 当前用户证书和 Schannel 上下文没有切换成另一个本地账户。

在 `network=1`、允许专用临时工作区的条件下，以下原始请求成功：

```text
C:\Windows\System32\curl.exe
  -L -sS
  --insecure --ssl-no-revoke
  https://github.com/KKKKhazix/human-writing/archive/refs/heads/main.zip
```

结果：退出码 0，生成 ZIP 44,320 字节，没有出现 `SEC_E_NO_CREDENTIALS`。

### 4. 工具兼容性

Low Integrity 会阻止写入普通 `%TEMP%`、用户缓存和包管理器目录。Gemini manager 没有自动为 `%TEMP%` 建立每次执行的可写区域。编译器、npm、pip、Git credential helper 或生成临时文件的工具可能因此失败。

实际接入时应为每次执行创建专用临时目录，将 `TEMP`、`TMP` 指向该目录，并只授权这个目录。不能直接把整个用户 Temp 降为 Low Integrity。

## 六、实测结果

测试均使用主分支原始 `GeminiSandbox.cs` 编译，网络参数设为允许，不评价网络限速实现。

| 测试 | 结果 |
|---|---|
| 无管理员编译 helper | 成功，17,408 字节 |
| 原 GitHub curl 下载 | 成功，退出码 0，44,320 字节 |
| 写入 allowed 工作区 | 成功 |
| 写入工作区外 Medium 目录 | 被拒绝，文件未创建 |
| 读取工作区外普通文件 | 成功 |
| 外部 PowerShell 读取 forbidden 文件 | 成功，说明 DACL 拒读没有生效 |
| 内部 `__read` 读取 forbidden 文件 | 被字符串检查阻止，但以 CLR 未处理异常退出 |
| `cmd /c exit 7` | helper 原样返回 7 |
| 主进程遗留普通子进程 | helper 退出时由 Job 终止 |
| WMI `Win32_Process.Create` 逃逸 | 本机返回 Access Denied，未创建外部文件 |

## 七、作为本项目依赖的可行性

### 直接依赖 `@google/gemini-cli-core`

技术上可行，因为 `WindowsSandboxManager` 已从 core 包导出。但不建议把整个 core 包只用于这项能力：

- 依赖体积大。
- manager 依赖 Gemini 的 policy、命令解析、secret 扫描和环境清理模块。
- helper 路径固定在模块目录，没有对外注入路径的构造参数。
- npm 包不带预编译 exe，首次运行尝试写包目录；Electron ASAR、Program Files 或只读安装位置会失败。
- GitHub 已出现 `GeminiSandbox.exe ENOENT` 的 P1 问题，说明打包闭环还不成熟。[6]

### 抽取原生 helper

代码量小，许可证允许，但这样会重新承担维护责任。至少必须先修复以下 P0 项：

1. 明确产品契约是“限制写入”，不要宣称当前实现能够隐藏任意 forbidden 文件。
2. ACL 或 Mandatory Label 应用失败必须终止执行，不能打印 Warning 后继续。
3. 保存原始安全描述符，并在正常退出、超时、崩溃恢复时回滚。
4. 为每次运行创建独立 Temp，并重写 `TEMP`、`TMP`。
5. 捕获所有异常，统一返回确定的错误码和结构化错误。
6. 对真实 exe 做 Windows 集成测试，而不只检查 manifest 字符串。
7. 验证 junction、symlink、reparse point、UNC、device path 和路径替换竞态。

## 八、推荐方向

如果网络隔离暂不考虑，建议保留 Gemini 的三个核心原语：

```text
当前用户 Restricted Token
        +
写入范围控制
        +
Job Object 进程树清理
```

但写入范围控制不建议长期依赖“把宿主工作区降成 Low Integrity 且不恢复”。值得做一个更小的 PoC：使用 `CreateRestrictedToken` 的 `WRITE_RESTRICTED` 和每次会话生成的 restricting SID。写入时让 Windows 同时检查当前用户 DACL与会话 SID，只给工作区添加该会话 SID 的临时 Allow ACE，执行后移除。这样有机会保留当前用户的读取和 Schannel 兼容性，同时避免把整个目录永久降为 Low Integrity。该方向需要先验证任意会话 SID、继承 ACE、并发和崩溃恢复行为，尚不能直接视为已完成方案。

短期判断：Gemini 方案值得继续做“无管理员写沙箱”原型；上游稳定包不能原样交给调用方当成成熟 sandbox runtime。

## 资料

[1] Microsoft, [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken) 与 [Restricted Tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)，官方 Win32 安全 API 文档。

[2] Microsoft, [Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)，官方 MIC 行为说明。

[3] Google Gemini CLI, [WindowsSandboxManager.test.ts](https://github.com/google-gemini/gemini-cli/blob/ac42fb0a24fe7349e9968e2359ef5232f1cb6e72/packages/core/src/sandbox/windows/WindowsSandboxManager.test.ts)，主分支测试源码。

[4] Google Gemini CLI, [Sandboxing 文档](https://github.com/google-gemini/gemini-cli/blob/ac42fb0a24fe7349e9968e2359ef5232f1cb6e72/docs/cli/sandbox.md#windows-native-sandbox-windows-only)，官方项目文档。

[5] Microsoft, [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)，官方进程树和 KILL_ON_JOB_CLOSE 文档。

[6] Google Gemini CLI, [`GeminiSandbox.exe ENOENT` issue #24365](https://github.com/google-gemini/gemini-cli/issues/24365)，官方仓库问题记录。

[7] Google Gemini CLI, [Windows MIC PR #24057](https://github.com/google-gemini/gemini-cli/pull/24057)，实现引入和评审记录。
