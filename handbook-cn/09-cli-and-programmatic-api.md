# 09 — CLI 与编程 API

## 9.1 CLI 表面(`srt`)

CLI 是 `src/cli.ts` 中的 `commander` 调用。子命令:

| 子命令             | 参数                                                                  | 效果                                                              |
| ---------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| (默认)              | `[command...]`,`-d, --debug`,`-s, --settings <path>`,`-c <cmd>`,`--control-fd <fd>` | 在沙箱中运行 `<command>`。                                    |
| `windows-install`      | `--sublayer-guid`,`--proxy-port-range`,`--sandbox-user`,`--force`       | 自提升安装(一次 UAC)。                            |
| `windows-uninstall`    | `--sublayer-guid`                                                          | 自提升卸载(一次 UAC)。                         |

### 默认子命令

```
srt [-d] [-s PATH] [-c "command string"] [--control-fd N] [-- ... arbitrary]
```

示例:

```bash
# 直接调用(每个 token 被 shell-quoted 到 `bash -c`):
srt curl https://example.com

# 运行 shell-piped 命令,避免转义麻烦:
srt -c "for f in *.txt; do echo \$f; done"

# 通过 fd 3 进行动态配置更新:
srt --control-fd 3 curl https://github.com
# (父进程将 JSON 行写入 fd 3;配置实时更新)
```

### 行为

1. 解析配置路径(默认 `~/.srt-settings.json`,或覆盖)。
2. 读取 + zod 校验 JSON。**缺失配置且显式指定 `--settings` 是硬错误**,永远不静默回退。
3. `SandboxManager.initialize(config)`。
4. 如果设置了 `--control-fd`,挂载一个 `readline` 接口读取以换行符分隔的 JSON 更新(仅网络——Windows 上的文件系统更改在运行期警告,macOS/Linux 上忽略)。
5. 计算包装后的命令(POSIX 上是 shell 字符串;Windows 是 `{argv, env}`)。
6. `spawn(...)`,继承 stdio;将 SIGINT/SIGTERM 转发给子进程。
7. 退出时:`cleanupAfterCommand()`(仅 Linux),`process.exit(code)`。
8. 进程退出 / SIGINT / SIGTERM 时:`reset()`(通过 `registerCleanup()` 注册)。

### 返回码

| 原因                                 | 退出码                              |
| ------------------------------------- | -------------------------------------- |
| 沙箱违规(网络被阻)   | 子进程正常退出码(如 curl 的 7) |
| 缺失或无效的 `~/.srt-settings.json` 且指定 `--settings` | 1 |
| 缺失依赖                  | 1(stderr 消息)                     |
| 安装/卸载 UAC 上用户取消 | 2                                     |
| Wrapper 失败                       | 1 |

### 内部说明

- `utils/shell-quote.ts` 的 `quote(commandArgs)` 将 argv 风格参数连接成 shell 安全字符串(如 `'foo bar'`、`'a "b"'`)。
- Windows 上,编排器使用 `spawn(argv[0], argv.slice(1), { shell: false })` 使用户提供的字节不会碰到 `cmd.exe`。
- `process.on('exit', cleanup)` 加 `process.on('SIGINT', cleanup)` 等。

## 9.2 编程表面(`SandboxManager`)

公开类型:

```ts
export const SandboxManager: ISandboxManager = {
  initialize,
  isSupportedPlatform,
  isSandboxingEnabled,
  checkDependencies,
  getFsReadConfig,
  getFsWriteConfig,
  getNetworkRestrictionConfig,
  getAllowUnixSockets,
  getAllowLocalBinding,
  getAllowMachLookup,
  getIgnoreViolations,
  getEnableWeakerNestedSandbox,
  getProxyPort,
  getProxyAuthToken,
  getSocksProxyPort,
  getLinuxHttpSocketPath,
  getLinuxSocksSocketPath,
  waitForNetworkInitialization,
  wrapWithSandbox,
  wrapWithSandboxArgv,
  cleanupAfterCommand,
  reset,
  getMitmCA,
  getSentinelRegistry,
  getMaskedFileStore,
  getSandboxViolationStore,
  annotateStderrWithSandboxFailures,
  getLinuxGlobPatternWarnings,
  getConfig,
  updateConfig,
} as const
```

`SandboxManager` 是 **单例** —— 一个进程,一份配置,一组代理。

### 生命周期方法

```ts
// 用配置初始化;第二次调用 no-ops(返回缓存的 init promise)。
await SandboxManager.initialize(config, askCallback?, enableLogMonitor?)

// 当前 OS 是否受支持(WSL1 等返回 false)。
SandboxManager.isSupportedPlatform()

// 如果 initialize() 至少运行过一次,则为 true。
SandboxManager.isSandboxingEnabled()

// 探测依赖。错误 = 无法运行;警告 = 降级。
const { errors, warnings } = SandboxManager.checkDependencies()
```

### Wrap 方法

```ts
// POSIX 返回值:可执行的 shell 命令字符串。用 `spawn(..., { shell: true })` 包装。
const wrapped: string = await SandboxManager.wrapWithSandbox(
  'curl https://example.com',
  binShell?: string,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal
)

// Windows 返回值:argv + env 用于 { shell: false } spawn。
const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
  'curl https://example.com',
  binShell?: string,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal,
  cwd?: string
)
```

`customConfig` 与会话配置按以下优先级 *合并*:

- `customConfig` 中每个存在的键覆盖会话配置。
- `customConfig.filesystem` 视为 *单一整体*:即使写为 `{disabled: false}`,只要该键出现,就完全替换会话的文件系统配置。
- `customConfig.network.allowedDomains !== undefined` 触发了本执行的代理使用(即使会话的 `allowedDomains` 是 `[]`)。

### 热重载 & 重置

```ts
// 热交换网络规则。Windows 上的文件系统规则 WARN;否则被忽略。
SandboxManager.updateConfig(newConfig)

// 完全拆除 —— 在重新初始化前调用。
await SandboxManager.reset()
```

### 可观测性方法

```ts
// 获取违规存储(以 encoded-command-b64 为键)。
const store = SandboxManager.getSandboxViolationStore()
for (const v of store.getViolationsForCommand(encodedCommand)) {
  console.error(v.line)
}

// 用子进程期间捕获的违规来注解子 stderr。
const annotated = SandboxManager.annotateStderrWithSandboxFailures(command, stderr)

// Linux 唯一的"配置中无法生效的 pattern"警告。
const unsupportedGlobs = SandboxManager.getLinuxGlobPatternWarnings()

// 有用的接入点
const token      = SandboxManager.getProxyAuthToken()
const muxPort    = SandboxManager.getProxyPort()
const socksPort  = SandboxManager.getSocksProxyPort()
const linuxHttpSock  = SandboxManager.getLinuxHttpSocketPath()
const linuxSocksSock = SandboxManager.getLinuxSocksSocketPath()
```

## 9.3 类型导出

```ts
// 配置类型
export type {
  SandboxRuntimeConfig,
  NetworkConfig,
  FilesystemConfig,
  CredentialsConfig,
  CredentialFileConfig,
  CredentialEnvVarConfig,
  CredentialMode,
  IgnoreViolationsConfig,
  WindowsConfig,
  SrtWinConfig,
}

// 运行时辅助类型
export type {
  SandboxAskCallback,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  CredentialRestrictionConfig,
  NetworkRestrictionConfig,
  NetworkHostPattern,
  FilterRequestCallback,
  RequestDecision,
  MutateForwardedHeaders,
  SandboxViolationEvent,
}

// Schemas(zod)
export {
  SandboxRuntimeConfigSchema,
  NetworkConfigSchema,
  FilesystemConfigSchema,
  CredentialsConfigSchema,
  IgnoreViolationsConfigSchema,
  RipgrepConfigSchema,
  WindowsConfigSchema,
  SrtWinConfigSchema,
}

// 辅助
export { getDefaultWritePaths }
export { getWslVersion }
```

## 9.4 为什么导出 Schema?

嵌入一个新 `ZodObject` 让消费者复用我们的校验:

```ts
import {
  SandboxRuntimeConfigSchema,
  type SandboxRuntimeConfig
} from '@anthropic-ai/sandbox-runtime'

const userConfig = JSON.parse(fs.readFileSync('user.json', 'utf8'))
const parsed: SandboxRuntimeConfig = SandboxRuntimeConfigSchema.parse(userConfig)
```

这意味着嵌入方不必重复校验逻辑;他们跟我们拿到一样的错误消息。

## 9.5 通过 `--control-fd` 的动态配置更新

一个二级输入通道,允许父进程在 CLI 仍在 `spawn` 阻塞时推送配置快照。线路协议:

- 每个一行一个完整的 JSON 对象(无格式化、无数组)。
- 与 `SandboxRuntimeConfigSchema` 同形。
- 网络更改在下一个请求生效。
- 文件系统更改在下一个 `wrapWithSandbox(...)` 调用生效。
- Windows 上,文件系统形状变化触发 stderr 警告且被忽略。
- 畸形行在 debug 级别记录后丢弃;合法行触发 `SandboxManager.updateConfig(line)`。

典型用法:

```bash
# 让沙箱 CLI 永远运行;守护进程观察某事并推送更新
srt --control-fd 3 daemon &
exec 3>#   # 管道的写入端
# 之后:向 fd 3 写 JSON:
echo '{"network":{"allowedDomains":["github.com"],"deniedDomains":[]}, …}' >&3
```

## 9.6 同步原语(`sandbox-exec` / `bwrap` / `srt-win exec`)

每个平台包装器最终产出宿主编排器可 spawn 的字符串:

| OS      | 返回路径                                         | 运行方式                                  |
| ------- | --------------------------------------------------- | ---------------------------------------- |
| macOS   | `env -u… ENV=… sandbox-exec -p '<profile>' bash -c '<cmd>'` | `spawn(cmd, { shell: true })`     |
| Linux   | `bwrap … apply-seccomp bash -c '<cmd>'` argv 形式 | `spawn(argv, { shell: false })`         |
| Windows | `srt-win exec … <shell> -c <cmd>` argv 数组        | `spawn(argv, { shell: false })`         |

注意 Windows 使用 `cmd.exe` 作为内部 shell(或 `binShell` 指定的任何东西——`pwsh`、WSL 中的 `bash` 等)。无论内部 shell 是什么,它都在沙箱用户下运行(srt-win 以沙箱用户运行 runner → 内部 shell 看到沙箱用户的环境)。

## 9.7 作为依赖添加库

```bash
npm install @anthropic-ai/sandbox-runtime
```

然后:

```ts
import { SandboxManager } from '@anthropic-ai/sandbox-runtime'
import type { SandboxRuntimeConfig } from '@anthropic-ai/sandbox-runtime'
```

README 在 "As a library" 下提供了精确的使用片段。

## 9.8 库消费者常见需求

### 想让 sandbox-exec 失败优雅降级

`SandboxManager.checkDependencies()` 是正确的预检查。那里的错误意味着 `wrapWithSandbox()` 会抛;消费者可以回退到非沙箱运行(带日志告警)。

### 想询问用户策略外网络请求

```ts
await SandboxManager.initialize(config, async ({ host, port }) => {
  return await confirmDialog(`Allow ${host}:${port}?`)
}, /* enableLogMonitor */ true)
```

回调由代理对每个请求调用。返回 `false` ⇒ 403;返回 `true` ⇒ 请求继续(纯 HTTP 走现有白名单语义)。

### 想要热配置更新

随时调用 `updateConfig(newConfig)`。网络更新在下个请求生效。文件系统更新在下次 `wrapWithSandbox()` 调用生效。

### 想要按调用覆盖(POSIX)

```ts
const wrapped = await SandboxManager.wrapWithSandbox(cmd, undefined, {
  filesystem: {
    denyRead: ['/extra'],
    allowWrite: ['/extra'],
    denyWrite: [],
  },
  network: {
    allowedDomains: ['api.example.org'],
    deniedDomains: [],
  },
})
```

### 想要按调用覆盖(Windows)

按调用的 `allowRead`/`allowWrite` 在 `wrapWithSandboxArgv()` 时抛错。只能使用 `denyRead`/`denyWrite`。

## 9.9 CLI 调试表面

- `SRT_DEBUG=1`(也 `-d, --debug`)→ 在 `process.env` 设为 `initialize()` 之前。日志全开输出到 stderr。
- `which srt` / `srt --version` —— 确认安装版本。
- `srt --settings /dev/null` —— 强制未加载配置时硬错误。
- `srt 'cat /etc/hosts'` 对抗 `denyRead: ['/etc']` —— 快速功能 smoke。
- 沙箱命令的 `$HTTP_PROXY` 可用 `srt 'env | grep -i proxy'` 检查。

## 9.10 库与 CLI 的区别

库表面是 CLI 行为的严格子集。CLI 做:
- 读/写 `~/.srt-settings.json`。
- 处理 `--control-fd`。
- 转发信号。
- 转换 argv → shell 字符串。
- 打印版本/帮助。

库不做那些 —— 它是一个状态对象,包装单个进程。需要类 CLI 行为的嵌入方应该 *派生* CLI 作为子进程,而不是用库;只需要 wrap + spawn 的嵌入方应用库。
