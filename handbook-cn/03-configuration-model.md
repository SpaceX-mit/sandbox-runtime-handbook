# 03 — 配置模型

## 3.1 配置存放位置

| 来源                                              | 使用方                  | 说明                                                                                                                                |
| --------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| `~/.srt-settings.json`                              | `srt` CLI                | 默认文件。缺失 → 默认配置(全网络阻隔、全读取、仅少量内置可写)。                                                                      |
| `--settings /path/to/settings.json`                 | `srt` CLI                | 显式缺失且指定 `--settings` → **硬错误**(静默回退会让你在未加固状态下运行命令)。                                                  |
| 程序进程环境(HTTP_PROXY 等) | sandbox-manager         | `parentProxy` 在配置省略时由 `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` 环境变量解析。                                                    |
| `--control-fd <fd>` 文件描述符                       | sandbox-manager         | CLI 存活期间按行投递 JSON 更新(网络热重载)。                                                                                        |
| 库调用                                            | 嵌入                     | `SandboxManager.initialize(cfg, askCb, enableLogMonitor)`。二次调用返回首次的缓存 promise。                                          |

## 3.2 Schema(TS-Zod 风格)

配置由 `sandbox/sandbox-config.ts` 中的 Zod schema 校验。该 schema 是机读契约;本文档是它的转写。

```text
SandboxRuntimeConfig
├── network: NetworkConfig
│     ├── allowedDomains: DomainPattern[]                    必填,可为 [] (=> 全阻)
│     ├── deniedDomains : (DomainPattern | "*")[]           必填,可为 []
│     ├── strictAllowlist?: boolean
│     ├── allowUnixSockets?: string[]                       macOS 路径白名单;Linux 上忽略
│     ├── allowAllUnixSockets?: boolean
│     ├── allowLocalBinding?: boolean                       默认 false
│     ├── allowMachLookup?: string[]                        可选尾 `*` 通配符前缀
│     ├── httpProxyPort?  : 1..65535                        外部代理覆盖
│     ├── socksProxyPort? : 1..65535
│     ├── mitmProxy?: { socketPath, domains: DomainPattern[] }
│     ├── filterRequest?: (req: Request) => {action,reason?}
│     ├── tlsTerminate?: {
│     │       caCertPath? / caKeyPath?
│     │       excludeDomains?: DomainPattern[]
│     │       extraCaCertPaths?: string[]                    }   # caCertPath ↔ caKeyPath 必须一起设
│     └── parentProxy?: { http?, https?, noProxy? }
├── filesystem: FilesystemConfig
│     ├── disabled?: boolean                                 (逃生口;默认 false)
│     ├── denyRead   : path[]   必填
│     ├── allowRead  : path[]   可选(在 denyRead 内开洞;优先级高)
│     ├── allowWrite : path[]   必填
│     ├── denyWrite  : path[]   必填(在 allowWrite 内挖洞;优先级高)
│     └── allowGitConfig?: boolean                           默认 false
├── credentials?: CredentialsConfig                         可选;见文档 08
│     ├── files?     : { path, mode, extract?, onExtractNoMatch?, maskDuplicates?, injectHosts? }[]
│     ├── envVars?   : { name, mode, injectHosts? }[]
│     └── allowPlaintextInject?: boolean                    默认 false;无 tlsTerminate 时的门
├── ignoreViolations?: Record<commandPattern, path[]>
├── ripgrep?: { command, args?, argv0? }
├── mandatoryDenySearchDepth?: 1..10                        默认 3 (仅 Linux)
├── allowPty?: boolean                                      仅 macOS
├── enableWeakerNestedSandbox?: boolean                     仅 Linux
├── enableWeakerNetworkIsolation?: boolean                  仅 macOS (trustd);弱化网络围栏
├── allowAppleEvents?: boolean                              仅 macOS;*移除代码执行隔离*
├── seccomp?: { applyPath?, argv0? }                        仅 Linux
├── bwrapPath?: 绝对路径                                    仅 Linux
├── socatPath?: 绝对路径                                    仅 Linux
└── windows?: WindowsConfig                                 仅 Windows
      ├── sandboxUser?: string (≤ 20 字符)
      ├── sublayerGuid?: UUID (规范) / wfpSublayerGuid? (别名)
      ├── proxyPortRange?: [lo, hi]                         宽度 ≤ 64
      └── srtWin?: { path? }
```

### 域名字典

| Pattern         | 含义                                                       | 匹配示例                            |
| --------------- | ---------------------------------------------------------- | ------------------------------------ |
| `example.com`   | 精确主机名(大小写不敏感)。                                | `EXAMPLE.com`                        |
| `*.example.com` | 仅严格子域(`sub.example.com`、`a.b.example.com`)。              | 不匹配 `example.com` 本身或 `a.example.co` |
| `*`             | 通配符(**仅**在 `deniedDomains` 中允许)。                  | 全部                                |
| `localhost`     | 字面允许(普通条目中不接受通配符)。                        | `localhost`                          |
| 其他                                              | 配置时拒绝(如 `*.com`、`*`、`https://x`)。                |                                      |

### 路径字典

| 形式                            | 行为                                                                                       |
| ------------------------------- | ----------------------------------------------------------------------------------------------- |
| `/abs/path`                     | 已解析字面路径。                                                                        |
| `~/x`                           | `os/user/home/x`;只接受 `~`。                                                              |
| `name/` 或 `name`               | 相对于 `process.cwd()`。                                                                  |
| `dir/**`                        | 尾部的 `**` 在解析时被 *剥离*(在 macOS 上视为 `dir/`,见文档 05)。                          |
| `dir/**/*.ext`                  | 完整 glob。macOS: regex 匹配(`globToRegex`)。Linux: ripgrep 展开为字面路径。                  |
| `dir/*`, `dir/?`, `dir/[abc]`   | macOS: regex 匹配。Linux: 拒绝(并警告),因为 `bwrap` 只接受字面路径。                       |

## 3.3 默认值与内置项

| 默认写路径(始终允许)               | 用途                                              |
| ----------------------------------- | ------------------------------------------------ |
| `/dev/null`                         | 许多工具将其用于输出重定向。                |
| `/dev/zero`, `/dev/random`, `/dev/urandom` | 随机数据源。                            |
| `/dev/tty`                          | 交互式 TTY 访问。                                |
| `/dev/dtracehelper`                 | macOS 上的 DTrace 支持。                         |
| `/tmp`, `/dev/shm`                  | POSIX 要求的临时空间。                            |
| macOS:`/private/tmp`,`/private/var/folders/...` | `os.tmpdir()` 符号链接指向这些路径。 |
| `/dev/stdout`, `/dev/stderr`        | 用于转发 stdio 的 wrapper。                       |
| Linux:`/dev/`(tmpfs 替换)          | bwrap 与大多数 CLI 必需。                       |

| 必拒写路径(各平台构建器自动加入)                                                                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Shell rc 文件:`.bashrc`、`.bash_profile`、`.zshrc`、`.zprofile`、`.profile`、`.zshenv`、`.bash_login`、`.zlogout`、`.bash_logout`。       |
| Git 文件:`.gitconfig`、`.gitmodules`;`.git/hooks/`(整个目录);`.git/config`(除非 `allowGitConfig: true`)。                                       |
| IDE 目录:`.vscode/`、`.idea/`。                                                                                                                  |
| Tool 目录:`.claude/commands/`、`.claude/agents/`。                                                                                              |
| Tool 文件:`.ripgreprc`、`.mcp.json`。                                                                                                            |
| macOS 专用(regex):等价的递归 glob(`**/.*rc` 等)。                                                                                              |
| Linux:ripgrep 找到以上任何命中(最多 `mandatoryDenySearchDepth` 层深),然后 bwrap 在每个匹配处挂载 `/dev/null`(或该文件本身)。                  |

## 3.4 优先级规则

### 文件系统读(deny-then-allow)

```
(allow file-read*)                                ← 默认:全可读
(deny  file-read* (subpath /Users))               ← 广域拒绝
(allow file-read* (subpath /Users/me/project))    ← 显式允许
```

- `denyRead` 列表先评估;匹配 **拒绝**。
- `allowRead` 匹配项即使在拒绝的父目录下也 **重新允许**(与写入相反;见下)。
- macOS Seatbelt 末位匹配胜出,re-allow 规则必须放在 deny 之后。
- Linux:拒绝目录变为 `--tmpfs`;其中的 `allowRead` 路径显式 `--ro-bind` 回来。
- 必拒写始终优先于用户允许的写(`allowWrite:['.']` 也不能覆盖)。

### 文件系统写(allow-then-deny)

```
(allow file-write* (subpath /Users/me/project))
(deny  file-write* (subpath /Users/me/project/.env))
```

- 只有 `allowWrite` 允许写入。空 ⇒ 不可写。
- `denyWrite` 在允许的路径内 **始终优于** 允许。
- `denyWrite: []` + `allowWrite: []` 处于最严姿态;仅默认写路径保留。

### 网络(allow-then-deny,带可选回调)

```
deniedDomains 先检查   ⇒ 匹配:        deny
否则  allowedDomains 检查  ⇒ 匹配:        allow
否则  if strictAllowlist=true ⇒ deny(从不调用回调)
否则  if askCallback 定义   ⇒ await askCallback({host, port})
否则                      ⇒ deny
```

- 回调 **永不** 对非网络协议决策或已被 `deniedDomains` 拒绝的主机触发。
- `strictAllowlist: true` 完全跳过回调;用于 `allowedDomains` 是策略而非提示的场景。

## 3.5 校验表面(Super-Refinement)

| 跨字段约束                                                                                                                            | 在哪里强制                          |
| ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| `tlsTerminate.caCertPath` 设置 ⇔ `caKeyPath` 设置                                                                                     | `tlsTerminate.refine()`             |
| `network.tlsTerminate` 与 `network.mitmProxy` XOR(同时设置报错)                                                                       | `SandboxManager.initialize()`        |
| 每个被掩码的凭证,至少要有 `{tlsTerminate, allowPlaintextInject}` 之一被设置                                                              | schema `superRefine`                 |
| 每个显式 `injectHosts` 条目必须能经 `allowedDomains` 抵达(语义覆盖,非字面——`*.foo.com` 覆盖 `bar.foo.com`)                            | schema `superRefine`                 |
| 每个显式 `injectHosts` 条目不得被 `tlsTerminate.excludeDomains` 完全覆盖(否则永远不会填回真值)                                         | schema `superRefine`                 |
| `allowMachLookup` 中仅允许单一尾 `*` 通配符                                                                                            | `NetworkConfigSchema.refine`         |
| `proxyPortRange[0] ≤ proxyPortRange[1]` 且宽度 ≤ 64                                                                                    | `WindowsConfigSchema`                |
| `mandatoryDenySearchDepth` ∈ [1, 10]                                                                                                  | `SandboxRuntimeConfigSchema`         |
| `windows.sandboxUser` ≤ 20 字符                                                                                                        | `WindowsConfigSchema`                |
| `bwrapPath` / `socatPath` 必须为 **绝对路径**                                                                                          | `binaryPathSchema`                   |
| `windows.srtWin.path`:设置时,二进制以 `--srt-win` argv\[1] 启动(多路分发路由)                                                          | 用于 `wrapCommandWithSandboxWindows` |

## 3.6 热重载(`updateConfig`)

`updateConfig(newConfig)` 交换全局 `config` 引用。各平台行为差异:

| 方面                | macOS              | Linux              | Windows            |
| --------------------- | ------------------ | ------------------ | ------------------ |
| `network.*`           | 热生效(下次请求) | 热生效(下次请求) | 热生效(下次请求) |
| `filesystem.*`        | 仅在 wrap 时生效   | 仅在 wrap 时生效   | 警告;需 reset+init    |
| `credentials.*`       | 仅在 wrap 时生效   | 仅在 wrap 时生效   | 警告;需 reset+init    |
| `proxyPorts`          | 需要重新绑定       | 需要重新绑定       | 需要重新绑定       |
| MITM CA 身份          | 需要重新绑定       | 需要重新绑定       | 需要重新绑定       |

实现使用 `structuredClone` 复制配置,剥离无法克隆的函数值 `filterRequest`,然后重新赋值。代理服务器 **不** 重新绑定;它们在构造时闭包捕获 `config`,通过闭包 `filterNetworkRequest(port, host, cb)` 每次请求读取 `config.network.*`。

## 3.7 禁用文件系统(逃生口)

`filesystem.disabled: true` 导致 **所有** 文件系统限制(读 deny、读 allow、写 allow、写 deny)被忽略。必拒列表也会被跳过。凭证 ENV 限制仍然生效(env 变量被取消设置或填入 sentinel)。凭证 FILE 限制随其他 fs 规则一起被丢弃。用户需要为替代 srt 的文件系统控制的另一个安全层负责。

该设置在全局配置中为 **会话级别**,也可通过 `wrapWithSandbox(customConfig)` 中的 `customConfig.filesystem.disabled` 覆盖。按调用 `disabled` 默认 `false`,*除非该键被省略*,此时采用会话值。
