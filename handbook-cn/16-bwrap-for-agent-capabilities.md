# 16 — Linux bwrap 与 Agent 能力总览

> 本文档定位：**端到端入门/串讲**。从高层视角说明 `sandbox-runtime` 在 Linux 下如何驱动 `bubblewrap`(`bwrap`),以及这些机制最终为 Agent 提供了什么能力。
>
> 与 `06-filesystem-isolation-linux.md`(逐参数详解)互补:本文档重在**全局视图**与**Agent 价值**,06 文档重在**参数级精度**。

---

## 一、项目定位

`anthropic-experimental/sandbox-runtime`(内部代号 `srt`)是 **Anthropic 为 Claude Code 开发并开源的沙箱运行时**,目标是为 Agent 控制的进程提供**默认安全**的执行环境。

README 第 5 行明确点出使用场景:

> `srt` uses native OS sandboxing primitives (`sandbox-exec` on macOS, `bubblewrap` on Linux) and proxy-based network filtering. **It can be used to sandbox the behaviour of agents, local MCP servers, bash commands and arbitrary processes.**

**核心抽象**:`srt` 不是 Agent 本身,而是 Agent **执行命令时的"保险箱"**。它不关心 Agent 在想什么,只关心 Agent **跑出来的进程能做什么、不能做什么**。

---

## 二、Linux 子系统的全景图

### 2.1 各组件职责

| 组件 | 文件 | 职责 |
|------|------|------|
| `bubblewrap` (`bwrap`) | 系统二进制 | 提供命名空间隔离 + bind mount + 进程隔离 |
| `apply-seccomp` | `vendor/`(项目内置静态 ELF) | 在 bwrap 内再做 BPF 过滤 + USER_NOTIF 观测 |
| `socat` | 系统二进制 | 把宿主代理的 Unix socket 桥接到沙箱内 localhost 端口 |
| HTTP/SOCKS 代理 | `src/sandbox/{http,socks,mux}-proxy.ts` | 域名白/黑名单 + 请求过滤 + 审计 |
| MITM CA | `src/sandbox/mitm-ca.ts` | TLS 解密,实现 HTTPS 请求的内容级过滤 |
| `linux-violation-monitor` | `src/sandbox/linux-violation-monitor.ts` | 通过 USER_NOTIF socket 接收违规事件 |
| `SandboxManager` | `src/sandbox/sandbox-manager.ts` | 跨平台统一入口,协调所有子系统 |
| `linux-sandbox-utils` | `src/sandbox/linux-sandbox-utils.ts` | **核心:bwrap 命令组装器** |

### 2.2 数据流

```
┌──────────────────────────────────────────────────────────┐
│  Agent / Claude Code / MCP Server / 用户 bash 命令       │
└────────────────────────┬─────────────────────────────────┘
                         │  "我要执行 curl https://api.github.com"
                         ▼
┌──────────────────────────────────────────────────────────┐
│  SandboxManager.wrapWithSandboxArgv()                    │
│  (Node.js 宿主进程,跑在沙箱外)                           │
│                                                          │
│  • 读取配置(网络/文件系统/凭据)                         │
│  • 调用 wrapCommandWithSandboxLinux()                   │
│  • 返回 { argv, env } 给 spawn()                        │
└────────────────────────┬─────────────────────────────────┘
                         │  argv = [bwrapPath, ...bwrapArgs, shell, '-c', cmd]
                         ▼
┌──────────────────────────────────────────────────────────┐
│  spawn(argv[0], argv.slice(1), { shell: false, env })   │
│  → 真实启动一个被沙箱化的子进程                          │
└────────────────────────┬─────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────┐
│  /usr/bin/bwrap --new-session ... -- /bin/bash -c "..."  │
│  (被沙箱化的进程,所有限制在此生效)                       │
└────────────────────────┬─────────────────────────────────┘
                         │
                         │  (违规事件通过 Unix socket 反向流出)
                         ▼
┌──────────────────────────────────────────────────────────┐
│  linux-violation-monitor → SandboxViolationStore        │
│  (宿主监听违规,供 UI / 日志展示)                        │
└──────────────────────────────────────────────────────────┘
```

---

## 三、`wrapCommandWithSandboxLinux()` 的 7 步组装流程

`src/sandbox/linux-sandbox-utils.ts:1254` 的 `wrapCommandWithSandboxLinux()` 是 bwrap 命令的**唯一组装点**。它根据入参 `LinuxSandboxParams` 动态拼装 bwrap 的命令行参数,最终通过我们熟悉的 `quote()` 函数(1529 行)转成可执行字符串。

### 步骤 1:基础标志

```ts
const bwrapArgs: string[] = ['--new-session', '--die-with-parent']
```

| 参数 | 作用 |
|------|------|
| `--new-session` | 创建新 session(脱离父进程控制组,防止 Ctrl+C 等信号影响) |
| `--die-with-parent` | 父进程退出时自动杀掉沙箱进程(防止孤儿进程残留) |

### 步骤 2:环境变量限制(可选)

```ts
if (hasEnvRestrictions) {
  for (const name of unsetEnvVars ?? []) {
    bwrapArgs.push('--unsetenv', name)         // 删除敏感变量
  }
  for (const [name, value] of Object.entries(setEnvVars ?? {})) {
    bwrapArgs.push('--setenv', name, value)    // 注入安全变量
  }
}
```

**典型场景**:Agent 运行时,自动**剥掉所有 API 凭据环境变量**(`AWS_*`、`ANTHROPIC_API_KEY`、`GITHUB_TOKEN` 等),只保留必要的代理配置。

### 步骤 3:网络限制(可选,**最强的一块**)

```ts
if (needsNetworkRestriction) {
  bwrapArgs.push('--unshare-net')   // 隔离整个网络命名空间
  bwrapArgs.push('--bind', httpSocketPath, httpSocketPath)
  if (socksSocketPath !== httpSocketPath) {
    bwrapArgs.push('--bind', socksSocketPath, socksSocketPath)
  }
  // 注入 HTTP_PROXY/HTTPS_PROXY 强制走代理
}
```

**关键设计**:

| 机制 | 作用 |
|------|------|
| `--unshare-net` | 沙箱进程**看不到宿主机的任何网络接口**(网卡全没了) |
| 绑定 Unix socket | 把宿主机的代理服务**穿透到沙箱内** |
| 强制代理环境变量 | 沙箱内任何 HTTP 请求**必须**走宿主机的代理 |
| 代理层做域名白名单 | 沙箱内访问 `github.com` 允许,访问 `evil.com` 拒绝 |

**双重保险**:
1. 没有代理 socket → 完全断网(`--unshare-net` 单独使用);
2. 有代理 socket → 所有流量走代理,代理按域名白名单过滤。

### 步骤 4:文件系统限制(最复杂的一块)

调用 `generateFilesystemArgs()`(818 行起)根据 `readConfig` 和 `writeConfig` 生成参数。

#### 4.1 写权限:allow-only 模式,默认禁止一切

```ts
if (writeConfig) {
  args.push('--ro-bind', '/', '/')   // 先把整个根目录设为只读
  for (const pathPattern of writeConfig.allowOnly || []) {
    args.push('--bind', normalizedPath, normalizedPath)  // 覆盖式 bind 为可写
  }
}
```

**用户配置示例**:
```json
"allowWrite": ["."]
```

**生成参数**:
```
--ro-bind / /
--bind /home/me/project /home/me/project
```

#### 4.2 读权限:deny-only 模式,默认全允许

通过 `pushReadDenyDirMounts()`(763 行起)对禁止路径做 tmpfs 覆盖或 `--ro-bind /dev/null` 屏蔽。

#### 4.3 危险文件强制屏蔽(mandatory denies)

**关键设计**:无论用户怎么配置,**这些文件永远读不到**:

- `~/.ssh/id_*`(SSH 私钥)
- `~/.aws/credentials`(AWS 凭据)
- `~/.npmrc`(npm 认证 token)
- `~/.docker/config.json`(Docker 认证)
- `~/.kube/config`(Kubernetes 凭据)
- `~/.netrc`、`~/.git-credentials` 等

这是 `secure-by-default` 哲学的核心:即使 Agent 试图 `cat ~/.ssh/id_rsa`,会被 `Operation not permitted` 直接拒绝。

### 步骤 5:进程隔离

```ts
bwrapArgs.push('--unshare-pid')
if (!enableWeakerNestedSandbox) {
  bwrapArgs.push('--proc', '/proc')   // 挂载全新的 /proc
}
```

**为什么重要**:不隔离 PID 时,沙箱内的进程可以看到宿主上其他进程的信息(用户名、运行的命令等),可能造成信息泄露。

### 步骤 6:可选的 seccomp 强化

```ts
if (!allowAllUnixSockets) {
  applySeccompPrefix = resolveApplySeccompPrefix(...)
  // BPF 过滤器禁止 socket(AF_UNIX, ...) 系统调用
}
```

**为什么需要这层**:
- bwrap 限制文件系统 + 网络命名空间;
- 但沙箱内进程**仍可创建 Unix socket**(IPC 方式),与宿主进程通信;
- seccomp 在**系统调用层面**直接禁止,根本不可能绕过。

**双层防护**:bwrap 看不见宿主 socket → 即使绕过了也没用,seccomp 在 syscall 层面禁死。

### 步骤 7:塞入用户命令并拼装

```ts
bwrapArgs.push('--', shell, '-c')
bwrapArgs.push(command)
const wrappedCommand = quote([bwrapPath ?? 'bwrap', ...bwrapArgs])
```

`--` 是 bwrap 的选项终止符,后面的 `shell -c command` 是被 exec 的真实命令。最终通过 `quote()` 安全拼接(详见之前对 `shell-quote.ts` 的分析)。

---

## 四、一个真实的命令示例

**用户配置**:
```json
{
  "filesystem": {
    "allowWrite": ["."],
    "denyRead": ["~/.ssh"]
  },
  "network": {
    "allowedDomains": ["api.github.com", "anthropic.com"]
  }
}
```

**执行**:`srt "curl https://api.github.com/users"`

**生成的完整 bwrap 命令**(简化展示):
```
/usr/bin/bwrap \
  --new-session --die-with-parent \
  --unsetenv AWS_ACCESS_KEY_ID --unsetenv AWS_SECRET_ACCESS_KEY \
  --unshare-net \
  --bind /tmp/srt-http.sock /tmp/srt-http.sock \
  --bind /tmp/srt-socks.sock /tmp/srt-socks.sock \
  --setenv HTTP_PROXY http://127.0.0.1:3128 \
  --setenv HTTPS_PROXY http://127.0.0.1:3128 \
  --ro-bind / / \
  --bind /home/me/project /home/me/project \
  --tmpfs /home/me/.ssh \
  --tmpfs /home/me/.aws \
  --tmpfs /home/me/.docker \
  --unshare-pid --proc /proc \
  -- /bin/bash -c "curl https://api.github.com/users"
```

**沙箱内的进程**:

- 整个文件系统只读,**只有当前项目可写**
- `~/.ssh`、`~/.aws` 被 `tmpfs` 覆盖,**根本读不到**
- 没有网卡,所有流量必须走代理
- 代理只允许 `api.github.com` 和 `anthropic.com`,其他域名被拒绝
- 看不到宿主进程
- 不能创建 Unix socket

**Agent 即使想"逃跑",也无处可逃**。

---

## 五、为 Agent 提供的 4 大核心能力

### 5.1 安全的 bash 命令执行

**场景**:Claude Code 这类 Agent 会执行用户的 bash 命令(`ls`、`cat`、`npm install` 等)。

**提供能力**:
- 自动剥离敏感环境变量(API keys)
- 阻止读取 `~/.ssh`、`~/.aws` 等敏感路径
- 限制可写范围,防止恶意代码破坏项目外文件
- 可选的完全断网模式

**用户体感**:
```bash
$ srt "cat ~/.ssh/id_rsa"
Running: cat ~/.ssh/id_rsa
cat: /home/me/.ssh/id_rsa: Operation not permitted  ← 被自动阻止
```

### 5.2 MCP 服务器沙箱化 ⭐ 重点使用场景

README 第 50-100 行专门讲了这个用例。

**没有沙箱时**(`.mcp.json`):
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"]
    }
  }
}
```
MCP 服务器在宿主上完全自由地运行——可以读任何文件、访问任何网络。

**有沙箱时**:
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "srt",                              // ← 把命令包成 srt
      "args": ["npx", "-y", "@modelcontextprotocol/server-filesystem"]
    }
  }
}
```

配上沙箱配置后,MCP 服务器被强制:
- 只能写指定目录
- 只能访问允许的域名
- 读不到系统敏感文件

**这是 Agent 生态的关键能力**——让第三方 MCP 服务器**默认安全**。

### 5.3 网络访问白名单

**场景**:Agent 需要调用外部 API(GitHub、Anthropic API 等),但不能随意访问任何网站。

**提供能力**:
- 默认禁止所有网络
- 显式允许 `allowedDomains` 列表中的域名
- 显式禁止 `deniedDomains` 列表中的域名
- HTTP 和 HTTPS 流量都通过代理层过滤

**配置示例**:
```json
{
  "network": {
    "allowedDomains": [
      "api.anthropic.com",
      "api.github.com",
      "*.npmjs.org"
    ],
    "deniedDomains": [
      "*.evil.com",
      "tracker.ad-network.com"
    ]
  }
}
```

### 5.4 违规监控(Violation Monitoring)

**场景**:当 Agent 试图做被禁止的事时(读 SSH 私钥、访问黑名单域名),记录下来告警。

**macOS**:直接接入 `sandbox-exec` 的违规日志。

**Linux**:通过 `observeSocketPath` 让 `apply-seccomp` 在 USER_NOTIF 模式下把违规事件流式发回:

```ts
bwrapArgs.push('--bind', observeSocketPath, observeSocketPath)
bwrapArgs.push('--setenv', 'SRT_OBSERVE_SOCK', observeSocketPath)
```

事件以**换行分隔的 JSON**格式流出,可以被宿主监听到。

---

## 六、对 Agent 生态的意义

### 6.1 解决的核心问题

> **Agent 时代最大的安全挑战:让 AI 控制的进程默认安全**

| 没有沙箱 | 有沙箱 |
|---------|-------|
| Agent 可以读 SSH 私钥 | 默认读不到 |
| Agent 可以装恶意 npm 包(影响全局) | 只能在项目目录写 |
| Agent 可以访问任意网站 | 只能访问白名单域名 |
| Agent 可以和宿主任意进程通信 | 默认无法 |
| Agent 可以发送主机上的任意文件 | 受写权限约束 |

### 6.2 真实使用场景(来自 README)

1. **Claude Code 自身**:官方工具,默认启用沙箱
2. **本地 MCP 服务器**:第三方工具默认隔离
3. **CI/CD 流水线**:跑不可信代码时隔离
4. **自动化脚本**:跑 Agent 生成的命令时隔离

### 6.3 与其他方案对比

| 方案 | 隔离强度 | 性能开销 | 易用性 | 适用场景 |
|------|---------|---------|--------|---------|
| **无沙箱** | 无 | 0 | 最简单 | 完全可信环境 |
| **Docker** | 强 | 中-高 | 中 | 服务部署 |
| **bwrap + srt** | 强 | **极低** | **简单** | **Agent 命令执行** |
| **gVisor / Kata** | 极强 | 高 | 复杂 | 多租户云 |

`srt` 的独特定位:**Agent 级别**的隔离——比 Docker 更轻量,比裸跑安全得多。

---

## 七、技术亮点

| 亮点 | 说明 |
|------|------|
| **多平台统一 API** | macOS/Linux/Windows 用同一个 `SandboxManager` 接口 |
| **默认安全** | 不配置 = 几乎所有危险操作都被阻止 |
| **细粒度配置** | 文件系统、网络、Unix socket、env 都能独立配置 |
| **零侵入** | 只需在命令前加 `srt`,无需修改业务代码 |
| **基于 OS 原语** | 不依赖 Docker,性能开销极小 |
| **显式 vs 隐式隔离** | 关键操作(读敏感文件)有显式路径检查,不依赖 syscall 拦截 |
| **可观测性** | 违规事件流式回传,可对接 UI / 日志 / 告警 |

---

## 八、与其他文档的关系

| 文档 | 内容 | 与本文档的关系 |
|------|------|---------------|
| `02-system-architecture.md` | 整体系统架构 | 互补:本文档聚焦 Linux + Agent |
| `04-network-isolation-design.md` | 网络隔离详细设计 | 深入:本文档只讲概述 |
| `06-filesystem-isolation-linux.md` | bwrap 参数级详解 | **深入**:本文档只讲流程 |
| `08-credential-masking.md` | 凭据屏蔽机制 | 互补:本文档一笔带过 |
| `11-violation-monitoring.md` | 违规监控设计 | 深入:本文档只提能力 |
| `13-security-model.md` | 安全模型论证 | 互补:本文档不展开威胁建模 |

---

## 九、一句话总结

> **`sandbox-runtime` 用 `bwrap` 作为底层容器工具,配合自研的代理层、seccomp 过滤器、违规监控,为 Agent 提供了一个默认安全的执行环境:文件系统只读+白名单可写、网络白名单、敏感凭据隔离、违规可观测**。
>
> **核心价值**:让 AI Agent 控制的进程**默认不可信**,但又能用最少的配置完成合法任务。这是 Agent 走向生产环境的关键基础设施。