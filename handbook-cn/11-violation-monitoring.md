# 11 — 违规监控

当沙箱进程尝试被拒的操作时,系统在 *内核侧* 强制该拒绝。但嵌入方(例如 `claude-code`)需要看到这些拒绝,以提示用户权限或解释原因。本文档介绍违规可观测性路径。

## 11.1 目标

沙箱违规是以下信息:
- 特定的命令(子进程的可执行 + args)尝试了
- 特定操作(open、write、connect)
- 针对特定资源(路径或网络主机:port)
- 且被拒绝。

嵌入方想要这些信息以:
- 显示 "此命令尝试 X 已被阻止" 消息。
- 弹一个权限对话框("是否允许下次运行?").
- 审计记录所有拒绝。

## 11.2 macOS —— 系统日志监控

### 事件保存位置

macOS `sandbox-exec` 违规写入统一日志的 `com.apple.sandbox` 子系统。每个条目携带 XPC-typed payload 和文本消息,包含触发规则(例如 `(with message "CMD64_…")` 注释)。

### 订阅

```ts
function startMacOSSandboxLogMonitor(
  onViolation: (v: SandboxViolationEvent) => void,
  ignoreViolations?: IgnoreViolationsConfig
): () => void {
  const stream = execFile('log', ['stream', '--predicate', 'subsystem == "com.apple.sandbox"', '--style', 'syslog']);
  // 逐行解析;按 logTag 过滤;产出 SandboxViolationEvent
}
```

(由于 Node 20 在 Darwin 上添加了 `os.unstable.log`,实现打算迁移到该表面;目前通过 `/usr/bin/log` 子进程化。)

### 过滤逻辑

每个生成的 profile 都携带一个唯一的 `<logTag>`,形式为 `CMD64_<base64(command)>_END_<session-random>_SBX`。监控器在 `Set<string>` 中保留当前活跃的 logTags;它解析每个传入的日志行,并丢弃消息不含这些 tag 的事件。这避免被同一机器上其他应用的沙箱事件淹没。

### 映射回命令

`onViolation` 收到:

```ts
type SandboxViolationEvent = {
  line: string,                 // 原始日志行文本
  command?: string,             // 解码后的命令(若我们匹配到已知 logTag)
  encodedCommand?: string,      // base64 编码命令(若我们知晓)
  timestamp: Date,
}
```

编码命令是保存在 logTag 中的 base64 形式;解码后的就是用户传给 `srt` 的命令。

### Ignore-violations 过滤

```json
{
  "ignoreViolations": {
    "*": ["/usr/bin", "/System"],
    "git push": ["/usr/bin/nc"]
  }
}
```

`ignoreViolations[*]` 是全局 deny 列表:任何试图访问这些路径的命令直接从违规流中丢弃而不呈现。按命令的条目按正则匹配。

## 11.3 Linux —— SECCOMP_RET_USER_NOTIF 监控

这比 `strace` 式检测优雅得多。

### 架构

```
Host                                                  Worker (inside bwrap)
────                                                  ──────────────────
apply-seccomp (outer stub)
    │
    │ ←───(socketpair; outer holds one end)──────────────────────────┐
    │                                                               │
    │      ┌─────────────────────┐                                  │
    │      │ apply-seccomp       │                                  │
    │      │   main() (worker)   │  install_user_notif_filter()     │
    │      │                     │                                  │
    │      │                     │ ← PR_SET_NO_NEW_PRIVS 完成       │
    │      │                     │ ← unix-block-bpf 已应用          │
    │      │                     │ → 通过 sp 发送 fd 给外 stub      │
    │      │                     │                                   │  用户命令运行
    │      │                     │                                   │  ───────────
    │      │                     │                                   │
    │      │  supervise(child,   │ ←── 在写意图 syscall 上 trap     │
    │      │   notify_fd,        │                                   │
    │      │   out_sock, …)      │                                   │
    │      └─────────────────────┘                                  │
    │         │ poll(notify_fd) → SECCOMP_IOCTL_NOTIF_RECV           │
    │         │ read_remote_cstr(workload_pid, path_arg, …)          │
    │         │ SECCOMP_IOCTL_NOTIF_SEND {flags: CONTINUE}           │
    │         │ emit out_sock 上的 JSON 行                           │
    │                                                               │
    ▼                                                               │
linux-violation-monitor.ts (Node)                                  
    net.createServer('/tmp/srt-observe.sock')                       
    on 'connection': readline → JSON.parse                          │
                       SandboxViolationStore.addViolation(…) ◀──────┘
```

### 为何 SECCOMP_RET_USER_NOTIF

这是观察 *每次* 尝试而不扰乱它的唯一内核认可方式。`strace` 增加巨大开销且本身是沙箱逃逸(ptrace attach)。具有 `SECCOMP_RET_LOG` 的 BPF 仅记录到 dmesg 且会使内核缓冲区溢出。USER_NOTIF 是合适的原语。

### 观察的内容

`observe_calls[]` 是列表:

```c
{ __NR_openat,    "openat",    …  },
{ __NR_openat2,   "openat2",   …  },
{ __NR_unlinkat,  "unlinkat",  …  },
{ __NR_mkdirat,   "mkdirat",   …  },
{ __NR_mknodat,   "mknodat",   …  },
{ __NR_symlinkat, "symlinkat", …  },
{ __NR_linkat,    "linkat",    …  },
{ __NR_renameat,  "renameat",  …  },
{ __NR_renameat2, "renameat2", …  },
{ __NR_fchmodat,  "fchmodat",  …  },
{ __NR_fchmodat2, "fchmodat2", …  },
{ __NR_fchownat,  "fchownat",  …  },
{ __NR_utimensat, "utimensat", …  },
#ifdef __x86_64__
{ __NR_open,      "open",      …  },
{ __NR_creat,     "creat",     …  },
{ __NR_unlink,    "unlink",    …  },
{ __NR_rmdir,     "rmdir",     …  },
… (仅 x86_64 上的遗留入口点)
#endif
```

### 过滤形状

BPF 在 *写意图* 上门控 trap:对于 `openat` 等,当 `args[flags] & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)` 非零时进行 trap。
这样,`cat /etc/passwd`(被 deny 的读)不生成 USER_NOTIF——内核已在 bwrap 的 bind-mount 层拒绝;`echo > /etc/passwd`(也被 deny,但为写) **会** 生成,因为 bwrap 层直到 syscall 实际尝试时才发声。

supervisor *总是* 以 `SECCOMP_USER_NOTIF_FLAG_CONTINUE` 回复 —— **永不** 拒绝该 syscall。内核级拒绝已经发生(bwrap 的 mount 命名空间阻止了访问)。supervisor 的工作只是记录尝试并让它自然失败。

### Emit JSON 形状

```json
{
  "nr": 257,
  "syscall": "openat",
  "pid": 42,
  "path": "/etc/passwd",
  "encodedCommand": "Y3VybCBleGFtcGxlLmNvbQ"
}
```

`encodedCommand` 通过单独 JSON 头行设置:在连接建立后,`{"encodedCommand":"Y3VybCBleGFtcGxlLmNvbQ"}` 被发送到 observe socket,这样每个事件行都有可用的编码命令。

### 路径解析

对于绝对路径(例如 `/etc/passwd`):直接复制到事件。

对于相对路径(例如 cwd 或 dirfd 中的 `foo.txt`):

```
host_proc_fd = open("/proc", O_PATH | O_DIRECTORY | O_CLOEXEC)   // 在 unsharing 之前固定

// 在 supervisor 内:
snprintf(link, 64, "%d/cwd", req->pid)
// 或:
snprintf(link, 64, "%d/fd/%d", req->pid, dirfd)

readlinkat(host_proc_fd, link, dst, dstcap)
memcpy(dst + blen + 1, relPath, relPathLen)
```

失败路径产生 `path` = "";node 端丢弃该行。

### 重要说明

- 工作负载的内存是 **攻击者控制的**。`process_vm_readv` 返回 worker 选择放在那里的任何内容。路径字符串被读入一个小固定缓冲区(`OBS_PATH_MAX = 4096`)。
- 竞争的兄弟线程可以在 trap 与 read 之间 `unlink()` 路径 —— `path` 可能过时。我们接受这点:它是诊断通道,不是强制通道。
- `kernel.yama.ptrace_scope=0` 允许被 ptrace 的进程彼此查看。user-notif 范围 `PR_SET_DUMPABLE=0` 在 inner init 上 + 嵌套 PID 命名空间缓解这个问题。

### Node.js 端:`linux-violation-monitor.ts`

C 端(`apply-seccomp`)负责拦截 syscall 并通过 socket 发 JSON 事件;**Node.js 端负责接收并判定哪些算"违规"**。这一半逻辑完全在 TypeScript 里,保持灵活性。

#### 11.3.1 入口与配置

```ts
export function startLinuxSandboxViolationMonitor(
  callback: SandboxViolationCallback,
  opts: LinuxViolationMonitorOptions,
): LinuxViolationMonitor
```

**关键参数**:
- `callback`: 收到违规事件时的回调(实际是 `violationStore.addViolation`)
- `allowWritePaths`: 用户配置的允许写路径(用于过滤"合法写")
- `denyWritePaths`: 用户配置的禁止写路径(过滤"白名单里的禁区")
- `ignoreViolations`: 噪声过滤规则

#### 11.3.2 Socket 路径生成

```ts
const sockDir = mkdtempSync(join(tmpdir(), 'srt-obs-'))
const sockPath = join(sockDir, `s${randomBytes(4).toString('hex')}.sock`)
```

**3 个设计要点**:

1. **`mkdtemp` + 随机名**:避免命名冲突,支持多 sandbox 并发
2. **临时目录**:每次启动创建,清理时 `rmSync` 删掉
3. **`randomBytes`**:16 位随机后缀,防猜测

#### 11.3.3 违规判定逻辑(核心算法)

```ts
const isDenied = (p: string): boolean => {
  const norm = posix.normalize(p)         // 规范化:消除 ./ 和 ../

  // 规则 1: 在 denyWrite 路径下 → 违规
  if (denyWritePaths.some(d => underPrefix(norm, d))) return true

  // 规则 2: 不在任何一个 allowWrite 路径下 → 违规
  return !allowWritePaths.some(a => underPrefix(norm, a))
}
```

**逻辑翻译**:

> 给定路径 `p`:
> 1. 先规范化(消除 `.` 和 `..`)
> 2. 在 denyWrite 黑名单下 → **违规**(如 `~/.ssh` 即使在 allowWrite 里也违规)
> 3. 不在 allowWrite 白名单下 → **违规**(如 `~/.aws`)
> 4. 否则 → **合法**(在白名单内)

**这是 bwrap mount 表的"镜像判定"**:

| bwrap 行为 | violation-monitor 判定 |
|-----------|----------------------|
| `--ro-bind / /` | 不在 allowWrite 的拒绝 |
| `--bind /allow /allow` | 在 allowWrite 的允许 |
| `--tmpfs ~/.ssh` (在 allowWrite 内) | 在 denyWrite 的拒绝 |

#### 11.3.4 噪声过滤(ignoreViolations)

```ts
const shouldIgnore = (path: string, command: string | undefined): boolean => {
  if (wildcardPaths.some(w => path.includes(w))) return true
  if (command) {
    for (const [pattern, paths] of commandPatterns) {
      if (command.includes(pattern) && paths.some(w => path.includes(w))) {
        return true
      }
    }
  }
  return false
}
```

**两种忽略规则**:

1. **通配符模式** `ignoreViolations['*']`:所有命令里这些路径都忽略
2. **按命令模式**:某个命令(如 `npm install`)里出现的某些路径(如 `node_modules`)忽略

**为什么需要?** 真实场景会有大量"已知无害"的违规:
- `npm install` 写 `node_modules/`(用户的 `allowWrite: ["."]` 没明确包含它)
- `git` 写 `.git/objects/`
- 各种工具的 cache 目录

不忽略的话,违规事件会被噪音淹没。

#### 11.3.5 事件处理管线

```ts
const handleEvent = (ev, encodedCommand) => {
  // 1. 过滤 BPF filter 没装上的错误
  if (ev.observe_init_error) { log...; return }

  // 2. 过滤没有路径的事件
  if (typeof ev.path !== 'string') return

  // 3. 只能分类绝对路径
  if (!ev.path.startsWith('/')) return

  // 4. 不违规就不上报(只关心被拒绝的操作)
  if (!isDenied(ev.path)) return

  // 5. 解码命令(从 base64)
  let command = encodedCommand ? decodeSandboxedCommand(encodedCommand) : undefined

  // 6. 噪声过滤
  if (shouldIgnore(ev.path, command)) return

  // 7. 上报
  callback({
    line: `deny ${ev.syscall ?? 'syscall'} ${ev.path}`,
    command, encodedCommand,
    timestamp: new Date(),
  })
}
```

**事件流**:

```
JSON 事件进来
   ↓ 解析
过滤 1: BPF 装失败(系统层错误)
   ↓
过滤 2: 没有 path 字段
   ↓
过滤 3: 非绝对路径(无法分类)
   ↓
过滤 4: 不违规(合法写)  ← 这是宿主"镜像 bwrap"的核心
   ↓
过滤 5: 噪声(ignore 规则)
   ↓
构造 violation 事件
   ↓
callback → violationStore.addViolation
```

#### 11.3.6 Socket 服务实现

```ts
const server: Server = createServer(conn => {
  let encodedCommand: string | undefined
  const rl = createInterface({ input: conn })   // 按行读 JSON
  rl.on('line', raw => {
    let ev: ObserveEvent
    try { ev = JSON.parse(raw) } catch { return }
    if (ev.encodedCommand && encodedCommand === undefined) {
      encodedCommand = ev.encodedCommand    // 第一行是命令 header
    }
    handleEvent(ev, encodedCommand ?? ev.encodedCommand)
  })
  conn.on('error', () => rl.close())
  conn.on('close', () => rl.close())
})
```

**几个关键设计**:

1. **`readline` 按行解析**:JSON Lines 格式,简单可靠
2. **第一行是 header**:带 `encodedCommand`(命令的 base64)
3. **错误容忍**:`JSON.parse` 失败不崩,只丢掉这一行
4. **连接关闭自动清理**:`rl.close()` 释放资源

#### 11.3.7 Graceful Degradation

```ts
server.on('error', err => {
  // listen 失败 → 优雅降级
  observeSocketPath = undefined
  resolveReady()
})
server.listen(sockPath, () => resolveReady())

const stop = (): void => {
  for (const s of sockets) s.destroy()
  server.close()
  try { rmSync(sockDir, { recursive: true, force: true }) } catch { /* best effort */ }
}
```

**重要**:如果 socket 创建失败 → `observeSocketPath = undefined` → 上层跳过违规监控功能,**沙箱本身照常工作**。

**这意味着 violation monitor 是"可选增强",不是关键路径**。即使它完全失败,安全保证(bwrap 自身)依然有效。

#### 11.3.8 为什么用文件系统 socket 而不是抽象 socket?

```ts
// 文件系统 socket (sun_path)
/tmp/srt-obs-xxxxx/random.sock

// 抽象 socket (vsock / abstract ns)
// @/srt-obs-xxxxx
```

**3 个原因**:

1. **`--unshare-net`** 隔离网络命名空间 → 抽象 socket(基于网络 ns)失效
2. **bwrap 关闭继承的 fd** → 抽象 socket 也走不通
3. **文件系统 socket** 通过 `--bind` 穿透 mount 命名空间 → 唯一可行方案

#### 11.3.9 为什么"合法写也上报,宿主再过滤"?

```ts
// apply-seccomp 上报所有写意图
// 宿主 isDenied() 判定后才算 violation
```

**为什么不直接在 apply-seccomp 里过滤?**

| 维度 | apply-seccomp 内过滤 | 宿主过滤 |
|------|---------------------|---------|
| **逻辑复杂度** | C 代码里写路径匹配 | Node.js 灵活 |
| **配置更新** | 需要重新编译 ELF | 直接读配置文件 |
| **ignore 规则** | 难表达(正则/glob) | JS 字符串操作 |
| **跨平台一致性** | Linux 单独实现 | 跟 macOS 同一套逻辑 |

**结论**:**只把决策逻辑放在宿主的 Node.js 里**,保持 C 代码的纯粹。

#### 11.3.10 反复强调的安全警告

```ts
// bwrap's mount table is the only enforcement boundary;
// the violation events emitted here are DIAGNOSTIC HINTS and
// must never gate a policy decision.
```

**翻译**:

> bwrap 的 mount 表才是**唯一**的强制边界。这些违规事件只是**诊断提示**,**绝不能**用来做策略决策。

**为什么?**

- 路径是攻击者控制的(从进程内存读)
- 可能有竞态(读路径时文件已被删)
- 事件可能被丢失(socket 满/进程被杀)

**含义**:即使 violation-monitor 报告"未违规",也**不能信任**这个报告。**唯一可信的是 bwrap 本身**。

#### 11.3.11 完整数据流

```
  ┌──────────────────────────────────────────────────────────┐
  │ 沙箱内 worker 进程(如 bash)                              │
  │   试图 write("/etc/passwd", ...)                         │
  └────────────────────────┬─────────────────────────────────┘
                           │ syscall: openat(O_WRONLY)
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │ Linux Kernel (BPF filter)                                │
  │   检测到 SECCOMP_RET_USER_NOTIF 标记的 syscall            │
  │   暂停 worker,通知 apply-seccomp supervisor              │
  └────────────────────────┬─────────────────────────────────┘
                           │ notification fd
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │ apply-seccomp supervisor (用户态)                        │
  │   1. 读 worker 内存: path = "/etc/passwd"                │
  │   2. 决定: 不在 allowWrite → 拒绝 → SECCOMP_RET_KILL    │
  │   3. 写事件到 socket: {"syscall":"openat",               │
  │                        "path":"/etc/passwd"}              │
  └────────────────────────┬─────────────────────────────────┘
                           │ Unix socket JSON
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │ 宿主 linux-violation-monitor (Node.js)                   │
  │   1. readline 解析 JSON                                  │
  │   2. isDenied("/etc/passwd") → true (不在白名单)         │
  │   3. shouldIgnore → false                                │
  │   4. callback(violation)                                 │
  └────────────────────────┬─────────────────────────────────┘
                           │ in-memory call
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │ SandboxViolationStore                                    │
  │   violations.push(event) → notifyListeners()             │
  └────────────────────────┬─────────────────────────────────┘
                           │ subscriber callback
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │ 宿主 UI / Claude Code / 日志系统                         │
  │   "User tried to write /etc/passwd" → 显示给用户          │
  └──────────────────────────────────────────────────────────┘
```

#### 11.3.12 与 macOS 实现的对比

| 维度 | macOS (Seatbelt) | Linux (USER_NOTIF) |
|------|-----------------|-------------------|
| **机制** | 系统原生 `log stream` | 内核 BPF + 用户态 supervise |
| **报告内容** | **只报被拒绝的**(denials) | **报所有写意图**(attempts) |
| **判定逻辑** | 内核做 | **宿主做**(mirror bwrap) |
| **实现复杂度** | 简单(读 log) | 复杂(USER_NOTIF 难调) |
| **可靠性** | 高(内核保证) | 中(可能有事件丢失) |

**Linux 实现更复杂的原因**:Seatbelt 自带 `log stream` 这个神器,Linux 没有等价物。USER_NOTIF 是 Linux 5.0 引入的"近亲"机制,但**需要用户态 supervise loop**,所以 sandbox-runtime 自己实现了 `apply-seccomp` 这个静态二进制。

## 11.4 Windows —— 暂无违规监控(v1)

`FWPM_LAYER_ALE_AUTH_CONNECT` 不携带 callout 驱动钩子(为此需要内核驱动)。被阻的连接仅返回 `WSAECONNABORTED`;载体侧应用看到连接错误。

对于文件系统违规,NTFS 从用户模式没有类似的每操作通知 API(FileSystemWatcher 尽力而为,且错过 EACCES)。

这是已知限制;README 在 "Known limitations" 下将其提及为未来工作。

## 11.5 `SandboxViolationStore`(进程内)

```ts
class SandboxViolationStore {
    violations = new Map<string /* b64(command) */, SandboxViolationEvent[]>()
    addViolation(v: SandboxViolationEvent) { … }
    getViolationsForCommand(command: string): SandboxViolationEvent[] { … }
    clear(): void
}
```

cli-and-programmatic-api 消费者使用此将违规回显给用户。注意它是 *每进程* —— 多宿主场景(两个 srt CLI 同时运行)各持有自己的存储。

## 11.6 `annotateStderrWithSandboxFailures(command, stderr)`

当编排器捕获子进程的 stderr 要展示给用户时,它可以追加:

```
<sandbox_violations>
[time] [operation/path/host blocked]
</sandbox_violations>
```

通过 `SandboxManager.annotateStderrWithSandboxFailures(...)` 启用;这是嵌入方可在用户可见错误输出中包含违规的方式,无需查询存储。

## 11.7 跨平台 Ignore-violations 语义

`ignoreViolations: { "*": [...], "<command regex>": [...] }`:

- `*` 是 glob(匹配任何内容;默认拒绝此项)。
- 每个条目是 `path`(mac、Linux)或 `host:port`(网络)的列表。对于网络 deny,按 host 或 host:port 匹配。

实现:按平台预过滤。

- macOS:在监控器层应用。不匹配的资源日志行被丢弃。
- Linux:在 supervisor 中应用。不匹配的 JSON 行被丢弃。
- Windows:不适用(无监控)。

## 11.8 关闭可观测性

`SandboxManager.initialize(config, askCb, /*enableLogMonitor=*/false)` 完全跳过监控器。这是默认。不需要违规流的嵌入方不会付出订阅开销。
