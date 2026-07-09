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
