# 20 — sandbox-runtime vs sbx-daemon 功能规格对比与待实现项

> 本文档对比 **Anthropic sandbox-runtime**(`/home/bianbu/aiws/tech-analysis/sandbox-runtime`)和 **sbx-daemon**(`/home/bianbu/aiws/sbx-daemon`)两个沙箱项目,梳理:
>
> 1. **功能规格对比表**:从维度、平台、特性、生态等 8 个角度对比
> 2. **搁置实现项详述**:双方各自"未实现"的功能,以及如何在另一个项目里补齐

---

## 一、项目定位对比

| 维度 | sandbox-runtime (srt) | sbx-daemon |
|------|----------------------|------------|
| **出品方** | Anthropic(为 Claude Code 开发) | 内部 Bianbu RISC-V 项目 |
| **目标场景** | Agent 命令执行 + MCP 服务器隔离 | 单进程 daemon,持久化 agent |
| **架构形态** | 库 + CLI(wraps 任意进程) | 长驻守护进程(管理多个 agent) |
| **实现语言** | TypeScript (~11,400 LOC) | Rust (~1,500 LOC) |
| **目标平台** | macOS / Linux / Windows(全平台) | Linux only(Bianbu 4.0.1, RISC-V) |
| **隔离原语** | bwrap + Seatbelt + WFP(按平台) | bwrap + libseccomp + cgroup v2 |
| **测试基线** | 100+ 测试 | 28 测试(18 unit + 10 integration) |
| **成熟度** | Beta Research Preview(开源) | v0.1.0(已完成 8/9 编号需求) |
| **许可证** | 内部 + 开源 | MIT |

---

## 二、核心功能规格对比表

### 2.1 文件系统隔离

| 子能力 | sandbox-runtime | sbx-daemon |
|--------|-----------------|------------|
| **底层机制** | bwrap `--ro-bind`/`--bind`/`--tmpfs` | bwrap `--ro-bind`/`--bind`/`--tmpfs` |
| **读模式** | deny-only(默认全可读) | allow-list 模式(`read_only` 白名单) |
| **写模式** | allow-only(默认全禁写) | allow-list 模式(`bind.writable=true` 白名单) |
| **强制屏蔽路径** | ✅ 22+ 类敏感路径(`~/.ssh`、`~/.aws` 等) | ❌ 无显式强制屏蔽(靠白名单兜底) |
| **危险目录扫描** | ✅ ripgrep 扫描 + 强制 deny | ❌ 无 |
| **符号链接攻击防护** | ✅ 检测符号链接指向白名单外 | ❌ 无显式防护 |
| **凭据文件 sentinel** | ✅ `maskedFileBinds`(假文件覆盖真文件) | ❌ 无 |
| **DENY 模式** | deny-then-allow(嵌套) | 仅顶层 allow-list |

### 2.2 网络隔离

| 子能力 | sandbox-runtime | sbx-daemon |
|--------|-----------------|------------|
| **底层机制** | bwrap `--unshare-net` + HTTP/SOCKS 代理 | bwrap `--unshare-net` 直接断网 |
| **代理层** | ✅ HTTP + SOCKS5 + Mux(multiplex) | ❌ 无 |
| **域名白名单** | ✅ 精确匹配(`allowedDomains`) | ⚠️ TODO(SBX-03,只有 deny 模式) |
| **域名黑名单** | ✅ `deniedDomains` | ❌ 无 |
| **TLS 中止 + MITM** | ✅ mitm-ca 签发 + mitm-leaf 拦截 | ❌ 无 |
| **HTTP 请求过滤** | ✅ `filterRequest` 回调(逐请求 hook) | ❌ 无 |
| **SOCKS5 代理** | ✅(用于非 HTTP 流量) | ⚠️ TODO(计划用 dante-server) |
| **多平台支持** | ✅ macOS/Linux/Windows 三种实现 | ❌ Linux only |

### 2.3 系统调用过滤

| 子能力 | sandbox-runtime | sbx-daemon |
|--------|-----------------|------------|
| **机制** | 静态 ELF(apply-seccomp)USER_NOTIF | libseccomp-sys 生成 BPF, fd 注入 |
| **默认策略** | **白名单 Unix socket**(禁 socket(AF_UNIX)) | **黑名单 22 项 syscall**(reboot/swapon/kexec...) |
| **自定义扩展** | ❌ 固定白名单 | ✅ `extra_blacklist` 字段 + 多 profile |
| **过滤范围** | 仅 Unix socket | 22 项高危 syscall |
| **违规观测** | ✅ USER_NOTIF + 实时上报 | ❌ 仅 KILL,无观测 |

### 2.4 资源配额(cgroup)

| 子能力 | sandbox-runtime | sbx-daemon |
|--------|-----------------|------------|
| **CPU 配额** | ❌ 无 | ✅ `cpu_quota = "100%"` |
| **内存上限** | ❌ 无 | ✅ `memory_max = "2G"` |
| **IO 权重** | ❌ 无 | ✅ `io_weight = 100` |
| **PID 限制** | ❌ 无 | ✅ `pids_max = 256` |
| **实现方式** | — | systemd-run --scope --property=... |
| **OOM 事件捕获** | ❌ 无 | ⚠️ TODO(P2) |

### 2.5 进程/会话隔离

| 子能力 | sandbox-runtime | sbx-daemon |
|--------|-----------------|------------|
| **unshare-user** | ✅(`--unshare-user-try`) | ✅ |
| **unshare-pid** | ✅ | ✅ |
| **unshare-ipc** | ❌ 默认不隔离 | ✅ |
| **unshare-uts** | ❌ 默认不隔离 | ✅ |
| **unshare-cgroup** | ❌ | ✅(cgroup-try) |
| **unshare-net** | ✅ | ✅ |
| **die-with-parent** | ✅ | ✅ |
| **new-session** | ✅ | ✅ |
| **PID 1 化** | ❌ | ⚠️ TODO(P2) |

### 2.6 能力裁剪(Capabilities)

| 子能力 | sandbox-runtime | sbx-daemon |
|--------|-----------------|------------|
| **cap drop** | ✅ 隐式(通过 unshare-user-try) | ✅ 显式 40 项全 0(测过) |
| **CAP_SYS_ADMIN** | ⚠️ apply-seccomp 需要(重新拿回) | ⚠️ 仅用于嵌套 user+pid ns |
| **Mach-lookup 允许(macOS)** | ✅ `allowMachLookup` | N/A |

### 2.7 状态管理与持久化

| 子能力 | sandbox-runtime | sbx-daemon |
|--------|-----------------|------------|
| **状态机** | ❌ 一次性 wrap,无状态 | ✅ BUILDING/RUNNING/STOPPED/FAILED |
| **状态文件** | ❌ 无 | ✅ JSON + 原子写 |
| **进程管理** | ❌ 不管生命周期 | ✅ daemon 长期管理多 agent |
| **stop 命令** | ❌ 无 | ✅ `sbx-daemon stop <agent-id>` |
| **status 查询** | ❌ 无 | ✅ `sbx-daemon status <id>` |
| **失败不降级** | ❌ 抛错即可 | ✅ 任何失败 → FAILED 状态 |

### 2.8 审计与可观测性

| 子能力 | sandbox-runtime | sbx-daemon |
|--------|-----------------|------------|
| **审计日志** | ⚠️ `annotateStderr` 文本注入 | ✅ JSONL 结构化(`audit.rs`) |
| **违规监控** | ✅ macOS 系统日志 + Linux USER_NOTIF | ❌ 仅 KILL |
| **violation store** | ✅ `SandboxViolationStore`(内存 100 条) | ❌ 无 |
| **ignore-violations 配置** | ✅ 跨平台 | ❌ 无 |
| **结构化日志** | ⚠️ `logForDebugging` 简单文本 | ✅ tracing + JSON output |
| **指标暴露** | ❌ 无 | ❌ 无 |

### 2.9 配置与 API

| 子能力 | sandbox-runtime | sbx-daemon |
|--------|-----------------|------------|
| **配置格式** | JSON(Zod schema 校验) | TOML(serde 解析) |
| **CLI 工具** | ✅ `srt` 命令 | ✅ `sbx-daemon run/status/stop/validate` |
| **库 API** | ✅ `SandboxManager` 单例 | ✅ `sbx_daemon` lib crate |
| **运行时改配** | ✅ `updateConfig()` | ❌ 必须重启 |
| **MCP 集成** | ✅ 专门优化 | ❌ 无 |
| **凭据 sentinel** | ✅ 完整方案 | ❌ 无 |
| **Callback(ask user)** | ✅ `sandboxAskCallback` | ❌ 无 |

### 2.10 平台支持

| 子能力 | sandbox-runtime | sbx-daemon |
|--------|-----------------|------------|
| **macOS** | ✅ Seatbelt 完整实现 | ❌ |
| **Linux** | ✅ bwrap + USER_NOTIF | ✅ bwrap + libseccomp + cgroup |
| **Windows** | ✅ WFP + srt-win(Rust 20k LOC) | ❌ |
| **WSL** | ⚠️ 部分 | ❌ |

---

## 三、搁置实现项详解

### 3.1 sandbox-runtime 缺什么(相比 sbx-daemon)

#### ❌ 缺失:资源配额(cgroup)

**现状**:sandbox-runtime **完全没有 cgroup 配额**。任何 sandboxed 进程可以吃掉所有 CPU/内存。

**实现思路**(从 sbx-daemon 借鉴):

```ts
// src/sandbox/linux-sandbox-utils.ts 新增
import { spawn } from 'node:child_process'

async function wrapWithCgroupQuota(
  command: string,
  quota: { cpu?: string; memoryMax?: string; pidsMax?: number }
): Promise<string> {
  // 思路 1: 在 bwrap 外层包 systemd-run
  const systemdArgs = [
    'systemd-run', '--scope', '--user',
    ...(quota.cpu ? [`--property=CPUQuota=${quota.cpu}`] : []),
    ...(quota.memoryMax ? [`--property=MemoryMax=${quota.memoryMax}`] : []),
    ...(quota.pidsMax ? [`--property=TasksMax=${quota.pidsMax}`] : []),
  ]
  return [...systemdArgs, await wrapCommandWithSandboxLinux(params)].join(' ')
}

// 思路 2(更轻): 直接写 cgroup fs(无需 systemd)
// 需要 --with-cgroup 标志
```

**关键点**:
- 需要 systemd 用户实例(`systemd --user`)
- 或者直接写 `/sys/fs/cgroup/user.slice/...`(需 root 或授权用户)
- OOM 事件需要 `cgroup.event_control` 监听(sbxaemon 也是 TODO)

#### ❌ 缺失:PID 1 化与孤儿进程回收

**现状**:sandbox-runtime 用 `--die-with-parent`,但**子沙箱内**如果 agent fork 出孤儿进程,会逃逸。

**实现思路**:

```ts
// 1. bwrap 启动一个 PID 1 占位进程(永不 exec)
// 2. PID 1 用 prctl(PR_SET_PDEATHSIG)等待
// 3. PID 1 reaper 所有孤儿子进程
// 4. 在 PID 1 内 fork 真正的 agent

// 类似 Linux init 进程的设计
```

参考 systemd 的 PID 1 逻辑或 sbx-daemon 的 `sandbox.rs`。

#### ❌ 缺失:状态机 + 持久化

**现状**:每次命令执行都是一次性,没有"长期管理的 agent"概念。

**实现思路**(迁移自 sbx-daemon):

```ts
// src/state.ts
enum SandboxState {
  Building = 'building',
  Running = 'running',
  Stopped = 'stopped',
  Failed = 'failed'
}

class SandboxStateStore {
  private states = new Map<string, SandboxState>()
  
  setState(agentId: string, state: SandboxState) {
    // 原子写到磁盘
    fs.writeFileSync(
      `/run/srt/agents/${agentId}.json`,
      JSON.stringify({ state, pid: ..., startedAt: ... })
    )
    this.states.set(agentId, state)
  }
  
  getState(agentId: string): SandboxState | undefined { ... }
}
```

但要注意:**sandbox-runtime 是单进程库**,引入状态机需要重新设计架构(可能要拆出 daemon)。

#### ❌ 缺失:信号转发

**现状**:Claude Code 的 Agent 想发 SIGTERM 给 sandboxed 进程时,只能通过 `kill -TERM <pid>`。

**实现思路**:

```ts
// 在 spawn sandboxed 进程时,保存 PID 映射
class SandboxProcessRegistry {
  private hostPidToSandboxPid = new Map<number, number>()
  
  register(hostPid: number, sandboxPid: number) { ... }
  forwardSignal(hostPid: number, signal: string) {
    const sandboxPid = this.hostPidToSandboxPid.get(hostPid)
    if (sandboxPid) {
      process.kill(sandboxPid, signal as any)
    }
  }
}
```

但因为 sandbox 有独立的 PID namespace,**必须用外部进程做信号桥接**(USER_NOTIF supervisor 或单独的 init)。

---

### 3.2 sbx-daemon 缺什么(相比 sandbox-runtime)

#### ❌ 缺失:域名级网络白名单(SBX-03)

**现状**:只支持 `--unshare-net` 完全断网,**没有按域名过滤**。

**实现思路**(路径 A:使用 dante-server):

```bash
# 1. 安装 dante-server
sudo apt install dante-server

# 2. 写 /etc/danted.conf
# 只 allow allow_domains 解析出的 IP
internal: 127.0.0.1 port = 1080
external: eth0
clientmethod: none
socksmethod: none

# 关键:pass/ block 规则
socks pass { from: 10.0.0.0/24 to: 0.0.0.0/0 }
socks block { from: 10.0.0.0/24 to: !allowlist_ips }

# 3. sandbox 进程通过 SOCKS5 出去
sbx-daemon run --setenv http_proxy=socks5://10.0.0.1:1080 ...
```

**实现思路**(路径 B:在 Rust 内置代理,**无 root 依赖**,推荐):

```rust
// src/proxy.rs(新增模块, ~300 LOC)
pub struct Socks5Proxy {
    bind: SocketAddr,
    allowed_domains: Vec<String>,  // 用 host-list 模式
}

impl Socks5Proxy {
    pub async fn handle(&self, req: SocksRequest) -> Result<()> {
        // 1. 解析域名 → DNS query
        let addrs = tokio::net::lookup_host(req.dest).await?;
        
        // 2. 检查每个解析 IP 是否在白名单
        for addr in addrs {
            if !self.is_allowed(&addr.ip()) {
                return Err(SbxError::DomainBlocked(req.dest));
            }
        }
        
        // 3. TCP connect 到目标
        let target = TcpStream::connect(req.dest).await?;
        
        // 4. 中继流量
        // ... bidirectional copy
    }
    
    fn is_allowed(&self, ip: &IpAddr) -> bool {
        // 简化: 解析 allow_domains 的所有 IP,缓存
        // 检查 IP 在缓存中
    }
}
```

**关键步骤**:
1. 启动 sbx-daemon 时,启动本地 SOCKS5 代理
2. 解析 `allow_domains` 所有 IP,缓存
3. sandboxed 进程环境变量 `http_proxy=socks5://127.0.0.1:1080`
4. 任何出站连接经过代理 → 域名/IP 检查 → 放行/拒绝

**注意 TOCTOU**:解析时 vs 连接时的 DNS 响应可能不同。需要 **pin resolved IP**(用 `gethostbyname` 一次,后续连接固定 IP)。

#### ❌ 缺失:违规监控(violation monitoring)

**现状**:seccomp 阻止 syscall 后就 KILL,**没有观测通道**告诉用户"为什么被 kill"。

**实现思路**(迁移自 sandbox-runtime):

```rust
// src/seccomp.rs 改用 USER_NOTIF 模式
pub struct ObserverSeccomp {
    notify_fd: RawFd,
    bpf_prog: BpfProgram,
}

// supervisor 线程
pub fn supervise_syscalls(notify_fd: RawFd, callback: impl Fn(SyscallEvent)) {
    loop {
        let mut req = SeccompNotif::default();
        // SECCOMP_IOCTL_NOTIF_RECV
        ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut req);
        
        // 读取路径(process_vm_readv)
        let path = read_tracee_path(req.pid, ...);
        
        // 上报
        callback(SyscallEvent {
            syscall: req.data.nr,
            pid: req.pid,
            path,
        });
        
        // 放行或 KILL
        let resp = SeccompNotifResponse {
            flags: if is_allowed { SECCOMP_USER_NOTIF_FLAG_CONTINUE } 
                   else { ... },
        };
        ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
    }
}
```

**关键技术点**:
- USER_NOTIF 需要 kernel 5.0+
- 用 `tokio` 异步 supervision loop
- 路径从 tracee 进程内存读(`process_vm_readv`)**不可信**

#### ❌ 缺失:凭据文件屏蔽(credential masking)

**现状**:如果 sandbox 进程读 `~/.aws/credentials`,**能直接读到真凭据**。

**实现思路**(迁移自 sandbox-runtime):

```rust
// src/credential.rs(新增)
pub struct CredentialMask {
    real_path: PathBuf,
    fake_path: PathBuf,  // 包含 sentinel 文本
}

impl CredentialMask {
    pub fn bind_args(&self, bwrap_args: &mut Vec<String>) {
        // --ro-bind fake_path real_path
        // 即:把 fake_path(只读)覆盖到 real_path 上
        bwrap_args.push("--ro-bind".into());
        bwrap_args.push(self.fake_path.display().to_string());
        bwrap_args.push(self.real_path.display().to_string());
    }
}

// 在 manifest.toml 中配置
[credentials]
mask_files = [
  { real = "/root/.ssh/id_rsa", fake = "/etc/sbx/sentinels/id_rsa" },
  { real = "/root/.aws/credentials", fake = "/etc/sbx/sentinels/aws-creds" },
]
```

#### ❌ 缺失:MCP 服务器集成

**现状**:sbx-daemon 是单进程 daemon,没有 MCP 这种"用 sandbox 包 MCP server"的快捷路径。

**实现思路**(参考 sandbox-runtime README 的 MCP 示例):

```toml
# mcp-filesystem-server.toml
[agent]
id = "mcp-filesystem"
binary = "/usr/bin/npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/home/agent"]

[fs]
read_only = ["/usr", "/etc", "/lib"]
tmpfs = ["/tmp"]
bind = [
  { src = "/home/agent", dst = "/home/agent", writable = true }
]

[network]
mode = "deny"  # MCP filesystem server 不需要网络
```

**结合 MCP 客户端**:Claude Code 的 `.mcp.json` 里:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "sbx-daemon",
      "args": ["run", "manifests/mcp-filesystem-server.toml"]
    }
  }
}
```

---

### 3.3 双方都缺的(生态级)

| 缺失能力 | 影响 | 借鉴方向 |
|---------|------|---------|
| **可视化 Web UI** | 无法直观看到 sandbox 状态 | sandbox-runtime 有部分 CLI,但缺 GUI |
| **远程审计聚合** | 多机部署时,审计分散 | 都需要 syslog/Loki 后端 |
| **多租户编排** | sbx-daemon 单租户,srt 也单进程 | Kubernetes Operator? |
| **Workspace 快照** | Agent 状态无法保存/恢复 | CRIU + bwrap 不兼容,需重新设计 |
| **跨平台统一工具** | 各自一套 CLI | sandbox-runtime 已经做了 |
| **网络请求内容审计** | 只到域名级,不解密 HTTPS | sandbox-runtime 有 MITM,sbx-daemon 无 |
| **凭据注入 API** | 外部 secret manager 集成 | Vault / sealed-secrets |

---

## 四、迁移路径建议

### 4.1 如果要让 sbx-daemon 达到 sandbox-runtime 水平

**优先级 P0(核心安全)**:
1. **SBX-03 SOCKS5 代理**(已规划,需 ~300 LOC Rust)
2. **凭据 sentinel masking**(从 srt 借鉴 ~150 LOC)
3. **违规观测 USER_NOTIF**(从 srt 借鉴 ~200 LOC)

**优先级 P1(生态)**:
4. **MCP 集成文档 + 示例 manifest**
5. **跨平台抽象层**(至少 macOS 基础支持)

**优先级 P2(优化)**:
6. **信号转发 + PID 1 化**
7. **TOML schema 校验升级**(用 schemars)

### 4.2 如果要让 sandbox-runtime 达到 sbx-daemon 水平

**优先级 P0(功能完整)**:
1. **cgroup 配额层**(systemd-run 或 cgroupfs 直写,~200 LOC)
2. **可选 seccomp 黑名单 profile**(扩展 apply-seccomp)

**优先级 P1(架构)**:
3. **可选 daemon 模式**(srt 作为长期守护进程)
4. **状态持久化 + status/stop 子命令**

**优先级 P2(观测)**:
5. **结构化 JSONL 审计日志**(替代文本)
6. **PID 1 化 + 信号转发**

---

## 五、一句话总结

> **sandbox-runtime 是"通用 Agent 沙箱库"**(生态丰富、跨平台、专注执行),**sbx-daemon 是"嵌入式 Agent 守护进程"**(性能极致、资源配额、结构精简)。
>
> 两者**互补性 > 竞争性**:
> - **srt 借鉴**:sbx 的 cgroup 配额、状态机、PID 1 化
> - **sbx 借鉴**:srt 的代理层网络白名单、USER_NOTIF 观测、凭据 sentinel
>
> 长期看,**两份代码可以共享一个核心规范**(都基于 bwrap),通过不同的"框架层"适配不同场景——这是 `handbook-cn/19-architecture-alternatives-srt-vs-sal.md` 提到的 SAL 架构的实际落地形式。