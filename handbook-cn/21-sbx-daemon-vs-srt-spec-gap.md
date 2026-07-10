# 21 — sbx-daemon 视角：已有规格 vs 缺失规格（对比 sandbox-runtime）

> **目标读者**：sbx-daemon 维护者 / 想给 sbx-daemon 加功能的开发者。
>
> **文档定位**：从 sbx-daemon 视角出发,逐项梳理:
> 1. **sbx-daemon 已有**的规格(含来源)
> 2. **sbx-daemon 缺失**的规格(sandbox-runtime 已有,标出参考实现位置)
>
> 与 ch.20 的"双向对比"互补:本文档是**单向深度**——专门帮 sbx-daemon 决定"下一步该做什么"。

---

## 总览

| 大类 | sbx-daemon 规格数 | 与 sandbox-runtime 对齐情况 |
|------|------------------|------------------------|
| 文件系统隔离 | 已有 4 项 / 缺失 7 项 | ⚠️ **差距最大**,需重点补齐 |
| 网络隔离 | 已有 1 项 / 缺失 6 项 | ❌ 大量缺失(SBX-03 TODO) |
| 系统调用过滤 | 已有 3 项 / 缺失 4 项 | ⚠️ 基础有,观测层缺 |
| 资源配额(cgroup) | 已有 4 项 / 缺失 3 项 | ✅ 反超 sandbox-runtime |
| 命名空间隔离 | 已有 7 项 / 缺失 2 项 | ✅ 反超 sandbox-runtime |
| 能力裁剪 | 已有 1 项 / 缺失 0 项 | ✅ 基本对齐 |
| 状态管理 | 已有 5 项 / 缺失 1 项 | ✅ 反超 sandbox-runtime |
| 审计与观测 | 已有 2 项 / 缺失 4 项 | ⚠️ 部分缺失 |
| 配置与 API | 已有 4 项 / 缺失 3 项 | ⚠️ 灵活度不足 |
| 平台支持 | 已有 1 项 / 缺失 2 项 | ❌ 仅 Linux |

**总结**:sbx-daemon 在**资源配额、状态管理、命名空间**上反超 srt;但在**文件系统精细化、网络隔离、审计观测**上差距明显。

---

## 一、文件系统隔离

### 1.1 sbx-daemon **已有** 的规格

| 规格 | 来源 | 状态 | 证据 |
|------|------|------|------|
| **ro-bind 白名单读** | `src/bwrap.rs:88-92` | ✅ 完成 | `--ro-bind <path> <path>` |
| **bind 读写白名单** | `src/bwrap.rs:94-101` | ✅ 完成 | `--bind` / `--ro-bind` 由 `writable` 字段决定 |
| **tmpfs 私有挂载** | `src/bwrap.rs:94-95` | ✅ 完成 | `--tmpfs <path>` |
| **伪 proc/dev 挂载** | `src/bwrap.rs:58-59` | ✅ 完成 | `--proc /proc`、`--dev /dev` |

**Manifest 字段**(`src/manifest.rs:53-71`):
```toml
[fs]
read_only = ["/usr", "/bin", "/lib", "/etc"]
tmpfs = ["/tmp", "/home", "/var", "/run"]
bind = [
  { src = "/home/agent", dst = "/home/agent", writable = true },
]
```

**验证证据**(`tests/sbx_integration.rs`):
```
✅ sbx_01_fs_isolation_blocks_out_of_scope_read
✅ sbx_01_fs_isolation_blocks_root_path
✅ sbx_01_fs_isolation_blocks_home_bianbu
✅ sbx_01_fs_isolation_allows_declared_ro
✅ sbx_01_fs_isolation_blocks_write_to_ro
✅ sbx_01_fs_isolation_blocks_pivot_root
```

### 1.2 sbx-daemon **缺失** 的规格

| 缺失规格 | sandbox-runtime 参考 | 实现价值 |
|---------|---------------------|---------|
| ❌ **强制危险路径屏蔽** | `linux-sandbox-utils.ts:linuxGetMandatoryDenyPaths()` + ripgrep 扫描 | 防止 agent 读 `~/.ssh`、`~/.aws` 等(白名单兜不住的场景) |
| ❌ **DENY-then-ALLOW 嵌套读模式** | `FsReadRestrictionConfig.denyOnly + allowWithinDeny` | 大范围 deny 后细粒度 allow,比纯 allow-list 灵活 |
| ❌ **符号链接攻击防护** | `linux-sandbox-utils.ts:findSymlinkInPath()` | 防止恶意符号链接指向白名单外 |
| ❌ **凭据 sentinel 屏蔽** | `credential-mask-files.ts` + `MaskedFileStore` | 关键能力:让 `~/.aws/credentials` 显示成假内容 |
| ❌ **写时的 mandatory deny** | `linuxGetMandatoryDenyPaths()` 复用于写场景 | 默认禁止写入 `.git/config`、`SSH` 等,即使在 allowWrite 内 |
| ❌ **globs/模式匹配** | `expandGlobPattern()` 在 utils 中 | 用户配 `["~/.ssh/**"]` 比逐条列出友好 |
| ❌ **路径存在性预检** | `fs.existsSync` + 跳过不存在的路径 | 启动时跳过无效路径,避免运行时报错 |

### 1.3 实现建议(优先级排序)

#### P0: 强制危险路径屏蔽

**借鉴来源**:`sandbox-runtime/src/sandbox/linux-sandbox-utils.ts` 第 ~700-1000 行 `linuxGetMandatoryDenyPaths()` + 第 880 行 ripgrep 调用。

**最小实现**:
```rust
// src/manifest.rs 新增
pub const MANDATORY_DENY_PATHS: &[&str] = &[
    "/root/.ssh",
    "/root/.aws",
    "/root/.docker",
    "/root/.kube",
    "/root/.netrc",
    "/root/.git-credentials",
    "/home/*/.ssh",
    "/home/*/.aws",
    "/etc/shadow",
    "/proc/*/environ",
];

// src/bwrap.rs 新增: 即使 read_only 包含也强制 deny
pub fn mandatory_deny_args() -> Vec<String> {
    let mut args = vec![];
    for path in MANDATORY_DENY_PATHS {
        // 目录用 --tmpfs,文件用 --ro-bind /dev/null
        if path.contains('*') {
            // glob 展开(Rust 用 glob crate)
            for expanded in glob::glob(path).unwrap().flatten() {
                if expanded.is_dir() {
                    args.push("--tmpfs".into());
                } else {
                    args.push("--ro-bind".into());
                    args.push("/dev/null".into());
                    args.push(expanded.display().to_string());
                }
                args.push(expanded.display().to_string());
            }
        }
    }
    args
}
```

**注意**:`--tmpfs` 会把目录变成空 tmpfs(完全看不到内容),这是最严格的屏蔽。

#### P0: 凭据 sentinel 屏蔽

**借鉴来源**:`sandbox-runtime/src/sandbox/credential-mask-files.ts` 完整实现 + `linux-sandbox-utils.ts:maskedFileBinds` 注入。

**最小实现**:
```rust
// src/credential.rs 新增
pub struct CredentialMask {
    pub real_path: PathBuf,
    pub fake_path: PathBuf,  // 含 sentinel 文本
}

// 在 manifest 中配置
[credentials]
mask_files = [
  { real = "/root/.aws/credentials", fake = "/etc/sbx/sentinels/aws-creds" },
]

// sandbox.rs 在 spawn 前注入
for m in &manifest.credentials.mask_files {
    args.push("--ro-bind".into());
    args.push(m.fake_path.display().to_string());
    args.push(m.real_path.display().to_string());
}
```

---

## 二、网络隔离

### 2.1 sbx-daemon **已有** 的规格

| 规格 | 来源 | 状态 |
|------|------|------|
| **完全断网模式** | `src/bwrap.rs:55`(条件 `--unshare-net`) | ✅ 完成 |

**Manifest**(`src/manifest.rs:88-95`):
```toml
[network]
mode = "deny"  # deny | allow
allow_domains = []  # mode=allow 时生效,但未实现
```

### 2.2 sbx-daemon **缺失** 的规格

| 缺失规格 | sandbox-runtime 参考 | 重要性 |
|---------|---------------------|--------|
| ❌ **HTTP 代理层** | `src/sandbox/http-proxy.ts`(完整实现) | 中等 |
| ❌ **SOCKS5 代理层** | `src/sandbox/socks-proxy.ts` | 关键 |
| ❌ **域名白名单(allow_domains)** | `src/sandbox/linux-sandbox-utils.ts:network restrictions` | **关键**(SBX-03 核心) |
| ❌ **域名黑名单** | `network.deniedDomains` | 中等 |
| ❌ **Mux 多路复用代理** | `src/sandbox/mux-proxy.ts`(HTTP+SOCKS 共用 socket) | 性能优化 |
| ❌ **MITM TLS 中止** | `src/sandbox/{mitm-ca,mitm-leaf}.ts` | 高(用于 HTTPS 内容过滤) |
| ❌ **逐请求 filterRequest 回调** | `src/sandbox/request-filter.ts` | 灵活 |

### 2.3 实现建议

#### P0: 域名白名单(SBX-03)

**借鉴来源**:`sandbox-runtime/src/sandbox/linux-sandbox-utils.ts` 第 ~1382 行 + `http-proxy.ts` + `socks-proxy.ts`。

**最小实现**(纯 Rust 内置代理,无 root 依赖):

```rust
// src/proxy.rs(新增模块,~300 LOC)
pub struct Socks5Proxy {
    bind: SocketAddr,
    allowed_domains: Vec<String>,
    allowed_ips: Arc<RwLock<HashSet<IpAddr>>>,  // 缓存解析结果
}

impl Socks5Proxy {
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.bind).await?;
        loop {
            let (stream, _) = listener.accept().await?;
            let proxy = self.clone();
            tokio::spawn(async move {
                proxy.handle_client(stream).await
            });
        }
    }
    
    async fn handle_client(&self, mut stream: TcpStream) -> Result<()> {
        // 1. SOCKS5 握手
        // 2. 读取 CONNECT 请求
        let req = read_socks5_request(&mut stream).await?;
        
        // 3. 域名解析 + IP 白名单检查
        let addrs = tokio::net::lookup_host(req.dest_host.to_string() + ":" + &req.dest_port.to_string()).await?;
        let mut allowed = false;
        for addr in addrs {
            if self.allowed_ips.read().await.contains(&addr.ip()) {
                allowed = true;
                break;
            }
        }
        if !allowed {
            // 返回 SOCKS5 拒绝
            write_socks5_response(&mut stream, 0x02).await?;  // Connection refused
            return Ok(());
        }
        
        // 4. TCP connect 到目标
        let target = TcpStream::connect(req.dest_host.to_string() + ":" + &req.dest_port.to_string()).await?;
        
        // 5. 双向中继
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
        Ok(())
    }
}
```

**集成到 sandbox.rs**:
```rust
// 在 bwrap 启动前启动 SOCKS5 代理
let proxy = Socks5Proxy::new(
    "127.0.0.1:1080".parse()?,
    manifest.network.allow_domains.clone(),
);
let proxy_handle = tokio::spawn(async move { proxy.run().await });

// 注入环境变量到 bwrap
args.push("--setenv".into());
args.push("http_proxy".into());
args.push("socks5://127.0.0.1:1080".into());
args.push("--setenv".into());
args.push("https_proxy".into());
args.push("socks5://127.0.0.1:1080".into());
```

**注意 TOCTOU**:需要在连接时**重新校验**(防止 DNS rebinding)。

---

## 三、系统调用过滤

### 3.1 sbx-daemon **已有** 的规格

| 规格 | 来源 | 状态 |
|------|------|------|
| **22 项默认黑名单** | `src/seccomp.rs:42-49` | ✅ 完成 |
| **3 种 profile** | `src/seccomp.rs:51-62` | ✅ 完成(default/permissive/strict) |
| **extra_blacklist 扩展** | `src/manifest.rs:97-103` | ✅ 完成 |
| **BPF 生成 + fd 注入** | `src/seccomp.rs:80-150` | ✅ 完成(libseccomp FFI) |

**黑名单内容**(`src/seccomp.rs:42-49`):
```rust
pub const DEFAULT_BLACKLIST: &[&str] = &[
    "reboot", "swapon", "swapoff", "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module",
    "mount", "umount2", "pivot_root", "chroot", "unshare", "setns",
    "ptrace", "process_vm_readv", "process_vm_writev",
    "perf_event_open", "bpf", "userfaultfd", "acct",
];
```

### 3.2 sbx-daemon **缺失** 的规格

| 缺失规格 | sandbox-runtime 参考 | 价值 |
|---------|---------------------|------|
| ❌ **违规观测(USER_NOTIF)** | `src/sandbox/linux-violation-monitor.ts` + apply-seccomp | **关键**(看到为什么被杀) |
| ❌ **白名单 Unix socket 阻止** | apply-seccomp 默认禁 `socket(AF_UNIX)` | 中等(防内部横向) |
| ❌ **动态规则(per-tool 精细化)** | 无直接对应,但 sandbox-runtime 是单 profile | 低 |
| ❌ **ignore-violations 过滤** | `IgnoreViolationsConfig` + monitor 中过滤 | 降噪 |

### 3.3 实现建议

#### P1: USER_NOTIF 违规观测

**借鉴来源**:sandbox-runtime 的 `linux-violation-monitor.ts` + `vendor/seccomp-src/apply-seccomp.c`(~600 行 C 代码)。

**最小 Rust 实现**:
```rust
// src/seccomp.rs 添加 USER_NOTIF 模式
pub struct ObserverSeccomp {
    pub notify_fd: RawFd,
    pub bpf_prog: BpfProgram,
}

pub fn install_user_notif_filter(blacklist: &[&str]) -> Result<ObserverSeccomp> {
    use libseccomp_sys::*;
    
    let ctx = unsafe { seccomp_init(SCMP_ACT_ALLOW) };
    for name in blacklist {
        let nr = resolve_syscall(name)?;
        unsafe { seccomp_rule_add(ctx, SCMP_ACT_KILL, nr, 0) };
    }
    
    // 关键:用 SCMP_ACT_TRAP 而不是 KILL,触发 USER_NOTIF
    unsafe { seccomp_load(ctx) };
    
    Ok(ObserverSeccomp {
        notify_fd: notify_fd_of_process(),
        bpf_prog: export_bpf(ctx)?,
    })
}

// supervisor 线程(在 sandbox.rs 启动)
pub async fn supervise_syscalls(
    notify_fd: RawFd,
    audit: &AuditLog,
) -> Result<()> {
    loop {
        let mut req = SeccompNotif::default();
        let ret = unsafe { ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut req) };
        if ret < 0 { break; }
        
        // 从 tracee 进程读路径
        let path = unsafe { read_tracee_path(req.pid, ...) };
        
        // 上报
        audit.write(AuditEvent::SyscallViolation {
            syscall_nr: req.data.nr,
            path,
            pid: req.pid,
        })?;
        
        // 放行(让 bwrap 自己决定是否拒绝)
        let resp = SeccompNotifResponse {
            val: 0,
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        };
        unsafe { ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) };
    }
    Ok(())
}
```

**注意**:USER_NOTIF 需要 kernel ≥ 5.0,在 Bianbu 6.18.3 上完全支持。

---

## 四、资源配额(cgroup)

### 4.1 sbx-daemon **已有** 的规格

| 规格 | 来源 | 状态 |
|------|------|------|
| **CPU 配额** | `src/cgroup.rs` + `systemd-run --property=CPUQuota` | ✅ 完成 |
| **内存上限** | `--property=MemoryMax` | ✅ 完成 |
| **IO 权重** | `--property=IOWeight` | ✅ 完成 |
| **PID 限制** | `--property=TasksMax` | ✅ 完成 |

**Manifest**(`src/manifest.rs:73-86`):
```toml
[resource]
cpu_quota = "100%"
memory_max = "2G"
io_weight = 100
pids_max = 256
```

### 4.2 sbx-daemon **缺失** 的规格

| 缺失规格 | sandbox-runtime 参考 | 价值 |
|---------|---------------------|------|
| ❌ **OOM 事件捕获** | 无直接对应 | 中等(知道为什么被杀) |
| ❌ **运行时动态配额调整** | 无 | 低 |
| ❌ **cgroup v1 兼容** | N/A(v2 已普及) | 低 |

### 4.3 实现建议

#### P2: OOM 事件捕获

**借鉴**:systemd 可以发 cgroup notification,或直接读 `memory.events` 中的 `oom_kill` 计数。

**最小实现**:
```rust
// src/cgroup.rs 添加
pub async fn watch_oom(cgroup_path: &Path) -> Result<()> {
    let oom_file = cgroup_path.join("memory.events");
    loop {
        let content = tokio::fs::read_to_string(&oom_file).await?;
        // 解析 "oom_kill 5" 这种 KV
        for line in content.lines() {
            if line.starts_with("oom_kill ") {
                let count: u64 = line.split_whitespace().nth(1).unwrap().parse()?;
                if count > last_count {
                    audit.write(AuditEvent::OomKill { ... })?;
                    last_count = count;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
```

---

## 五、命名空间隔离

### 5.1 sbx-daemon **已有** 的规格

**Manifest**(`src/manifest.rs:106-138`):
```toml
[security]
unshare_user = true
unshare_pid = true
unshare_ipc = true
unshare_uts = true
unshare_cgroup = true
unshare_net = true
clearenv = true
die_with_parent = true
new_session = true
```

| 规格 | 来源 | 状态 |
|------|------|------|
| **7 个独立 namespace** | `src/bwrap.rs:46-56` | ✅ 完成 |
| **clearenv 清空环境** | `src/bwrap.rs:79` | ✅ 完成 |
| **die_with-parent** | `src/bwrap.rs:107` | ✅ 完成 |
| **new-session** | `src/bwrap.rs:111` | ✅ 完成 |

### 5.2 sbx-daemon **缺失** 的规格

| 缺失规格 | sandbox-runtime 参考 | 价值 |
|---------|---------------------|------|
| ❌ **PID 1 化(孤儿进程回收)** | 无 | 中等(防逃逸) |
| ❌ **可配置的 unshare 粒度** | 简单 true/false | 低 |

### 5.3 实现建议

#### P2: PID 1 化

**借鉴**:systemd 的 init 设计、Linux init 进程模式。

**最小实现**:在 `bwrap` 启动一个永不 exec 的 PID 1 占位进程,该进程:
1. 调用 `prctl(PR_SET_CHILD_SUBREAPER)` 成为 subreaper
2. 循环 `waitpid(-1)` 收割所有孤儿
3. 在 PID 1 内 fork 真正的 agent

```rust
// src/sandbox.rs 改 spawn 流程
let pid1_cmd = bwrap_with_pid1_wrapper(bwrap_args)?;
let mut child = pid1_cmd.spawn()?;

// PID 1 子进程:成为 subreaper,fork agent
unsafe {
    libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1);
    let agent_pid = libc::fork();
    if agent_pid == 0 {
        // 子:exec 真正的 agent
        libc::execvp(...);
    }
    // 父:reap 循环
    loop {
        let status = libc::waitpid(-1, ...);
        if status.pid == agent_pid { break; }
        // 记录孤儿回收
    }
}
```

---

## 六、能力裁剪(Capabilities)

### 6.1 sbx-daemon **已有** 的规格

| 规格 | 来源 | 状态 | 证据 |
|------|------|------|------|
| **40 项 cap 全 drop** | unprivileged user namespace 天然 | ✅ 完成 | `sbx_05_capabilities_dropped` 测试通过 |

**注**:这是通过 `--unshare-user` 实现的,无需额外代码。

### 6.2 sbx-daemon **缺失** 的规格

无 — sandbox-runtime 也没有显式的 cap drop。

---

## 七、状态管理

### 7.1 sbx-daemon **已有** 的规格

| 规格 | 来源 | 状态 |
|------|------|------|
| **4 态状态机** | `src/state.rs:19-26` | ✅ 完成(BUILDING/RUNNING/STOPPED/FAILED) |
| **状态文件持久化** | `src/state.rs` JSON + 原子写 | ✅ 完成 |
| **stop/status 命令** | `src/main.rs` | ✅ 完成 |
| **失败不降级(FR-SBX-07)** | `src/sandbox.rs` 多处显式检查 | ✅ 完成 |
| **审计日志** | `src/audit.rs` JSONL | ✅ 完成 |

### 7.2 sbx-daemon **缺失** 的规格

| 缺失规格 | sandbox-runtime 参考 | 价值 |
|---------|---------------------|------|
| ❌ **状态查询的 IPC 接口** | N/A(srt 是库,不是 daemon) | 低 |

无关键缺失 — sbx-daemon 在状态管理上**反超 sandbox-runtime**。

---

## 八、审计与观测

### 8.1 sbx-daemon **已有** 的规格

| 规格 | 来源 | 状态 |
|------|------|------|
| **结构化 JSONL 审计** | `src/audit.rs` | ✅ 完成 |
| **tracing 日志** | `Cargo.toml` + `src/main.rs` | ✅ 完成 |

### 8.2 sbx-daemon **缺失** 的规格

| 缺失规格 | sandbox-runtime 参考 | 价值 |
|---------|---------------------|------|
| ❌ **违规事件流(violation stream)** | `SandboxViolationStore` + `linux-violation-monitor.ts` | **关键**(见 3.3) |
| ❌ **网络请求级审计** | `request-filter.ts` 逐请求 hook | 中等 |
| ❌ **指标/Metrics 暴露** | N/A | 低 |
| ❌ **stderr 自动标注违规** | `annotateStderrWithSandboxFailures` | 中等(用户体验) |

### 8.3 实现建议

#### P1: stderr 自动标注违规

**借鉴**:`sandbox-runtime/src/sandbox/sandbox-manager.ts:annotateStderrWithSandboxFailures`。

**最小 Rust 实现**:
```rust
// src/audit.rs 添加
pub fn annotate_stderr_with_violations(
    agent_id: &str,
    stderr: &str,
    audit: &AuditLog,
) -> String {
    let violations = audit.get_violations_for_agent(agent_id);
    if violations.is_empty() {
        return stderr.to_string();
    }
    
    let mut result = stderr.to_string();
    result.push_str("\n\n<sandbox_violations>\n");
    for v in violations.iter().take(10) {
        result.push_str(&format!("[{}] {}\n", v.timestamp, v.description));
    }
    result.push_str("</sandbox_violations>\n");
    result
}
```

---

## 九、配置与 API

### 9.1 sbx-daemon **已有** 的规格

| 规格 | 来源 | 状态 |
|------|------|------|
| **TOML manifest** | `src/manifest.rs` | ✅ 完成 |
| **CLI 子命令** | `src/main.rs`(run/status/stop/validate) | ✅ 完成 |
| **库 API** | `src/lib.rs`(作为 crate) | ✅ 完成 |
| **manifest 校验** | `Manifest::validate()` | ✅ 完成 |

### 9.2 sbx-daemon **缺失** 的规格

| 缺失规格 | sandbox-runtime 参考 | 价值 |
|---------|---------------------|------|
| ❌ **运行时改配(`updateConfig`)** | `SandboxManager.updateConfig()` | 中等 |
| ❌ **schema 形式校验(JSON Schema)** | `sandbox-config.ts` 用 Zod | 中等(防止 manifest 错) |
| ❌ **Callback(运行时问用户)** | `SandboxAskCallback` | 低 |

---

## 十、平台支持

### 10.1 sbx-daemon **已有** 的规格

| 规格 | 状态 |
|------|------|
| **Linux(Bianbu 4.0.1, RISC-V)** | ✅ 主要目标 |

### 10.2 sbx-daemon **缺失** 的规格

| 缺失规格 | sandbox-runtime 参考 | 价值 |
|---------|---------------------|------|
| ❌ **macOS 支持(Seatbelt)** | `macos-sandbox-utils.ts` 完整 | 跨平台需要 |
| ❌ **x86_64 Linux 兼容** | N/A | 通用性需要 |

---

## 十一、迁移优先级总结

| 优先级 | 缺失项 | 工作量估计 | 关键参考 |
|--------|-------|-----------|---------|
| **P0-1** | 强制危险路径屏蔽 | ~80 LOC Rust | `linuxGetMandatoryDenyPaths()` |
| **P0-2** | 凭据 sentinel 屏蔽 | ~150 LOC Rust | `credential-mask-files.ts` |
| **P0-3** | 域名白名单(SOCKS5 代理) | ~300 LOC Rust | `linux-sandbox-utils.ts` 网络部分 |
| **P1-1** | USER_NOTIF 违规观测 | ~200 LOC Rust + supervisor | `linux-violation-monitor.ts` |
| **P1-2** | stderr 自动标注违规 | ~30 LOC Rust | `annotateStderrWithSandboxFailures` |
| **P2-1** | OOM 事件捕获 | ~50 LOC Rust | systemd cgroup notification |
| **P2-2** | PID 1 化 | ~80 LOC Rust | Linux init 设计 |
| **P3-1** | macOS 跨平台 | ~500 LOC Rust + Objective-C | `macos-sandbox-utils.ts` |

**总体估算**:P0 完成约 530 LOC Rust + 测试,**2-3 周工作量**(假设单人全职)。

---

## 十二、参考来源(完整索引)

### sbx-daemon 内部来源

| 文件 | 内容 |
|------|------|
| `src/manifest.rs` | Manifest 数据结构 + 校验 |
| `src/bwrap.rs` | bwrap 命令行拼装 |
| `src/seccomp.rs` | libseccomp BPF 生成 |
| `src/cgroup.rs` | cgroup v2 配额 |
| `src/sandbox.rs` | 主流程编排 |
| `src/state.rs` | 状态机 + 持久化 |
| `src/audit.rs` | JSONL 审计 |
| `REQUIREMENTS.md` | 需求追踪 + TODO 列表 |
| `README.md` | 项目状态 + 测试覆盖 |

### sandbox-runtime 参考来源

| 文件 | 用于借鉴 |
|------|---------|
| `src/sandbox/linux-sandbox-utils.ts` | bwrap 命令组装 + 网络隔离 |
| `src/sandbox/linux-violation-monitor.ts` | USER_NOTIF 观测 |
| `src/sandbox/credential-mask-files.ts` | 凭据 sentinel |
| `src/sandbox/{http,socks,mux}-proxy.ts` | 代理层实现 |
| `src/sandbox/{mitm-ca,mitm-leaf}.ts` | TLS 中止 |
| `src/sandbox/sandbox-config.ts` | Zod schema 校验 |
| `src/sandbox/sandbox-violation-store.ts` | 违规事件存储 |
| `vendor/seccomp-src/apply-seccomp.c` | USER_NOTIF supervisor C 实现 |
| `handbook-cn/04-network-isolation-design.md` | 网络架构详细设计 |
| `handbook-cn/11-violation-monitoring.md` | 违规监控 + 11.3.1-12 子节 |
| `handbook-cn/08-credential-masking.md` | 凭据屏蔽详细设计 |

---

## 十三、一句话总结

> **sbx-daemon 当前 8/9 需求达成**,在**资源配额 / 状态管理 / 命名空间**上已超过 sandbox-runtime。
>
> 关键缺口集中在 **文件系统精细化**(危险路径屏蔽 + 凭据 sentinel)和**网络隔离**(SBX-03 域名白名单)+ **观测**(USER_NOTIF)。
>
> 按 P0 → P1 → P2 顺序补齐,**530 LOC Rust + 2-3 周**即可达到与 sandbox-runtime 隔离能力持平的水平。