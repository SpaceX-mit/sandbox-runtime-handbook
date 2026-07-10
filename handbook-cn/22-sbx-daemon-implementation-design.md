# 22 — sbx-daemon 实现设计稿（AI Coder 实施指南）

> **目标读者**:AI coder / 自动化编码 agent
>
> **文档定位**:基于 ch.21 的规格缺口分析,给出**面向实现**的设计稿——按模块拆分,每个模块包含:
> - 接口签名(Rust 类型 + 函数)
> - 数据结构(manifest 扩展)
> - 实现步骤(伪代码骨架)
> - 集成点(与现有代码的连接)
> - 单元测试要点
> - 参考实现(sandbox-runtime 代码位置)
>
> **前提**:ch.21 锁定的范围(不做跨平台,只做 RISC-V Linux)。
>
> **依赖**:Bianbu 4.0.1, kernel 6.18.3,bwrap 0.11.1,libseccomp 2.x。

---

## 一、目标与范围

### 1.1 本次实施包含 7 个模块

| ID | 模块 | 优先级 | LOC 估计 |
|----|------|--------|---------|
| M1 | mandatory_deny(强制危险路径屏蔽) | P0 | ~120 |
| M2 | credential(凭据 sentinel 屏蔽) | P0 | ~200 |
| M3 | socks5_proxy(域名白名单代理) | P0 | ~350 |
| M4 | seccomp_observer(USER_NOTIF 违规观测) | P1 | ~250 |
| M5 | stderr_annotate(stderr 自动标注) | P1 | ~60 |
| M6 | oom_watcher(OOM 事件捕获) | P2 | ~80 |
| M7 | pid1_subreaper(PID 1 化孤儿回收) | P2 | ~120 |
| **合计** | | | **~1180 LOC Rust + ~300 LOC 测试** |

### 1.2 不在本次范围

- macOS / x86_64 跨平台(见 ch.21 决定)
- HTTP 代理(本次只做 SOCKS5,因为 SOCKS5 通用 + 无需 MITM)
- TLS 中止 / MITM(本次不做,只过滤到域名级)
- 运行时动态配额调整
- 跨平台 schema(继续用 TOML)

---

## 二、整体架构

### 2.1 新增模块在 crate 中的位置

```
src/
├── lib.rs                  [修改] 注册新模块
├── main.rs                 [可能修改] 启动流程
├── manifest.rs             [修改] 新增结构体 + 校验
├── bwrap.rs                [修改] 调用新增模块生成 args
├── seccomp.rs              [修改] 加 USER_NOTIF 模式
├── cgroup.rs               [修改] 加 OOM watcher
├── sandbox.rs              [修改] 串联新模块
├── state.rs                [无需修改]
├── audit.rs                [已有 FsBlocked / SeccompBlocked / OomKill 事件,直接复用]
│
├── mandatory_deny.rs       [新增 M1]
├── credential.rs           [新增 M2]
├── socks5_proxy.rs         [新增 M3]
├── seccomp_observer.rs     [新增 M4]
├── stderr_annotate.rs      [新增 M5]
├── oom_watcher.rs          [新增 M6]
└── pid1.rs                 [新增 M7]
```

### 2.2 数据流(以 P0 三件套为例)

```
sandbox::run(manifest)
    │
    ├─ 1. 解析 manifest → Manifest
    │
    ├─ 2. mandatory_deny::inject_into_args(&manifest, &mut bwrap_args)
    │       ↓
    │       检查 /root/.ssh 等危险路径
    │       生成 --tmpfs 或 --ro-bind /dev/null
    │
    ├─ 3. credential::prepare_sentinels(&manifest)
    │       ↓
    │       生成假凭据文件到 /tmp/sbx-sentinels-<id>/
    │
    ├─ 4. credential::inject_into_args(&sentinels, &mut bwrap_args)
    │       ↓
    │       生成 --ro-bind fake real
    │
    ├─ 5. socks5_proxy::start_if_needed(&manifest).await
    │       ↓
    │       启动本地 SOCKS5 代理,返回 listen 地址
    │
    ├─ 6. socks5_proxy::inject_into_args(proxy_addr, &mut bwrap_args)
    │       ↓
    │       生成 --setenv http_proxy=...
    │
    ├─ 7. seccomp::build_bpf_with_observer(...) → 触发 M4
    │
    └─ 8. Command::new(bwrap).args(bwrap_args).spawn()
```

### 2.3 Manifest 扩展

**新增字段**(在 `src/manifest.rs` 现有结构体上扩展):

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FsConfig {
    // ... 现有字段 ...

    /// 新增: 强制屏蔽的危险路径(即使不在 read_only 也要屏蔽)
    #[serde(default)]
    pub mandatory_deny: Vec<String>,  // 额外补充,内置默认还有一份

    /// 新增: 凭据 sentinel 屏蔽
    #[serde(default)]
    pub credential_masks: Vec<CredentialMask>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMask {
    /// 沙箱内看起来的路径(如 /root/.aws/credentials)
    pub real: String,
    /// 宿主上假文件路径(sbx-daemon 启动时生成)
    pub fake_content: String,  // 用户也可以留空,使用内置模板
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    // ... 现有字段 ...

    /// 新增: SOCKS5 代理监听地址(默认 127.0.0.1:1080)
    #[serde(default = "default_socks5_bind")]
    pub socks5_bind: String,
}
fn default_socks5_bind() -> String { "127.0.0.1:1080".into() }
```

---

## 三、模块详细设计

### M1: mandatory_deny — 强制危险路径屏蔽

**目标**:即使 manifest 不小心把 `read_only = ["/"]` 这种危险配置,也要强制 deny 关键路径。

**文件**:`src/mandatory_deny.rs`（新增）

#### 3.1.1 接口签名

```rust
//! 强制危险路径屏蔽（M1）
//! 参考: sandbox-runtime/src/sandbox/linux-sandbox-utils.ts:linuxGetMandatoryDenyPaths()

use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DenyError {
    #[error("path escape attempt: {0}")]
    PathEscape(String),
}

/// 内置默认危险路径（不论 manifest 怎么配都屏蔽）
pub const DEFAULT_MANDATORY_DENY: &[&str] = &[
    // SSH
    "/root/.ssh", "/root/.ssh/authorized_keys", "/root/.ssh/id_*",
    "/home/*/.ssh", "/home/*/.ssh/id_*",
    // 云凭据
    "/root/.aws", "/root/.docker", "/root/.kube", "/root/.config/gcloud",
    "/home/*/.aws", "/home/*/.docker", "/home/*/.kube",
    // 包管理器凭据
    "/root/.npmrc", "/root/.pypirc", "/root/.netrc", "/root/.git-credentials",
    "/home/*/.npmrc", "/home/*/.pypirc", "/home/*/.netrc", "/home/*/.git-credentials",
    // 系统敏感
    "/etc/shadow", "/etc/sudoers", "/etc/gshadow",
    "/proc/*/environ", "/proc/*/cmdline",
    // sandbox daemon 自身
    "/run/bianbu-agents", "/var/log/bianbu-agents",
];

/// 把路径(可能是 glob)展开成实际路径列表
pub fn expand_glob(pattern: &str) -> Result<Vec<std::path::PathBuf>, DenyError> {
    use glob::glob;
    glob(pattern).map_err(|e| DenyError::PathEscape(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>()
        .pipe(Ok)  // 简写示意
}

/// 生成 bwrap 参数,屏蔽指定路径
/// - 目录 → --tmpfs <path>(挂载为空,看不见任何内容)
/// - 文件 → --ro-bind /dev/null <path>(覆盖成空设备)
/// - 不存在 → 跳过(避免启动报错)
pub fn deny_args(
    patterns: &[&str],          // 用户 manifest 里补充的
    bwrap_args: &mut Vec<String>,
) -> Result<(), DenyError> {
    let all: Vec<&str> = DEFAULT_MANDATORY_DENY.iter()
        .copied()
        .chain(patterns.iter().copied())
        .collect();

    for pattern in all {
        let paths = expand_glob(pattern)?;
        for path in paths {
            if !path.exists() { continue; }
            let path_str = path.display().to_string();
            if path.is_dir() {
                bwrap_args.push("--tmpfs".into());
                bwrap_args.push(path_str);
            } else {
                bwrap_args.push("--ro-bind".into());
                bwrap_args.push("/dev/null".into());
                bwrap_args.push(path_str);
            }
        }
    }
    Ok(())
}
```

#### 3.1.2 Manifest 集成(`manifest.rs` 改)

```rust
impl Manifest {
    pub fn validate(&self) -> Result<(), ManifestError> {
        // ... 现有校验 ...

        // 新增: 校验 mandatory_deny 路径不能含 `..` 逃逸
        for p in &self.fs.mandatory_deny {
            if p.contains("..") {
                return Err(ManifestError::Invalid(format!(
                    "mandatory_deny contains '..': {p}"
                )));
            }
        }
        Ok(())
    }
}
```

#### 3.1.3 bwrap.rs 集成

```rust
// src/bwrap.rs:build_args() 内,在 read_only 循环之后追加:
use crate::mandatory_deny;
mandatory_deny::deny_args(
    &m.fs.mandatory_deny.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    &mut args,
).map_err(|e| BwrapError::DenyError(e.to_string()))?;
```

#### 3.1.4 单元测试要点

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_deny_covers_ssh() {
        let mut args = vec![];
        deny_args(&[], &mut args).unwrap();
        let s = args.join(" ");
        assert!(s.contains("--tmpfs") || s.contains("--ro-bind"));
    }

    #[test]
    fn file_path_uses_ro_bind_dev_null() {
        let mut args = vec![];
        // 假设 /etc/shadow 存在
        deny_args(&["/etc/shadow"], &mut args).unwrap();
        assert!(args.windows(3).any(|w| {
            w[0] == "--ro-bind" && w[1] == "/dev/null" && w[2] == "/etc/shadow"
        }));
    }

    #[test]
    fn nonexistent_path_is_skipped() {
        let mut args = vec![];
        deny_args(&["/nope/does/not/exist"], &mut args).unwrap();
        // 不应报错,也不应注入任何参数
        assert!(args.is_empty());
    }

    #[test]
    fn glob_pattern_expanded() {
        let mut args = vec![];
        deny_args(&["/home/*/.ssh"], &mut args).unwrap();
        // 视平台而定
        assert!(!args.is_empty());
    }
}
```

#### 3.1.5 Cargo.toml 新依赖

```toml
[dependencies]
glob = "0.3"
```

---

### M2: credential — 凭据 sentinel 屏蔽

**目标**:让 sandbox 内 `cat ~/.aws/credentials` 读到假内容,而不是真凭据。

**文件**:`src/credential.rs`（新增）

#### 3.2.1 接口签名

```rust
//! 凭据 sentinel 屏蔽（M2）
//! 参考: sandbox-runtime/src/sandbox/credential-mask-files.ts

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use crate::manifest::{CredentialMask, Manifest};

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// 假凭据的默认内容（按真实文件名匹配）
fn default_fake_content(real_path: &str) -> &'static str {
    if real_path.ends_with("/.aws/credentials") {
        "[default]\naws_access_key_id = AKIAFAKEFAKEFAKEFAKE\naws_secret_access_key = FAKE\n"
    } else if real_path.contains("/.ssh/id_rsa") || real_path.contains("/.ssh/id_ed25519") {
        "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE_KEY_FOR_SANDBOX\n-----END OPENSSH PRIVATE KEY-----\n"
    } else if real_path.ends_with("/.netrc") {
        "machine fake login anonymous password anon\n"
    } else if real_path.ends_with("/.git-credentials") {
        "https://fake:anonymous@github.example.invalid\n"
    } else {
        "# sandboxed: real credentials are masked\nFAKE CONTENT\n"
    }
}

/// 准备 sentinel 文件(写到宿主临时目录),返回 (real_path, fake_path) 列表
pub fn prepare_sentinels(
    manifest: &Manifest,
    state_dir: &Path,
) -> Result<Vec<(PathBuf, PathBuf)>, CredentialError> {
    let sentinel_dir = state_dir.join(format!("sentinels-{}", manifest.agent.id));
    std::fs::create_dir_all(&sentinel_dir)?;
    
    let mut result = Vec::new();
    for m in &manifest.fs.credential_masks {
        let real_path = PathBuf::from(&m.real);
        let fake_path = sentinel_dir.join(
            // 用 base64 编码 real_path 避免文件名冲突
            format!("{}.fake", base64_encode(&m.real))
        );
        let content = if m.fake_content.is_empty() {
            default_fake_content(&m.real)
        } else {
            m.fake_content.as_str()
        };
        std::fs::write(&fake_path, content)?;
        // 权限:让 bwrap 进程能读
        std::fs::set_permissions(&fake_path, std::fs::Permissions::from_mode(0o444))?;
        result.push((real_path, fake_path));
    }
    Ok(result)
}

/// 注入 bwrap 参数: --ro-bind fake real
pub fn inject_into_args(
    sentinels: &[(PathBuf, PathBuf)],
    bwrap_args: &mut Vec<String>,
) {
    for (real, fake) in sentinels {
        bwrap_args.push("--ro-bind".into());
        bwrap_args.push(fake.display().to_string());
        bwrap_args.push(real.display().to_string());
    }
    // 整个 sentinel 目录自己也设为只读,防 agent 看到文件内容
    if let Some(dir) = sentinels.first().map(|(_, f)| f.parent().unwrap().to_path_buf()) {
        bwrap_args.push("--ro-bind".into());
        bwrap_args.push(dir.display().to_string());
        bwrap_args.push(dir.display().to_string());
    }
}

/// 清理 sentinel 目录(在 sandbox.rs 退出时调用)
pub fn cleanup_sentinels(sentinels: &[(PathBuf, PathBuf)]) {
    if let Some(dir) = sentinels.first().map(|(_, f)| f.parent().unwrap().to_path_buf()) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

fn base64_encode(s: &str) -> String {
    // 用 simple base64（实际可用 base64 crate）
    s.bytes().map(|b| format!("{b:02x}")).collect()
}
```

#### 3.2.2 sandbox.rs 集成

```rust
// src/sandbox.rs:run() 函数中,在 bwrap args 拼装前:
let sentinels = credential::prepare_sentinels(&m, state_dir)?;
credential::inject_into_args(&sentinels, &mut args);

// 在 spawn 之前,记录用于 cleanup:
let sentinels_for_cleanup = sentinels.clone();

// spawn 之后(不论成败):
let cleanup_result = credential::cleanup_sentinels(&sentinels_for_cleanup);
```

#### 3.2.3 单元测试

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn prepare_writes_fake_aws_creds() {
        let dir = TempDir::new().unwrap();
        let m = make_test_manifest_with(vec![CredentialMask {
            real: "/root/.aws/credentials".into(),
            fake_content: "".into(),  // 用默认
        }]);
        let sents = prepare_sentinels(&m, dir.path()).unwrap();
        assert_eq!(sents.len(), 1);
        let content = std::fs::read_to_string(&sents[0].1).unwrap();
        assert!(content.contains("AKIAFAKEFAKEFAKEFAKE"));
        assert!(!content.contains("AKIA")); // 不应包含真 key 前缀
    }

    #[test]
    fn custom_content_overrides_default() {
        let dir = TempDir::new().unwrap();
        let m = make_test_manifest_with(vec![CredentialMask {
            real: "/root/.aws/credentials".into(),
            fake_content: "MY_CUSTOM_FAKE".into(),
        }]);
        let sents = prepare_sentinels(&m, dir.path()).unwrap();
        let content = std::fs::read_to_string(&sents[0].1).unwrap();
        assert_eq!(content, "MY_CUSTOM_FAKE");
    }

    #[test]
    fn inject_args_uses_ro_bind() {
        let sentinels = vec![(
            PathBuf::from("/root/.aws/credentials"),
            PathBuf::from("/tmp/sbx/fake1"),
        )];
        let mut args = vec![];
        inject_into_args(&sentinels, &mut args);
        assert!(args.windows(3).any(|w|
            w[0] == "--ro-bind" && w[1] == "/tmp/sbx/fake1" && w[2] == "/root/.aws/credentials"
        ));
    }
}
```

#### 3.2.4 Manifest 示例

```toml
[fs.credential_masks]
[[fs.credential_masks]]
real = "/root/.aws/credentials"
fake_content = ""  # 空 = 用内置 sentinel

[[fs.credential_masks]]
real = "/root/.ssh/id_rsa"
fake_content = "-----BEGIN...\nSANDBOX_KEY\n-----END...\n"
```

---

### M3: socks5_proxy — SOCKS5 域名白名单代理

**目标**:实现本地 SOCKS5 代理,只允许 `allow_domains` 解析出的 IP 出站。

**文件**:`src/socks5_proxy.rs`（新增）

#### 3.3.1 接口签名

```rust
//! SOCKS5 域名白名单代理（M3，SBX-03）
//! 参考: sandbox-runtime/src/sandbox/{http,socks}-proxy.ts

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("bind: {0}")]
    Bind(#[from] std::io::Error),
    #[error("socks protocol: {0}")]
    Protocol(String),
    #[error("domain blocked: {0}")]
    Blocked(String),
    #[error("dns: {0}")]
    Dns(String),
}

/// SOCKS5 代理服务
#[derive(Clone)]
pub struct Socks5Proxy {
    bind: SocketAddr,
    allowed_domains: Arc<Vec<String>>,
    allowed_ips: Arc<RwLock<HashSet<IpAddr>>>,
    audit: Arc<crate::audit::AuditLog>,
}

impl Socks5Proxy {
    pub fn new(bind: SocketAddr, allowed_domains: Vec<String>, audit: Arc<crate::audit::AuditLog>) -> Self {
        Self {
            bind,
            allowed_domains: Arc::new(allowed_domains),
            allowed_ips: Arc::new(RwLock::new(HashSet::new())),
            audit,
        }
    }

    /// 预解析所有允许域名到 IP(在启动时一次性完成)
    pub async fn pre_resolve(&self) -> Result<(), ProxyError> {
        use std::net::ToSocketAddrs;
        let mut set = self.allowed_ips.write().await;
        for domain in self.allowed_domains.iter() {
            // "example.com:443" → lookup all IPs
            let addrs: Vec<SocketAddr> = (domain.as_str(), 443)
                .to_socket_addrs()
                .map_err(|e| ProxyError::Dns(e.to_string()))?
                .collect();
            for addr in addrs {
                set.insert(addr.ip());
                info!(domain = %domain, ip = %addr.ip(), "resolved allowlist");
            }
        }
        Ok(())
    }

    pub async fn run(&self) -> Result<(), ProxyError> {
        self.pre_resolve().await?;
        let listener = TcpListener::bind(self.bind).await?;
        info!(bind = %self.bind, "SOCKS5 proxy listening");
        loop {
            let (stream, peer) = listener.accept().await?;
            let proxy = self.clone();
            tokio::spawn(async move {
                if let Err(e) = proxy.handle_client(stream).await {
                    warn!(peer = %peer, error = %e, "client handler failed");
                }
            });
        }
    }

    async fn handle_client(&self, mut client: TcpStream) -> Result<(), ProxyError> {
        // 1. SOCKS5 握手 (RFC 1928)
        // ... 协商无认证
        // ... 接收 CONNECT 请求
        let (host, port) = read_socks5_connect(&mut client).await?;
        
        // 2. 域名/IP 检查
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{host}:{port}")).await
            .map_err(|e| ProxyError::Dns(e.to_string()))?
            .collect();
        if addrs.is_empty() {
            write_socks5_reply(&mut client, 0x04).await?;  // Host unreachable
            self.audit.write(crate::audit::AuditEvent::SeccompBlocked {
                agent_id: "proxy".into(),
                pid: std::process::id(),
                syscall: format!("network_denied: dns_failed {host}"),
            }).ok();
            return Err(ProxyError::Blocked(host.clone()));
        }

        let allowed = {
            let cache = self.allowed_ips.read().await;
            addrs.iter().any(|a| cache.contains(&a.ip()))
        };
        if !allowed {
            write_socks5_reply(&mut client, 0x02).await?;  // Connection refused
            self.audit.write(crate::audit::AuditEvent::SeccompBlocked {
                agent_id: "proxy".into(),
                pid: std::process::id(),
                syscall: format!("network_denied: {host}:{port}"),
            }).ok();
            return Err(ProxyError::Blocked(format!("{host}:{port}")));
        }
        
        // 3. TCP 连接目标(用第一个解析的 IP 防 DNS rebinding)
        let target = TcpStream::connect(&addrs[0]).await?;
        write_socks5_reply(&mut client, 0x00).await?;  // Success
        
        // 4. 双向中继
        let (mut cr, mut cw) = client.split();
        let (mut tr, mut tw) = target.split();
        tokio::select! {
            _ = tokio::io::copy(&mut cr, &mut tw) => {}
            _ = tokio::io::copy(&mut tr, &mut cw) => {}
        }
        Ok(())
    }

    /// 注入 bwrap 环境变量
    pub fn inject_into_args(&self, bwrap_args: &mut Vec<String>) {
        let url = format!("socks5://{}", self.bind);
        bwrap_args.push("--setenv".into());
        bwrap_args.push("http_proxy".into());
        bwrap_args.push(&url);
        bwrap_args.push("--setenv".into());
        bwrap_args.push("https_proxy".into());
        bwrap_args.push(&url);
        bwrap_args.push("--setenv".into());
        bwrap_args.push("all_proxy".into());
        bwrap_args.push(&url);
        // NO_PROXY 包含 localhost,免得 sandbox 内的本地服务被代理
        bwrap_args.push("--setenv".into());
        bwrap_args.push("no_proxy".into());
        bwrap_args.push("localhost,127.0.0.1,::1".into());
    }
}

/// 读取 SOCKS5 CONNECT 请求,返回 (host, port)
async fn read_socks5_connect(stream: &mut TcpStream) -> Result<(String, u16), ProxyError> {
    // VER, NMETHODS
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 { return Err(ProxyError::Protocol("not SOCKS5".into())); }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    
    // 选 NO AUTH (0x00)
    stream.write_all(&[0x05, 0x00]).await?;
    
    // CONNECT request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
    let mut req_head = [0u8; 4];
    stream.read_exact(&mut req_head).await?;
    if req_head[0] != 0x05 || req_head[1] != 0x01 {
        return Err(ProxyError::Protocol("not CONNECT".into()));
    }
    let host = match req_head[3] {
        0x01 => {  // IPv4
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)).to_string()
        }
        0x03 => {  // Domain
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain).map_err(|_| ProxyError::Protocol("invalid domain".into()))?
        }
        0x04 => {  // IPv6
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)).to_string()
        }
        _ => return Err(ProxyError::Protocol(format!("unknown ATYP {}", req_head[3]))),
    };
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);
    Ok((host, port))
}

async fn write_socks5_reply(stream: &mut TcpStream, rep: u8) -> Result<(), ProxyError> {
    // VER, REP, RSV, ATYP(IPv4 0.0.0.0), BND.PORT(0)
    stream.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}
```

#### 3.3.2 sandbox.rs 集成

```rust
// src/sandbox.rs:run() 函数中,在 bwrap spawn 之前:
let audit_arc = Arc::new(audit);  // audit 需要 Arc 包装
let bind: SocketAddr = manifest.network.socks5_bind.parse()
    .map_err(|e| SandboxError::Manifest(ManifestError::Invalid(format!("socks5_bind: {e}"))))?;
let proxy = socks5_proxy::Socks5Proxy::new(
    bind,
    manifest.network.allow_domains.clone(),
    audit_arc.clone(),
);
let proxy_handle = tokio::spawn({
    let proxy = proxy.clone();
    async move { proxy.run().await }
});
// 等待 proxy ready
tokio::time::sleep(Duration::from_millis(100)).await;

proxy.inject_into_args(&mut bwrap_args);

// 后续:bwrap spawn ...
// 退出时:
proxy_handle.abort();
```

#### 3.3.3 单元测试

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn parse_socks5_ipv4_request() {
        // 0x05 0x01 0x00 0x01 <4 bytes IP> <2 bytes port>
        let bytes = vec![0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x1f, 0x90];  // 1.2.3.4:8080
        // 测试 read_socks5_connect 需要 mock stream,这里只测试编码逻辑
    }
    
    #[tokio::test]
    async fn blocks_unlisted_domain() {
        // 起 proxy, allow=["github.com"]
        // 用 tokio::net::TcpStream 模拟 client 发 CONNECT 到 evil.com
        // 验证收到 0x02 reply
    }
    
    #[tokio::test]
    async fn allows_listed_domain() {
        // 同样,但目标是 github.com,应能成功
    }
}
```

#### 3.3.4 集成测试(`tests/sbx_integration.rs`)

```rust
#[tokio::test]
async fn sbx_03_socks5_blocks_unlisted_domain() {
    // 1. 启动 sbx-daemon run with [network] allow_domains=["example.com"]
    // 2. 在 sandbox 内运行 curl https://evil.com
    // 3. 验证:exit code != 0,stderr 含 "Connection refused" 或类似
}

#[tokio::test]
async fn sbx_03_socks5_allows_listed_domain() {
    // 1. allow_domains=["example.com"]
    // 2. curl https://example.com
    // 3. 验证:exit code == 0,有 HTML 输出
}
```

---

### M4: seccomp_observer — USER_NOTIF 违规观测

**目标**:让 seccomp 不只是 KILL 违规 syscall,还要**上报事件**,让宿主能看到"为什么被杀"。

**文件**:`src/seccomp_observer.rs`（新增）

#### 3.4.1 接口签名

```rust
//! USER_NOTIF 违规观测（M4）
//! 参考: sandbox-runtime/src/sandbox/linux-violation-monitor.ts
//!        + sandbox-runtime/vendor/seccomp-src/apply-seccomp.c

use std::os::unix::io::RawFd;
use std::path::Path;
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tracing::warn;

#[derive(Debug, Error)]
pub enum ObserverError {
    #[error("ioctl: {0}")]
    Ioctl(std::io::Error),
    #[error("invalid syscall nr: {0}")]
    InvalidNr(i64),
}

/// seccomp notif 结构(简化版,kernel ABI)
#[repr(C)]
struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}
#[repr(C)]
struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}
#[repr(C)]
struct SeccompNotifResponse {
    pub id: u64,
    pub val: i64,
    pub flags: i64,
}

const SECCOMP_IOCTL_NOTIF_RECV: u64 = 0xfffd_ffe0;
const SECCOMP_IOCTL_NOTIF_SEND: u64 = 0xfffd_ffe1;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: i64 = 0x0000_0001;

/// 启动 supervisor 任务,监听 seccomp notify_fd,违规上报
pub async fn supervise_syscalls(
    notify_fd: RawFd,
    syscall_names: &'static std::collections::HashMap<i32, &'static str>,
    audit: std::sync::Arc<crate::audit::AuditLog>,
    agent_id: String,
) -> Result<(), ObserverError> {
    let fd = notify_fd;
    loop {
        let mut req = SeccompNotif {
            id: 0,
            pid: 0,
            flags: 0,
            data: SeccompData { nr: 0, arch: 0, instruction_pointer: 0, args: [0; 6] },
        };
        let ret = unsafe { libc::ioctl(fd as _, SECCOMP_IOCTL_NOTIF_RECV, &mut req) };
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) { continue; }
            return Err(ObserverError::Ioctl(e));
        }
        
        // 解析 syscall 名
        let nr = req.data.nr;
        let name = syscall_names.get(&nr).copied().unwrap_or("unknown").to_string();
        
        // 尝试读第一个参数(常是路径指针)
        let path = unsafe { read_tracee_path(req.pid, req.data.args[0] as *const u8) };
        
        // 上报
        if let Err(e) = audit.write(crate::audit::AuditEvent::SeccompBlocked {
            agent_id: agent_id.clone(),
            pid: req.pid,
            syscall: name,
        }) {
            warn!("audit write failed: {e}");
        }
        if let Some(p) = path {
            // 也发 FsBlocked 事件
            audit.write(crate::audit::AuditEvent::FsBlocked {
                agent_id: agent_id.clone(),
                pid: req.pid,
                path: p,
            }).ok();
        }
        
        // 放行(让 bwrap 自己决定)
        let resp = SeccompNotifResponse {
            id: req.id,
            val: 0,
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        };
        let ret = unsafe { libc::ioctl(fd as _, SECCOMP_IOCTL_NOTIF_SEND, &resp) };
        if ret < 0 { return Err(ObserverError::Ioctl(std::io::Error::last_os_error())); }
    }
}

/// 尝试从 tracee 进程读 C 字符串
unsafe fn read_tracee_path(pid: u32, ptr: *const u8) -> Option<String> {
    if ptr.is_null() { return None; }
    let mut buf = vec![0u8; 4096];
    let iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let mut remote_iov = libc::iovec {
        iov_base: ptr as *mut _,
        iov_len: buf.len(),
    };
    let n = libc::process_vm_readv(
        pid as _,
        &mut iov, 1,
        &mut remote_iov, 1,
        0,
    );
    if n <= 0 { return None; }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}
```

#### 3.4.2 seccomp.rs 改动(关键)

把 `SCMP_ACT_KILL` 改成 `SCMP_ACT_TRAP`(需要新常量):

```rust
// 新增常量
const SCMP_ACT_TRAP: u32 = 0x0003_0000;  // 触发 USER_NOTIF

// 修改 build_bpf:
pub fn build_bpf_observable(
    profile: &str,
    extra: &[String],
    notify_fd_out: &mut Option<RawFd>,  // 返回 fd 给 supervisor
) -> Result<std::path::PathBuf, SeccompError> {
    unsafe {
        let ctx = libseccomp_sys::seccomp_init(SCMP_ACT_ALLOW);
        // ... 添加黑名单,但用 SCMP_ACT_TRAP 而不是 KILL:
        for n in &names {
            let r = libseccomp_sys::seccomp_rule_add_exact(ctx, SCMP_ACT_TRAP, nr, 0);
            // ...
        }
        
        // 创建 notify_fd
        let notify_fd = libc::dup(libc::STDERR_FILENO).unwrap();  // 实际应 seccomp_notify_fd
        // ↑ 简化示意,正确做法是 SECCOMP_IOCTL_NOTIF_RECV 用一个 ioctl-based fd
        // 真实场景:bwrap 启动 seccomp 后,把 notify_fd 通过环境变量传给 sbx-daemon
        *notify_fd_out = Some(notify_fd);
        
        // 导出 BPF 同 build_bpf ...
    }
}
```

**注意**:USER_NOTIF 的实际集成比较复杂,bwrap 不直接支持 notify_fd 传递。**简化做法**:
- 不改 seccomp.rs(继续 KILL)
- 单独启动一个 supervisor 子进程,用 `prctl(PR_SET_NO_NEW_PRIVS)` + seccomp + 主进程传 fd

**替代实现路径**(更现实):

```rust
// 1. sbx-daemon fork 一个 supervisor 子进程
// 2. supervisor 子进程:
//    a. prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
//    b. seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog)
//       返回 listen_fd
//    c. 把 listen_fd 通过 unix socket 传给 sbx-daemon 主进程
//    d. 进入 supervise_syscalls() loop,放行所有(SECCOMP_USER_NOTIF_FLAG_CONTINUE)
// 3. bwrap 启动 agent 时,bwrap 用 --seccomp fd 加载这个 BPF(此时 syscall 已被 trap)
// 4. agent 的 syscall → BPF → notify supervisor → 审计 + 放行 → 内核执行 syscall
// 5. bwrap 的 mount 表继续拒绝真正越权的 syscall
```

#### 3.4.3 测试要点

- 单元:测试 `read_tracee_path` 对无效指针返回 `None`
- 单元:测试 syscall nr → name 映射
- 集成:`sbx_04_seccomp_emits_violation_event` —— agent 触发 `reboot` → 审计日志含 `SeccompBlocked { syscall: "reboot" }`

---

### M5: stderr_annotate — stderr 自动标注违规

**目标**:在 sandbox 进程退出后,把违规事件追加到 stderr,让用户看到。

**文件**:`src/stderr_annotate.rs`（新增）

#### 3.5.1 接口签名

```rust
//! stderr 自动标注违规（M5）
//! 参考: sandbox-runtime/src/sandbox/sandbox-manager.ts:annotateStderrWithSandboxFailures

use crate::audit::{AuditEvent, AuditLog};

/// 在 sandbox 进程退出后,把违规摘要追加到 stderr
pub fn annotate(agent_id: &str, original_stderr: &str, audit: &AuditLog) -> String {
    // 从 audit log 文件读这个 agent 的所有事件
    let events = read_events_for(agent_id, audit);
    let violations: Vec<&AuditEvent> = events.iter().filter(|e| {
        matches!(e, AuditEvent::FsBlocked { .. } | AuditEvent::SeccompBlocked { .. })
    }).collect();
    
    if violations.is_empty() {
        return original_stderr.to_string();
    }
    
    let mut out = original_stderr.to_string();
    out.push_str("\n\n<sandbox_violations agent_id=\"");
    out.push_str(agent_id);
    out.push_str("\">\n");
    for v in violations.iter().take(10) {
        let line = match v {
            AuditEvent::FsBlocked { path, .. } => format!("  fs_blocked: {path}\n"),
            AuditEvent::SeccompBlocked { syscall, .. } => format!("  syscall_blocked: {syscall}\n"),
            _ => unreachable!(),
        };
        out.push_str(&line);
    }
    if violations.len() > 10 {
        out.push_str(&format!("  ... and {} more\n", violations.len() - 10));
    }
    out.push_str("</sandbox_violations>\n");
    out
}

fn read_events_for(_agent_id: &str, _audit: &AuditLog) -> Vec<AuditEvent> {
    // 实现:读 audit.jsonl,过滤出 agent_id 匹配的
    // 简化:用 if let AuditEvent::FsBlocked { agent_id, .. } = ...
    // 真实:用 serde_json::Deserializer::from_reader().into_iter::<AuditEvent>()
    Vec::new()  // 占位
}
```

#### 3.5.2 集成

在 `sandbox::run` 末尾,捕获 child stderr 后:

```rust
let stderr = read_child_stderr(child);
let annotated = stderr_annotate::annotate(&m.agent.id, &stderr, &audit);
eprintln!("{annotated}");  // 输出到 sbx-daemon 自身的 stderr
```

---

### M6: oom_watcher — OOM 事件捕获

**目标**:监听 cgroup 的 memory.events,捕获 OOM kill 事件。

**文件**:`src/oom_watcher.rs`（新增）

#### 3.6.1 接口签名

```rust
//! OOM 事件捕获（M6）
//! 通过轮询 cgroup v2 memory.events

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::warn;

pub async fn watch_oom(
    cgroup_path: &Path,
    agent_id: String,
    audit: Arc<crate::audit::AuditLog>,
) {
    let events_file = cgroup_path.join("memory.events");
    let mut last_oom_kill = 0u64;
    let mut last_oom_group_kill = 0u64;
    
    loop {
        sleep(Duration::from_millis(500)).await;
        
        let content = match tokio::fs::read_to_string(&events_file).await {
            Ok(c) => c,
            Err(_) => continue,  // cgroup 可能已删除
        };
        
        let (oom, oom_group) = parse_memory_events(&content);
        if oom > last_oom_kill {
            let delta = oom - last_oom_kill;
            audit.write(crate::audit::AuditEvent::OomKill {
                agent_id: agent_id.clone(),
                pid: 0,
            }).ok();
            warn!(agent = %agent_id, count = delta, "OOM kill detected");
            last_oom_kill = oom;
        }
        if oom_group > last_oom_group_kill {
            let delta = oom_group - last_oom_group_kill;
            warn!(agent = %agent_id, count = delta, "OOM group kill detected");
            last_oom_group_kill = oom_group;
        }
    }
}

fn parse_memory_events(content: &str) -> (u64, u64) {
    let mut oom = 0;
    let mut oom_group = 0;
    for line in content.lines() {
        if let Some((k, v)) = line.split_once(' ') {
            match k {
                "oom_kill" => oom = v.parse().unwrap_or(0),
                "oom_group_kill" => oom_group = v.parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    (oom, oom_group)
}
```

#### 3.6.2 集成

```rust
// sandbox.rs spawn 之后:
let cgroup_for_oom = std::path::PathBuf::from(&cgroup_path);
let audit_oom = audit_arc.clone();
let agent_id_oom = m.agent.id.clone();
let oom_handle = tokio::spawn(async move {
    oom_watcher::watch_oom(&cgroup_for_oom, agent_id_oom, audit_oom).await;
});

// 退出时:
oom_handle.abort();
```

---

### M7: pid1_subreaper — PID 1 化孤儿回收

**目标**:防止 sandbox 内 agent fork 出的孤儿进程逃逸。

**文件**:`src/pid1.rs`（新增）

#### 3.7.1 接口签名

```rust
//! PID 1 化 + 孤儿进程回收（M7）
//! 在 sandbox 内启动一个永生 PID 1 占位进程

use std::os::unix::process::CommandExt;
use std::process::Command;

pub const PID1_HELPER: &str = include_str!("../assets/pid1_helper.rs");

/// 生成 PID 1 占位进程的二进制(或使用嵌入式 shell 脚本)
/// 这里简化:用 shell 脚本作为占位
pub fn build_pid1_wrapper(agent_cmd: &[String]) -> Vec<String> {
    let cmd_str = agent_cmd.iter().map(|a| shell_escape(a)).collect::<Vec<_>>().join(" ");
    vec![
        "/bin/sh".into(),
        "-c".into(),
        format!(
            "trap 'kill -TERM -$$ 2>/dev/null' EXIT; \
             exec {}; \
             while true; do wait; done",
            cmd_str
        ),
    ]
}

fn shell_escape(s: &str) -> String {
    if s.chars().all(|c| c.is_alphanumeric() || "/-_.:=".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// 用 PID 1 包装启动 bwrap
pub fn wrap_command_with_pid1(original_args: Vec<String>) -> Vec<String> {
    let sep_idx = original_args.iter().position(|a| a == "--").unwrap();
    let mut left = original_args[..sep_idx].to_vec();
    let mut right = original_args[sep_idx+1..].to_vec();
    
    // 在 -- 后面插入 PID 1 占位
    let pid1_args = build_pid1_wrapper(&right);
    
    // bwrap 默认会 exec 第一个参数,我们让 bwrap exec 我们的 /bin/sh -c "..."
    // 这个 sh 会 fork agent,然后 wait 循环回收孤儿
    left.extend(pid1_args);
    left
}
```

**注意**:这个简化实现实际**不够健壮**(bash 子 shell 不能 reaper 所有孙子)。**更稳的做法**:

```rust
// 1. 单独编译一个 pid1 helper 二进制(或用 #[used] 嵌入到 sbx-daemon)
// 2. helper 的逻辑:
//    - prctl(PR_SET_CHILD_SUBREAPER, 1)  // 成为 subreaper
//    - fork
//    - 子进程 exec agent
//    - 父进程循环 waitpid(-1, ..., WNOHANG) 处理孤儿
//    - 当 agent 退出时, kill 所有剩余孤儿,再退出

// 完整实现参考 systemd 的 PID 1 设计(Linux init 进程)
```

**实施建议**:M7 标记为 P2 风险项,初期**只用简化版本**(接受"可能漏掉孙子进程"的限制),后续迭代再写专门的 helper 二进制。

---

## 四、lib.rs 注册

```rust
// src/lib.rs
pub mod manifest;
pub mod state;
pub mod audit;
pub mod seccomp;
pub mod bwrap;
pub mod cgroup;
pub mod sandbox;
pub mod mandatory_deny;   // M1
pub mod credential;       // M2
pub mod socks5_proxy;     // M3
pub mod seccomp_observer; // M4
pub mod stderr_annotate;  // M5
pub mod oom_watcher;      // M6
pub mod pid1;             // M7
```

---

## 五、sandbox.rs 主流程改造

```rust
// src/sandbox.rs:run() 函数完整流程

pub async fn run(...) -> Result<i32, SandboxError> {
    // 0. 准备(已存在)
    let m = Manifest::from_file(manifest_path)?;
    let audit = Arc::new(AuditLog::open(audit_dir)?);
    
    // === 新增:M3 启动 SOCKS5 代理 ===
    let bind: SocketAddr = m.network.socks5_bind.parse()?;
    let proxy = socks5_proxy::Socks5Proxy::new(
        bind,
        m.network.allow_domains.clone(),
        audit.clone(),
    );
    let proxy_handle = tokio::spawn({ let p = proxy.clone(); async move { p.run().await } });
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // 1. 拼装 bwrap args(扩展)
    let mut args = bwrap::build_args(&m)?;
    mandatory_deny::deny_args(&m.fs.mandatory_deny.iter().map(|s| s.as_str()).collect::<Vec<_>>(), &mut args)?;
    let sentinels = credential::prepare_sentinels(&m, state_dir)?;
    credential::inject_into_args(&sentinels, &mut args);
    proxy.inject_into_args(&mut args);
    
    // 2. seccomp(扩展:可能启动 observer)
    let bpf_path = seccomp::build_bpf(&m.seccomp.profile, &m.seccomp.extra_blacklist)?;
    // 启动 seccomp observer(M4,简化:暂用 KILL 模式)
    
    // 3. cgroup + systemd-run(已存在)
    
    // 4. spawn bwrap(已存在)
    let child = Command::new("bwrap").args(&args).spawn()?;
    
    // === 新增:M6 OOM watcher ===
    let oom_handle = tokio::spawn({
        let cgroup = std::path::PathBuf::from(&cgroup_path);
        let id = m.agent.id.clone();
        let a = audit.clone();
        async move { oom_watcher::watch_oom(&cgroup, id, a).await }
    });
    
    // 5. wait(已存在)
    let status = child.wait()?;
    
    // === 新增:M5 stderr 标注 ===
    let stderr = String::from_utf8_lossy(&output.stderr);
    let annotated = stderr_annotate::annotate(&m.agent.id, &stderr, &audit);
    eprint!("{}", annotated);
    
    // 6. cleanup
    credential::cleanup_sentinels(&sentinels);
    proxy_handle.abort();
    oom_handle.abort();
    
    Ok(status.code().unwrap_or(-1))
}
```

---

## 六、测试策略

### 6.1 单元测试(每个模块内部)

```bash
cargo test --lib
# 应该新增 ~30 个 unit test
```

### 6.2 集成测试(在 `tests/sbx_integration.rs` 添加)

| 测试函数 | 验证 |
|---------|------|
| `sbx_m1_blocks_ssh_default` | sandbox 内 `cat /root/.ssh/id_rsa` → EACCES/ENOENT |
| `sbx_m1_blocks_docker_default` | sandbox 内 `cat /root/.docker/config.json` → 同样 |
| `sbx_m2_reads_fake_aws_creds` | 配置 sentinel,sandbox 内 `cat ~/.aws/credentials` 看到 FAKE |
| `sbx_m2_real_creds_not_visible` | 确认 sentinel 不含真凭据前缀 |
| `sbx_m3_blocks_unlisted_domain` | curl https://evil.com → "Connection refused" |
| `sbx_m3_allows_listed_domain` | curl https://example.com → 成功 |
| `sbx_m4_seccomp_emits_event` | 触发 reboot,审计日志含 SeccompBlocked |
| `sbx_m5_stderr_contains_violations` | 触发违规,stderr 含 `<sandbox_violations>` |
| `sbx_m6_oom_event_recorded` | 触发 OOM,审计日志含 OomKill |
| `sbx_m7_orphan_reaped` | agent fork 孤儿进程,孤儿被杀 |

### 6.3 Manifest 示例(更新)

```toml
[agent]
id = "test-agent-001"
binary = "/bin/bash"
args = ["-c", "echo hi"]
home = "/tmp/sbx-test"

[fs]
read_only = ["/usr", "/bin", "/lib", "/etc"]
tmpfs = ["/tmp"]
bind = [
  { src = "/tmp/sbx-test", dst = "/home/agent", writable = true },
]
mandatory_deny = ["/etc/cron.deny"]  # 用户补充

# 新增:凭据屏蔽
[[fs.credential_masks]]
real = "/root/.aws/credentials"
fake_content = ""

[[fs.credential_masks]]
real = "/root/.ssh/id_rsa"
fake_content = ""

[network]
mode = "allow"
allow_domains = ["api.github.com", "*.anthropic.com"]
socks5_bind = "127.0.0.1:1080"

[resource]
cpu_quota = "100%"
memory_max = "1G"
io_weight = 100
pids_max = 256

[seccomp]
profile = "default-blacklist"
extra_blacklist = ["clock_settime"]

[security]
unshare_user = true
unshare_pid = true
# ... 其他
```

---

## 七、实施顺序与依赖

```
阶段 1 (P0 必做,~2 周)
  M1 mandatory_deny ──┐
                       ├── 互相独立,可并行
  M2 credential ───────┤
                       │
  M3 socks5_proxy ─────┘

阶段 2 (P1,~1 周)
  M4 seccomp_observer (依赖 M3 的审计)
  M5 stderr_annotate  (依赖 M4)

阶段 3 (P2,~1 周,可选)
  M6 oom_watcher (独立)
  M7 pid1_subreaper (独立,简化版即可)
```

**总计**:P0+P1+P2 = 4-5 周(单人全职)。

---

## 八、给 AI Coder 的具体指令模板

如果你要喂给 AI coder,**每个模块一条独立任务**:

```markdown
## 任务:实现 M1 mandatory_deny 模块

**文件**: 在 `src/mandatory_deny.rs` 新建

**参考**:
- sbx-daemon 已有的 `src/seccomp.rs` 风格(thiserror + 单元测试)
- sandbox-runtime/src/sandbox/linux-sandbox-utils.ts:linuxGetMandatoryDenyPaths()

**接口**: 见 ch.22 文档 §3.1.1

**集成点**: 
- src/lib.rs 加 `pub mod mandatory_deny;`
- src/manifest.rs 在 FsConfig 加 `pub mandatory_deny: Vec<String>`
- src/bwrap.rs 在 read_only 循环后调 `deny_args(...)`

**依赖**: Cargo.toml 加 `glob = "0.3"`

**测试**: 至少 4 个单元测试(见 ch.22 §3.1.4)

**验收**:
- `cargo test --lib mandatory_deny` 全过
- `cargo build --release` 无 warning
- 新建测试 manifest,运行 `sbx-daemon run` 验证 /root/.ssh 真的读不到
```

---

## 九、风险与已知问题

| 风险 | 缓解 |
|------|------|
| **M4 USER_NOTIF 集成复杂**(bwrap 不直接传 fd) | 阶段 2 优先用简化 supervisor 进程方案;长期可 fork bwrap 补丁 |
| **M7 PID 1 化的 sh 包装不够健壮** | 接受限制,标记为 P2;后续写专门的 helper binary |
| **M3 DNS rebinding**(解析时 vs 连接时 IP 不同) | 已 pin 第一个解析 IP,防止 rebinding |
| **M3 启动顺序**:proxy 必须早于 bwrap | 用 `tokio::time::sleep(100ms)` 简单解决;长期应等 proxy ready 信号 |
| **M2 sentinel 文件权限**:agent 可能改全局目录权限导致读不到 | 已 chmod 0o444 + ro-bind 双重保护 |

---

## 十、一句话总结

> 本设计稿给出 sbx-daemon 补齐 7 个缺失能力的**完整实现路径**:
> - 3 个 P0 模块(强制 deny、凭据 sentinel、SOCKS5 代理)= ~670 LOC + 2 周
> - 2 个 P1 模块(USER_NOTIF、stderr 标注)= ~310 LOC + 1 周
> - 2 个 P2 模块(OOM、PID 1)= ~200 LOC + 1 周
>
> **每个模块都有**接口签名 + 集成点 + 测试要点 + 参考代码位置,AI coder 可以**按章节顺序直接照着实现**。