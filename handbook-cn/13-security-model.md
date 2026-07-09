# 13 — 安全模型

本文档是威胁模型与安全不变式。枚举运行时防御什么,不防御什么,以及防御如何分层。

## 13.1 威胁模型

### 范围内对手

1. **被入侵的沙箱工具** —— 被 `srt` 包装的工具。该工具可能:
    - 读取不该读的文件(`~/.ssh`、`/etc/shadow` 等)。
    - 写入不该写的文件(`.git/hooks/pre-commit`、shell rc 文件)。
    - 打开任意 TCP 连接(DNS rebinding、外泄)。
    - 生成试图继承工具权限的子进程。
    - 尝试绕过域模式检查(`*.attacker.com\x00.example.com`)。
    - 通过 symlink、竞争条件、fd-passing 尝试逃逸。

2. **同一宿主上的被动观察者** —— 能读 `/proc`、查看编排器 stdout、或拨号 `127.0.0.1:<port>` 的另一进程。
   - 我们通过 **16 字节 token 鉴权代理** 来防御。
   - 通过 Windows 上的 **state.db DACL** 来防御。
   - 通过 Linux 上仅 Unix-domain socket 来防御。

3. **路径上的网络攻击者** —— 宿主机和上游之间的任何人:
   - 如果 SRT 已中止 TLS,导致 TLS MITM。
   - 读取 TLS 字节(仅当 SRT 在攻击者上游中止;我们始终以 `rejectUnauthorized:true` 与宿主捆绑根或额外根 re-originate)。
   - 伪造到白名单主机名的 DNS 响应。

### 范围外对手

1. **宿主上有 `root`/`admin` 的用户** —— 他们能 dump `/proc/<pid>/mem` 或将调试器附加到编排器。我们帮不了。安装/卸载提权步骤是用户自己的选择。
2. **内核级入侵** —— rootkit、BPF 程序滥用、侧信道攻击。超出范围。
3. **编排器操作员的胁迫** —— 用户自己运行工具。社工是另一个问题。

## 13.2 纵深防御

防御是 **分层的**。攻击者必须突破多层:

| 层                         | 它做什么                                       | 防御什么                                                          |
| ----------------------------- | -------------------------------------------------- | ------------------------------------------------------------------- |
| **文件系统隔离**      | 通过 OS 原语进行读/写 deny。                  | 源码/密钥的读/写泄漏。                          |
| **网络隔离**         | 所有出站通过本地代理。                  | 直接 TCP/UDS 到互联网。                                   |
| **代理过滤**              | 域 allow/deny + 每请求过滤回调。   | 需要更细规则(例如 GitHub 上的 `PUT`)的白名单主机。   |
| **代理鉴权**                | 每个请求需要 16 字节十六进制 token。       | 宿主进程拨号 loopback 代理。                   |
| **必拒**            | 始终阻断危险文件(`.git/hooks`、`.bashrc` 等)。          | 允许写入敏感文件的入侵。                  |
| **移动阻断 deny**      | 在保护路径及其祖先上拒绝 `file-write-unlink` 与 `file-write-create`。 | `mv foo bar && rm foo` 风格的逃逸。                |
| **TPM/DPAPI** (仅 Windows)  | `state.db` 凭据静态加密。            | 磁盘盗窃/冷启动。                                       |
| **沙箱用户** (仅 Windows) | 沙箱子进程作为专用 SID 运行。            | 通过任务计划程序/COM 的跨会话 SID 劫持。        |
| **WFP 围栏** (仅 Windows)  | 内核按 SID 过滤出站。                     | 沙箱用户内的 token 劫持。                      |
| **TLS 中止**           | 可选的进程内 TLS 中止 + 签名叶子。 | 服务端锁定 / mTLS 上游。                          |
| **Sentinel 替换**     | 隐藏的真实 secret 值,仅在出口替换。 | 工具运行期外泄 secret。                  |
| **违规流**            | 记录每次被拒尝试(mac、Linux)。           | 内部监控 / 用户对话框。                           |

## 13.3 关键不变式

这些不变式在实现正确时成立。绕过任一都是 CVE。

### 网络不变式

1. **沙箱进程不经代理无法访问互联网。**
   - macOS:SBPL `(allow network-outbound (remote ip "localhost:<port>"))` 是唯一出站规则。
   - Linux:`--unshare-net` 加 `socat` 桥意味着没有网卡。
   - Windows:WFP 过滤器 `(allow) 127/8:[lo..hi]` 加 `(block) <sandbox SID>` 是穷尽的。

2. **代理鉴权每个请求。**
   - HTTP:`Proxy-Authorization: Basic srt:<token>`。
   - SOCKS5:RFC 1929 USER/PASS `srt:<token>`。

3. **deny 列表先于 allow 列表检查。**
   - `filterNetworkRequest` 顺序:`deniedDomains` 先,然后 `allowedDomains`,然后可选回调。

4. **主机名规范化在匹配前发生。**
   - `canonicalizeHost` 在 `matchesDomainPattern` 前运行,以击败 IPv4/整数歧义、尾点等。

5. **代理验证主机名不含控制字节。**
   - `isValidHost` 拒绝 NUL、`%` 等。

### 文件系统不变式

1. **发到 OS 原语的所有文件路径都已规范化。**
   - `~` 展开跨平台一致应用。
   - 尾 `/**` 被剥离(`removeTrailingGlobSuffix`)。
   - Glob 字符被展开(Linux)或转为 regex(macOS)。

2. **必拒始终胜出。**
   - 即使 `allowWrite: ['.']` 也不能写入 `.git/hooks/pre-commit`。
   - macOS profile 最后输出;Linux wrapper 在 bind 循环之后输出;Windows 先盖印再 grant。

3. **移动阻断保护拒绝路径的 `mv` 与 `unlink`。**
   - macOS SBPL 与 Linux bwrap 都阻止取消父目录的链接。
   - Windows 上,父目录上的 ACE `FILE_DELETE_CHILD` DENY。

4. **读允许路径内的读 deny 路径显式重新 deny。**
   - 末位匹配胜出是 macOS 规则;算法跟踪这点。
   - Linux 上,bind-mount 语义正确处理 re-allow。

5. **检测到 symlink-write-traversal。**
   - `realpathSync` + `isSymlinkOutsideBoundary` 拒绝 `allowWrite: ['/tmp/link']`,如果链接指向任何允许区域之外。

### 凭证不变式

1. **真实凭证从不进入沙箱进程地址空间。**
   - 例外:mode='mask' with `allowPlaintextInject` 是显式 opt-in。

2. **真实凭证仅经 TLS 中止连接离开宿主。**
   - 发往 `injectHosts` 中白名单主机时。

3. **Sentinel 按会话唯一。**
   - `<srt:NAME:32-hex>` —— 随机 nonce 防止跨会话关联。

4. **TLS 中止叶由沙箱子进程信任的同一 CA 铸造。**
   - 每次 `initialize()` 时 `state.db` 指纹检查。
   - CRL 分发点从 loopback 代理服务。

### 进程级不变式

1. **编排器是唯一宿主侧进程。**
   - 所有沙箱子进程都从它生成。

2. **编排器的清理是 fail-safe。**
   - `reset` 为 exit、SIGINT、SIGTERM 注册。

3. **Linux 隔离层不能被重新附加。**
   - 内部 PID 命名空间;`PR_SET_DUMPABLE=0` 在 inner init;`ptrace_scope=0` 不起效(我们在另一个 PID ns)。

4. **Windows 沙箱用户对真实用户文件没有固有权利。**
   - ACE 写入是加性的,且是访问的唯一路径。

## 13.4 已知限制

这些在 README 中有文档,嵌入方必须理解。

### 允许广泛域名有外泄风险

允许 `github.com` 让沙箱工具可以 push 到任意仓库。代理不检查合法外观 HTTP 请求的出站 HTTPS body 内容。建议使用自定义插件策略。

### Domain fronting

工具可以向 CDN 出示 TLS SNI=`example.com` 然后隧道到不同后端。`srt` 无法防御,除非启用 `tlsTerminate`(此时代理看到协商的 HTTP/2 流并可应用 `filterRequest`)。以信任敏感的部署为目标的嵌入方应启用 TLS 中止。

### Linux 上的 Unix 域套接字

seccomp 过滤器阻断 `socket(AF_UNIX, ...)` 与 `io_uring_*`。它 *不* 阻断对继承 FD 的操作。从父进程接收 Unix 套接字 FD 的工具超出范围 —— 没有有用的方法阻止。

### Linux 代理绕过

忽略 `HTTP_PROXY` 环境变量的工具(某些老 Python、某些手工 Go、某些路由器)无法访问代理。未来改进:`proxychains` 风格 `LD_PRELOAD` 注入。

### Linux 上不存在文件的必拒

SBPL 在 exec 时评估 glob;如果文件路径匹配 `**/foo` 但加载规则时文件不存在,该文件仍会在 deny 下创建:内核按 profile 求值 syscall 并拒绝。macOS 正确处理这点;Linux 必拒是即时的(rg 只找到现存匹配)。

### Windows 注册表 / 服务配置

SID 围栏不到 `HKLM` 或 Windows 服务。创建作为不同用户运行的服务的沙箱进程...不能,因为沙箱用户的 token 受限,且默认情况下没有其他服务在该 SID 的组中。

### Windows `proxyAuthToken` 暴露

~150ms 内,token 在 runner 的 cmdline 中,具有 `PROCESS_QUERY_LIMITED_INFORMATION` 的同级宿主进程能读取它。token 也在子 env 中,所以 runner 的 cmdline 暴露是传递性因素。在单机开发机上可接受;在共享主机上是考虑因素。

### Windows TLS CRL 获取

我们从 loopback 代理服务空 CRL 以让 schannel 高兴。仍检查吊销但不采用 schannel 的工具(例如 Python 的 `verify_mode=CERT_REQUIRED` + `revocation_mode=REVOKE_CHECK`)可能在第一次 CRL 获取时硬失败。

### macOS DNS

DNS 解析器作为 `netd` / `systemd-resolved` 在沙箱外运行。DNS rebinding 部分被 `canonicalizeHost` 缓解。如果上游 DNS 被劫持,已解析 IP 仍可能在 `allowedDomains` 中。通过 TLS 证书(检查 CN/SAN,不查 IP)验证的工具受保护。

## 13.5 纵深防御模式

### Pre-spawn 验证

`SandboxManager.checkDependencies()` 在 `initialize()` 中运行 —— 不会推迟到按命令检查。缺失依赖在进程开头失败,而不是首次用户命令时。

### 无静默回退默认

`--settings <path>` 缺失文件是硬错误。CLI 永远在没有显式配置的情况下运行,除非 `~/.srt-settings.json` 缺失且未提供 `--settings`。

### 结构化日志

`logForDebugging(msg, {level: 'warn'|'error'})` 在 `SRT_DEBUG=1` 可见。库从不发出 stdout,除非用户 opt-in。

### Token 是 Token

`proxyAuthToken` 每次会话重新生成。即使泄露,也是每次运行的。

## 13.6 分层不防御什么

**编排器自身。** 如果攻击者能入侵编排器进程(例如通过读 `~/.srt-settings.json` 并写自己的 `network.allowedDomains: ['*']`),他们赢了。防御在宿主的文件系统保护层(用户主目录上的文件 ACL),而非 srt 中。

**意外的凭证泄露。** 在环境变量中被掩码的凭证也可能被粘贴到 srt 看不到的配置文件(例如工具解压出来的工具的内部存储)。srt 可以掩码 env var,但无法掩码工具自身的内部存储,除非该存储在 srt 知道含凭证的目录中。

**编排器供应链攻击。** 如果 `npm install -g @anthropic-ai/sandbox-runtime` 本身被入侵,srt 也被入侵。标准 npm/PyPI 威胁模型适用。

## 13.7 为何设计成立

Linux 沙箱成立因为:
- `bwrap` 广泛部署、已审计、被 Flatpak/Podman 使用。
- `apply-seccomp` ~600 行,完全审计,安全关键部分(BPF 程序)已被审阅。
- `--unshare-net` 移除了网卡。

macOS 沙箱成立因为:
- Apple 自 10.5 起发布 `sandbox-exec`,CVE 很少。
- `(with message "<logTag>")` 发射覆盖每个操作。
- 动态 profile 生成比每个应用写一次的 sandbox profile 更安全。

Windows 沙箱成立因为:
- `WFP` 是与 IP 栈在同一条代码路径求值的内核原语。
- `NTFS DACL` 是每个其他应用使用的同一条代码路径 —— 没有新的攻击面。
- 沙箱子进程作为不同用户运行,任何逃逸尝试现在处于沙箱用户的上下文中,它没有固有权利。

凭证注入层成立因为:
- sentinel 不透明且按会话。
- 替换发生在 JS 中,在 `filter()` 批准与 TLS 验证之后。
- TLS 信任链锚定在 srt 管理的 CA 与 srt 提供服务的 CA CRL。
