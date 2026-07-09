# 15 — 术语表

本手册中使用的术语按字母顺序的简短参考。

| 术语                    | 含义                                                                                                                                  |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **ACD**                 | Access Control Entry —— NTFS ACL 中的单个 allow/deny 规则。                                                                     |
| **ACE**                 | Access Control Entry —— 同 ACD(Windows 术语)。                                                                                                      |
| **audit arch**          | 内核的每架构标识符(`seccomp_data.arch`,如 `AUDIT_ARCH_X86_64`)。用于按架构门控 BPF 程序。                                                              |
| **ask callback**        | 用户提供的 `(host,port) => boolean`,在无规则匹配时由代理调用。"权限对话框"的编程形式。                |
| **agent**               | 一个更高级别的工具(通常是 LLM),包装任意命令;`srt` 是 agent 用以更安全的一层之一。                |
| **ale_user_id**         | 按出站连接的载体令牌中的用户 SID 键控的 WFP 条件。                                                                            |
| **ambient capability**  | 跨 `execve` 存活的 Linux 能力。srt 的 `apply-seccomp` 在 worker `execve` 之前清空它们。                            |
| **apparmor_restrict_unprivileged_userns** | Ubuntu 24.04 sysctl,从 `CLONE_NEWUSER` 剥离 caps。建议禁用。                                          |
| **bwrap**               | bubblewrap —— 一个小的 setuid-free 二进制,创建 user/pid/net/mount 命名空间并绑定挂载。    |
| **bfe**                 | Base Filtering Engine —— 运行 WFP 的 Windows 服务。                                                                                |
| **bind mount**          | mount(2) 调用,使一个目录出现在另一个路径。`--bind <src> <dst>`。                                          |
| **bp filter / bpf**     | Berkeley Packet Filter —— Linux 内核 VM,为 seccomp 所用。                                                                         |
| **cdp**                 | CRL Distribution Point —— X.509 证书中的扩展,指向 CRL 所在的 URL。                                                            |
| **canonical host**      | 主机名的规范化形式(小写、无尾点、十进制 IPv4 → 点分形式等)。                                     |
| **cert store**          | Windows 专有证书库。`CurrentUser\Root` 是 schannel 查找信任锚的地方。                                   |
| **cli**                 | 命令行接口。`srt` 二进制。                                                                                                        |
| **cll (cap list)**      | 进程 token 的能力列表。                                                                                                      |
| **connector**           | macOS `sandbox-exec` profile 操作,允许向特定远程的网络绑定/入站/出站。                                |
| **container inherit (CI)** / **object inherit (OI)** | NTFS ACE 标志,使规则传播到保护目录内的新文件/子目录。                                |
| **coredump / dumpable** | 进程的 "may-be-ptraced" 标志。`PR_SET_DUMPABLE=0` 使进程不可被 ptrace。                                                     |
| **connect (SOCKS5)**    | SOCKS5 动词 `0x01` —— 代理初始化到所请求远程的 TCP 连接。                                                          |
| **cpuid**               | CPU 架构标识符,用于可信代码识别。                                                                                |
| **crl**                 | Certificate Revocation List。用于传达链中无证书已被吊销。                                        |
| **cwd**                 | 当前工作目录。                                                                                                               |
| **dacl**                | Discretionary Access Control List —— NTFS 安全描述符中持有 ACE 的部分。                                              |
| **dispatcher**          | 在多路二进制模式中,二进制的 argv\[1] 是 `--srt-win`,二进制 main() 路由到正确的子命令。                   |
| **dpapi**               | Windows Data Protection API。加密数据绑定到用户或机器作用域。用于在静态加密沙箱用户的密码。        |
| **dynamic plist**       | 每次调用 feed 给 `sandbox-exec -f` 的 `.sb` profile 文件,与嵌入在 argv 中的 -p 相对。                                                   |
| **epem (Ephemeral)**    | 在会话启动时生成的短期 CA。存于 `state.db`(Windows)或临时目录(其他),在 reset 时销毁。    |
| **execve**              | Linux `execve(2)` 系统调用 —— 用新镜像替换当前进程。                                                           |
| **filesystem disabled**  | `filesystem.disabled: true` —— 绕过所有文件系统规则生成。文档化的逃生口。                                            |
| **filter callback**     | `network.filterRequest` —— 编程细粒度的 HTTP 级过滤器,在 allow/deny 决策后运行。                                       |
| **fwpm**                | C 风格的 Windows Filtering Platform API(`Fwpm*` 函数)。                                                                          |
| **fwp_value0**          | 持有单个 WFP 条件值的变体结构。                                                                                  |
| **host**                | 主机 OS + 宿主用户,从编排器视角看。                                                                            |
| **hostname canonicalization** | 在模式匹配前让主机名一致(如尾点、小写化)。                                               |
| **idempotent install**  | 再次运行 `install` 不会破坏;而是轮换密码 + 调和过滤器。                                                  |
| **impersonate**         | 为另一用户获取线程令牌(用于在沙箱用户的注册表中安装 CA)。                                         |
| **io_uring**            | 异步 IO 内核 API;Linux 5.19+ 还能做 socket 操作,所以我们阻断它。                                                                |
| **ipc-posix-shm / sem** | POSIX 共享内存/信号量的 SBPL 权限。Python multiprocessing 需要 `sem`。                                            |
| **job object**          | Windows 内核对象;聚合进程杀除 + 内存限制。Windows 上用作沙箱边界。                                  |
| **js proxy**            | Node 端 HTTP/SOCKS 正向代理,执行 allow/deny。                                                                         |
| **kdump**               | Linux 内核崩溃转储。srt 不触发此,但应用者应知道 BPF bug 可触发它。                              |
| **last-match-wins**     | SBPL 规则顺序 —— profile 中后输出的规则覆盖同操作/路径的早输出规则。                                                                                                           |
| **leaf cert**           | 由 MITM CA 签发的每主机名 X.509 证书,服务给沙箱中与代理通信的工具。                                 |
| **listen-in-range**     | 将 mux-proxy 前端绑定到 `[low, high]` 区间内的空闲 TCP 端口。Windows 上 WFP 围栏此区间时使用。                         |
| **log monitor**         | 沙箱违规反馈 —— macOS 统一日志订阅或 Linux SECCOMP_RET_USER_NOTIF supervisor。                                       |
| **logTag**              | 嵌入每个 SBPL `(with message ...)` 的唯一标识符,用于按命令过滤 macOS 日志行。                                 |
| **look-up**             | mach-lookup —— macOS 上的 XPC 服务命名;显式 profile。                                                                        |
| **luid**                | Logon ID —— Windows 特定会话标识符。                                                                                     |
| **mitm_ca**             | MITM CA(X.509 证书 + 私钥),用于铸造被中止 TLS 连接的叶子。                                       |
| **macos seatbelt**      | Apple 的沙箱 profile 语言(SBPL)。                                                                                                 |
| **mcp**                 | Model Context Protocol —— srt 的常见嵌入上下文;不被特定依赖。                                                          |
| **namespace**           | Linux 内核概念:标识符的单独映射(挂载、PID、网络、用户)。bwrap 进行 unsharing。                           |
| **node-forge**          | srt 的 MITM 路径中使用的纯 JS X.509 + RSA 实现。                                                                         |
| **notify fd**           | `SECCOMP_FILTER_FLAG_NEW_LISTENER` 返回的内核侧监听器 FD。让 supervisor 接收 USER_NOTIF 回调请求。    |
| **openat**              | Linux `openat(2)` 系统调用 —— `open(2)` 的 *at 族变体。                                                                      |
| **parent proxy**        | 编排器自身用来访问互联网的 HTTP/SOCKS 代理。用于宿主在公司代理后面时。                   |
| **pbac (per-exec)**     | 自定义配置传给 `wrapWithSandbox(...)`,仅覆盖你指定的字段。                                                                      |
| **pidfd**               | 引用进程的 Linux FD —— 用于不通过轮询等待 `pid_exit`。                                                                  |
| **posix sem / shm**     | POSIX 信号量/共享内存。Python multiprocessing 使用;SBPL 允许。                                                |
| **profile**             | SBPL 文本字符串;有时称为 `.sb` 语法。                                                                                  |
| **proxyAuthToken**      | 每会话生成的 16 字节十六进制随机串;HTTP/SOCKS5 鉴权所需。                                                          |
| **ptrace_scope**        | Yama sysctl —— 控制哪些进程可以 ptrace 彼此。srt 依赖于处于独立 PID 命名空间,而不是 ptrace_scope。    |
| **rbac**                | 基于角色的访问控制 —— 另一种 NTFS 概念(权限,不是 DACL)。                                                              |
| **registry (HKU)**      | Windows 注册表中的每用户 hive;沙箱用户的 `CurrentUser\Root` 证书库位于 `HKEY_USERS\<sid>\…\Root`。            |
| **revocation checking** | Schannel 的在线 CRL/OCSP 获取 —— 其 CDP 不可达的沙箱会让 TLS 失败。我们服务空 CRL 让它保持存活。                 |
| **ripgrep**             | 用于在 Linux 上的子目录中查找必拒文件的搜索工具。                                                                      |
| **sandbox-exec**        | Apple 的用户态沙箱引擎。接收 SBPL profile 作为输入。                                                                |
| **sbpl**                | Sandbox Profile Language —— Seatbelt 的 SBPL 语法。                                                                                |
| **seatbelt**            | Apple 的沙箱内核子系统(也是整个家族的通用术语)。srt 的 SBPL profile 目标是内核 Seatbelt。           |
| **seccomp**             | 使用 BPF 程序过滤系统调用的 Linux 内核特性。                                                                         |
| **SECCOMP_RET_USER_NOTIF** | 截获 syscall 进入用户态监听器的 seccomp 返回码(supervisor)。                                                |
| **SECCOMP_IOCTL_NOTIF_*_RECV/SEND** | supervisor 用于读通知与回复的两个 ioctl。                                                       |
| **schannel**            | Windows 的 TLS 实现;只信任 OS 证书库。                                                                              |
| **sentinel**            | 用于在沙箱内掩码真实凭证的占位字符串。格式:`<srt:NAME:32-hex>`。                                       |
| **session**             | 编排器的一次进程调用(从 `initialize` 到 `reset`/exit)。                                                          |
| **shell-quote**         | `utils/shell-quote.ts` 中的 POSIX shell 引号转义工具。                                                                                   |
| **signal forwarding**   | 编排器通过 `child.kill` 将 SIGINT/SIGTERM 转发到沙箱子进程。                                                        |
| **state.db**            | Windows 端的 SQLite 数据库位于 `%LOCALAPPDATA%\sandbox-runtime\state.db`,存储 DPAPI 凭据、ACE 记录、CA 证书。       |
| **stripHopByHop**       | 代理转发中应用的 RFC 7230 hop-by-hop 头部移除。                                                                          |
| **subprocess**          | 由编排器通过 `spawn()` 生成的子进程。                                                                              |
| **symlink outside boundary** | 通过 symlink 解析到 allowWrite 之外的路径。                                                               |
| **sysctl**              | Linux 内核可调参数(如 `kernel.yama.ptrace_scope`)。SBPL 白名单特定 sysctl 读/写。                                    |
| **tcsd / tcsm**         | Apple 特定 sysctl 相关术语,用于 SBPL sysctl-read 白名单。                                                              |
| **tee (body tee)**      | HTTP 代理中的 `Readable.toWeb(req).tee()` 分割,给过滤器回调一个流,给上游转发一个流。                                                  |
| **tls-terminate-proxy** | CONNECT handler,使用新铸造的叶子将 TCP 套接字升级到 TLS。                                                       |
| **tmpfs**               | RAM 支持的文件系统;在 bwrap 中用于 `/tmp`、`/run` 等,作为拒绝机制(`--tmpfs <deny>`)。                          |
| **token (Windows)**     | 附加到进程的安全令牌;`CreateRestrictedToken` 删除权利。                                                         |
| **trust bundle**        | 沙箱子读取为 CA 根的 PEM 文件;合并 MITM CA + 宿主常规根 + 额外。                                |
| **trustd.agent**        | 验证 TLS 证书的 macOS 服务;受 `enableWeakerNetworkIsolation` 门控。                                                  |
| **unshare**             | Linux `unshare(2)` 系统调用;bwrap 命名空间的支柱。                                                                         |
| **user-notif**          | SECCOMP_RET_USER_NOTIF。用于 Linux 违规监控。                                                                              |
| **violation event**     | `SandboxViolationStore` 中的单个记录。                                                                                              |
| **violation store**     | `SandboxViolationStore` 实例。                                                                                                        |
| **vnode-type**          | Seatbelt 上的文件类型过滤器(如 `CHARACTER-DEVICE`、`DIRECTORY`)。                                                                |
| **wfp**                 | Windows Filtering Platform。                                                                                                              |
| **wfp / wfpStatus**     | `windows-sandbox-utils.ts` 的子模块,返回当前 WFP 过滤器状态(仅管理员)。                                           |
| **workspace**           | 用户在 `wrapWithSandbox(...)` 时的工作目录(`process.cwd()`)。                                                    |
| **x32**                 | x86_64 下的 ILP32 调用约定。被 BPF 过滤器阻断。                                                                    |
| **zero-runtime-deps**   | 里程碑:打包中预编译的二进制;安装时无 `gcc`/`cargo`。                                                |
| **observe_calls[]**     | 在 `apply-seccomp.c` 中,被 SECCOMP_RET_USER_NOTIF 过滤拦截的 syscall 列表。                                        |
| **encoded command**     | 命令的 base64 编码形式,在 logTag 与 observe JSON 头行中使用。                                                                  |
| **host process**        | 主协调进程的 Node 进程。                                                                                                                                                |

### 缩略语索引

| 缩略语          | 含义                                                      |
| ---------------- | ------------------------------------------------------------ |
| ACL              | Access Control List (Windows)                                |
| ACE              | Access Control Entry                                          |
| AKI              | Authority Key Identifier (X.509)                              |
| AU               | Audit (e.g. AUDIT_ARCH_X86_64)                                |
| BFE              | Base Filtering Engine                                         |
| BPF              | Berkeley Packet Filter                                       |
| CA               | Certificate Authority                                         |
| CDP              | CRL Distribution Point                                         |
| CRL              | Certificate Revocation List                                    |
| DACL             | Discretionary Access Control List                              |
| EOF              | End of File                                                   |
| IPC              | Inter-Process Communication                                    |
| LSA              | Local Security Authority (Windows)                            |
| MITM             | Man-In-The-Middle                                              |
| NS / NS          | Namespace                                                      |
| OS               | Operating System                                                |
| PTY              | Pseudo-Terminal                                                 |
| RPC              | Remote Procedure Call                                          |
| SBPL             | Sandbox Profile Language                                        |
| SID              | Security Identifier                                             |
| SKI              | Subject Key Identifier                                          |
| SSH              | Secure Shell                                                    |
| TCC              | Transparency, Consent, and Control (macOS)                     |
| TCP              | Transmission Control Protocol                                    |
| TLS              | Transport Layer Security                                         |
| URI / URL        | Uniform Resource Identifier / Locator                           |
| XPC              | macOS 上的进程间通信                                            |
