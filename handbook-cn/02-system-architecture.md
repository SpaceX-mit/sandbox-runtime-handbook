# 02 — 系统架构

## 2.1 进程拓扑

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                  HOST                                       │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                srt (Node ≥ 20 编排器进程)                           │    │
│  │                                                                     │    │
│  │  ┌──────────────────┐    ┌────────────────────┐  ┌─────────────┐    │    │
│  │  │  SandboxManager  │───▶│  HTTP 正向代理     │  │ SOCKS 代理  │    │    │
│  │  │   (单例)         │    │   (多路复用前端,    │  │ (后端挂在   │    │    │
│  │  │                  │    │    单 TCP 端口)    │  │  同一个多路 │    │    │
│  │  │                  │    │                    │  │  复用端口)  │    │    │
│  │  │                  │    │  - CONNECT: TLS    │  │             │    │    │
│  │  │                  │    │    中止           │  │  - SOCKS5   │    │    │
│  │  │                  │    │  - filterRequest   │  │  - 过滤     │    │    │
│  │  │                  │    │  - sentinel 注入   │  │  - 父级     │    │    │
│  │  │                  │    │  - 父级代理        │  │    代理     │    │    │
│  │  └──────────────────┘    └────────────────────┘  └─────────────┘    │    │
│  │            │                       │                                 │    │
│  │            │                       │                                 │    │
│  │  ┌─────────▼───────────┐  ┌────────▼────────────┐                  │    │
│  │  │ linux-violation-    │  │ credential sentinel │                  │    │
│  │  │ monitor (SECCOMP_   │  │ 注册表 + 掩码       │                  │    │
│  │  │ RET_USER_NOTIF)     │  │ 文件存储           │                  │    │
│  │  └─────────────────────┘  └─────────────────────┘                  │    │
│  │            │                                                       │    │
│  │  ┌─────────▼─────────────────────────────────────────────────────┐  │    │
│  │  │              SandboxViolationStore (进程内)                  │  │    │
│  │  └───────────────────────────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│       ┌──────────────┐          ┌──────────────────────────────────┐         │
│       │ socat 桥接    │◀─────────│ bwrap 沙箱 (Linux)               │         │
│       │ (Unix sock → │ Unix     │  --unshare-net, --unshare-pid,   │         │
│       │  TCP → 代理) │ socket   │  --unshare-user, bind-mount       │         │
│       └──────────────┘          │  ─────────────────────────────── │         │
│                                 │  apply-seccomp (PID 1)           │         │
│                                 │  │                               │         │
│                                 │  ├─ socat 3128 → Unix            │         │
│                                 │  ├─ socat 1080 → Unix            │         │
│                                 │  └─ 用户命令 (BPF 已生效)        │         │
│                                 └──────────────────────────────────┘         │
│                                                                             │
│       ┌──────────────────────────────────────────────────────────────┐      │
│       │ sandbox-exec (macOS)                                          │      │
│       │   每个 wrap 时动态生成的 Seatbelt profile                     │      │
│       │   ──────────────────────────────────────────────              │      │
│       │   <用户命令>                                                  │      │
│       └──────────────────────────────────────────────────────────────┘      │
│                                                                             │
│       ┌──────────────────────────────────────────────────────────────┐      │
│       │ srt-win.exe runner → 受限 token 子进程 (Windows)             │      │
│       │   (broker → CreateProcessWithLogonW → runner as srt-sandbox    │      │
│       │    → 受限 token + job 对象 → <用户命令>)                     │      │
│       └──────────────────────────────────────────────────────────────┘      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 边界事实

1. **编排器(Node 进程)始终在所有沙箱之外。** 它拥有代理、违规存储和生命周期。
2. **沙箱进程始终是编排器的子进程。** 通过 `wrapWithSandbox(Argv)` 的输出用 `spawn` 调用。
3. **代理从不运行在沙箱内。** 它们运行在宿主编排器的 127.0.0.1 端口上。编排器的 `proxyAuthToken`(16 字节随机十六进制)把关,这样其他宿主进程拨号 loopback 端口无法触达 `filterNetworkRequest`。
4. **原生辅助程序(`apply-seccomp`、`srt-win.exe`)位于边界上。** 它们是用最小代码封装的 OS 原语 shim。

## 2.2 模块映射

| 模块                                 | 职责                                                                                                                                | 代码行数(约) |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| `cli.ts`                              | commander 驱动的 `srt` 命令。默认子命令 → 运行命令;`windows-install`/`windows-uninstall` 自提升的一次性命令。                       | 285 |
| `sandbox/sandbox-manager.ts`          | 单例编排器。掌管代理、ACE、seccomp 监控、MITM CA、sentinel 注册表。公共表面封装在 const 对象后。                                       | 2000 |
| `sandbox/sandbox-config.ts`           | Zod schemas;superRefinement 用于跨字段合法性(injectHosts ⊆ allowedDomains、tlsTerminate 与 mitmProxy 互斥等)。                       | 850 |
| `sandbox/sandbox-schemas.ts`          | 内部 TS 类型(FsReadRestrictionConfig、FsWriteRestrictionConfig、NetworkRestrictionConfig)。                                          | 80  |
| `sandbox/sandbox-violation-store.ts`  | 进程内事件存储,以编码后命令为键。Append-only,公共读 API。                                                                          | 150 |
| `sandbox/http-proxy.ts`               | HTTP 正向代理:CONNECT 处理、TLS 中止、MITM unix-socket 路由、逐请求过滤、头部变更、父级代理。                                          | 1100 |
| `sandbox/socks-proxy.ts`              | SOCKS5 正向代理:ADDRESS 解析、canonicalizeHost、主机过滤回调、父级代理。                                                              | 350 |
| `sandbox/mux-proxy.ts`                | 单 TCP 端口前端,根据首字节分发到 HTTP 或 SOCKS5 后端。                                                                               | 350 |
| `sandbox/mitm-ca.ts`                  | 临时或用户提供的 CA。构造信任包(CA + 宿主根 + extraCaCertPaths)。CRL 生成。                                                          | 380 |
| `sandbox/mitm-leaf.ts`                | 用 CA 签发的每个主机名叶子证书。                                                                                                    | 250 |
| `sandbox/tls-terminate-proxy.ts`      | peek ClientHello,然后用铸造的叶子升级 socket 为 TLS;对真实 TLS 上游转发解密字节。                                                  | 350 |
| `sandbox/parent-proxy.ts`             | 直连 vs 父级代理辅助。NO_PROXY 解析和 CIDR 匹配。                                                                                    | 220 |
| `sandbox/request-filter.ts`           | 把 `IncomingMessage` 适配为 Web 标准 `Request`;tee body 用于过滤检查;失败即拒绝。                                                   | 170 |
| `sandbox/credential-sentinel.ts`      | Symbol-keyed 映射:sentinel 字符串 ↔ 真实 secret。`injectHosts` 访问控制。                                                            | 110 |
| `sandbox/credential-mask-files.ts`    | 读真实文件、注册 sentinel、向受管临时目录写入假文件。整文件掩码与正则抽取两种模式。                                                  | 280 |
| `sandbox/macos-sandbox-utils.ts`      | 构造 SBPL profile 文本;输出 `(allow/deny file-read*|file-write*|network-*)` 规则;`wrapCommandWithSandboxMacOS` → `sandbox-exec -p <…> -- <cmd>`。 | 1100 |
| `sandbox/linux-sandbox-utils.ts`      | `bwrap` argv 合成(mount 命名空间、--unshare-net、bind mounts),危险路径 ripgrep 检测,seccomp 集成,通过 socat 网络桥。                | 1500 |
| `sandbox/windows-sandbox-utils.ts`    | spawn `srt-win` argv 合成(`acl grant/stamp/revoke/restore`)、`wfp status|verify`、ACE 展开、install/uninstall 自提升。                | 2500 |
| `sandbox/linux-violation-monitor.ts`  | `SECCOMP_RET_USER_NOTIF` 过滤(`apply-seccomp` 端)+ Unix socket 上的 JSON 行接收器。通过 `/proc/<pid>/{cwd,fd/N}` 解析路径。           | 250 |
| `sandbox/sandbox-utils.ts`            | 跨 OS 工具:路径规范化、glob-to-regex、默认写路径、危险文件/目录列表。                                                                | 450 |
| `sandbox/domain-pattern.ts`           | 通配符后缀匹配,IP 字面量被拒绝。运行时主机过滤和配置校验共用。                                                                      | 80  |
| `sandbox/listen-in-range.ts`          | 将多路复用前端绑定到 `[low, high]` 区间内的空闲 TCP 端口(Windows 上用于 WFP PERMIT 范围内)。                                         | 60  |
| `sandbox/generate-seccomp-filter.ts`  | 定位(`apply-seccomp-x64` / `apply-seccomp-arm64`)当前架构。构建期预生成的过滤码在 `vendor/seccomp-src/seccomp-unix-block.c` 中烘焙。 | 80  |
| `utils/config-loader.ts`              | 读/解析 `~/.srt-settings.json`(zod 校验)。支持 control-fd 实时更新(JSON 行协议)。                                                  | 90  |
| `utils/debug.ts`                      | `logForDebugging(msg)` 受 `SRT_DEBUG=1` 控制。                                                                                       | 30  |
| `utils/platform.ts`                   | `getPlatform()` → `'darwin'|'linux'|'win32'|'wsl'`(经 `/proc/version`)。                                                            | 30  |
| `utils/shell-quote.ts`                | POSIX shell 引号转义(`'a b' → "'a b'"`)。                                                                                          | 50  |
| `utils/which.ts`                      | PATH 查找(Node 不再内建 `which`)。                                                                                                  | 30  |
| `utils/ripgrep.ts`                    | 异步 rg 子进程,支持 depth/glob 标志。                                                                                              | 50  |
| `vendor/seccomp-src/apply-seccomp.c`  | 单个静态二进制,~600 行。Unshare(pid+mounts(+user fallback))、fork outer stub、fork inner init、fork worker;worker 安装 BPF + exec。    | 600 |
| `vendor/srt-win-src/src/*.rs`         | Rust 辅助程序,提供单一 CLI:`install`、`uninstall`、`exec`、`wfp status|verify`、`acl grant|revoke|recover|stamp|restore`、`user status|trust-ca`。约 2 万行。 | — |

## 2.3 OS 原语边界选型

| OS      | 文件系统强制                                    | 网络强制                                                                                                | Unix 套接字                                                                                           | PTY | 违规反馈 |
| ------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | --- | -------- |
| macOS   | Seatbelt(`sandbox-exec -f <(echo)`)在 wrap 时生成;glob 通过 `regex` 匹配;`file-write-create`/`file-write-unlink` 被拒以阻断 symlink 替换攻击。 | 代理仅监听 localhost:<port>;`(allow network-outbound (remote ip "localhost:PORT"))`                     | `allowUnixSockets` / `allowAllUnixSockets`                                                            | `allowPty: true` → `(allow pseudo-tty)` 与 `/dev/ptmx`+`/dev/ttys*` | `log stream --predicate 'message CONTAINS "<logTag>"'` 通过 `node:os` `log` API 解析 |
| Linux   | `bwrap --unshare-{net,pid,user}` + 递归 bind mounts(`--ro-bind / /`,然后 `--bind <allow> <allow>` 用于写,`--ro-bind /dev/null <deny>` 用于不存在的 deny,`--tmpfs <deny>` 用于已存在的目录);必拒文件同方式挂载 | `bwrap --unshare-net` + 2 个 `socat TCP-LISTEN:<port>,fork UNIX-CONNECT:<unix-sock>`;宿主代理监听固定 TCP 端口;去除 IP 后,只有 loopback 桥可达 | `socket(AF_UNIX)` 被 seccomp BPF 拦截(`SECCOMP_RET_ERRNO|EPERM`),当 `network.allowAllUnixSockets === false` 时;另阻断 `io_uring_setup/enter/register`(5.19+ `IORING_OP_SOCKET` 旁路) | 不适用 | `SECCOMP_RET_USER_NOTIF` 过滤写意图 fs 系统调用;监控上报每次尝试(允许或拒绝);store 根据 `allowWrite`/`denyWrite` 去重 |
| Windows | NTFS ACL,在 `initialize()` 时盖印在 **配置定义** 的路径上:`allowWrite` → `(OI)(CI) MODIFY_NO_FDC` ALLOW;`allowRead` → `(OI)(CI) READ|EXECUTE`;`denyRead`/`denyWrite` → 目标显式 DENY + 父目录 `(OI)(CI) FILE_DELETE_CHILD` DENY。`reset()` 时清理 ACE(尽力而为) | 安装时一次设定 `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`:按 `ALE_USER_ID==<sandbox SID>` BLOCK;按 `(127.0.0.0/8 OR ::1) AND remote port ∈ [lo, hi]` PERMIT。代理绑定在 `[lo, hi]` 内 | 不在 OS 层强制;sandbox 用户 SID 的默认拒绝施加在所有出站 | 不适用 | v1 未实现 |

## 2.4 生命周期(CLI)

```
              ┌────────┐
              │ argv   │
              └───┬────┘
                  │  commander parse
                  ▼
         ┌────────────────────┐
         │  加载配置           │  从 $HOME/.srt-settings.json OR --settings OR 默认
         │  (zod 校验)         │
         └────────┬───────────┘
                  │
                  ▼
         ┌────────────────────┐
         │ SandboxManager.    │  启动 HTTP 代理、SOCKS 代理、mux 前端
         │  initialize(cfg)   │  可选:macOS 日志监控、Linux SECCOMP_RET_USER_NOTIF 监控
         └────────┬───────────┘
                  │
                  ▼   (每个命令)
         ┌─────────────────────────┐
         │ wrapWithSandbox(argv)   │  返回一个宿主编排器可执行的 shell 字符串;
         │  或 wrapWithSandboxArgv │  Windows 上返回 argv[] + env 给 {shell: false}
         └────────┬────────────────┘
                  │
                  ▼
         ┌────────────────┐
         │ spawn(...)     │  stdio: inherit,信号转发,abort 处理
         └────────┬───────┘
                  │
                  ▼  (子进程退出)
         ┌──────────────────────────────┐
         │ cleanupAfterCommand()        │  仅 Linux:删除 bwrap 空挂载点
         │                              │  activeSandboxCount 递减
         │ reset() on exit/SIGINT/SIGTERM│
         └──────────────────────────────┘
```

## 2.5 跨切关注点

| 关注点            | 模式                                                                                                                                                                                                                                  |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 幂等性            | `initialize` 与 `reset` 都是可重入的;清理对 bwrap mount-point 引用计数;Windows 上 ACE 撤销在 `reset()` 时尽力而为。                                                                       |
| 并发              | 管理器状态(config、代理句柄)对编排器进程来说单线程;代理本身是异步(Node net.Server / Bun)。跨进程安全通过 WFP 持久化和 Windows 上的 DPAPI machine scope 实现。                                                                       |
| 错误处理          | `initialize` 期间失败同步抛出(调用方永远不会看到半初始化沙箱)。`wrapWithSandbox` 期间的失败向上传递;平台构建器返回错误字符串,用户在运行期看到。                                                                                |
| 配置热重载        | 网络规则可热替换(`updateConfig`)。文件系统规则要求 `reset()` + `initialize()`。在 Windows 上,当文件访问集合变化时 `updateConfig` 时给出警告。                                                                                                |
| 日志              | `logForDebugging(msg, {level})`(debug/info/warn/error),受 `SRT_DEBUG=1` 控制。默认情况下不打印日志,以保持 stdout 干净。                                                                                                               |
| 追踪              | 沙箱 profile 嵌入唯一 `logTag`(`CMD64_<base64-encoded-command>_END_<random>_SBX`),以便 macOS 日志流和 Linux 监控 JSON 流按子进程精确过滤。                                                                                              |
