# 14 — 落地路线图

按务实顺序在其他语言中复刻该项目。每个里程碑自含且可测。

## 14.1 建议技术栈

| 关注点            | Go                                    | Rust                                   | Python                              |
| ------------------ | ------------------------------------- | -------------------------------------- | ----------------------------------- |
| CLI                | `cobra` + `urfave/cli`                | `clap`                                 | `click` 或 `typer`                  |
| 配置校验  | 手写 + validator 代码生成             | `validator` derive + 自定义            | `pydantic` v2                       |
| HTTP server        | `net/http` + `httputil.ReverseProxy`  | `axum` + `tokio`                       | `aiohttp`                           |
| TLS 中止   | `crypto/tls` + 自定义                 | `rustls` / `native-tls`                | `ssl` + 自定义                      |
| macOS 沙箱      | CGo + `sandbox-exec`                  | Objective-C rs + `sandbox-exec`        | PyObjC + `sandbox-exec`             |
| Linux bwrap        | `os/exec`                             | `std::process::Command`                | `subprocess`                        |
| Linux seccomp      | CGo + libseccomp                      | `libseccomp-rs` / 裸 syscall          | CFFI + libseccomp / ctypes          |
| Windows WFP/ACL    | `golang.org/x/sys/windows` 的 Win32 API| `windows` crate                      | pywin32 / `ctypes`                  |
| Build              | `mage` 或普通 `Makefile`              | `cargo`                                | `hatch`                             |
| Tests              | `testing` + stretchr/testify          | `cargo test`                           | `pytest`                            |

本文档假设复刻者选择其中任一种并相应调整。模块结构是与语言无关的。

## 14.2 里程碑

### M0 — 项目骨架(1 周)

交付物:加载 JSON 配置并打印其解析形式的二进制。

任务:
1. 模块布局(对应 `02-system-architecture.md` §2.2)。
2. CLI 脚手架:`srt` 命令 + 版本 + 帮助。
3. 用于 `SandboxRuntimeConfig` 等价的 JSON-schema 加载器。
4. Lint + format + test runner 接入。
5. 带使用示例的 README。

验收:`srt --help` 工作。`srt --version` 返回包版本。加载合法 JSON 打印解析对象;加载非法 JSON 出错并带有结构化消息。

### M1 — 配置 Schema(1-2 周)

交付物:基于 `03-configuration-model.md` 的完整配置校验。

任务:
1. 重新实现 `SandboxRuntimeConfig` schema 和校验器。
2. 域模式校验:
    - 拒绝 `*.com`、`*`、`*.foo.*` 等。
    - 接受 `example.com`、`*.foo.example.com`、`localhost`。
3. 路径校验:
    - 拒绝空字符串。
    - 允许 `~`、绝对、相对路径。
4. 跨字段校验:
    - `tlsTerminate.caCertPath ⇔ caKeyPath`。
    - 掩码凭证要求 `tlsTerminate` 或 `allowPlaintextInject`。
    - `injectHosts ⊆ allowedDomains` 语义。
5. 测试覆盖 ≥ 95% 的校验规则。

验收:移植 `config-validation.test.ts` 中的每个测试都通过。

### M2 — 宿主侧网络代理(3-4 周)

交付物:HTTP 和 SOCKS5 正向代理,带域过滤 + 鉴权。

任务:
1. 绑定 TCP 服务器(mux 前端可选,推迟到 M6)。
2. 实现 `parseConnectTarget("example.com:443")`。
3. 鉴权握手(HTTP 用 Basic,SOCKS5 用 USER/PASS)。
4. 过滤管线:
    - `deniedDomains` 检查。
    - `allowedDomains` 检查。
    - 可选回调。
    - `canonicalizeHost` + `isValidHost`。
5. CONNECT 处理:
    - 直连拨号(TCP connect + 回 200)。
    - 或,若配置了 `parentProxy`,通过 CONNECT 隧道。
6. 纯 HTTP 处理:
    - 检测绝对 URI 形式。
    - 转发上游。
    - 剥离 hop-by-hop 头部。
7. SOCKS5:
    - 读取问候 + 选择鉴权方式。
    - 读取 IPv4/IPv6/域名 ATYP 请求。
    - 直连或经父级。
8. 测试:`mux-proxy`、`parent-proxy`、`request-filter`、`tls-terminate-proxy` 中所有单元测试(可选部分 OK)。

验收:`host:port` 对被 deny 的域返回 403;对允许的域返回 200。鉴权 token 错误时返回 407。

### M3 — 沙箱管理器生命周期(1 周)

交付物:拥有代理、暴露 `initialize` / `reset` / `wrapWithSandbox`(目前返回字符串)的单例状态机。

任务:
1. 模块级状态(`config`、代理句柄、鉴权 token、mitm CA)。
2. `initialize` 是幂等的。
3. `reset` 是尽力清理。
4. 每平台的 `checkDependencies` 脚手架。
5. 更新 + 克隆配置;热重载仅应用网络规则。
6. 单例通过 `SandboxManager.<method>` 接口导出。

验收:单元测试中编程生命周期工作。

### M4 — macOS 沙箱(2-3 周)

交付物:`wrapCommandWithSandbox` 输出强制执行配置规则的有效 `sandbox-exec` profile。

任务:
1. 从读/写配置生成 SBPL。
2. 通过 regex 转换处理 glob 模式。
3. 读规则输出 deny-then-allow;允许在允许内嵌套的允许重新输出逻辑。
4. 写规则输出 allow-then-deny。
5. 针对每个保护路径 + 祖先的移动阻断规则。
6. 必拒模式(rc 文件、git hooks 等)。
7. 网络规则(bind/inbound 到 localhost:代理端口)。
8. PTY 透传。
9. `env -u/ENV=val` 语法与正确的 shell 引号转义。
10. 测试:`macos-seatbelt.test.ts`、`macos-pty.test.ts`、`macos-allow-local-binding.test.ts`。

验收:macOS smoke 测试(`denyRead:['/etc']` 下的 `srt 'cat /etc/hosts'`)返回 EPERM。

### M5 — Linux 沙箱(4-5 周)

交付物:`bwrap` argv 合成器 + `apply-seccomp` 等价物。

任务:
1. 通过 ripgrep 解析必拒。
2. 写入上的 symlink 边界检查。
3. Bind-mount 循环:
    - `--ro-bind / /` 然后 `--bind` 覆盖。
    - `--tmpfs` 用于 deny 目录;deny tmpfs 后重新绑定写入。
    - `--ro-bind /dev/null` 用于不存在的 deny 路径(带清理)。
4. 网络桥(宿主 socat + bind 到沙箱)。
5. `apply-seccomp.c` 移植(或用 Rust 实现替换)。
6. BPF 过滤器:
    - 阻断 `socket(AF_UNIX)`。
    - 阻断 io_uring 系统调用。
    - 允许 `setuid/setgid` 等。
7. env 接入(代理变量、信任包变量、掩码 env 变量、取消设置 env 变量)。
8. `cleanupBwrapMountPoints` 引用计数。
9. 测试:`linux-violation-monitor.test.ts`、`mandatory-deny-paths.test.ts`、`integration.test.ts`、`seccomp-filter.test.ts`、`symlink-boundary.test.ts`、`symlink-write-path.test.ts`、`pid-namespace-isolation.test.ts`。

验收:Linux smoke 测试(`denyRead:['/etc']` 下的 `srt 'cat /etc/passwd'`)返回 EPERM。seccomp 阻断 `socket(AF_UNIX)`。

### M6 — Mux 前端(1 周)

交付物:服务 HTTP 与 SOCKS5 的单端口。

任务:
1. 首次包字节嗅探(SOCKS greeting 以 `0x05` 起始)。
2. 分发到 handlers。
3. 当两个外部 `httpProxyPort` 与 `socksProxyPort` 都设置时跳过 mux。
4. Windows 上,绑定在配置的端口范围内。
5. 测试:`mux-proxy.test.ts`、`mux-proxy-e2e.test.ts`。

验收:`srt 'curl -x http://127.0.0.1:<port> example.com'` 与 SOCKS5 客户端在同一端口都成功。

### M7 — TLS 中止(3-4 周)

交付物:可选进程内 TLS 中止 + 合成叶子铸造。

任务:
1. CA 加载器/生成器。
2. 信任包组成(CA + 宿主根 + 额外)。
3. 叶子铸造,SKI/AKI 匹配。
4. SecureContext 按主机名缓存。
5. CONNECT 路径升级。
6. CRL 生成。
7. 沙箱中的信任 env 变量。
8. 在中止请求上调用 `filterRequest`。
9. 变更头部(sentinel 注入)。
10. 测试:`tls-terminate-proxy.test.ts`、`tls-terminate-trust-env.test.ts`、`mitm-ca.test.ts`、`mitm-leaf.test.ts`。

验收:针对代理的 `curl --cacert ca.pem` 成功;上游在白名单主机上为 `Authorization` 看到替换后的 sentinel。

### M8 — 凭证掩码(1-2 周)

交付物:`credentials` 块端到端被尊重。

任务:
1. Sentinel 注册表(每进程 map)。
2. `register(name, real, injectHosts)` 返回 sentinel。
3. `substituteInHeaders`(代理路径)。
4. Mode=deny:env 取消设置,文件不可读。
5. Mode=mask:env=sentinel;在真路径上绑定 fake 文件;按 sentinel 的 injectHosts 限制。
6. 结构化抽取(带捕获组 1 的 regex)。
7. 跨字段校验(在 M1 中覆盖)。
8. 测试:`credential-deny.test.ts`、`credential-mask.test.ts`、`credential-mask-files.test.ts`。

验收:带 `ANTHROPIC_API_KEY=<sentinel>` 的沙箱进程无法提取真值,但代理在出站请求至 `*.anthropic.com` 时替换。

### M9 — Windows 路径(4-6 周)

交付物:带 WFP + ACE 隔离的 Windows 沙箱。

任务:
1. `windows-install`/`windows-uninstall` 自提升入口点。
2. `srt-win`(或等价物)辅助程序:
    - WFP 过滤器集安装/卸载/验证。
    - 沙箱用户配置。
    - DPAPI 加密凭据。
    - ACL stamp/revoke/restore/recover。
    - 带受限 token + job 的双段式启动。
3. 用你选择的语言调用 Win32:
    - `CreateProcessWithLogonW`、`LogonUser`。
    - `FwpmFilterAdd0`、`FwpmSubLayerAdd0`。
    - `SetSecurityInfo`、`GetSecurityInfo`。
    - `CryptProtectData`、`CryptUnprotectData`。
4. `wrapWithSandboxArgv`(Windows 上无 shell 字符串)。
5. CRL 分发点(仅 Windows)。
6. 在沙箱用户的 `CurrentUser\Root` 库中安装 CA。
7. 测试:`winsrt.test.ts`、`winsrt-paths.property.test.ts`,加 CI smoke。

验收:沙箱用户对 `127.0.0.1:[60080,60089]` 之外的出站 TCP 被阻断。`allowRead` 之外目录的读取被拒绝。

### M10 — 沙箱违规监控(1-2 周)

交付物:违规存储由 mac 和 Linux 填充。

任务:
1. `SandboxViolationStore`(进程内 map)。
2. macOS 日志订阅(或 shell 化到 `log stream`)。
3. Linux SECCOMP_RET_USER_NOTIF 监听器。
4. supervisor 的路径解析(相对路径经 `/proc/<pid>/cwd`)。
5. `encodedCommand` 传播。
6. `ignoreViolations` 过滤。
7. 测试:`linux-violation-monitor.test.ts`。

验收:被拒操作将违规记录写入存储。

### M11 — Control FD + CLI 润色(1 周)

交付物:完整 CLI 表面。

任务:
1. `srt` 默认子命令。
2. `--settings`(缺失时硬错误的 CLI flag)。
3. `-c` 原始命令字符串。
4. `--control-fd` 实时更新。
5. `-d, --debug` 表示 `SRT_DEBUG`。
6. 信号转发(SIGINT → child)。
7. exit/SIGINT/SIGTERM 时清理。
8. `--version` 中的版本字符串。
9. 测试:`cli.test.ts`、`cli-config-loading.test.ts`、`control-fd.test.ts`。

验收:CLI 在移植后通过 `cli.test.ts` 与 `cli-config-loading.test.ts` 中的每个测试。

## 14.3 可复用测试不变量

完整测试套件(约 500 个测试)即为规范。每个上述里程碑对应一组移植:

| 里程碑 | 测试(移植时)                                                              |
| --------- | -------------------------------------------------------------------------------- |
| M0        | `platform.test.ts`、`shell-quote.test.ts`、`which.test.ts`                      |
| M1        | `config-validation.test.ts`                                                     |
| M2        | `parent-proxy.test.ts`、`request-filter.test.ts`、`mux-proxy.test.ts`(稍后)   |
| M3        | `domain-pattern.test.ts`、`ripgrep.test.ts`、`update-config.test.ts`            |
| M4        | `macos-*` 集成套件                                                     |
| M5        | `linux-*` 集成套件 + `seccomp-filter.test.ts` + `pid-namespace-isolation.test.ts` |
| M7        | `tls-terminate-*`、`mitm-*`                                                     |
| M8        | `credential-*`                                                                  |
| M9        | `winsrt*.test.ts`                                                                |
| M10       | `linux-violation-monitor.test.ts`                                               |

## 14.4 风险与转向

| 风险                                                                | 缓解措施                                                                  |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| 目标 Linux 发行版没有 libseccomp                                     | 像 srt 一样捆绑静态 `apply-seccomp` 二进制。                    |
| macOS API 漂移(`os.unstable.log` 不稳定)                      | shell 化到 `/usr/bin/log stream` 是完美后备。        |
| Docker 环境中 bubblewrap 不可用                                     | `enableWeakerNestedSandbox: true` 打开降级路径,使用更宽松的 unsharing。记录它。 |
| Windows 安装需要管理员                                       | 是的。嵌入方可以提示用户一次并打包。                       |
| 用户无 CA 轮换纪律                                | 每次 `initialize()` 时的 CRL + 指纹检查防止陈旧安装。 |
| bubblewrap 或 sandbox-exec 中有新的 CVE                              | 更新依赖;复现测试;发布补丁。                          |

## 14.5 复刻的参考布局

```
<project>/
├── cmd/srt/main.go             (或等价物)
├── internal/
│   ├── cli/                    CLI 解析 + 信号转发
│   ├── config/                 Schema + 校验
│   ├── manager/                SandboxManager 状态机
│   ├── proxy/
│   │   ├── http.go
│   │   ├── socks.go
│   │   ├── mux.go
│   │   ├── parent.go
│   │   ├── filter.go
│   │   ├── mitm_ca.go
│   │   ├── mitm_leaf.go
│   │   └── terminate.go
│   ├── sandbox/
│   │   ├── macos/profile.go
│   │   ├── linux/bwrap.go
│   │   ├── linux/seccomp/      Rust crate 或 C shim
│   │   └── windows/
│   │       ├── wfp.go
│   │       ├── acl.go
│   │       ├── launch.go
│   │       └── trust.go
│   └── credentials/
├── shims/                      (编译后二进制,类似此处的 vendor/)
├── testdata/                   TLS 证书
├── tests/                      移植的测试文件
├── README.md                   (使用与上游相同的示例)
├── LICENSE                     (Apache-2.0)
└── Cargo.toml / go.mod / pyproject.toml
```
