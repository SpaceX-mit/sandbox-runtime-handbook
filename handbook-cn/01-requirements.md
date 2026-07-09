# 01 — 需求分析

## 1.1 产品目标

Sandbox Runtime(`srt`)是一个研究阶段的工具,目的是通过在 OS 级别强制实施明确的文件系统和网络访问白名单来 **让任意不受信任的进程运行起来更安全**。它是满足以下三个特性的最小原语:

| ID   | 目标                                                                                                                                                                                                                       |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| G-1  | **文件系统隔离。** 子进程只能读取配置的 *deny-then-allow* 读取集合中允许的路径,只能写入配置的 *allow-then-deny* 写入集合中允许的路径。 |
| G-2  | **网络隔离。** 默认情况下,不允许任何出站网络流量。允许的流量必须匹配配置的白名单,且不得匹配配置的黑名单。 |
| G-3  | **跨平台。** macOS、Linux 和 Windows 均使用各自平台的 **自身** 原语获得内核级强制隔离——不依赖 Docker 也不依赖自研内核。 |

次级目标:

| ID     | 目标                                                                                                                                                                                                            |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| G-4    | **双重使用。** 即可作为 CLI(`srt <command>`),也可作为库(`SandboxManager.wrapWithSandbox` / `wrapWithSandboxArgv`)。                                                                                  |
| G-5    | **默认安全。** 空白名单 ⇒ 零网络访问;空白写入名单 ⇒ 禁止写入(除少量内置项外)。默认值需要显式 opt-in 才能用起来。                                                                                            |
| G-6    | **透明性。** 沙箱进程看到与正常 OS 视图一样的文件系统视图,只是受到限制。无 LD_PRELOAD hack,无代理自动配置奇迹(mitm 怪招)。                                                                                    |
| G-7    | **可观测。** 沙箱进程被拒绝时,违规行为可被宿主观测到(订阅者回调 + stderr tag)。`claude-code` 用它将拒绝事件转成权限申请对话框。                                                                              |
| G-8    | **可嵌入。** 编排器(`srt`)是一个小的 Node ≥ 18 进程,可以编程方式驱动。平台原生辅助程序(`apply-seccomp` 对应 Linux,`srt-win` 对应 Windows)作为子进程调用。                                                  |

## 1.2 非目标

- **不是完整容器。** 没有镜像分层、没有 overlay fs、没有 cgroup/ulimit、没有 seccomp DSL、没有 Linux 能力授予。srt 只把 bwrap 用于 `unshare-{net,pid,user}` 与 bind-mount 表面。
- **不是策略引擎。** 库接受 *配置* 而非 *策略*。嵌入方(claude-code、MCP host)将自己的策略转译为配置。
- **不是多租户调度器。** 一个宿主进程 = 一份沙箱配置 = 一组代理。不协调多个并发宿主。
- **无文件恢复模式。** 沙箱进程删掉的文件无法撤销(遵循 POSIX `unlink` 的标准语义)。
- **无 TPM 引导证明。** 假设本地可信。

## 1.3 用户故事

1. *作为 MCP host:* 用 `srt` 作为 argv\[0] 来包装 `npx @modelcontextprotocol/server-filesystem`,这样该 server 只能读取其工作目录、写入沙箱目录。
2. *作为 CLI 用户:* 配置 `*.github.com` 白名单,执行 `srt 'curl https://github.com'`。其他域名一律拒绝。
3. *作为 agent:* 自动屏蔽 `~/.ssh` 读取和 `.git/hooks` 写入。必拒集合无需手动配置。
4. *作为运维:* 通过 "control fd" 实时收紧策略——把 JSON 行通过管道送入 fd 3,正在运行的 CLI 即时更新规则(仅限网络,见 §4.7)。
5. *作为安全审计员:* 通过违规存储查看沙箱进程尝试过什么,映射回调用它的工具。

## 1.4 成功标准

| ID     | 准则                                                                                                                                                                                                          | 验证方式                                                |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| S-1    | macOS 上,`sandbox-exec -f <profile> <command>` 在内核层(`allowRead` 外拒绝读、`allowWrite` 外拒绝写),并返回 `EPERM`。                                                              | `test/sandbox/macos-seatbelt.test.ts`                    |
| S-2    | Linux 上,`bwrap …` + `apply-seccomp …` 用 `EPERM` 拦截 `socket(AF_UNIX, …)`。子进程不能看见或 ptrace 自身 PID 命名空间外的任何进程。                                                                       | `test/sandbox/linux-violation-monitor.test.ts`           |
| S-3    | Windows 上,沙箱进程对 `127.0.0.1:[60080..60089]` 之外的出站 TCP connect 在内核解析目的地之前即被 WFP 过滤器集拦截。                                                                                            | `verifyWindowsWfpEgress()`(运行于 `initialize()`)        |
| S-4    | 配置 `tlsTerminate` 时,宿主代理中止 HTTPS;`network.filterRequest` 可单独拒绝某些请求,且上游收到通过证书校验的请求。                                                                                            | `test/sandbox/tls-terminate-proxy.test.ts`               |
| S-5    | `network.updateConfig` 可在子进程已经运行的前提下动态放行新域名,且无需重新绑定代理。                                                                                                                            | `test/sandbox/update-config.test.ts`                     |
| S-6    | `credentials.envVars[].mode == 'mask'` 将真实值替换为 sentinel;代理在配置了 `tlsTerminate` 的情况下,把真值回填至出站 HTTPS 请求头中。                                                                        | `test/sandbox/credential-mask.test.ts`                   |

## 1.5 质量目标(非功能性)

| NFR    | 目标                                                                                                                            |
| ------ | --------------------------------------------------------------------------------------------------------------------------------- |
| NFR-1  | 沙箱启动 macOS P50 ≤ 200ms,Linux ≤ 400ms(不含 `srt-win install`,该步骤是一次性)。                                                |
| NFR-2  | 代理中的逐请求开销 P50 ≤ 1ms。代理位于 loopback 热路径;每个 socket 都付出这点开销。                                                |
| NFR-3  | 清理是 **fail-safe**:即便 `SIGKILL`,也不残留宿主端的工件(已对 Linux 的 bwrap mount-point 清理钩子验证)。                        |
| NFR-4  | 不存在向不安全默认的静默回退。缺失依赖或陈旧安装必须返回硬错误。                                                                  |

## 1.6 约束

- License:**Apache-2.0**(见 `LICENSE`)。C 和 Rust 辅助程序同样遵循此 License。
- Node 引擎:**>=20.11.0**(`package.json` 中的 `engines.node`)。CI 使用 Node 20 LTS。
- Rust 工具链(`srt-win`):edition 2021,MSRV 在 `vendor/srt-win-src/Cargo.toml` 中固化。
- 库 **永远不会** 在用户运行时依赖 `npm install`——所有原生产物(`apply-seccomp`、`srt-win.exe`)都已预编译并随包发布。

## 1.7 定义完成(每个里程碑)

| 里程碑                                | 验收                                                                                                                                  |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 配置 Schema 与校验                      | `SandboxRuntimeConfigSchema` 接受和拒绝所有字段如 `sandbox-config.ts` 所述;super-refinement 捕获 injectHosts/excludeDomains 冲突。         |
| macOS 沙箱                              | `denyRead: ['/etc']` 之下执行 `srt 'cat /etc/hosts'` 返回 `Operation not permitted`。                                                  |
| Linux 沙箱                              | `srt --enable-seccomp curl example.com` 对白名单域生效;沙箱内部的 `socket(AF_UNIX)` 返回 `EPERM`。                                       |
| Windows 沙箱                            | `verifyWindowsWfpEgress()` 中的行为型 connect 探针仅在过滤器存在并匹配沙箱 SID 时返回成功。                                              |
| 网络代理强制                             | `deniedDomains` *先* 检查;`allowedDomains` 后检查;不匹配的 HTTP 连接关闭并回 403,SOCKS 静默关闭。                                       |
| 逐请求过滤                              | `filterRequest` 返回 `{action:'deny'}` 时,响应为 403,且头部为 `X-Proxy-Error: blocked-by-sandbox-runtime`。                              |
| TLS 中止 + 凭证注入                      | Sentinel 仅在发往 `injectHosts` 主机的请求头中出现,且仅当该主机的 TLS 已被本进程中止时。                                              |
