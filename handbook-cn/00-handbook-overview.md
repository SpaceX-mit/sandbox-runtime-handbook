# Anthropic Sandbox Runtime (srt) — 复刻手册(中文版)

本手册对 `anthropic-experimental/sandbox-runtime` 项目进行了端到端分析,并提供了在任何语言中重新实现它的完整蓝图。每份文档都阐明 *做什么*(功能契约)、*为什么这么做*(安全/UX 论证)以及 *如何实现*(接口、算法、数据结构)。

## 阅读顺序

| #  | 文档                                    | 内容                                                                                |
| -- | ------------------------------------------- | ----------------------------------------------------------------------------------- |
| 01 | requirements.md                             | 产品目标、非目标、用户故事、成功标准                                                |
| 02 | system-architecture.md                      | 进程拓扑、模块拆分、操作系统隔离边界选型                                            |
| 03 | configuration-model.md                      | JSON Schema、语义(allow/deny 优先级)、校验                                         |
| 04 | network-isolation-design.md                 | HTTP + SOCKS 代理、多路复用前端、TLS 中止、父级代理                                 |
| 05 | filesystem-isolation-macos.md               | Seatbelt(`sandbox-exec`)配置文件生成                                                |
| 06 | filesystem-isolation-linux.md               | bubblewrap(bwrap) + seccomp BPF + 必拒路径                                          |
| 07 | filesystem-isolation-windows.md             | NTFS ACE + WFP 出站围栏 + srt-win 辅助进程                                          |
| 08 | credential-masking.md                       | 基于 sentinel 的文件和环境变量凭证掩码                                              |
| 09 | cli-and-programmatic-api.md                 | 命令行表面、库 API、动态配置                                                        |
| 10 | platform-shim-and-build.md                  | 原生辅助程序(apply-seccomp C、srt-win Rust)、打包                                   |
| 11 | violation-monitoring.md                     | macOS 系统日志监控、Linux SECCOMP_RET_USER_NOTIF 监控                               |
| 12 | testing-strategy.md                         | 单元、集成、属性测试,以及平台专项测试                                               |
| 13 | security-model.md                           | 威胁模型、安全不变式、已知限制                                                      |
| 14 | implementation-roadmap.md                   | 分阶段实施计划                                                                      |
| 15 | glossary.md                                 | 术语表(SBPL、ACE、BPF、CRL 等)                                                      |

## 配套参考文件

仓库中的以下文件为本手册提供依据:

- `src/index.ts` — 公开库导出
- `src/cli.ts` — CLI 入口(基于 commander)
- `src/sandbox/sandbox-manager.ts` — 核心编排器(约 2,000 行)
- `src/sandbox/sandbox-config.ts` — 基于 Zod 的运行时配置 Schema
- `src/sandbox/{http,socks,mux}-proxy.ts` — 正向代理服务器
- `src/sandbox/{macos,linux,windows}-sandbox-utils.ts` — 按 OS 的封装
- `src/sandbox/{mitm-ca,mitm-leaf,tls-terminate-proxy,parent-proxy}.ts` — TLS 中止/上游代理管道
- `src/sandbox/credential-{sentinel,mask-files}.ts` — sentinel 掩码
- `src/sandbox/{sandbox-violation-store,linux-violation-monitor,sandbox-utils}.ts` — 可观测性
- `vendor/seccomp-src/apply-seccomp.c` — 约 600 行 C 语言辅助程序,安装 BPF 过滤器并在嵌套 PID 命名空间中 fork 出工作负载
- `vendor/srt-win-src/` — Rust 辅助程序(约 2 万行),实现 WFP 过滤器、ACL 操作、沙盒用户配置和两段式启动

## 项目定位(一句话)

它在子进程外围包装一层 **内核强制** 的沙箱:读写路径和网络可达性通过各 OS 原语(Seatbelt / bubblewrap + seccomp / WFP + NTFS ACE)进行约束,并且沙箱进程被 **强制路由** 到运行在本地的 HTTP+SOCKS5 正向代理,由这些代理执行域名白/黑名单以及可选的逐请求过滤回调。

## 非目标(本项目不做什么)

- **不是**一个功能完备的容器运行时(无镜像管理、无文件系统分层、无资源 cgroup、无 seccomp 策略 DSL)。
- **不**试图对特定工具具备策略感知能力。每个嵌入方(`claude-code`、MCP server 等)各自维护高层策略;srt 是它们共享的 OS 级强制原语。
- **不**提供多租户编排器。每个进程获得自己的沙箱;管理器是单进程、单租户的。
- **不**附带 seccomp 策略语言。`network.filterRequest` 是逐请求 HTTP 拦截的唯一逃生口,库的使用方自行负责匹配规则。
