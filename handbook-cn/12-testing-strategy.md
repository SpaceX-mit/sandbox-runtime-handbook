# 12 — 测试策略

该项目随附一个综合测试套件,涵盖全部三个平台以及 JS 端抽象。测试在 **Bun**(`bun test`)下运行,而非默认的 `npm test`。仓库通过 `package.json` 中的 `test` 脚本暴露它。

## 12.1 测试布局

```
test/
├── cli-config-loading.test.ts        14 个单元测试
├── cli.test.ts                        25 个单元测试
├── config-validation.test.ts         ~290 个单元测试(zod schema)
├── configurable-proxy-ports.test.ts   30 个单元测试(mux 与每端口覆盖)
├── control-fd.test.ts                 8 个单元测试(实时配置更新)
├── docker-weak-sandbox.test.ts         5 个单元测试
├── fixtures/
│   └── tls-terminate/                5 张自签名证书
│       ├── ca.{cert,key}.pem
│       ├── leaf.example.com.{cert,key}.pem
│       ├── leaf.npmjs.org.{cert,key}.pem
│       └── leaf.test.local.{cert,key}.pem
├── helpers/
│   ├── platform.ts                   isLinux/isMacOS/isWindows
│   └── spawn.ts                      spawnAsync utilities
├── sandbox/                          ← 跨平台集成测试
│   ├── allow-read.test.ts
│   ├── check-dependencies.test.ts
│   ├── connect-non-tls.test.ts
│   ├── credential-deny.test.ts
│   ├── credential-mask-files.test.ts
│   ├── credential-mask.test.ts
│   ├── domain-pattern.test.ts
│   ├── filesystem-disabled.test.ts
│   ├── glob-expand.test.ts
│   ├── integration.test.ts
│   ├── linux-bridge-spawn-error.test.ts
│   ├── linux-dependency-error.test.ts
│   ├── linux-violation-monitor.test.ts
│   ├── macos-allow-local-binding.test.ts
│   ├── macos-apple-events.test.ts
│   ├── macos-pty.test.ts
│   ├── macos-seatbelt.test.ts
│   ├── mandatory-deny-paths.test.ts
│   ├── mitm-ca.test.ts
│   ├── mitm-leaf.test.ts
│   ├── mux-proxy-e2e.test.ts
│   ├── mux-proxy.test.ts
│   ├── parent-proxy-tunnel.test.ts
│   ├── parent-proxy.test.ts
│   ├── pid-namespace-isolation.test.ts
│   ├── proxy-env-vars.test.ts
│   ├── request-filter.test.ts
│   ├── sandbox-env-tmpdir.test.ts
│   ├── seccomp-filter.test.ts
│   ├── symlink-boundary.test.ts
│   ├── symlink-write-path.test.ts
│   ├── tls-terminate-proxy.test.ts
│   ├── tls-terminate-trust-env.test.ts
│   ├── update-config.test.ts
│   ├── winsrt-paths.property.test.ts  (仅 Windows,fast-check 属性测试)
│   ├── winsrt.test.ts                 (仅 Windows,运行 srt-win CLI)
│   └── wrap-with-sandbox.test.ts
└── utils/
    ├── platform.test.ts
    ├── ripgrep.test.ts
    ├── shell-quote.test.ts
    ├── which-node-test.mjs
    └── which.test.ts
```

总计:跨单元、集成和基于属性的(fast-check)约 500 个测试。

## 12.2 测试类别

### 单元测试(不调用 OS 原语)

`config-validation.test.ts` 是单一最大的:涵盖 `sandbox-config.ts` 中每个 Zod 优化——域模式、glob 模式、必拒搜索深度边界、Windows 专属设置、superRefinement 规则(injectHosts 覆盖、tlsTerminate/mitmProxy XOR、不带 tlsTerminate 的 mask)。纯数据,快。

其他单元测试:
- `domain-pattern.test.ts` —— 主机名匹配、通配符语义、IP 字面量拒绝。
- `shell-quote.test.ts` —— POSIX 引号转义边界情况。
- `which.test.ts` —— PATH 查找语义。
- `platform.test.ts` —— `getWslVersion` 解析。
- `ripgrep.test.ts` —— rg 子进程驱动。

### 组件测试

等价的 `http-proxy.test.ts` 测试(`mux-proxy.test.ts`、`request-filter.test.ts`、`tls-terminate-proxy.test.ts`、`parent-proxy.test.ts`):
- 在进程内启动 JS 服务器(`createServer()` with `127.0.0.1:0`)。
- 使用 `node:http` / `node:net` 发起 HTTP / SOCKS 请求。
- 用 `bun:test` 断言响应码、正文字节、头部变更。
- 快照时序/排序。

### 集成测试(按平台)

每个平台有专用集成测试,实际调用 OS 原语。它们只在该平台运行;其他 OS 上 `it.skip(...)`。

#### macOS

```
macos-seatbelt.test.ts          ← 真 sandbox-exec;在 denyRead 下 cat /etc/hosts 被阻
macos-allow-local-binding.test.ts ← 真网络绑定测试
macos-pty.test.ts               ← 真 PTY 分配
macos-apple-events.test.ts      ← (allow appleevent-send) 对 osascript/open 有效
```

#### Linux

```
integration.test.ts             ← 在 bwrap 中 spawn curl/python;检查通过代理的出站
linux-bridge-spawn-error.test.ts← 坏的 socat 路径 → 优雅失败
linux-dependency-error.test.ts  ← 缺失 bwrap/socat → 可操作错误
linux-violation-monitor.test.ts ← SECCOMP_RET_USER_NOTIF → JSON 流 → 存储
seccomp-filter.test.ts          ← 直接二进制调用,验证 BPF 行为
pid-namespace-isolation.test.ts ← /proc/<pid>/mem ptrace 在 worker 内不可能
symlink-boundary.test.ts        ← 通过 symlink 的 allow-write 被拒
symlink-write-path.test.ts      ← 与上述针对读相同
mandatory-deny-paths.test.ts    ← ripgrep 查找并 deny
```

#### Windows

```
winsrt.test.ts                  ← 为 install/uninstall/exec/acl/wfp 运行 `srt-win` 子进程
winsrt-paths.property.test.ts   ← fast-check 生成随机路径集合,运行 `srt-win acl stamp`
```

#### 跨平台抽象测试

```
mitm-ca.test.ts                ← CA 生成、bundle 组成、CRL
mitm-leaf.test.ts               ← 叶子铸造、AKI 匹配
credential-deny.test.ts        ← 文件和 env 的 mode='deny'(在 mac 降级)
credential-mask.test.ts        ← Linux 上的 mode='mask':在真路径上绑定 fake
credential-mask-files.test.ts  ← 整文件与结构化抽取
proxy-env-vars.test.ts         ← HTTP_PROXY/HTTPS_PROXY/NO_PROXY 烘焙
sandbox-env-tmpdir.test.ts     ← 沙箱内 /tmp 是新鲜的 tmpfs
filesystem-disabled.test.ts    ← disabled:true 绕过所有 fs 规则
allow-read.test.ts             ← 在 denyRead 内的 allowRead 工作
update-config.test.ts          ← 热重载语义
mux-proxy-e2e.test.ts          ← 通过一个端口的双协议
connect-non-tls.test.ts        ← 在纯流上的 CONNECT(SSH)仍被白名单
```

### 属性测试(fast-check)

`winsrt-paths.property.test.ts` 生成随机路径集合并确保 `expandWindowsFsPaths` 函数是总和的 —— 任何路径集合都不会让展开崩溃。

## 12.3 测试执行

```bash
# 运行所有测试
bun test

# 仅运行与平台相关的子集
bun test --testPathPattern=sandbox
bun test test/sandbox/seccomp-filter.test.ts   # 仅 Linux
```

CI(`.github/workflows/integration-tests.yml`)矩阵:

| OS       | 架构       | Runner                    |
| -------- | ---------- | ------------------------- |
| Linux    | x86_64     | ubuntu-latest             |
| Linux    | arm64      | ubuntu-24.04-arm          |
| macOS    | x86_64     | macos-15-large            |
| macOS    | arm64      | macos-14                  |
| Windows  | x86_64     | windows-latest            |
| Windows  | arm64      | windows-11-arm            |

所有六个平台在每个 PR 与推送到 `main` 时运行。`release.yml` 工作流额外构建并发布 npm 包。

## 12.4 夹具

`test/fixtures/tls-terminate/` 包含:
- `ca.cert.pem`、`ca.key.pem` —— 自签 MITM CA。
- `leaf.example.com.{cert,key}.pem` —— 叶子 CN=`example.com`。
- `leaf.npmjs.org.{cert,key}.pem` —— 叶子 CN=`npmjs.org`。
- `leaf.test.local.{cert,key}.pem` —— 叶子 CN=`test.local`。

被 `tls-terminate-proxy.test.ts` 用于验证代理中止 TLS、交换可验证叶子、上游 cert-validates 正确。

## 12.5 Mocking 策略

项目 **不 mock** OS 原语。测试运行真实命令在真实沙箱中:

- `bwrap …` 真实调用 bubblewrap。
- `sandbox-exec -p ...` 真实调用 Apple 的二进制。
- `srt-win install` 真实调用打包的 Rust 辅助。

这是纪律。唯一的 mocking 发生在网络层 —— 需要特定 TCP 服务的测试指向同一测试进程内的 `127.0.0.1:<port>`,启动一个小的 Node `http.Server` 或 `net.Server`。

## 12.6 慢测试

少量测试耗时 5-10 秒:
- `linux-violation-monitor.test.ts` —— spawn `apply-seccomp` 并等待 `pidfd` 关闭。
- `pid-namespace-isolation.test.ts` —— 演练完整 `apply-seccomp` 生命周期。
- `integration.test.ts` —— 每个测试用例多个 `child_process.spawn`。

CI 每作业超时为 30 分钟;每测试默认 5 秒,但慢测试覆盖:

```ts
it('does X', async () => {
  // ...
}, /* timeout */ 30_000)
```

`sandbox-manager.ts` 中的桥退出超时为 1500 ms —— 设计为赢得测试运行器的 5 秒 hook 超时之争。

## 12.7 测试辅助

```ts
// test/helpers/platform.ts
export function isLinux(): boolean { return process.platform === 'linux' }
export function isMacOS(): boolean { return process.platform === 'darwin' }
export function isWindows(): boolean { return process.platform === 'win32' }

// test/helpers/spawn.ts
export async function spawnAsync(
  cmd: string,
  args: string[],
  opts: { timeoutMs?: number; env?: NodeJS.ProcessEnv } = {}
): Promise<{ stdout: string; stderr: string; code: number }>
```

`spawnAsync` 是 `child_process.spawn` 的薄包装,带 5 秒默认超时和完整 stdout/stderr 捕获。被各处使用。

## 12.8 测试配置模式

```ts
function createTestConfig(testDir: string): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: ['example.com'],
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowRead: [],
      allowWrite: [testDir],
      denyWrite: [],
    },
  }
}
```

这个最小可行配置让测试一次专注于一种行为。

## 12.9 测试捕获的缺陷(值得注意)

这些是测试套件防御的 bug 类别:

1. **macOS 中的 profile-ordering bug**(`macos-seatbelt.test.ts`)。
   - `(subpath "/")` 拒绝根并破坏路径解析 → 重新允许 `(literal "/")`。
   - 读允许内部的读 deny → 再次输出 deny。
2. **BPF 过滤器漂移**(`apply-seccomp.c` + `seccomp-filter.test.ts`)。
   - 错误的 arch 检查 → 错误的 syscall ID。
   - x32 ABI 字节范围缺失。
3. **Symlink 边界**(`symlink-boundary.test.ts`)。
   - `realpathSync` 未调用 → 允许写入跟随 symlink 到 /etc。
4. **主机名中的 NUL 字节**(`matchesDomainPattern` + `isValidHost`)。
   - `evil.com\x00.allowed.com` 滑过 endsWith。
5. **`canonicalize` 中的 IPv6**(`parent-proxy.test.ts`)。
   - `127.1` 应该匹配 `127.0.0.1`。
   - 带尾点的 FQDN 被去掉。
6. **io_uring 旁路**(Linux 5.19+ IORING_OP_SOCKET)。
   - BPF 过滤器必须同时阻断 `io_uring_setup/enter/register` syscall。
7. **Token 数学**(`sandbox-env-tmpdir.test.ts`)。
   - 在 bwrap 内,`$TMPDIR` 必须是 bwrap tmpfs,不是宿主的。

## 12.10 测试约定

- 使用 `describe` 块按特性而非按文件分组。
- 使用 `it.skip(...)` 在错误的 OS 上跳过平台专属测试。
- 使用 `beforeEach` 在 `/tmp/srt-test-<rand>/` 下创建新的临时目录。
- 使用 `afterEach` 清理它们;不依赖 `process.exit()` 来 GC。
- 所有测试是扁平的 —— 除了按特性分组,无嵌套 `describe`。
- 测试 **并行** 运行 —— Bun 默认 fork;集成测试使用独立端口范围避免冲突。

## 12.11 覆盖率

项目在 CI 中不运行覆盖率工具。覆盖率是概念性的;套件结构化以行使每个代码路径:

- Schema 优化 → 详尽的表驱动 config-validation。
- 平台包装器 → 每个行为维度至少一个测试。
- 代理管线 → 控制面(鉴权、过滤)与数据面(CONNECT、MITM、变更头部)。
- 原生 shim → 单元 + 集成。

任何非平凡的代码更改预期伴随行使它的测试。
