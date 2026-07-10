# 19 — 架构对照:本项目 vs 可插拔 Sandbox Abstraction Layer

> 本文档是另一种视角的设计记录。前面 15 份文档描述了 `srt` 的"是什么 / 怎么做";
> 这一份记录为什么本项目 **不** 是另一种合理的架构,以及何时应该选另一种。
>
> 适用读者:**正在自研 agent 系统** 的设计者,需要在多种容器/沙箱策略间做权衡。

---

## 19.1 核心结论(放在最前面)

**这个项目 (`srt`) 与可插拔的 Sandbox Abstraction Layer (SAL) 架构不是一回事。** 它有意地走了相反的方向——把抽象与实现压在同一层,按 OS 硬编码唯一的内核原语。两种都是严肃的工程决策,服务于不同的需求,但不能混用。

| 维度 | srt(本项目) | SAL 架构 |
|------|-------------|-------------|
| **抽象边界** | 没有抽象层。每个 OS 一个 wrapper,平台实现细节直接暴露给上层 | 抽像层 SAL,统一接口,后端可替换 |
| **后端选择** | 编译期硬编码,按 OS 选**唯一**原语(macOS→Seatbelt,Linux→bwrap+seccomp,Windows→WFP+NTFS ACE) | 运行时按 capability / profiling / dev-vs-prod 等策略**动态**选择(bwrap/nsjail/Docker/Firecracker) |
| **隔离粒度** | 一个进程 = 一个沙箱,通过 `updateConfig`/`reset` 调整,**不**支持并发多沙箱 | 多沙箱实例共存,各自独立的 Workspace / Capability / Resource 视图 |
| **资源管理** | 代理跑在宿主,**所有**沙箱共享同一组代理 | 每个沙箱可独立拥有 / 共享资源(网络、文件系统、内存配额) |
| **能力模型** | 策略集中在配置 JSON(`SandboxRuntimeConfig` Schema) | 由 Capability Manager 单独表达,可被 Loop Engine 动态调整 |
| **持久化模型** | Snapshot 通过 `--ro-bind` 实现,且**无** checkpoint/restore | Workspace Manager 显式管理 snapshot/branch/commit |

## 19.2 用一张图对比

```
                  srt 实际架构                          SAL 架构
                  ──────────                          ─────
                                                     Agent Runtime
                                                            │
                                                        Loop Engine
                                                            │
                  SandboxManager 单例                   ┌────┴────┐
                  (compile-time 选择路径)              │         │
                          │                Workspace Mgr │         │
        ┌─────────────────┼────────────────┐ │  Resource Mgr│ Capability Mgr│
        │                 │                │ │           └─────┬─────┘
   wrapMacos       wrapLinux           wrapWin                  │
        │                 │                │            Sandbox Abstraction Layer
   Seatbelt       bwrap+seccomp       WFP+ACE                  (统一接口)
                                                                  │
                                                       ┌──────┬───┴────┬──────────┐
                                                       │     │        │          │
                                                     bwrap nsjail  Docker  Firecracker
                                                       │     │        │          │
                                                       └─────┴────┴────┴──────────┘
                                                                    │
                                                              Linux Kernel
```

`srt` 把"抽象"和"实现"压在了同一层 `SandboxManager`;SAL 在抽象层下又压了 4 个独立实现。

---

## 19.3 为什么 srt 不做这件事?(它是有道理的取舍)

我先承认 `srt` 的设计是**自洽的、有论据的**,然后指出为什么你的 agent 系统应该走不同的路。

### 19.3.1 srt 的核心论点

> "如果抽象层有 bug,所有上层都失败。直接对内核原语编程意味着攻击面尽可能小,且每个 OS 只有一个值得审查的代码路径。"

落到实践上:

| 优势 | 体现 |
|------|------|
| **攻击面可控** | `wrapCommandWithSandboxMacOS` 生成 SBPL 字符串,中间没有 container runtime、OCI runtime、image registry、tar stream、cgroup hierarchy 这些潜在 RCE 入口 |
| **冷启动极快** | bwrap 是 ~600 LOC 的 C;Firecracker 启动是几百毫秒,前者是几毫秒 |
| **不需要信任链** | Docker 镜像 → 签名验证 → registry → rootfs 完整性;这条链一断就破。bwrap → 直接 bind mount 宿主页 → 没有信任链 |
| **代码量小** | `vendor/seccomp-src/apply-seccomp.c` 600 行。整个 OS 原语层不到 5 万行,审计得过来 |

### 19.3.2 srt 的代价

| 局限 | 影响 |
|------|------|
| **不可插拔** | 要给一个 Linux 沙箱增加 `unshare --user-try --map-root-user` 之外的策略,得改 `wrapCommandWithSandboxLinux` |
| **不抽象 OS 差异** | `wrapWithSandboxArgv`(Windows)和 `wrapWithSandbox`(POSIX)签名不同,调用方必须分支 |
| **没有 lifecycle 抽象** | `initialize`/`reset` 是会话级,而非 instance 级 |
| **没有 capability 协议** | `askCallback` 是单一函数指针,没有可枚举的"这个 agent 想要 X"的协议面 |
| **没有 persistent state** | Loop Engine 想 spawn 1000 次相同 sandbox?—— 都得重新 build profile / argv |

### 19.3.3 一句话总结

> srt 是 **monolithic-policy + per-OS-primitive**;
> SAL 是 **pluggable-backend + capability-based**。

两者都是严肃架构决策,不存在谁对谁错,但服务的需求确实不同。

---

## 19.4 你的设计为什么更适合你的 agent 系统

把你的 layered 架构(Sandbox Abstraction Layer)展开,放在 agent 视角下,我能马上看出**至少五件** srt 干不了的、但你的 agent 可能干的事。

### 19.4.1 不同操作走不同隔离等级

```
agent.task[1] = "fetch https://npmjs.org/package/x"     → nsjail (低开销)
agent.task[2] = "execute user-uploaded.py"              → Firecracker (硬隔离)
agent.task[3] = "git commit to user's main branch"      → bwrap (中等)
agent.task[4] = "merge PR #123 into main"               → Docker (快速可重现)
```

srt 把所有命令走同一条 bwrap 路径,代价高且不一致。SAL 让 Loop Engine 按风险等级挑后端。

### 19.4.2 Snapshot / Branch / Commit

Workspace Manager 想做:

```
sandbox.snapshot()         → 在这个 sandbox 的 rootfs 上打 tag
sandbox.fork(times=N)      → 并发做 10 个尝试,各自从同一快照开始
sandbox.merge(handle_1, handle_2)   → 文件系统级三方合并
```

srt 做不到这个,它的"沙箱状态"在 `process exit()` 时销毁。Firecracker 的 snapshot+restore(DM snapshot)是这种语义的最佳载体。

### 19.4.3 Capability 的动态收紧

```
loop iteration 5:
  agent 想要执行 curl example.com
  Capability Manager 检查:
    - 上次违规:3 次 deny
    - 当前已用 CPU:80%
  → 临时 deny,等 5 秒后重试
```

srt 不支持这种 policy-suspended behavior,只能一次性给整张配置。

### 19.4.4 资源配额(cgroup / memory / pids)

```
sandbox.set(resource={cpu:0.5, mem:256MB, pids:64})
sandbox.status() → {cpu: 0.3, mem: 80MB, pids: 12}
```

srt 用 `bwrap --die-with-parent` 但**不**做 cgroup 限制。

### 19.4.5 调试与可重现性

```
sandbox.exportSpec()          → "用了 bwrap,profile X,env Y,root mount Z"
spec.replay(handle)           → 在另一台机器 1:1 重现
```

srt 的 wrap 输出是命令行字符串,无法结构化 round-trip。

---

## 19.5 实现 SAL 的工程建议

如果你要在你的 agent 系统里实现 `Sandbox Abstraction Layer`,我推荐下面这套结构。这是从 srt + 类似项目(nsjail、agent-sandbox、JPMorgan 的 `finest-proxy`)综合而来的。

### 19.5.1 SAL 接口(语言无关)

```typescript
interface SandboxSpec {
  backend: 'bwrap' | 'nsjail' | 'docker' | 'firecracker'
  image?: string                    // docker/firecracker 后端用
  rootfs?: { type: 'dir' | 'squashfs' | 'block', path: string }
  resources: { cpus: number, memMb: number, pids: number, diskMb?: number }
  capabilities: CapabilitySet       // 见 §19.5.2
  mounts: Mount[]
  network: NetworkPolicy
  env: EnvPolicy
  workspace?: WorkspacePolicy        // 见 §19.5.3
  timeoutMs?: number
}

interface SandboxHandle {
  id: string
  spec: SandboxSpec                  // round-trip 友好
  state: 'creating' | 'running' | 'paused' | 'exited' | 'destroyed'

  exec(cmd: string, args: string[], opts?: ExecOpts): Promise<ExecResult>
  execStream(cmd: string, args: string[], opts?: ExecOpts): AsyncIterable<StreamEvent>
  snapshot(): Promise<SnapshotHandle>
  forkFrom(snap: SnapshotHandle): Promise<SandboxHandle>
  status(): Promise<ResourceUsage>
  destroy(): Promise<void>
  events(): AsyncIterable<SandboxEvent>     // violations, resource pressure, etc.
}

interface SandboxBackend {
  name: 'bwrap' | 'nsjail' | 'docker' | 'firecracker'
  capabilities: BackendCapabilitySet        // 自己的能力声明
  create(spec: SandboxSpec): Promise<SandboxHandle>
  health(): Promise<{available: boolean, version: string, error?: string}>
  cleanup(): Promise<void>                  // 全局清理
}
```

### 19.5.2 Capability 模型(关键设计)

srt 的"白名单域名 + 必拒路径"是**单一答案**;你的 SAL 应该支持**多维能力**,每个能力有不同生命周期:

```typescript
type Capability =
  | NetCapability            // "可以连到 *.example.com"
  | FsReadCapability         // "可以读 /workspace/project/**"
  | FsWriteCapability        // "可以写 /workspace/project/.tmp/**"
  | SyscallCapability        // "可以调 connect();禁止 socket(AF_UNIX)"
  | DeviceCapability         // "可以打开 /dev/null"
  | EnvCapability            // "可以读 PATH;秘密 MASK 化"
  | EphemeralResourceCap     // "这个 sandbox 寿命 ≤ 30s,CPU ≤ 0.5"
```

**Loop Engine 和 Capability Manager** 的协议:

```
agent.requestCapabilities([
  { type: 'NetCapability',    host: 'api.anthropic.com', scope: 'egress' },
  { type: 'FsReadCapability', path: '/workspace/project/**' },
  { type: 'FsWriteCapability', path: '/workspace/project/.tmp/**' },
  { type: 'EnvCapability',    mode: 'mask', name: 'ANTHROPIC_API_KEY' },
])

capabilityManager.evaluate(request):
  // srt 风格:
  //   { allow: [Net, FsRead], deny: [FsWrite] }
  // 你的 agent 风格:
  //   { allow: [Net, FsRead, FsWrite 路径受限], require: { ttl: 30s, audit: true } }
```

### 19.5.3 Workspace 模型

```typescript
interface WorkspacePolicy {
  mode: 'ephemeral' | 'persistent' | 'branched'
  baseSnapshot?: SnapshotHandle      // 从已有 sandbox 派生
  bindMounts?: { src: string, dst: string, readOnly: boolean }[]
  outputTo?: string                   // 结束时把变更回传到主项目
  excludePatterns?: string[]
}
```

实现来源:

| Workspace mode | 实现方式 |
|----------------|----------|
| **ephemeral** | `bwrap --tmpfs <path>` 然后 bind 注入主工作树 |
| **persistent** | 直接 bind 主项目目录 |
| **branched** | overlayfs 上层 + 下层是 base snapshot,变 commit 到 overlay |

### 19.5.4 后端选择策略(Loop Engine 的依据)

```
┌─────────────────┐
│  request:       │
│  - trust level  │ ←── user-input 来源(本地/远端/上传)
│  - has upload?  │
│  - duration     │
│  - reproducibility │
└────────┬────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│   policy table                            │
│                                           │
│   (trust=local, has_upload=true)         │
│     → Firecracker                         │
│                                           │
│   (trust=remote, duration > 60s)         │
│     → Docker (可重现镜像 + 资源配额)     │
│                                           │
│   (trust=local, has_upload=false, fast)  │
│     → bwrap (最快冷启动)                │
│                                           │
│   (需要 syscall 精细控制, 无 net)        │
│     → nsjail                              │
└──────────────────────────────────────────┘
```

### 19.5.5 Backend 实现要点

#### bwrap backend

```typescript
class BwrapBackend implements SandboxBackend {
  capabilities = {
    namespaces: ['pid', 'net', 'mount', 'user'],
    seccomp: false,                    // 除非带 apply-seccomp shim
    snapshot: false,
    persistence: false,
    crossPlatform: false,
    cgroups: false,
  }

  async create(spec: SandboxSpec): Promise<SandboxHandle> {
    const argv = this.composeArgv(spec)      // 类似 srt 的 generateFilesystemArgs
    const proc = spawn('bwrap', argv, { stdio: 'pipe' })
    return new BwrapHandle(proc, spec)
  }

  private composeArgv(spec: SandboxSpec): string[] {
    // 借鉴本手册第 06 章的 bwrap argv 合成
    // 借鉴第 06.4 节的 symlink 边界检查
    // 借鉴第 06.3 节的 mandatory-deny 路径
  }
}
```

#### Firecracker backend(可选,但强大)

```typescript
class FirecrackerBackend implements SandboxBackend {
  capabilities = {
    namespaces: false,
    seccomp: true,                          // guest 内独立 BPF
    snapshot: true,                         // ★ DM snapshot
    persistence: true,                      // ★ block device 可挂载
    crossPlatform: false,
    cgroups: true,
  }

  async create(spec: SandboxSpec): Promise<SandboxHandle> {
    const vm = await this.fc.createVM({
      kernel: spec.kernel,
      rootfs: spec.rootfs.path,
      vcpuCount: spec.resources.cpus,
      memSizeMib: spec.resources.memMb,
      // ...
    })
    return new FirecrackerHandle(vm, spec)
  }

  async snapshot(): Promise<SnapshotHandle> {
    // ★ 与 srt 根本不同的能力
    return this.fc.takeSnapshot(this.vm.id)
  }

  async forkFrom(snap: SnapshotHandle): Promise<SandboxHandle> {
    // ★ 在 100ms 内启动新的 VM,与已有 sandbox 共享 rootfs 状态
    return this.fc.restoreSnapshot(snap.id)
  }
}
```

---

## 19.6 推荐的实现顺序(给 SAL 版本)

下面是我的"我会这么干"建议,按依赖关系排序:

| 阶段 | 任务 | 建议的库/工具 | 何时可并行 |
|------|------|------------|-----------|
| **SAL-0** | 定义 `SandboxSpec` / `SandboxHandle` / `SandboxBackend` 三接口;写 JSON Schema | 自己(zod / pydantic 等价物) | — |
| **SAL-1** | 实现 `BwrapBackend`(直接复刻 srt 第 06 章) | 直接照搬 srt 第 06 节 | — |
| **SAL-2** | 实现 `Spec → argv` 序列化器,确保 round-trip 友好 | — | — |
| **SAL-3** | 实现 `DockerBackend`(注意 srt 的网络路径在这里变,你要复用 docker bridge) | — | — |
| **SAL-4** | 实现 `LoopEngine ↔ Backend` 的 capability 协议 | — | — |
| **SAL-5** | 实现 `Workspace Manager`(ephemeral/persistent/branched 三种模式) | — | — |
| **SAL-6** | 用 `bwrap + docker` 两个后端跑通所有 happy path 测试 | — | — |
| **SAL-7** | 接入 `nsjail`(如果你需要 syscall 过滤比 bwrap 强) | nsjail 配置 | 与 SAL-6 并行 |
| **SAL-8** | 接入 `Firecracker`(用作硬隔离后端;预计投入 2-3 周) | firecracker + jailer | 与 SAL-7 并行 |
| **SAL-9** | 实现 `snapshot / forkFrom`(仅 Firecracker 后端可用) | — | — |
| **SAL-10** | `Capability Manager` 的动态收紧能力(Loop Engine 用) | — | — |

预计整体工时:**6-10 周**做 SAL-1 到 SAL-6,4-8 周做 SAL-7 到 SAL-10。

---

## 19.7 从 srt 学到可直接复用的东西

不要从头造轮子。srt 的以下子系统在你的 SAL 实现里几乎不需要改,直接抄:

| srt 组件 | 你能怎么用 |
|---------|-----------|
| `src/sandbox/domain-pattern.ts` | 域名通配符匹配。**任何**后端都需要这个判断"出口目标是否在 allow-list",原样搬走 |
| `src/sandbox/request-filter.ts` | filterRequest 的 Web 标准 Request 适配 + body tee + fail-closed。Hot 复用 |
| `src/sandbox/credential-sentinel.ts` | sentinel 注册表与 injectHosts 限制。挪到你的 `CapabilityManager.EphemeralSecret` 类 |
| `src/sandbox/credential-mask-files.ts` | 整文件/结构化掩码。挪到 CapabilityManager |
| `src/sandbox/parent-proxy.ts` | NO_PROXY + CIDR 匹配 + 上游代理。Hot 复用 |
| `src/sandbox/mitm-ca.ts` + `mitm-leaf.ts` + `tls-terminate-proxy.ts` | TLS 中止,在你的 SAL 中作为**基础设施层**放在 SAL 下面、所有 backend 共享 |
| `src/sandbox/linux-sandbox-utils.ts` 的必拒路径解析 | 直接抄 |
| `vendor/seccomp-src/apply-seccomp.c` | 给 `BwrapBackend` 作为可选能力(配置开启时启用 seccomp) |

---

## 19.8 最后的判断表

如果你的目标是:

| 目标 | 该用 srt 还是自己写 SAL |
|------|------------------------|
| 做最小可审计的沙箱工具 | **用 srt**(等它走出 alpha) |
| 给现有 agent 系统加一层 OS 级隔离 | **用 srt 直接嵌入**(`SandboxManager.wrapWithSandboxArgv`) |
| 在 agent 系统内实现"多后端可插拔 + 工作区分级 + snapshot/fork + capability 协议" | **写 SAL**,把上面的清单作为参考 |

总之,**这个项目为你想要的设计提供了"领域知识"而不是"架构模板"**。建议把它当作"协议 + 实现范例"来用,从它的网络代理、必拒机制、credential masking 抄过去,但抽象层和接口完全自己设计。

如果想深入到 SAL 的某个具体子层(bwrap backend 实现 / Workspace Manager 的 overlay 设计 / Firecracker snapshot 协议 / Capability Manager 的状态机),告诉我们从哪个开始,可以就着 srt 的现有代码写一个对应的"在 SAL 里的等价物"的详细设计文档。

---

## 19.9 与本手册其他章节的关系

| 上文章节 | 在 SAL 设计中的角色 |
|---------|---------------------|
| 第 02 章 系统架构 | 描述 srt 的"对照组"——单 OS 原语 + 单态管理 |
| 第 04 章 网络隔离 | 网络过滤、TLS 中止、parent proxy 等基础设施可被 SAL 共享 |
| 第 06 章 Linux 文件系统隔离 | SAL 的 `BwrapBackend` 的关键参考实现 |
| 第 07 章 Windows 文件系统隔离 | SAL 的"未来 Windows 后端"参考 |
| 第 08 章 凭证掩码 | Capability Manager.EphemeralSecret 的实现源头 |
| 第 11 章 违规监控 | SAL 的统一 `events()` 流可以包多种后端的监控源 |
| 第 12 章 测试策略 | 测试 BwrapBackend 的测试用例直接移植 |
| 第 13 章 安全模型 | SAL 必须重新满足的不变式清单 |
| 第 14 章 落地路线图 | 本章对 SAL 路线图(§19.6)是另起一卷 |

---

## 19.10 术语补充(SAL 特有)

| 术语 | 含义 |
|------|------|
| **SAL** | Sandbox Abstraction Layer,沙箱抽象层 |
| **backend** | SAL 下的一个具体实现(bwrap、nsjail、Docker、Firecracker) |
| **capability** | 描述"agent 想要做什么"的声明;被 Manager 评估成 allow/deny + 时长 + 配额 |
| **Capability Manager** | 评估 capability 集合,按策略决定 sandbox 实际获得什么 |
| **Workspace Manager** | 管理 sandbox 的文件系统视图(ephemeral/persistent/branched) |
| **Resource Manager** | 管理 sandbox 的运行期资源(cgroup/memory/pids) |
| **Loop Engine** | 主循环:tool call → sandbox exec → observe → retry |
| **Snapshot** | sandbox 状态在某一时刻的固化(主要靠 Firecracker DM snapshot) |
| **forkFrom** | 从 snapshot 派生新 sandbox(用于并发尝试) |
| **DM snapshot** | Linux device-mapper snapshot;Firecracker 用它做 VM 状态保存 |
| **overlayfs** | Linux Union 文件系统;branched workspace 用它做上层 FS |
