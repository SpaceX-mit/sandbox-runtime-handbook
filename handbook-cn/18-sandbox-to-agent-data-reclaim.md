# 18 — 沙箱到 Agent 的数据回收模式

> 本文档回答一个核心架构问题:**当 Agent 把命令/工具放进沙箱执行后,产生的数据(输出、文件、状态)如何回收给主 Agent**?
>
> 定位:**通信层架构指南**。聚焦沙箱 ↔ 宿主的数据通道设计。
>
> 与 `16-bwrap-for-agent-capabilities.md`(底层机制)和 `17-agent-tool-strategy-and-sandbox-differentiation.md`(工具层策略)互补:本文档聚焦**数据回收通道**这一独立维度。

---

## 一、问题的本质

```
┌─────────────────────┐         ┌─────────────────────┐
│  主 Agent(宿主)    │  ───?──→  │ 沙箱/容器(隔离环境)│
│                     │         │                     │
│  发起命令            │         │  执行命令/工具        │
│                     │         │                     │
│  期望拿回结果        │  ←──?──  │  产生了输出/文件/数据 │
└─────────────────────┘         └─────────────────────┘
```

**隔离是双向的**:
- 沙箱**看不见**宿主(被隔离)→ 这是安全
- 宿主**也看不见**沙箱内部 → 这是问题

必须设计**单向或双向的数据通道**。

---

## 二、6 种主流回收方式

### 方式 1️⃣:stdout / stderr 捕获(最常用,占 90% 场景)

**原理**:命令的标准输出本身就是设计好的"返回通道"。

**Node.js 宿主示例**:
```typescript
import { spawn } from 'node:child_process'

// 沙箱化的命令
const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
  'cat /etc/os-release'
)

const child = spawn(argv[0], argv.slice(1), {
  shell: false,
  env,
})

let stdout = ''
let stderr = ''
child.stdout.on('data', d => stdout += d.toString())
child.stderr.on('data', d => d.toString())
child.stderr.on('data', d => stderr += d.toString())

child.on('close', code => {
  console.log('exit code:', code)
  console.log('output:', stdout)        // ← 数据在这里被收回
  console.log('error:', stderr)
})
```

**优点**:
- 零额外架构:每个 Unix 进程天生支持
- 自动缓冲/管道:OS 内核处理
- **沙箱完全无感**:本来就在用

**缺点**:
- 大量数据(>10MB)会撑爆内存
- 只能传文本/可序列化数据,不能传二进制文件

**适用**:Agent 大部分命令场景(`ls`、`cat`、`grep`、`npm test`)

---

### 方式 2️⃣:共享挂载点(Shared Volume)

**原理**:在沙箱里 bind mount 一个目录,宿主和沙箱都能读写。

**bwrap 配置**:
```bash
bwrap \
  --bind /tmp/agent-shared /tmp/agent-shared \   # 双向共享
  ...
  -- /bin/bash -c "do_work > /tmp/agent-shared/result.json"
```

**宿主读取**:
```typescript
// 沙箱跑完后,宿主直接读文件
const result = JSON.parse(
  fs.readFileSync('/tmp/agent-shared/result.json', 'utf-8')
)
```

**优点**:
- 大文件无压力(流式读写)
- 适合二进制、图像、压缩包等
- 双向:宿主也能传配置进沙箱

**缺点**:
- 路径需要预先约定
- 有大小/数量限制(不能滥用)
- **要小心**:共享目录破坏了部分隔离性(沙箱内恶意代码可能写宿主文件)

**适用**:构建产物、日志文件、训练数据下载等

---

### 方式 3️⃣:Unix Domain Socket(结构化流式通信)

**原理**:沙箱内启动一个 socket 服务,宿主连接读取。

**bwrap 配置**:
```bash
bwrap \
  --bind /tmp/srt-observe.sock /tmp/srt-observe.sock \  # 把宿主的 socket 透传进沙箱
  ...
```

**沙箱内进程**(用 socat / 自研工具):
```bash
# 沙箱内的 apply-seccomp 把违规事件写到 socket
echo '{"event": "blocked", "path": "/root/.ssh/id_rsa"}' \
  > /tmp/srt-observe.sock
```

**宿主监听**:
```typescript
// sandbox-runtime/linux-violation-monitor.ts 的实际做法
const socket = net.createServer(client => {
  client.on('data', line => {
    const event = JSON.parse(line)
    violationStore.record(event)
  })
})
socket.listen('/tmp/srt-observe.sock')
```

**优点**:
- **流式**:边产生边传,不阻塞
- **结构化**:天然适合 JSON/Protobuf
- **反向**:沙箱主动推数据给宿主

**缺点**:
- 协议需要双方约定
- 生命周期管理复杂(断线重连)

**适用**:日志流、违规监控、长任务进度上报

---

### 方式 4️⃣:JSON 输出约定(最实用)

**原理**:命令直接打印 JSON 到 stdout,宿主解析。

**示例**:
```bash
# 沙箱内执行的命令
echo '{
  "status": "success",
  "data": {
    "files_changed": ["src/foo.ts", "src/bar.ts"],
    "tests_passed": 42,
    "duration_ms": 1234
  }
}'
```

**宿主**:
```typescript
const result = JSON.parse(stdout)
// 直接喂给 Agent 作为工具返回值
```

**优点**:
- 简单到极致:就是 stdout 模式 + JSON 约定
- 跨语言通用
- Agent 友好(JSON 是 LLM 最易消化的格式)

**缺点**:
- 仍然受 stdout 体积限制

**适用**:**Agent 工具调用**的标准做法

---

### 方式 5️⃣:哨兵文件(Sentinel File)

**原理**:用文件存在性作为"完成信号"。

**示例**:
```bash
# 沙箱内
do_long_computation
echo "done" > /tmp/computation.done
echo "$RESULT" > /tmp/computation.json
```

**宿主**:
```typescript
// 轮询等待
while (!fs.existsSync('/tmp/computation.done')) {
  await sleep(100)
}
const result = JSON.parse(fs.readFileSync('/tmp/computation.json'))
```

**优点**:
- 解耦完成信号和数据
- 适合长任务

**缺点**:
- 轮询浪费 CPU(更好的做法是 inotify)
- 多任务时需要唯一文件名

**适用**:异步任务、后台作业

---

### 方式 6️⃣:MCP 协议(Agent 工具调用标准)

**原理**:MCP (Model Context Protocol) 用 JSON-RPC over stdio。

**架构**:
```
Agent (Claude Code)
   ↓ 启动 MCP server(被沙箱包裹)
srt npx -y some-mcp-server
   ↓ MCP server 通过 stdout 吐 JSON-RPC 响应
Agent 解析响应,作为工具调用结果
```

**MCP 消息示例**(沙箱内 MCP server 输出):
```json
{"jsonrpc": "2.0", "id": 1, "result": {
  "content": [{"type": "text", "text": "File list: foo.txt, bar.md"}]
}}
```

**优点**:
- **标准化**:所有 MCP 工具用同一套协议
- 自带请求/响应关联
- 完美适配 Agent 工具调用模型

**适用**:Claude Code 等 Agent 的工具集成。**这是 sandbox-runtime 的主要使用场景**

---

## 三、`sandbox-runtime` 的实际做法

### 3.1 核心结论:`sandbox-runtime` 本身不做数据回收

它**只负责安全沙箱化**,数据回收完全交给调用方:

```typescript
// sandbox-manager.ts 的设计契约
async function wrapWithSandboxArgv(
  command: string,
  ...
): Promise<{ argv: string[]; env: NodeJS.ProcessEnv }>
```

返回值是 `{ argv, env }`——**就是个 spawn 描述符**,调用方照常:

```typescript
const { argv, env } = await SandboxManager.wrapWithSandboxArgv(cmd)
const child = spawn(argv[0], argv.slice(1), { shell: false, env })
// ↑ 之后全是标准 Node.js 进程管理
// ↑ 数据通过 stdout 自然回到这里
```

**设计哲学**:sandbox-runtime 是**透明的中间件**,不发明新协议。

### 3.2 唯一例外:违规监控用 Unix Socket

`sandbox-runtime` 内部有一个反向通道——违规事件流:

```
┌──────────────────────────────────────────────────┐
│  沙箱内 apply-seccomp 进程                        │
│  ↓ 检测到 blocked syscall                         │
│  echo '{"event":"blocked",...}' > observe.sock   │
└────────────────────────┬─────────────────────────┘
                         │ 通过 Unix socket 反向流出
                         ▼
┌──────────────────────────────────────────────────┐
│  宿主的 linux-violation-monitor                  │
│  ↓ 解析 JSON                                     │
│  ↓ 存入 SandboxViolationStore                    │
└──────────────────────────────────────────────────┘
```

这是 srt **唯一**自带的"沙箱→宿主"主动数据流机制,原因:
- 违规事件是**流式的**(不是命令结束才有)
- 不能等命令结束才上报(可能命令挂死)
- 必须用反向通道

### 3.3 Claude Code 实际怎么用?

Claude Code 把所有命令都包成 srt:

```typescript
// Claude Code 内部(伪代码)
async function executeBashCommand(command: string) {
  const { argv, env } = await SandboxManager.wrapWithSandboxArgv(command)

  const child = spawn(argv[0], argv.slice(1), { shell: false, env })

  // 完全是标准做法
  const stdout = await captureStdout(child)
  const stderr = await captureStderr(child)
  const code = await waitExit(child)

  return {
    success: code === 0,
    output: stdout,
    error: stderr,
    exitCode: code
  }
}
```

**数据回收方式 = 方式 1(stdout)**。

---

## 四、实战选择决策树

```
要传什么数据?
│
├─ 文本 / JSON(<10MB)
│   └─ 用 stdout(方式 1/4)✅ 最简单
│
├─ 大文件 / 二进制
│   └─ 用共享挂载点(方式 2)
│
├─ 实时流式(边产生边传)
│   └─ 用 Unix Socket(方式 3)
│
├─ 长任务完成信号
│   └─ 用哨兵文件(方式 5)
│
└─ Agent 工具调用(MCP 协议)
    └─ 用 JSON-RPC over stdio(方式 6)
```

---

## 五、最佳实践(避坑指南)

### 5.1 数据大小预估

| 数据量 | 推荐方式 | 备注 |
|--------|---------|------|
| < 1 MB | stdout | 默认 |
| 1-10 MB | stdout + 流式处理 | 用 `data` 事件而不是 buffer |
| > 10 MB | 共享挂载 | 文件路径要安全 |
| 流式 / 实时 | Unix socket | 需要服务端配合 |

### 5.2 常见反模式

❌ **把整个 git history 通过 stdout 传** → 用 git bundle 写到挂载点

❌ **在 stdout 里塞二进制图像** → 写到文件,挂载点共享

❌ **无限循环打印日志** → 用 socket 流式 + 速率限制

### 5.3 安全考量

⚠️ **共享挂载点 = 隔离性降低**:
```ts
// 沙箱内恶意代码可能写宿主文件
--bind /host/shared /sandbox/shared  // 小心这个!
```

缓解措施:
- 共享目录用专用路径(`/tmp/srt-shared-{uuid}/`)
- 任务结束后立即清理
- 校验沙箱内文件的权限/内容

⚠️ **stdout 数据可能含敏感信息**:
- 命令里包含密码(如 `mysql -uroot -pMyPassword`)会在进程列表泄露
- 改用 `MYSQL_PWD` 环境变量 + `--unsetenv` 隔离

---

## 六、给 Agent 框架设计者的建议

### 6.1 工具调用结果的标准结构

```ts
interface ToolResult {
  // 命令执行结果
  success: boolean
  exitCode: number
  stdout: string
  stderr: string
  duration: number

  // 元数据(供 Agent 推理用)
  truncated: boolean          // stdout 是否被截断
  totalBytes: number          // 原始 stdout 大小
  filesChanged: string[]      // 共享挂载点里变化的文件

  // 安全相关
  blockedAttempts: ViolationEvent[]   // 沙箱拒绝的操作
  resourceUsage: {                    // 资源消耗
    cpuMs: number
    peakMemoryMb: number
  }
}
```

### 6.2 分层架构

```
┌─────────────────────────────────────┐
│  Agent Layer(理解工具调用)         │  ← LLM 处理 ToolResult
├─────────────────────────────────────┤
│  Tool Runtime Layer(执行 + 回收)  │  ← 选择回收方式(stdout/文件/socket)
├─────────────────────────────────────┤
│  Sandbox Layer(隔离执行)           │  ← srt / bwrap / Docker
└─────────────────────────────────────┘
```

每一层只关心**自己相邻层**的接口:
- Agent 层 → Tool Runtime:`ToolResult`
- Tool Runtime → Sandbox Layer:`{argv, env}` + spawn

**sandbox-runtime 在最底层,让上层无需关心隔离细节**。

### 6.3 多通道协同的典型场景

```typescript
// 复杂任务:同时用多个通道
async function runComplexTask(command: string) {
  // 1. 启动宿主的监听服务(Unix Socket)
  const monitor = startViolationMonitor()        // 通道 3:违规事件
  
  // 2. 准备共享挂载点(大文件用)
  const sharedDir = createSharedDir()            // 通道 2:大文件
  
  // 3. 启动沙箱命令(标准 stdout)
  const { argv, env } = await wrapWithSandbox(command, {
    bindShared: sharedDir,
    observeSocket: monitor.socketPath
  })
  
  const child = spawn(argv[0], argv.slice(1), { env })
  
  // 4. 同时收集三个通道的数据
  return {
    stdout: collectStdout(child),               // 通道 1
    violations: monitor.events,                  // 通道 3
    outputFiles: listDir(sharedDir),             // 通道 2
  }
}
```

---

## 七、与其他文档的关系

| 文档 | 内容 | 与本文档的关系 |
|------|------|---------------|
| `11-violation-monitoring.md` | 违规监控设计 | **深入**:本文档提及但未展开 |
| `16-bwrap-for-agent-capabilities.md` | bwrap 能力总览 | 前置阅读:理解沙箱机制 |
| `17-agent-tool-strategy-and-sandbox-differentiation.md` | 工具策略 | **强相关**:本文档是它的"数据通道"补充 |
| `02-system-architecture.md` | 系统架构 | 互补:本文档聚焦通信层 |

---

## 八、一句话总结

> **沙箱数据回收的本质 = 设计"出沙箱"的通道**。90% 场景用 stdout,文件类用共享挂载,流式用 socket。
>
> **`sandbox-runtime` 的设计哲学是透明**:只做隔离,不发明新协议。数据回收用最朴素的 `spawn() + stdout`,调用方零学习成本。
>
> **给 Agent 框架**:把 `ToolResult` 标准化(success + output + metadata + security events),让 LLM 能推理"这次工具调用发生了什么"。