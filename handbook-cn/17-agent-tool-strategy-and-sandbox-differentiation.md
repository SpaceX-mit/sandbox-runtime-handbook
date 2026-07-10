# 17 — Agent 工具策略与沙箱差异化

> 本文档回答一个核心问题:**像 Claude Code 这样的 AI Agent 是如何针对不同工具类型(文件类/命令类/网络类)做差异化处理的**?
>
> 定位:**实战架构指南**。基于 `sandbox-runtime` 的能力边界,讲解 Agent 上层应如何设计与工具类型的协同。
>
> 与 `16-bwrap-for-agent-capabilities.md`(基础设施视角)互补:本文档聚焦**工具层策略**,16 文档聚焦**沙箱底层机制**。

---

## 一、为什么需要差异化?

**核心洞察**:Agent 控制的进程可能做任何事——读文件、写文件、访问网络、执行命令。但**每种操作的危险程度差异巨大**。

| 操作 | 危险度 | 最小特权配置 |
|------|-------|------------|
| 读文件 | 低 | 只需要读权限 |
| 搜索文件 | 低 | 只需要读权限 |
| 写文件 | **中** | 需要精确的写路径 |
| 执行任意命令 | **高** | 默认断网、默认禁写 |
| 访问网络 | 中-高 | 白名单域名 |

**最小特权原则(LPP)**:给每个工具**刚好够用**的权限,不多给。

---

## 二、工具类型全景图

### 2.1 三大类别

```
┌─────────────────────────────────────────────────────┐
│  Agent 工具集(以 Claude Code 为参照)                 │
├─────────────────────────────────────────────────────┤
│                                                      │
│  📖 只读类(无文件改动)                               │
│     • Read      - 读文件                             │
│     • Grep      - 内容搜索                           │
│     • Glob      - 文件查找                           │
│     • WebFetch  - 抓取网页                           │
│                                                      │
│  ✏️  文件操作类(有文件改动)                          │
│     • Write     - 写入/创建文件                      │
│     • Edit      - 编辑现有文件                       │
│     • NotebookEdit - 编辑 Jupyter notebook          │
│                                                      │
│  💻 命令执行类(混合:可能读、可能写、可能联网)         │
│     • Bash      - 任意 shell 命令                    │
│     • MCP tools - 通过 MCP 协议调用                  │
│                                                      │
└─────────────────────────────────────────────────────┘
```

### 2.2 与沙箱配置的自然映射

`sandbox-runtime` 提供的配置结构天然映射到这些工具类型:

```typescript
{
  filesystem: {
    denyRead: [...],      // 读类工具关心
    allowRead: [...],
    allowWrite: [...],    // 写类工具关心
    denyWrite: [...],
  },
  network: {
    allowedDomains: [...],  // 网络类工具关心
    deniedDomains: [...],
  }
}
```

---

## 三、差异化的 3 个维度

### 3.1 维度 1:沙箱配置(最重要)

| 工具类型 | read config | write config | 网络 |
|---------|-------------|--------------|------|
| **Read** | 需要 | **不需要** | 通常不需要 |
| **Grep/Glob** | 需要 | **不需要** | 不需要 |
| **Write/Edit** | 需要 | **需要**(精确路径) | 通常不需要 |
| **Bash(读类)** | 需要 | **不需要** | 看情况 |
| **Bash(写类)** | 需要 | **需要** | 看情况 |
| **WebFetch** | 需要 | 不需要 | **必须** |
| **MCP** | 看工具 | 看工具 | 看工具 |

### 3.2 维度 2:数据回收方式

不同工具的"产出"形态不同:

| 工具 | 数据形态 | 回收方式 |
|------|---------|---------|
| **Read** | 文件内容(文本) | 直接读文件,inline 在工具结果里 |
| **Grep** | 匹配行 | stdout(`rg` 输出) |
| **Write** | 写入成功 + 路径 | 沙箱返回值(不需要大块数据) |
| **Edit** | diff(前后对比) | 沙箱生成 diff 返回 |
| **Bash** | stdout + stderr + exit code | 标准进程捕获 |
| **MCP** | JSON-RPC 响应 | 协议解析 |

### 3.3 维度 3:错误处理粒度

| 工具类型 | 失败模式 | Agent 应知道的 |
|---------|---------|---------------|
| **只读类** | 文件不存在/无权限 | 可以重试、换路径 |
| **文件操作** | 冲突/权限/磁盘满 | 需要回滚策略 |
| **Bash** | exit code / 信号 / 超时 | 需要 stdout 分析 |
| **MCP** | JSON-RPC 错误码 | 按工具语义处理 |

---

## 四、各工具类型的实际处理流程

### 4.1 Read 工具(只读)

**调用流程**:

```
LLM 决策:调用 Read("src/foo.ts")
       ↓
沙箱配置:denyRead=[敏感路径], allowWrite=undefined
       ↓
执行:在沙箱内 cat src/foo.ts
       ↓
返回:{content: "...文件内容...", file_path: "src/foo.ts"}
       ↓
LLM:阅读内容继续推理
```

**沙箱特点**:
- **不需要写权限**(最小特权);
- 必须有读权限(否则 EPERM);
- 不需要网络。

**为什么这样设计**:
- Read 是**最高频**的操作;
- 给它最小权限 = 即使 LLM 出错也不会破坏文件系统;
- 即使攻击者控制 LLM 让它读 SSH 私钥 → 沙箱 deny 直接挡掉。

### 4.2 Write/Edit 工具(文件修改)

**调用流程**:

```
LLM 决策:调用 Write("src/foo.ts", content)
       ↓
沙箱配置:allowWrite=["src/", "/tmp/"] (精确范围)
       ↓
执行:在沙箱内写入
       ↓
返回:{success: true, file_path, bytes_written}
       ↓
LLM:通知用户"已修改"
```

**沙箱特点**:
- **精确的写权限范围**(最小特权原则);
- 通常要求用户**确认**(Claude Code 的 permission prompt);
- 不需要网络。

**为什么这样设计**:
- Write 是**最危险**的操作之一;
- 即使 LLM 出错,也只能写到允许的目录;
- 用户能看到 diff,有机会拒绝。

### 4.3 Bash 工具(命令执行)

**调用流程**:

```
LLM 决策:调用 Bash("npm install lodash")
       ↓
判断:是否需要网络?
       ├─ 是 → 沙箱配置带网络白名单(npmjs.org)
       └─ 否 → 沙箱配置完全断网
       ↓
执行:spawn(sandboxed_command)
       ↓
返回:{stdout, stderr, exitCode, duration}
       ↓
LLM:分析输出继续推理
```

**沙箱特点**:
- **网络默认关闭**,按需放行;
- 写权限默认关闭,按需放行;
- **强制捕获所有输出**。

**为什么这样设计**:
- Bash 是**最灵活**也最危险的工具;
- 一个 `rm -rf` 可以毁掉一切;
- 必须用最小权限 + 严格审计。

---

## 五、关键设计模式

### 5.1 按工具类型生成不同沙箱配置

```typescript
// Agent 内部的工具沙箱配置选择
function getSandboxConfigForTool(
  tool: ToolName,
  baseConfig: SandboxRuntimeConfig
): SandboxRuntimeConfig {
  switch (tool) {
    case 'Read':
    case 'Grep':
    case 'Glob':
      return {
        ...baseConfig,
        filesystem: {
          ...baseConfig.filesystem,
          allowWrite: [],  // 强制不允许写
        }
      }

    case 'Write':
    case 'Edit':
      return {
        ...baseConfig,
        filesystem: {
          ...baseConfig.filesystem,
          // 用户显式配置的写路径(精确范围)
        }
      }

    case 'Bash':
      return baseConfig  // 按用户配置 + 启发式判断

    case 'WebFetch':
      return {
        ...baseConfig,
        network: {
          allowedDomains: [
            ...baseConfig.network.allowedDomains,
            /* 从 URL 提取的域名 */
          ],
        }
      }
  }
}
```

### 5.2 工具调用结果的统一封装

无论工具类型,结果都封装成统一的 `ToolResult`:

```typescript
interface ToolResult {
  // 通用字段
  success: boolean
  toolName: string
  duration: number

  // 内容(不同工具不同)
  content?: string           // Read: 文件内容
  filePath?: string          // Write/Edit: 写入的路径
  diff?: string              // Edit: diff 内容
  stdout?: string            // Bash: 标准输出
  stderr?: string            // Bash: 标准错误
  exitCode?: number          // Bash: 退出码
  matches?: GrepMatch[]      // Grep: 匹配行

  // 安全相关(沙箱特有)
  blocked?: boolean          // 是否被沙箱阻止
  violation?: ViolationEvent // 违规事件详情
}
```

### 5.3 工具描述对 LLM 透明化

在工具 schema 里**明确告诉 LLM**这个工具能做什么、不能做什么:

```json
{
  "name": "Read",
  "description": "Reads a file from the local filesystem. The file must exist and be readable. ...",
  "input_schema": {
    "type": "object",
    "properties": {
      "file_path": {
        "type": "string",
        "description": "The absolute path to the file to read"
      },
      "limit": {
        "type": "number",
        "description": "Maximum number of lines to read"
      }
    },
    "required": ["file_path"]
  }
}
```

LLM 看 schema 就知道:
- Read 只能读,不能改;
- 给了错误路径会失败;
- 不需要传任何"环境/网络"参数。

---

## 六、最关键的差异化:错误信号传递

### 6.1 文件类错误的特征

```
Read("/root/.ssh/id_rsa")
→ 返回 EPERM 错误

LLM 看到的:
{
  "success": false,
  "error": "EACCES: permission denied",
  "stderr": "cat: /root/.ssh/id_rsa: Permission denied"
}

LLM 的反应:
- "哦,这个文件读不到"
- "可能没权限"
- "换条路试试"(而不是傻乎乎重试)
```

**关键**:错误信号要**清晰告诉 LLM 失败原因**,让 LLM 能调整策略。

### 6.2 网络类错误的特征

```
Bash("curl https://evil.com")
→ 返回网络被阻止

LLM 看到的:
{
  "success": false,
  "error": "Connection blocked by network allowlist",
  "stderr": "..."
}

LLM 的反应:
- "哦,这个域名被白名单挡住了"
- "我应该用 allowedDomains 里的域名"
- "或告诉用户去配置"
```

### 6.3 Bash 超时的处理

```typescript
// 沙箱化的 Bash 应该带超时
const result = await runBashInSandbox(command, { timeoutMs: 30000 })

if (result.timedOut) {
  return {
    success: false,
    error: `Command timed out after 30s. Consider breaking it into smaller parts.`,
    partialStdout: result.stdout,  // 部分输出也有用
  }
}
```

**LLM 学到的经验**:
- "这个命令需要更长时间"
- "我应该分步执行"
- "或换种思路"

---

## 七、最佳实践总结

### 7.1 工具与沙箱的映射原则

| 原则 | 含义 |
|------|------|
| **最小权限** | 工具能用啥就给啥,不多给 |
| **按需网络** | 默认断网,需要的域名显式开 |
| **结果透明** | 错误信息要让 LLM 推理出原因 |
| **可观测** | 所有操作都可审计 |

### 7.2 反模式 vs 正模式

❌ **反模式**:所有工具都用同一个超集配置

```typescript
// 给 Read 也开放写权限?
{ allowWrite: ["."] }  // Read 不需要写!
```

✅ **正模式**:按工具精细化

```typescript
Read:   { allowWrite: [] }              // 强制只读
Write:  { allowWrite: ["."] }           // 按需
Bash:   动态判断                        // 启发式
WebFetch: { network: { 动态白名单 } }  // 按 URL
```

### 7.3 Bash 命令的启发式判断

```typescript
// 根据命令内容启发式判断是否需要网络/写权限
function inferBashSandboxConfig(command: string): Partial<SandboxRuntimeConfig> {
  const overrides: Partial<SandboxRuntimeConfig> = {}

  // 检测网络需求
  if (/curl|wget|fetch|git\s+(clone|pull|push)|npm|pip|apt/.test(command)) {
    overrides.network = {
      allowedDomains: inferDomainsFromCommand(command),
      // 例如: "curl https://api.github.com" → api.github.com
    }
  }

  // 检测写需求
  if (/rm|mv|cp\s|>|>>|tee|touch|mkdir/.test(command)) {
    overrides.filesystem = {
      allowWrite: inferWritePathsFromCommand(command),
      // 例如: "rm /tmp/foo" → /tmp
    }
  }

  return overrides
}
```

---

## 八、给 Agent 框架设计者的建议

### 8.1 工具 schema 设计原则

```typescript
// 好的 schema:清晰、具体、有边界
{
  name: 'Read',
  description: `
    Reads a file from the local filesystem.

    Usage:
    - The file_path must be an absolute path
    - Cannot read files larger than 10MB
    - Cannot read system files (e.g. /etc/shadow)

    Returns:
    - { content, file_path, size_bytes }

    Errors:
    - FILE_NOT_FOUND: file doesn't exist
    - PERMISSION_DENIED: file is protected
    - FILE_TOO_LARGE: file exceeds size limit
  `,
  input_schema: { ... }
}

// 不好的 schema:模糊、无边界
{
  name: 'Read',
  description: 'Reads a file',
  input_schema: { ... }
}
```

### 8.2 错误信息组织

```typescript
// 好的错误信息:让 LLM 能推理
{
  success: false,
  error_code: 'PERMISSION_DENIED',
  error_message: 'Cannot read /root/.ssh/id_rsa: file is in denyRead list',
  suggestions: [
    'Try a different file path',
    'Check if you need to add this path to allowRead',
    'Ask the user to grant access'
  ]
}

// 不好的错误信息:LLM 推理不出原因
{
  success: false,
  error: 'Operation failed'
}
```

### 8.3 分层架构

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

---

## 九、与其他文档的关系

| 文档 | 内容 | 与本文档的关系 |
|------|------|---------------|
| `02-system-architecture.md` | 整体系统架构 | 互补:本文档聚焦工具层 |
| `09-cli-and-programmatic-api.md` | API 使用方式 | 互补:本文档讲设计原则 |
| `11-violation-monitoring.md` | 违规监控 | 互补:本文档涉及错误信号 |
| `13-security-model.md` | 安全模型论证 | 互补:本文档讲实战策略 |
| `16-bwrap-for-agent-capabilities.md` | bwrap 能力总览 | **前置阅读**:理解底层机制 |

---

## 十、一句话总结

> **Agent 工具策略的核心是「按工具类型给最小权限」**:Read 类不需要写权限,Write 类需要精确写权限,Bash 类按需网络。
>
> **`sandbox-runtime` 在底层提供统一的 `wrapWithSandboxArgv()` 接口,但上层 Agent 必须自己决定每个工具调用配什么沙箱配置**。
>
> **真正的难点不是沙箱本身,而是工具 schema 设计、错误信息组织、LLM 可理解的 ToolResult 结构**——这些决定了 Agent 能否"聪明地"使用工具。