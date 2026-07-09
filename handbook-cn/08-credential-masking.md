# 08 — 凭证掩码

凭证系统是常规 deny-by-default 网络与文件系统策略之上的第二层。它让运维表达:"这个特定的 secret 被掩码:它仅在访问该特定主机时才离开本机。"

## 8.1 威胁模型假设

伪装场景:
1. 沙箱工具有合法需求调用 `api.example.com`。
2. 该工具在环境变量中获得 API key —— `EXAMPLE_API_KEY=sk_live_abc123`。
3. 运维想要在沙箱会话期间 **撤销** 该 key,但工具 *需要* 一个值存在(没有 `unset EXAMPLE_API_KEY` 会破坏某些工具)。
4. **要么**:运维希望工具仅在调用 `api.example.com` 时使用真 key,而非其他主机;**或者**:工具做自己的管道,运维希望核实正在发送什么。

掩码系统两者都给:
- 子进程看到 sentinel —— 一个无用途的占位字符串。
- 代理在出口替换为真值,**仅** 限于白名单主机且 **仅** 限于出口 TLS 被中止的情况(以便运维也能检查请求)。

## 8.2 Sentinel 生命周期

```
HOST                              CHILD                              UPSTREAM
─────                             ─────                              ───────
realValue = process.env.SECRET                                   
         │                                                        
         ▼                                                        
register("SECRET", realValue, [hosts])                            
         │                                                        
         ├── returns sentinel = "<srt:SECRET:<rand>>"             
         ▼                                                        
wrap-time: setEnvVars = { SECRET: sentinel }                      
         │                                                        
         ├── bwrap --setenv SECRET sentinel                        child sees SECRET=sentinel
         │                                                        
         ▼                                                        
HTTPS request to api.example.com                                  
         ├ Host: api.example.com                                  
         ├ X-Auth-Token: <srt:SECRET:<rand>>                      
         │                                                        
         ▼   (proxy connects to upstream with HTTPS, child cert-verified)
proxy intercepts:
    mutateHeaders(req, "api.example.com"):
        header["X-Auth-Token"] = <srt:SECRET:<rand>> → realValue
         │                                                        
         ▼                                                        
upstream sees X-Auth-Token: realValue                              ✓
```

## 8.3 每凭证配置

### 文件凭证

```json
{
  "path": "/home/me/.npmrc",
  "mode": "mask",
  "extract": "_authToken = \"([^\"]+)\"",
  "onExtractNoMatch": "warn",      // 默认; "deny" 或 "error" 可选
  "maskDuplicates": false,         // 同时扫描未匹配 span(对短值有风险)
  "injectHosts": ["*.npmjs.org"]   // 默认:network.allowedDomains
}
```

| 字段               | 含义                                                                                              |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| `path`              | 凭据文件。支持与 `filesystem.denyRead` 相同的路径形式。                                  |
| `mode`              | `"deny"`(不可读)或 `"mask"`(sentinel 内容)。                                                |
| `extract`           | 可选正则。第 1 组被替换为 sentinel,文件其余字节保留。 |
| `onExtractNoMatch`  | `"warn"` / `"deny"` / `"error"` —— 见文档 03。                                                  |
| `maskDuplicates`    | 同时替换在 regex 匹配 span 之外的每个字面出现。                              |
| `injectHosts`       | 代理在何处替换回真值。默认 = `network.allowedDomains`。                  |

### Env 凭证

```json
{ "name": "ANTHROPIC_API_KEY", "mode": "mask", "injectHosts": ["api.anthropic.com"] }
```

| 字段         | 含义                                                                                                       |
| ------------- | ------------------------------------------------------------------------------------------------------------- |
| `name`        | POSIX 环境变量名(regex 校验以避免 flag 解析)。                                                   |
| `mode`        | `"deny"`(在沙箱内 unset)或 `"mask"`(sentinel)。                                                      |
| `injectHosts` | 同文件的语义。                                                                                     |

### 跨字段校验

- `injectHosts` pattern 必须能经 `network.allowedDomains` 抵达(语义 —— `*.github.com` 覆盖 `api.github.com`)。
- `injectHosts` pattern 不得被 `network.tlsTerminate.excludeDomains` 完全覆盖(否则何处都不会注入)。
- `injectHosts: []`(显式空)被拒绝 —— 自相矛盾。
- `mode: "mask"` 要求设置 `network.tlsTerminate`,或 `credentials.allowPlaintextInject: true`(明文显式 opt-in)。
- `mode: "mask"` 的文件 `path` 以 `/` 结尾被拒绝(单文件掩码对目录无定义)。

## 8.4 SentinelRegistry

编排器进程内的单例。每个进程的 Map:

```
sentinelRegistry = {
    nameToSentinel: Map<name, sentinelString>,
    sentinelToReal:  Map<sentinelString, realString>,
    sentinelToHosts: Map<sentinelString, string[]>   // injectHosts
}
```

`register(name, real, injectHosts)` 返回 sentinel 并存储两个映射。`clear()` 丢弃所有(`reset()` 时调用)。

### Sentinel 格式

`<srt:NAME:RANDOM>`,其中:
- `<NAME>` 是环境变量名或经消毒的文件/路径哈希。
- `<RANDOM>` 是每个注册 16 个随机 hex 字节(32 字符),通过 `crypto.randomBytes` 生成。

唯一随机后缀意味着同一个凭证在两次不同会话被掩码产生不同 sentinel —— 防止跨会话关联(持有一次会话字节的攻击者无法在未来会话识别同一值)。

### 替换算法

`substituteInHeaders(headers, destHost, matchesDomainPattern)`:

```
for each [headerName, headerValue] in headers:
    for each (sentinel, real) in sentinelToReal:
        if destHost 匹配 sentinelToHosts[sentinel] 中的每个 host:
            headerValue = headerValue.replace(sentinel, real)
    headers[headerName] = headerValue
```

迭代 header(而非构造新 Headers 对象)保持就地变更 —— 这很重要,因为 header 反向引用 Node 的 `OutgoingMessage` 直接。

### TLD 时 sentinel 查找

`namesInjectableAt(host, matches)` 返回其 `injectHosts` 会在该主机上注入的凭证名列表。用于网络决策点,从而我们可以记录 "这个被掩码的凭证具有占位符正在出站,因为该主机从 TLS 中止排除"。

## 8.5 掩码文件存储(`MaskedFileStore`)

*必须* 读取凭证文件的沙箱进程(因为未掩码的工具在没有时失败)得到一个托管的伪造版本。

### 存储做了什么

`buildMaskedFileBinds(credentialFiles, allowedDomains, sentinelRegistry, store)`:

```
for each credentialFile in credentialFiles:
    skip if mode != "mask"
    realPath = expandUserPath(credentialFile.path)
    realBytes = readFileSync(realPath)             ← 可能抛错;若抛就跳过
    extract = credentialFile.extract
    if extract:
        re = new RegExp(extract, 'g')
        sentinel = register(realPath, realBytes.match(re)?.[1] ?? "", allowedDomains)
        maskedBytes = realBytes.replace(re, m => m.replace(matchedValue, sentinel))
        if maskDuplicates:
            maskedBytes = maskedBytes.replace(sentinel, sentinel)   ← noop,加上原始替换
        if onExtractNoMatch == "warn":
            if no match found: console.warn("...")
        if onExtractNoMatch == "deny":
            downgrade to mode="deny"   ← 折叠进文件 deny 集合
        if onExtractNoMatch == "error":
            throw
    else (整文件掩码):
        sentinel = register(realPath, realBytes, allowedDomains)
        maskedBytes = sentinel

    fakePath = store.write(realPath, maskedBytes)
    bind = { realPath, fakePath }
    maskedFileBinds.push(bind)

return { binds: maskedFileBinds, degradeToDenyPaths }
```

`MaskedFileStore` 写入一个托管的临时目录(在首次调用时懒创建)。目录中所有文件在 `reset()` 时删除。该目录只读 bind-mount 到沙箱内(Linux/macOS),因此沙箱可读不可写。

### 整文件 vs 结构化掩码

```
realFile:
    registry=https://registry.npmjs.org/
    _authToken = "abc123def456"

整文件掩码:
    <srt:/home/me/.npmrc:abc123def>
    (整内容被替换)

结构化掩码 (extract = '_authToken = "([^"]+)"'):
    registry=https://registry.npmjs.org/
    _authToken = "<srt:/home/me/.npmrc:abc123def>"
    (仅捕获组被替换)
```

工具解析文件时结构化更优。整文件用于内容本身即凭证的工具。

## 8.6 按 OS 模式影响

| OS      | mode = "deny"                                  | mode = "mask"                                                                |
| ------- | ---------------------------------------------- | ---------------------------------------------------------------------------- |
| macOS   | `readConfig.denyOnly.push(realPath)`           | `readConfig.denyOnly.push(realPath)`(降级;SBPL 当前不能重定向读)      |
| Linux   | bwrap `--ro-bind /dev/null <realPath>`          | `--ro-bind <fakePath> <realPath>`(只读),fakePath 由宿主拥有              |
| Windows | `acl grant` 不包含;只有 ALLOW 给沙箱用户添加 deny path(沙箱用户反正没有权利);文件变成不可读 |
| Windows | 与 macOS 相同 —— SBPL 等价物是 ACL stamp/grant;在 Windows 上 mask 在 DYLD 等价物出现前也降级为 deny。 |

## 8.7 每 OS 注入触发

| OS      | 替换发生位置                                                                                 |
| ------- | -------------------------------------------------------------------------------------------------------------- |
| macOS   | JS HTTP 代理内部的 TLS 中止路径(`mutateHeaders` 回调)。                                |
| Linux   | 同 macOS。                                                                                                 |
| Windows | 同 macOS(Node ↔ Node 代理内)。叶子在 JS 中铸造;替换在 JS 端。                       |
| 网络请求路径(无中止) | `mutateHeadersPlaintext` 回调若调用方设了 `allowPlaintextInject: true`。否则 sentinel 保留原状。 |
| 不透明隧道 CONNECT(排除的主机) | 不注入 —— 代理看不见 HTTPS 字节。Sentinel *对上游可见* 如果上游就是合法主机,这就是为什么 `excludeDomains` 是按主机 opt-out(mTLS/锁定),而非全局。 |

## 8.8 跨切:Schema 校验

`SandboxRuntimeConfigSchema` 有 `superRefine` 遍历 `credentials.{files, envVars}` 并:

1. 验证 `injectHosts[i]` 经 `network.allowedDomains` 可达(语义覆盖)。
2. 验证 `injectHosts[i]` 不被 `tlsTerminate.excludeDomains` 完全覆盖。
3. 设置 `hasMasked` flag;若任一凭证有 `mode == "mask"` 且既未设 `tlsTerminate` 也未设 `credentials.allowPlaintextInject`,则 schema 拒绝整个配置。

## 8.9 心智模型:为什么它强大

天真的 "把环境变量掩码成 dummy,工具会泄漏它" 防御有缺陷。工具可能从任何地方提取值——自己的二进制、配置文件、其他进程的内存缓存——并发送给选择的主机。

`srt` 模型带给你的是:

- 替换发生在 **最后可能时刻**(代理出口),由证书验证 + 域名白名单 + 凭证白名单把关。工具永远不会持有真值。
- 工具 *无法* 到达任何其他主机(网络围栏仍生效)。
- 工具 *也无法* 通过 `~/.npmrc` 外泄(文件被掩码或 deny)。

一次沙箱突破必须规避全部三者:文件隔离、网络隔离,**并**找到绕过 TLS 中止端点的方法。这距离大多数当代沙箱突破的发生点隔了两个原语。

## 8.10 v2 待解决问题

- **macOS 上的 DYLD interposer** —— 让 `mode: "mask"` 不降级到 `mode: "deny"`。
- **文件内容之外的请求体内结构化替换** —— 当前我们在 HTTP 头部和代理请求体中替换;HTTPS POST 请求体内的替换字节只有在 `filterRequest` 实际查看时才被代理看到。
- **在宿主上按写重新盖印** —— 当前掩码文件存储持有掩码字节;worker 可以写出 sentinel,然后让工具通过后续读"看到"真字节。目前还不令人担忧,因为 write-deny 占优。
