# 04 — 网络隔离设计

本文档涵盖沙箱的网络半边:宿主代理、其过滤管线、TLS 中止衔接、父级代理逃生口,以及沙箱内的宿主路由链。

## 4.1 目标

| ID  | 目标                                                                                                                       |
| --- | -------------------------------------------------------------------------------------------------------------------------- |
| N-1 | 沙箱的所有出站网络流量对宿主 **可观测**(便于过滤、凭证替换、MITM)。                                                |
| N-2 | 域白/黑名单在代理边界而非工具级别强制。                                                                                  |
| N-3 | 默认姿态是 *完全没有网络*(空的 `allowedDomains`)。添加域名必须是显式选择。                                              |
| N-4 | 代理 **鉴权**:一个 16 字节十六进制 token 把守每个 CONNECT / absolute-URI 请求。                                            |
| N-5 | HTTP 代理可选执行 **进程内 TLS 中止**(`tlsTerminate`),使宿主能看到解密的 HTTPS。                                          |
| N-6 | 逐请求 body & 头部访问通过 `network.filterRequest` 开启。崩溃或 reject **拒绝** 请求。                                      |

## 4.2 宿主架构

```
                ┌─────────────────────────────────────────────────────────────┐
                │                       srt-host                              │
                │                                                             │
client ─── TCP ──▶ muxProxyServer (单端口,按首字节分发)                  │
                │     │                                                       │
                │     ├─[ HTTP 方法前缀  ]─▶ createHttpProxyServer()         │
                │     │                          │                            │
                │     │                          ├▶ 纯 HTTP 请求 ⇒ 上游       │
                │     │                          ├▶ CONNECT + 非 TLS = 不透明隧道│
                │     │                          ├▶ CONNECT + TLS ⇒            │
                │     │                          │     terminateAndForward()  │
                │     │                          ├▶ GET/POST http://host ⇒      │
                │     │                          │     可选 UDS MITM            │
                │     │                          │     可选 filterRequest       │
                │     │                          │     可选 mutateHeaders       │
                │     │                          ├▶ cert+key 覆盖              │
                │     │                          └▶ tlsTerminateUpstreamCA     │
                │     │                                                       │
                │     └─[ SOCKS greeting ]────▶ createSocksProxyServer()      │
                │                                └▶ dialDirect / 父级代理   │
                └─────────────────────────────────────────────────────────────┘
```

mux(`sandbox/mux-proxy.ts`)必不可少,因为:

1. 某些客户端(Java 的 `Proxy.Type.HTTP` 选择器)只给出 **一个** 代理 URL;同一 shell 混用的工具不应该需要两个 URL。
2. Windows WFP 过滤器对 loopback 仅 PERMIT 一段端口范围;共享一个端口将范围消耗减半。
3. 站在用户视角,"HTTP 代理在 :N" 与 "SOCKS 在 :M" 表达的是同一个白名单,没有语义差别。

mux 分发是简单的字节嗅探:任何首字节位于 `{0x04,0x05}`(SOCKS4/5)且前 4 字节看起来像 SOCKS greeting ⇒ SOCKS 处理器。其余则交给 HTTP 处理器。

## 4.3 HTTP 代理管线(`http-proxy.ts`)

### 步骤

1. **接受 TCP** 在绑定的 loopback 端口上。
2. **鉴权** —— 若设了 `proxyAuthToken`,校验 `Proxy-Authorization: Basic base64("srt:<token>")`。畸形头部 → `407 Proxy Authentication Required`。
3. **`CONNECT` 方法:**
    1. 解析请求 URL 中的 `<host>:<port>`。
    2. 运行 `filter(port, host)`。阻截 → `403 Forbidden` + `X-Proxy-Error: blocked-by-allowlist`。
    3. **路由决策**,按优先级:
        1. `tlsTerminate` 且 `shouldTerminateTLS(host, port) === true` ⇒ `terminateAndForward`。
        2. `mitmProxy?.domains` 匹配 ⇒ 通过 Unix-domain-socket MITM 代理(`UNCONNECT` 到 `socketPath`)隧道。
        3. `parentProxy` 通过 `selectParentProxyUrl(host, port, noProxy)` 解析 ⇒ 通过 HTTP CONNECT 隧道。
        4. 否则 `dialDirect(host, port)`。
    4. 向客户端发送 `HTTP/1.1 200 Connection Established\r\n\r\n`。
4. **纯 HTTP**(绝对 URI 形式:`GET http://example.com/foo HTTP/1.1`):
    1. 校验鉴权。
    2. `filter(port, host)`。
    3. 若 `tlsTerminate` 且主机未被排除 ⇒ 使用 CA 的叶子证书升级到 TLS,然后作为 HTTPS 运行(罕见路径——`tlsTerminate` + 纯 HTTP 请求会进入相同处理器,因为无论如何都能读字节)。
    4. 若配置了 `filterRequest`,调用 `decideAndRespond(filterRequest, req, res, url, signal)`。只有 **解密-中止** 路径能看见 body;**不透明隧道** 的 CONNECTs 不可读。
    5. `mutateHeaders`(凭证注入器)在允许决策之后、出站 `http(s).request` 之前运行。
    6. 通过以下方式转发:
        - 若配置 `parentProxy`(通过 CONNECT 隧道);
        - 否则 `dialDirect`,然后 `httpRequest`(HTTP)或 `httpsRequest`(HTTPS)。
    7. 通过 `stripHopByHop` 删除 hop-by-hop 头部后将上游响应回传给客户端。

### 为什么 `request.body` 要 tee

`filterRequest` 接收带 `.body` 可读流的 Web 标准 `Request`。无 body 的方法(GET/HEAD/OPTIONS)跳过 tee——字节直接透传给上游。对于 PUT/POST/PATCH 等:

```ts
const web = Readable.toWeb(req).tee()
const [forCallback, forUpstream] = web
// forCallback 进入 `new Request(url, { body, signal })`
// forUpstream 进入实际上游管道
```

如果 `filterRequest` 不读取它那一支(常见情况——大多数过滤器检查 URL/method/头部,不查 body),我们取消它,这样 tee 不会再缓冲上传内容。

## 4.4 SOCKS5 代理管线(`socks-proxy.ts`)

### 方法协商

```
client →  05 01 00      (greeting: SOCKS5, 1 method, "NO AUTH")
server ←  05 00         (选定 "NO AUTH";或 02 00 02 表示口令鉴权)
```

如果设了 `proxyAuthToken`,服务端回复 `02 00 02`(USER/PASS)并校验 `username:password === "srt:<token>"`(token 跟 HTTP basic 一样——客户端 URL 相同)。

### 请求阶段

```
client →  05 01 00 01 7f 00 00 01 00 50  ...
          ver cmd rsv atyp addr            port
```

- `atyp=01` IPv4 ⇒ 4 字节
- `atyp=03` DOMAINNAME ⇒ 1 字节长度 + N 字节 ⇒ 经 `canonicalizeHost` 后,过与 HTTP 相同的 `filter(port, host)`
- `atyp=04` IPv6 ⇒ 16 字节

主机过滤与 HTTP 完全相同,因此嵌入方的 allow/deny/ask 逻辑是单一来源。**认证不匹配 → 0x01(一般 SOCKS 失败)**。允许不匹配 → `0x02`(规则集不允许连接),客户端得到清晰"否",且不泄露主机是否可达。

### 上游路由

与 HTTP CONNECT 相同的决策树,但对父级使用 SOCKS5 CONNECT:`socks://user:token@host:port`(HTTP 父级)或 `socks://user:token@host:port`(SOCKS 父级)。

## 4.5 共享过滤管线(`sandbox-manager.ts`)

`filterNetworkRequest(port, host, askCb)` 是单入口。实现:

```
isValidHost(host)            // 拒绝 NUL/控制字符;IPv6 zone-id;括号
canonicalHost = canonicalizeHost(host) ?? host   // inet_aton 形式、尾部点等

for each deniedDomain in deniedDomains:
    if matchesDomainPattern(canonicalHost, deniedDomain):
        return false

for each allowedDomain in allowedDomains:
    if matchesDomainPattern(canonicalHost, allowedDomain):
        return true

if not askCb or strictAllowlist:
    return false

return askCb({host, port})
```

`isValidHost` 与 `canonicalizeHost` 是关键防御:

- `evil.com\x00.example.com` 会通过朴素的 `endsWith` 匹配;`isValidHost` 拒绝任何控制字节。
- `2852039166`(= `169.254.169.254` 的十进制)绕过针对 `169.254.169.254` 的黑名单;`canonicalizeHost` 在匹配前将其解析为同一字符串。
- 带尾点的 FQDN(`example.com.`)如果按字面比较就会绕过黑名单;规范化会去掉那个点。

## 4.6 域模式匹配(`domain-pattern.ts`)

```
function matchesDomainPattern(hostname, pattern):
    h = lowercase(hostname)
    if pattern == "*": return true                              (仅 deniedDomains)
    if pattern 以 "*." 开头:
        if isIP(h): return false                                (拒绝为 IP 字面量做通配后缀匹配)
        return h 以 "." + pattern[2..].lower() 结尾             (仅严格子域)
    return h == pattern.lower()
```

注意:`*.example.com` *不* 匹配 `example.com` 本身。要包含 apex,你必须同时加上裸域(`example.com`)——这与用户的真实意图一致。

## 4.7 热重载(`updateConfig`)

网络规则是热的:重新赋值 `config`,下一个请求读到新列表。代理对象(`httpProxyServer`、`socksProxyServer`)通过闭包捕获 `filterNetworkRequest`,因此新闭包在下一次调用时看到的是新 `config` 引用。不需要 rebind;不发生端口变化。

Windows 热重载相同——JS 代理仍然闭包 `config`,WFP 层看不到新规则,因为 Windows 没有按 deny 的过滤(它有通用的"按沙箱 SID BLOCK")。热重载只影响 `network.*`。Windows 上的文件系统热重载被 *警告* 但不应用——需要 reset+init。

## 4.8 TLS 中止(`tls-terminate-proxy.ts`、`mitm-ca.ts`、`mitm-leaf.ts`)

### 为何需要自定义 MITM

库暴露一个可选的进程内 MITM 路径,用于检查沙箱工具。生态:

| 用户的工具 | TLS 校验来源 | 输入的信任包 |
| ----------- | ----------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `curl`      | `SSL_CERT_FILE`、`CURL_CA_BUNDLE`   | 指向信任包路径                                                                                       |
| `git`       | `GIT_SSL_CAINFO`(per-system fallback to OpenSSL) | 指向信任包路径                                                                       |
| `node`      | `NODE_EXTRA_CA_CERTS`               | 指向信任包路径                                                                                       |
| `python`    | `REQUESTS_CA_BUNDLE`、`SSL_CERT_FILE` | 指向信任包路径                                                                                     |
| `cargo`     | `CARGO_HTTP_CAINFO`                 | 指向信任包路径                                                                                       |
| schannel(Windows `curl.exe`、`Invoke-WebRequest`、.NET、git 默认后端) | OS 证书库 | 沙箱用户的 `CurrentUser\Root` 通过 `srt-win user trust-ca <path>` 更新 |
| msys2 / OpenSSL | env vars                       | 与 curl/git 同                                                                                       |

### 信任包组成

`mitmCA.trustBundlePath` 是 `createMitmCA()` 写入的单一 PEM 文件:

```
<MITM CA 证书>
-----BEGIN CERTIFICATE-----
<Mozilla 根库串联为 PEM>
-----BEGIN CERTIFICATE-----
<NODE_EXTRA_CA_CERTS 内容(剥离非 CERTIFICATE 块)>
<tlsTerminate.extraCaCertPaths 文件(类似处理)>
```

清理步骤(`PEM_CERT_BLOCK` 正则)防止合并的 PEM 文件(如 `cert+key.pem`)把私钥泄漏进全局可读的 bundle。

### 铸叶子协议

当 CONNECT 抵达代理决定中止的主机时:

1. 在 `mitmCA.leafCerts` 缓存中查找 `(host:port)`;命中即复用。
2. 铸造新叶子:
    - Common Name = SAN = `<host>`。
    - SubjectAltName = `DNS:<host>, DNS:*.<host-base>`(单标签通配符以接受 `a.b.host`)。
    - 用 `mitmCA.key` 签名。叶子的 SKI 字节 = AKI key identifier(与 CA 的 SKI 匹配;node-forge 将 SKI 存为 hex,而 AKI 期望 bytes——应用前转换)。
    - 有效期 24 小时(保持风险面小)。
3. 构造 `tls.createSecureContext({cert, key})`,按主机名缓存。
4. `socket.once('data', sniff-for-ClientHello)` —— 实际上,在向客户端写入 `200 Connection Established` 之前,通过 `peekForClientHello` 完成。
5. 用缓存的上下文将 socket 升级为 TLS;从升级后的流中得到 HTTP 请求。

### 排除的主机(`tlsTerminate.excludeDomains`)

某些主机 **不应** 被中止:

- **mTLS 上游** —— 只有沙箱内的客户端持有客户端证书。中止会让代理重新发起连接,上游拒绝。
- **证书锁定客户端** —— 它们拒绝 MITM CA。例如锁定 API 服务器公开证书的云 CLI 的一部分。

对被排除的主机,代理让 CONNECT 作为不透明字节隧道(仍然经 `filter` 域名白名单,但 **不** 经 `filterRequest` 检查,**也** 不对 HTTPS 流量进行 sentinel 注入)。对这些主机的明文 HTTP 请求仍走正常管线(无需 TLS 中止即可见)。

### CRL 服务(仅 Windows)

在叶子带有 CRL Distribution Point 扩展时,schannel 执行在线撤销检查。如果从沙箱用户 URL 不可达(通常不可达——沙箱只有 loopback 出站),链就会以 `CRYPT_E_REVOCATION_OFFLINE` 失败。

为此,`srt-win` 将空 CRL 写入 `state.db`,JS 代理在 mux 绑定端口的 `/srt.crl`(origin-form 路径 `CRL_PATH`)服务它。CRL 由同一 MITM CA 签名。每个铸造的叶子都带有指向 `http://127.0.0.1:<muxPort>/srt.crl` 的 CDP 扩展。Schannel → "已检查,未吊销" → 沙箱正常。

> **注意**:该设置仅对 Windows 连线。Linux 上,子进程在 `bwrap --unshare-net` 下运行,CDP URL 从宿主命名空间无法到达。Linux 上默认检查吊销的工具(支持矩阵中无)会硬失败;我们接受这种行为,因为它不是已部署的平台。

## 4.9 父级代理(`parent-proxy.ts`)

当用户的网络只允许通过公司代理出站时,编排器自身必须使用该父级才能访问互联网。`parentProxy` 配置:

```ts
{
  http?:  "http://user:pass@proxy.corp:8080",
  https?: "http://user:pass@proxy.corp:8443",   // 可选,未设时回退 http
  noProxy: ".corp,10.0.0.0/8,127.0.0.0/8"      // 逗号分隔后缀或 CIDR
}
```

如果两个字段都未设,管理器回退到环境变量(`HTTP_PROXY` 等),但它 **不** 将父级 URL 回显到子 env(我们设 `HTTP_PROXY=http://127.0.0.1:<port>` 指向我们自己)。

匹配逻辑:

1. 仅在 init 时解析一次 `noProxy`(懒解析)。
2. 对每个目的地 `(host, port)`:
    - 若 `host` 匹配任何 `noProxy` 后缀或 CIDR ⇒ **直连**。
    - 否则 ⇒ 拨号 `selectParentProxyUrl(host, port, noProxy)`,按协议选用。
3. 对 HTTPS 上游:对父级 HTTPS URL 进行 `CONNECT host:port`,通过 `http.request({host:parent, port:parentHttpsPort, method:'CONNECT'})`。
4. 对 HTTP 上游:绝对 URI 形式于代理(`GET http://example.com/foo HTTP/1.1`)。

子进程 **永远** 看不到父级凭据:沙箱 env 中只设 `HTTP_PROXY=http://127.0.0.1:<ourport>`。

## 4.10 沙箱内路由

| OS        | 机制                                                                                                                                                                                       |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| macOS     | `(allow network-outbound (remote ip "localhost:<httpProxyPort>"))`,SOCKS 同理。忽略 `HTTP_PROXY` 的工具(罕见)无法访问互联网。                              |
| Linux     | `--unshare-net` + 将两个 Unix 套接字 bind-mount 到沙箱内。沙箱内两个 `socat` 监听 TCP `:3128`(HTTP)和 `:1080`(SOCKS)。子工具只看到这两个端口。 |
| Windows   | WFP 过滤集 PERMIT 仅 `127.0.0.0/8:low..high`。沙箱账号对其他一切 BLOCK。JS 代理在该范围内绑定,子 env 的 `HTTP_PROXY`/`HTTPS_PROXY` 指向它们。 |

这就是第 1.3 节 G-3 中的双重隔离保证:沙箱进程除了经过审计的代理,无法访问互联网。

## 4.11 逐请求过滤

`network.filterRequest` 是在代理内添加策略的唯一允许接口。契约:

- **输入**:Web 标准 `Request` 对象。延迟 body 流(tee)。
- **输出**:`{action: 'allow'} | {action: 'deny', reason?: string}`。
- **失败模式**:抛出或 reject ⇒ `deny`,reason = 错误消息(fail-closed)。
- **适用范围**:经代理的纯 HTTP,以及任何被中止的 CONNECT(`tlsTerminate`)。**不**适用于不透明隧道 CONNECT(排除的主机)。

常见用例:

- body 大小上限(拒绝 >10MB 的 POST body)。
- URL 前缀限制(拒绝 `PUT https://github.com/...`,即使 `github.com` 已在白名单)。
- 方法限制(只读 API 上拒绝 PATCH)。
- 审计(为合规记录 body 字节;然后 `allow`)。

## 4.12 凭证替换(Sentinel 注入)

sentinel 注册表为每个被掩码的凭证保存一个字符串:

```
sentinelRegistry.register("OPENAI_API_KEY", realValue, [allowedDomains])
   → 返回 "<srt:OPENAI_API_KEY:abc123...>"   (每个注册唯一)
   → 将 realValue 存入每个进程的 Map
```

子 env 得到 `OPENAI_API_KEY="<srt:OPENAI_API_KEY:abc123...>"`(按 `wrapCommandWithSandboxX`.`setEnvVars`)。在代理 TLS 中止路径内部:

```
mutateHeaders = (headers, destHost) => sentinelRegistry.substituteInHeaders(headers, destHost, matchesDomainPattern)
```

对每个头部值、每个 sentinel `<srt:NAME:RAND>`(在 `destHost` 允许),替换为真实字节。按 sentinel 的 `injectHosts` 确保凭证 A 的 sentinel 不能通过凭证 B 允许的主机洗白。

替换仅在 TLS 中止路径上发生(否则上游字节被加密)。对纯 HTTP,`mutateHeadersPlaintext` 通过 `credentials.allowPlaintextInject`(默认 false)开启。

## 4.13 代理鉴权 Token

Token 是 16 字节十六进制字符串(`randomBytes(16).toString('hex')`),代理启动时生成。同一会话内所有 `wrapWithSandbox(...)` 调用间复用。

嵌入于:

- `HTTP_PROXY=http://srt:<token>@127.0.0.1:<port>`
- `HTTPS_PROXY=http://srt:<token>@127.0.0.1:<port>`
- `ALL_PROXY=socks://srt:<token>@127.0.0.1:<port>`(支持处)

校验:

- HTTP:将 `Proxy-Authorization` 按 Basic 解析,用户名 `srt`、密码 `<token>`。
- SOCKS:RFC 1929 USER/PASS 子协商,同样的键值对。

忽略鉴权的外部程序(某些 `curl --proxy-anyauth` 重载,或从 URL 解析 user:pass 的 curl)仍然工作。遵循标准库的程序也工作。剥离 URL 凭证的程序:丢失连接(预期——它们没鉴权就不该到达代理)。

Token **对沙箱进程不是机密**(它出现在子看到的 URL 中)。它对其他拨号 loopback 端口的宿主进程构成屏障。
