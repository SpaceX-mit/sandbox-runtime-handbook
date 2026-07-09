# 07 — Windows 文件系统与网络隔离

Windows 是 srt 中架构上最独特的平台。这里没有 Seatbelt 或 bubblewrap 的等价物。实现复用 **两个 Windows 现有原语**:

1. **NTFS discretionary ACL(`DACL`)** —— 每个文件系统权限决策(读、写、修改、删除子项)由内核通过 DACL 强制执行。
2. **Windows Filtering Platform(`WFP`)** —— 内核的网络策略层;我们在 `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` 上添加过滤条件。

诀窍:**沙箱进程不作为调用用户运行。** 它以一个专用的、机器本地的 `srt-sandbox` 用户运行,密码是随机的、DPAPI 加密的。该用户在调用用户的文件上没有 *任何* 固有权利(不像调用用户拥有自己的 profile 目录)。然后我们 **盖印** 给 `srt-sandbox` SID 加性的 ACE 到用户想要可访问的路径。

其他一切——WFP 过滤器、ACL 盖印/撤销、沙箱用户配置、CA 信任安装、两段式启动——都在打包的 `srt-win` 辅助程序中(Rust 二进制,~2 万行)。

## 7.1 一次性安装(`srt-windows-install`)

每次宿主机执行一次的自提升 CLI 调用。顺序:

```
srt → 通过 ShellExecuteEx(runas) + UAC 派生提权的 `srt-win install`
srt-win install (已提权):
    1. 创建本地用户 `srt-sandbox`
         net user srt-sandbox <random-pw> /add
       如果该名字的用户存在但并非我们之前安装 → 拒绝。
    2. 将其加入 `sandbox-runtime-users` 组
       该组可读 state.db 但无法解密 DPAPI blob。
    3. DPAPI 加密随机密码(机器作用域)
       写入 %LOCALAPPDATA%\sandbox-runtime\state.db(DACL 盖印为仅 broker)
    4. 打开 BFE(底过滤引擎);我们通过提权获得管理员权限
    5. 配置 WFP sublayer + 4 个过滤器(在 v4/v6 各 PERMIT loopback + BLOCK 沙箱 SID)
    6. 如交互式:向用户确认过滤器已生效
```

### 安装幂等性

第二次 `install` 运行:
- 若用户已存在并携带相同 marker,复用同一 SID。
- 轮换密码(写新 DPAPI blob)。
- 通过 `wfp filter enum` 调和 WFP 过滤器 → 删除并替换。

### 留在磁盘上的文件

- `%LOCALAPPDATA%\sandbox-runtime\state.db` —— DACL 盖印;永远不会保存明文凭据。
- `HKLM\…\srt-sandbox-profile` 键。
- 沙箱用户的 profile 目录 `C:\Users\srt-sandbox`。

## 7.2 每个 Init 的盖印(`SandboxManager.initialize` 在 Windows 上)

当 `initialize` 在 Windows 上运行时,管理器:

1. 解析 `srt-win`(默认:`vendor/srt-win/<arch>/srt-win.exe`)。
2. 运行 `srt-win user status` → 确保用户已配置且凭据存在。
3. 运行 `srt-win wfp verify` → 行为型 connect 探针(下文详述)。
4. 如果 `tlsTerminate` → 运行 `srt-win user status ca-cert` 并比对指纹。
5. 根据配置计算访问集:
    - `grantRead` = 展开的 `filesystem.allowRead`。
    - `grantWrite` = 展开的 `filesystem.allowWrite`。
    - `denyRead` = 展开的 `filesystem.denyRead ∪ credential-deny-file-paths`。
    - `denyWrite` = 展开的 `filesystem.denyWrite`。
6. 调用 `srt-win acl grant` → 在每个 grant 路径上为 `<sandbox SID>` 写入 `(OI)(CI)` ACE。
7. 调用 `srt-win acl stamp` → 在 deny 路径上写入显式 DENY ACE,并在每个 deny 路径的父目录上写入 `(OI)(CI) FILE_DELETE_CHILD` DENY。

盖印集合被跟踪在模块状态(`windowsFsStampedSet`),以便 `reset()` 准确撤销加上过的内容。

### 路径展开(`expandWindowsFsPaths`)

与 mac/Linux 的 glob 展开语义相同,但是:
- glob 展开使用 `rg --files` 在 `initialize` 时执行。
- 不跟随 symlinked 路径;我们盖印用户给出的路径。
- `allowRead`/`allowWrite` 中不存在的路径以 debug 日志丢弃。

### 必拒路径

SDK 没有 mac/linux 那种 rc 文件与 git-config 必拒列表——Windows 用户使用不同工具,LibDirs 模式不同。改为:
- 必需的 `.git/hooks` 阻断相同。
- 其余的必拒委托给用户配置(嵌入方通常 deny `%USERPROFILE%` 整片,除非明确 allow-list)。

### ACE 顺序

当两个 ACE 指向同一 trustee,**更具体** 的 ACE 胜出(deny 先于 allow)。SDK 按以下顺序写规则:
1. 先 `acl grant`(这样沙箱用户已有工作树访问权限)。
2. 然后 `acl stamp`(显式 deny 放最后)。

如果 `initialize` 在步骤 1 之后、步骤 2 之前抛错,catch 块调用 `acl revoke` 与 `acl restore` 来释放已落地的 ACE。

## 7.3 文件读 deny 盖印

对每个 `denyRead` 路径:

```
(grant) [沙箱 SID]  R+X 于 <allowRead 子路径>     ← 仅当一个子路径是 allowRead-only 时输出

(deny)  [沙箱 SID]  R+W+X+D 于 <denyRead 路径>     ← 完全 deny ACE

(<denyRead 路径的父>)  (deny) [沙箱 SID]  FILE_DELETE_CHILD
```

`(OI)(CI)` 标志("object inherit, container inherit")让 ACE 流向所有后代;父的 `FILE_DELETE_CHILD` deny 阻止沙箱进程重命名或删除被 deny 的子树。

### `allowRead` 的 ALLOW ACE

SDK 视 `allowRead` 为 "在更广的 deny 内 re-allow",与 macOS 相同。在 `denyRead: ['/home']` 下的 `allowRead: ['/home/me/project']` 路径产生:

1. DENY `/home` 给沙箱 SID。
2. ALLOW `/home/me/project` 给沙箱 SID。

ALLOW 在重构顺序中 *不* 覆盖 DENY。所以 ACE 发射顺序很重要:SDK 在路径上(不是祖先)直接写 ALLOW ACE,这样它们与 `/home` 上的 DENY 位于不同的 inode。内核按 "lowest-priority-number-first" 顺序求值 ACE,因此更具体(最内层)的 ACE 胜出。

## 7.4 文件写 deny 盖印

对每个 `denyWrite` 路径:

```
(deny)  [沙箱 SID]  R+W+X+D 于 <denyWrite 路径>
(父) (deny) [沙箱 SID]  FILE_DELETE_CHILD
```

并且对每个 `allowWrite` 路径:

```
(allow) [沙箱 SID]  MODIFY_NO_FDC 于 <allowWrite 路径>     ← R+W+X+D 减去 FILE_DELETE_CHILD
```

`MODIFY_NO_FDC` 访问掩码授予 `READ | WRITE | EXECUTE | DELETE`(以及若干 flag)。我们故意扣留 `FILE_DELETE_CHILD`——没有它,沙箱进程可以通过对父的 `MoveFileEx` 重命名 deny 文件。父 deny 盖印保证连那条路径也被封闭。

## 7.5 ACL 清理(`reset`)

在 `reset()` 时,SDK 遍历 `windowsFsStampedSet` 并调用:

- `srt-win acl revoke <sb-SID>` —— 移除每个 broker 加入的 ALLOW ACE。
- `srt-win acl restore <sb-SID>` —— 在盖印时记录的原值还原。

`srt-win` 在 `state.db` 中为每个 broker-PID 保留引用计数,因此并发宿主不会互相踩。

### 崩溃恢复(`srt-win acl recover`)

如果 broker 进程在 `reset()` 运行前被杀,`state.db` 持有原始 ACE 字节。随后的 `srt-win install` 调用(或 `acl recover`)遍历表、重新派生原始 DACL,并将其写回磁盘。这会重新盖印所有路径的安全设置。

## 7.6 WFP 出站围栏

### `install` 时过滤集

```
FWPM_SUBLAYER0
    key      = <sublayerGuid>(默认常量;通过 --sublayer-guid 可覆盖)
    flags    = PERSISTENT
    display  = "srt-sandbox ALE filter sublayer"

FWPM_FILTER0 (×4):
    layer       = FWPM_LAYER_ALE_AUTH_CONNECT_V4 (和 V6)
    sublayerKey  = <sublayerGuid>
    action.type = FWP_ACTION_PERMIT  (weight 0)
    providerData= { tool:"srt", kind:"permit-loopback", port_range:[lo,hi] }
    conditions  = [
       IP_REMOTE_ADDRESS ∈ { 127.0.0.0/8  (v4) 或 ::1 (v6) } 使用 FWP_MATCH_EQUAL
       AND
       IP_REMOTE_PORT    ∈ [lo, hi]                              使用 FWP_MATCH_RANGE
    ]

FWPM_FILTER0 (×4):
    layer       = FWPM_LAYER_ALE_AUTH_CONNECT_V4 (和 V6)
    sublayerKey = <sublayerGuid>
    action.type = FWP_ACTION_BLOCK   (weight 0xFFFFFFFF — 高优先级)
    providerData= { tool:"srt", kind:"block-sandbox-user", user_sid:"<sandbox SID>" }
    conditions  = [
       ALE_USER_ID security descriptor 匹配当 AccessCheck 授予 ← 沙箱 SID 的 SD
    ]
```

### 为何按用户 SID

`FWPM_CONDITION_ALE_USER_ID` 通过针对提供的安全描述符的 `AccessCheck` 求值。内核为每个使用沙箱用户作为令牌的出站 `connect()` 调用。其他令牌(真实用户、SYSTEM、服务)不匹配 → 默认放行。

这让多种逃逸不可能:
- **替代生成**:`schtasks /create /tn "x" /tr "..." /sc once` —— task 的令牌属于沙箱用户的 SID → BLOCKED。
- 对 broker 拥有的进程采用 `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` 的 `CreateProcess` → 仍产生沙箱用户 SID 中的令牌 → BLOCKED。
- **BITS / RunAs "Interactive User"** COM → 沙箱用户 SID → BLOCKED。

### 为何 `ALE_AUTH_CONNECT`(而非 `STREAM` 或 `DATAGRAM`)

auth-connect 层对每个 `connect()` 尝试 **只运行一次**,在名称解析之后。在此处阻断意味着:

- 连接不会到达 `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4`(这里可以发生 MITM)。
- DNS 经 UDP/53 仍然经过 DNS 服务(它作为 `NETWORK SERVICE` 运行 → 不是沙箱用户 → 不被 BLOCK 匹配)。现代 schannel/OpenSSL 工具通过代理在 TCP 上做自己的解析,不经 UDP/53 DNS。

这 **镜像了 macOS DNS 解析器豁免**(README 中也明确说明)。

### 行为验证(`srt-win wfp verify`)

通过 `FwpmFilterEnum0` 列出 BFE 过滤器是 **仅管理员** 的。非提权进程得到 `FWP_E_ACCESS_DENIED`。要验证非提权安装确实在起作用,SDK 执行:

1. 连 `127.0.0.1:<port_inside_permit_range>` → 预期成功。
2. 连 `127.0.0.1:<port_outside_range>` → 预期 `WSAECONNREFUSED`(无监听器;两种情况下结果相同)。
3. 连 `127.0.0.1:0`(唯一保证未绑定的范围外端口)→ 也是 `ECONNREFUSED`。
4. 用 WinAPI 技巧:`WSAGetLastError()` 区分 "过滤器丢弃" 与 "没有人在监听"。BLOCK 动作会让内核过滤器返回 `WSAECONNABORTED`,而不是 `WSAECONNREFUSED`。

如果该技巧在被阻断的目标上返回 `WSAECONNABORTED`,围栏是活的。否则 SDK 抛出可操作错误并拒绝初始化。

这 **每个进程仅运行一次**(而非每次 `initialize`)。围栏是安装时状态;管理器缓存 `windowsWfpVerified = true`。

## 7.7 信任 CA 生命周期(Windows 上的 `tlsTerminate`)

现代 Windows API 期望使用 **schannel**,它只信任 OS 证书库(env vars 被基于 schannel 的工具忽略)。要让沙箱中的 `Invoke-WebRequest`、`curl.exe`、`git`(默认后端)验证代理铸造的叶子,MITM CA 必须安装在 **沙箱用户的** `CurrentUser\Root` 存储中。

### 安装步骤(手动,与 `windows-install` 分开)

```
srt-win user trust-ca <path-to-mitm-ca.crt>
    读取证书
    通过 LogonUser 获取 srt-sandbox 用户的令牌(使用 DPAPI 存储的密码)
    冒充该用户
    读取沙箱用户注册表 (HKU\<sid>\…\Root\Certificates)
    将证书加入其中
```

退出每条路径时丢弃令牌;注册表写入已完成。

### 每次会话校验

`initialize()` 将会话的 MITM CA 指纹与注册表中的比对:

```
sessionThumb = SHA1(certPem).toUpper()
installedThumb = 从注册表读取
```

不匹配 → `tlsTerminate on Windows: the sandbox's installed CA (thumb=…) doesn't match this session's CA (thumb=…). Run \`srt-win user trust-ca …\` to update it.`

陈旧的安装时 CA 不能悄无声息地破坏 TLS——网关失败关闭。

### OpenSSL 层级工具(msys2 curl,git -c http.sslBackend=openssl,Node,Python,cargo)

这些读环境变量。编排器设置:

```
NODE_EXTRA_CA_CERTS=<bundlePath>
SSL_CERT_FILE=<bundlePath>
CURL_CA_BUNDLE=<bundlePath>
GIT_SSL_CAINFO=<bundlePath>
CARGO_HTTP_CAINFO=<bundlePath>
```

bundle 写入 broker 的 `%TEMP%`,沙箱用户没有固有读权——所以管理器在 `initialize()` 时将 bundle 路径加到 **会话级** `allowRead` 授权集中。

## 7.8 两段式启动

`srt-win exec -- <user command>` 运行:

```
broker (NT 进程,真实用户)
    ↓ spawn (CreateProcessWithLogonW, --sandbox-user srt-sandbox, --password <pw>)
runner (NT 进程,srt-sandbox 用户)
    ↓ spawn (CreateProcessWithRestrictedToken, -- jobObject, -- 完整性级别 medium)
child (NT 进程,srt-sandbox 用户,受限 token)
    用户命令在此运行
```

### 为何是两段

单段意味着 broker 持有沙箱用户凭据的时间足够 `CreateProcessWithLogonW`。那是凭据泄露窗口。两段:

1. **Broker** 读取 DPAPI blob,每个 `wrapWithSandbox` 调用解密一次,通过 runner 的 spawn 上的 `--password <pw>` argv 参数把明文传给 runner。
2. **Runner** 立即构造受限 token + job,运行子进程,之后 **永不** 记录明文。
3. **Runner 退出**:令牌被销毁;密码参数仅在 runner 的命令行短暂出现。

对 runner 进行 `PROCESS_QUERY_LIMITED_INFORMATION` 查询在 ~150ms 内能以明文密码揭示该密码。这是文档化的限制。

### Job 对象

子进程运行在 `JOB_OBJECT` 内:
- 限制 `KILL_ON_JOB_CLOSE`,这样 broker 死亡时子进程也死。
- 设置 `JOB_OBJECT_LIMIT_PROCESS_MEMORY` 为可配置上限(默认无限)。
- 禁止嵌套 job 突围。

Job 在 `reset()` 时关闭;SDK 在 `state.db` 中为每个 broker 保留句柄。

### Token 限制

- `DISABLE_MAX_PRIVILEGE`
- `SANDBOX_INTEGRITY`(或低完整性,如果请求则类似 AppContainer 隔离)
- `NO_WRITE_UP`(medium→high 拒绝)
- 从默认 DACL 组列表移除特定 SID

### 工作目录 / 起始路径

runner 可执行文件(`srt-win.exe`)在 exec 前被 bind-mount 到沙箱用户的 `%APPDATA%` 目录下某路径(以便子进程需要时能找到自己的辅助)。子进程继承 **沙箱用户** 的 `%TEMP%`、`%APPDATA%` 等,而不是 broker 的。

## 7.9 argv 构造(`wrapWithSandboxArgv`)

Windows 路径根本不同。**没有返回 shell 字符串。** 只有 `{ argv, env }`:

```ts
srt-win
  --srt-win                                 ← 多路分发(path 自定义时)
  exec
  --binary <srtWinSpawn.path>
  --user  srt-sandbox
  --pw    <明文>
  --cwd   <cwd>
  --allow-write <grantWrite path>...        ← 重复
  --proxy   http://srt:<token>@127.0.0.1:<httpPort>
  --socks   socks://srt:<token>@127.0.0.1:<socksPort>
  --trust-bundle <mitmCA.trustBundlePath>
  --deny-read  <perExecDenyRead path>...
  --deny-write <perExecDenyWrite path>...
  --env <NAME>=<VAL>...
  --env NAME
  --
  <shell-path> -c <user-command>
```

其中:

- `<shell-path>` 通过 `binShell` 经 `parseWindowsBinShell` 解析(未指定时默认 `cmd.exe /c`)。
- `--allow-write` 列表是 **会话级** 授权集(`initialize()` 时记录);不支持按调用覆盖(会抛错)。
- `--env NAME=`(无值)意为 "unset" —— 用于 credential-mode=deny。
- `--env NAME=VAL` 意为用 sentinel 设置 —— 用于 credential-mode=mask。

### 为何 env 不走 Shell

`spawn([...], { shell: false })` 是 Windows 上的安全边界。如果你走 `cmd.exe /c "..."`,你会继承:

- 命令行长限制(已经痛苦,但不是问题)。
- Shell 解析(我们正试图沙箱它)。
- 变量展开,可能解析到 broker 的值。
- broker 的 `%PATH%` 路径搜索顺序,而不是沙箱用户的。

因此 `wrapWithSandboxArgv()` 是 Windows 上唯一正确的 API,`wrapWithSandbox()` 是抛出错误的空操作。

## 7.10 `reset()` 时的清理

`reset()` 执行:
- 调用 `srt-win acl revoke <sb-SID>` 与 `srt-win acl restore <sb-SID>`(仅当 `windowsFsStampedSet` 非空)。
- 尽力记录任何非异常 ACE 状态(SDK 接受 `revoked`、`restored`、`stillHeld`、`alreadyOriginal` 为成功)。
- **不**清除 `windowsWfpVerified`(围栏是安装时状态)。
- **不**关闭 job 对象(broker 已经有为整个会话运行的一个长期 job;reset 只是停止生成新的子进程)。

## 7.11 已知限制(README § "Windows (alpha)")

直接从 README 引用;这些是 v1 中已记录的缺陷:

- **schannel 下 CRL 获取** 通过 §7.12 中的进程内 CRL 服务被解除阻塞。
- **每用户工具安装**(nvm、fnm、pip user 等)不可达,因为沙箱用户无法遍历你的 profile。添加至 `allowRead`,或进行机器范围安装。
- **每执行的 `allowRead`/`allowWrite` 覆盖抛出** —— 授权是会话级的;`srt-win exec` 仅接受每执行 deny。
- **`proxyAuthToken` 在 runner cmdline 中可见** ~150ms。
- **DNS 通过 WinAPI 绕过围栏**(通过 SYSTEM DNS 服务解析名)。TCP 层 CONNECT 仍经过围栏。绕过 TCP 的工具(`nslookup`、`dig`)被围栏。

## 7.12 CRL 分发点(仅 Windows)

`mitm-ca.ts` 中的代码记录 `crlDer: Buffer` —— 一个由 MITM CA 签名的空 CRL。Mux 代理在 mux 绑定端口的 `CRL_PATH == "/srt.crl"` 服务它。

每个铸造的叶子嵌入 `cRLDistributionPoints = http://127.0.0.1:<muxPort>/srt.crl`。Schannel 取 → "已检查,未吊销" → TLS 握手继续。

> **Linux/macOS 注意:** CDP URL 仅在 Windows 上设置。Linux 上子进程在 `bwrap --unshare-net` 下运行,CDP 也无法到达,因此我们省略。macOS 默认无 schannel 等价物在线检查吊销。

### 生成空 CRL

`genCRL(caCert, caKey)`(在 `mitm-ca.ts`)创建一个空 X.509 v2 CRL,issuer 与 MITM CA 相同,由 CA 的 RSA 密钥签名。DER 编码预计算一次并存储在 `MitmCA` 结构上。

## 7.13 边界事实在此回顾(Windows)

1. **沙箱进程有 *不同* 的 SID**,与任何人类用户或系统服务不同。围栏以它为键。
2. **ACE 写入是加性的** —— 我们从不替换路径的已有 DACL。
3. **job 对象归 broker 所有**,而非 runner。关闭 broker 即关闭 job → 杀掉所有子进程。
4. **`state.db` 是唯一的机密存储。** DPAPI blob 是机器作用域下 DPAPI 加密的 + DACL 盖印,即使沙箱用户也无法解密。
5. **启动路径上无 shell。** argv 是契约。
