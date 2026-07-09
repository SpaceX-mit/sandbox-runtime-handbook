# 05 — macOS 文件系统隔离

本文档涵盖 macOS 实现:Seatbelt profile 是如何生成的,沙箱命令如何通过 `sandbox-exec` 启动。

## 5.1 OS 原语

`/usr/bin/sandbox-exec -f <profile> -p <profile> <command>` 在给定 SBPL profile 下运行 `<command>`。内核对每个 VFS、IPC、信号操作按 profile 求值。操作按 **profile 出现顺序求值,末位匹配胜出**。

公开参考:<https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf>。
注意 Apple 已将该二进制标为公共 SDK 的 `__DebugSymbols`;语法稳定但头文件未文档化。

## 5.2 Profile 骨架

`generateSandboxProfile({...})` 产出 SBPL 字符串。骨架:

```sbpl
(version 1)
(deny default (with message "<logTag>"))

; ─── 进程基础 ───
(allow process-exec)
(allow process-fork)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
(allow mach-priv-task-port (target same-sandbox))

; ─── 用户偏好、最小 IOKit ───
(allow user-preference-read)
(allow iokit-open (iokit-registry-entry-class "IOSurfaceRootUserClient") … )
(allow iokit-get-properties)
(allow sysctl-read (sysctl-name "hw.activecpu") … )    ← 显式白名单
(allow file-ioctl (literal "/dev/null") …)
(allow ipc-posix-shm) (allow ipc-posix-sem)            ← Python multiprocessing 等

; ─── Mach lookup ───
(allow mach-lookup
  (global-name "com.apple.audio.systemsoundserver")
  (global-name "com.apple.distributed_notifications@Uv3")
  …)
; 可选:
(allow mach-lookup (global-name "com.apple.trustd.agent"))   ← enableWeakerNetworkIsolation
(allow appleevent-send) (allow lsopen)                       ← allowAppleEvents

; ─── 网络 ───
(if needsNetworkRestriction:
   (allow network-bind (local ip "*:*"))            ← allowLocalBinding
   (allow network-inbound (local ip "*:*"))
   (allow network-outbound (remote ip "localhost:*"))
   (allow system-socket (socket-domain AF_UNIX))    ← allowAllUnixSockets / allowUnixSockets
   (allow network-outbound (remote ip "localhost:<HTTP_PORT>"))
   (allow network-outbound (remote ip "localhost:<SOCKS_PORT>"))
)

; ─── 文件系统 ───
<读规则>     ← deny-then-allow
<写规则>    ← allow-then-deny
```

`logTag` 形如 `CMD64_<base64(command)>_END_<sessionSuffix>_SBX`。系统日志在每次拒绝操作时显示它,便于违规监控按子进程过滤。

## 5.3 读规则(`generateReadRules`)

```
(allow file-read*)                                     ← 默认

for each pathPattern in denyOnly:
    if containsGlobChars(pathPattern):
        (deny file-read* (regex "<globToRegex(path)>"))
    else:
        (deny file-read* (subpath "<path>"))

if deniesRoot:
    (allow file-read* (literal "/"))                  ← ls / 可用

for each pathPattern in allowWithinDeny:
    if containsGlobChars(pathPattern):
        (allow file-read* (regex "<globToRegex(path)>"))
    else:
        (allow file-read* (subpath "<path>"))

<re-emit 在 allowedSubpaths 内嵌套的拒绝子路径>          ← 末位匹配胜出

if denyOnly.length > 0:
    (allow file-read-metadata (vnode-type DIRECTORY))  ← realpath() 可以 lstat

<针对每个 denyOnly 路径的移动阻断拒绝>

<针对每个 writeAllowPaths 的 file-write-unlink/file-write-create 重新允许>
```

### 为何要重新允许 file-write-unlink

`generateMoveBlockingRules(denyOnly)` 对每个 deny 路径及其祖先目录都拒绝
`file-write-unlink` 与 `file-write-create`。意图:阻止 `mv ~/.config/foo ~/.config/bar` 然后 `cat ~/.config/bar`。

但这也杀死写允许目录中的删除,因为 Seatbelt 在求值时,特定 denials 优先于通用 allows。所以我们在移动阻断 deny 输出之后,显式重新允许这两个操作。

`denyWrite` 规则稍后会再次拒绝这两个操作(因此优先级为):

```
写允许路径上的净效应:
    1. allow file-write*
    2. deny file-write-unlink/file-write-create (deny-then-allow)
    3. allow file-write-unlink/file-write-create (此处的重新允许)
    4. deny file-write* (denyWrite)
    5. deny file-write-unlink/file-write-create (denyWrite 的移动)
⇒ 删除对不在 denyWrite 内的路径是被允许的(3 胜 2)
⇒ denyWrite 内的文件永远不能 unlink(5 胜 3)
```

## 5.4 写规则(`generateWriteRules`)

```
for each pathPattern in allowOnly:
    (allow file-write* (subpath "<path>"))     或 (regex "<globToRegex>")

denyPaths = denyWithinAllow ∪ macGetMandatoryDenyPatterns(allowGitConfig)

for each pathPattern in denyPaths:
    (deny file-write* (subpath "<path>"))     或 (regex)

<针对每个 denyPath 的移动阻断拒绝>
```

`macGetMandatoryDenyPatterns` 是 *静态* 的 glob 编译(不需要 ripgrep):

```
cwd 锚定的 deny 路径:
    .bashrc、.bash_profile、.zshrc、.zprofile、.profile、.zshenv、.bash_login、.zlogout、.bash_logout
    .gitconfig、.gitmodules、.ripgreprc、.mcp.json
    .git/hooks/(当 allowGitConfig 时排除 .git/config)
递归 glob:
    **/.bashrc、**/.zshrc、**/.git/hooks/**、**/.git/config 等
    **/.vscode/**、**/.idea/**
    **/.claude/commands/**、**/.claude/agents/**
```

### 移动阻断规则

对每个被保护路径(读或写):

```
(deny file-write-unlink (subpath "<p>") (with message "<logTag>"))
(deny file-write-unlink (literal "<ancestorOf_p>") (with message "<logTag>"))   ← 直到 /
(deny file-write-create (subpath "<p>") (with message "<logTag>"))
(deny file-write-create (literal "<ancestorOf_p>") (with message "<logTag>"))
```

祖先拒绝阻止 `mv /a/secret /a/innocent && rm /a/innocent && rm /a/secret` 风格的攻击。

### 为何需要这个

macOS VFS 允许 `rename(2)` 与 `unlink(2)` 触碰任何子进程有 *某项* 权利的目录——包括之前已允许、稍后被删的父目录。拒绝被保护路径及其祖先的 `file-write-unlink` 与 `file-write-create` 可保证该文件(及其所在目录)无法通过侧门消失。

代价:`rm -rf ~` 不可能。这是有意为之。

## 5.5 Glob 处理

macOS SBPL 没有原生 glob。我们将 `*.ext`、`**/foo`、`dir/*` 等编译为 ECMAScript 风格的正则,使用 `globToRegex`:

| Glob       | 正则(锚定)              |
| ---------- | ----------------------------- |
| `*`        | `[^/]*`                       |
| `**`       | `.*`                          |
| `?`        | `[^/]`                        |
| `[abc]`    | `[abc]`                       |
| 尾 `/**`   | 剥离(视为目录)        |

带有 metadata 通配符(如 `**`)的路径用 SBPL 中的 `(regex "<…>")` 匹配。普通路径用 `(subpath "<p>")`(更快,是内核 VFS 查找,更精确)。

## 5.6 规范化

```
normalizePathForSandbox("/some/path/"):
    将 ~ 解析为用户主目录
    在可能处解析 symlink
    去掉末尾 /(除非是 "/")
    在可解析处折叠 "..";否则保留给内核
    在 macOS 上解析 /private/tmp → /tmp 等(但保留公共路径;内核在 VFS 层处理 symlink)
```

结果是我们在 profile 中输出的路径字符串。

## 5.7 网络规则生成

| 配置                        | 输出规则                                                                                                |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `needsNetworkRestriction: false` | `(allow network*)` —— 不需要代理。                                                                  |
| `needsNetworkRestriction: true` + `allowLocalBinding: false` | `(allow network-bind (local ip "localhost:<HTTP_PORT>"))`,SOCKS 同理。不允许本地绑定。 |
| `...` + `allowLocalBinding: true` | 同时 `(allow network-bind (local ip "*:*"))` 与 `(allow network-inbound (local ip "*:*"))`,`(allow network-outbound (remote ip "localhost:*"))`。 |
| `allowAllUnixSockets: true`   | `(allow system-socket (socket-domain AF_UNIX))`,加上 `(allow network-bind (local unix-socket (path-regex #"^/")))`,加上 `(allow network-outbound (remote unix-socket (path-regex #"^/")))`。 |
| `allowUnixSockets: [...]`     | 同上,但每个条目显式 `(subpath "<sock>")`。                                                                  |
| 设置 `httpProxyPort`           | `(allow network-outbound (remote ip "localhost:<port>"))`                                                  |
| `socksProxyPort !== httpProxyPort` | 同时 `(allow network-outbound (remote ip "localhost:<SOCKS_PORT>"))`                                  |

### IPv4 映射的 IPv6 怪癖

Java/AArch64 运行时默认采用 AF_INET6 双栈。对 `127.0.0.1` 的 `connect()` 在报文层面以 `::ffff:127.0.0.1` 出现。Seatbelt 的 `localhost` 关键字匹配 `127.0.0.1` 与 `::1`,但 **不** 匹配 `::ffff:127.0.0.1`。我们通过向 `JAVA_TOOL_OPTIONS` 追加 `-Djava.net.preferIPv4Stack=true` 强制 IPv4 栈(保留继承的值(若它未包含该 flag);但若 `JAVA_TOOL_OPTIONS` 在凭据 deny 列表中,则完全丢弃继承值)。

## 5.8 Wrap 粘合

profile + env 生成后,`wrapCommandWithSandboxMacOS()` 返回:

```
env -u ENV_A -u ENV_B ENV_C=val JAVA_TOOL_OPTIONS=... \
  sandbox-exec -p '<profile>' <shell> -c <userCommand>
```

- `env -u` 剥离凭据 denied 环境变量(`mode=deny`)。
- `env NAME=val` 注入凭据掩码变量(`mode=mask` 返回 sentinel)。
- profile 通过 `-p` 标志传入(或者过长时用 `-f <file>`;我们永远用 `-p`)。
- shell 包装保留别名/快照/init 脚本。

编排器用 `shell: true` 外部 spawn,使 shell 解析它。

## 5.9 解析 `binShell`

`binShell` 默认为 `"bash"`。`whichSync()` 把它解析为绝对路径;SBPL 按字面使用该路径,因为 sandbox-exec 以其真实路径加载二进制到沙箱中。

如果解析失败,wrap 被中止,硬错误返回。

## 5.10 PTY 支持(`allowPty: true`)

设置后,profile 增加:

```
(allow pseudo-tty)
(allow file-ioctl (literal "/dev/ptmx") (regex #"^/dev/ttys"))
(allow file-read* file-write* (literal "/dev/ptmx") (regex #"^/dev/ttys"))
```

这让沙箱进程能打开 `/dev/ptmx` 并使用 BSD 风格伪终端 API。除非显式 allowWrite,沙箱仍拒绝打开其他 `/dev/*`。

PTY 是 macOS 在用户态使用真 PTY 的唯一路径;否则编排器的 stdio 就是宿主的 stdio。

## 5.11 通过 `cli.ts` 启动

```
spawn(wrappedCommand, { shell: true, stdio: 'inherit' })
```

信号(`SIGINT`、`SIGTERM`)转发给子进程:

```
process.on('SIGINT',  () => child.kill('SIGINT'))
process.on('SIGTERM', () => child.kill('SIGTERM'))
```

wrap 命令对父 shell 是一个逻辑实体;信号自然流动。

## 5.12 沙箱违规日志监控(`macos-sandbox-utils.ts` > `startMacOSSandboxLogMonitor`)

通过 `SandboxManager.initialize(cfg, askCb, /*enableLogMonitor=*/ true)` 开启。

实现:

1. 通过 `os.unstable.log subscribe` 订阅 `os_log`(Node 20 上的 Darwin 有 `node:os` 的 `log` 命名空间)。
2. 用下列谓词过滤事件:`subsystem == "com.apple.sandbox" AND composedMessage CONTAINS[c] "<logTag>"`。
3. 将匹配的事件推入提供的回调(`(violation: SandboxViolationEvent) => void`)。
4. 将每个违规存入 `SandboxViolationStore`,以 base64 编码的命令为键。
5. 通过 `getSandboxViolationStore().getViolationsForCommand(command)` 向宿主公开;可选在子 stderr 末尾加 `<sandbox_violations>` 块。

监控仅在宿主进程显式 opt-in 时运行。默认不启用(避免把 `os.unstable` 引入稳定 API 表面)。

## 5.13 优先级陷阱回顾

| 陷阱                                                   | 缓解措施                                                         |
| --------------------------------------------------------- | ------------------------------------------------------------------ |
| `(subpath "/")` 拒绝一切非其子路径的东西                 | 若根已被 deny,重新允许 `(literal "/")`                            |
| 尾部的 `/**` 否则永远不会匹配任何东西                    | `removeTrailingGlobSuffix` 在输出 profile 前剥离它                 |
| 读允许路径内的读 deny 路径                              | 在 allow 之后再次输出 deny                                         |
| 读 deny 后的写允许嵌套情况                              | denyWrite 在 allowWrite 之后输出(末位匹配胜出)                 |
| `mv foo bar` 删了父目录                                 | 移动阻断 deny 父目录的字面路径                                    |
| `ln -s /etc/passwd /tmp/symlink && cat /tmp/symlink`     | symlink 解析不变;`subpath` 匹配 `cat` 的目标                       |

macOS 实现依托 **profile 顺序**。末位匹配胜出是契约——每个代码路径必须按顺序 profile,测试验证精确顺序(`test/sandbox/macos-seatbelt.test.ts`、`macos-pty.test.ts`)。

## 5.14 Mac 的范围外事项

- **内核扩展、沙盒扩展、容器技术** —— 未使用。
- **代码签名强制** —— 沙箱应用于任何被 exec 的二进制;代码签名检查在 macOS 的进程启动路径上,与我们路径无关。
- **硬件级 I/O 隔离(USB 等)** —— 没有 profile 规则处理;我们接受沙箱进程只能与允许的 IOKit 客户端通信。
- **宿主上的防火墙** —— 超出范围;若你需要,放在 VM 内运行。
