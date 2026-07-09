# 06 — Linux 文件系统隔离

Linux 使用 **bubblewrap**(bwrap)做文件系统与命名空间隔离,加上可选的 **seccomp BPF** 过滤器对 Unix 套接字访问进行控制,以及 **SECCOMP_RET_USER_NOTIF** 做违规观测。内核中没有 glob——它们在配置与 wrap 时展开。

## 6.1 架构支柱

1. **bubblewrap(`bwrap`)** —— 一个小的 setuid-free 二进制,执行的工作通过:
    - `--unshare-user-try` + 显式 UID/GID 配置。
    - `--unshare-pid` 让 PID 1 成为一个长寿命占位(便于清理)。
    - `--unshare-net` 移除网络命名空间(强制;见 §6.6)。
    - Bind mounts(`--ro-bind / /` 做只读根;`--bind <src> <dst>` 做可读可写)。
    - `--tmpfs <path>` 拒绝某目录(已存在目录的读 deny)。
    - `--ro-bind /dev/null <path>` 拒绝单文件(不存在的或单文件路径的读 deny)。
    - `--proc`、`--dev`、`--tmpfs` 用于合成挂载。
2. **socat** —— 宿主侧两个桥,沙箱内两个监听器,把 TCP localhost 隧道到宿主的 Unix socket。
3. **apply-seccomp** —— 一个小的静态 ELF,负责:
    - 创建一个外部 user+pid+mount 命名空间(或依赖 bwrap 的)。
    - Fork 一个外部 stub 用于信号/观察转发。
    - Fork 一个内部 init 用于挂载新的 /proc。
    - Fork 真正的工作 worker,装上 BPF 过滤器,然后 `execve`。

宿主 Node 进程永远看不到 worker 的 PID。worker 只能看到自身及其子进程的 PID。

## 6.2 合成的 bubblewrap 参数

### 顶层 argv

```
bwrap
  --unshare-user-try                 # 允许时使用 CLONE_NEWUSER
  --unshare-pid                      # 占位符是新的 PID 1(我们不 exec 它;exec apply-seccomp)
  --unshare-net                      # 移除网络命名空间
  --cap-add CAP_SYS_ADMIN            # apply-seccomp 的嵌套命名空间需要
  --die-with-parent                  # srt 退出时退出
  --new-session                      # 不在调用方的 ctty 中
  --proc /proc
  --dev-bind /dev /dev
  --tmpfs /tmp                       # POSIX 唯一有效的 tmpfs
  --tmpfs /run
  --tmpfs /var/tmp
  --ro-bind /usr /usr                # 通常只读的系统文件
  --ro-bind /bin /bin
  --ro-bind /lib /lib
  --ro-bind /etc /etc                # 整个 /etc(可配置)
  --ro-bind /etc/resolv.conf /etc/resolv.conf   # 网络名称解析
  --ro-bind /etc/ssl /etc/ssl        # 宿主 CA 根,除非 tlsTerminate
  --ro-bind /etc/pki /etc/pki
  --ro-bind /nix/store /nix/store    # nix 系统
  --ro-bind <allowReadMounts> ...    # 用户请求的只读挂载
  --ro-bind /                        # 读 deny 基底
  --bind <allowWriteMounts> ...      # 用户请求的可读可写挂载
  --bind <allowGitConfigMount> ...   # .git/config 当 allowGitConfig
  --ro-bind /dev/null <必拒文件> ...  # 必拒(文件)
  --tmpfs <必拒目录> ...     # 必拒(目录)
  --bind <maskedFileBind> ...        # 凭据掩码:fakePath 只读绑定到 realPath 上
  --ro-bind <maskedFileStoreDir> /tmp/srt-mask   # store dir 只读
  --bind <observeSocketPath> /tmp/srt-observe.sock
  --bind <httpSocketPath> /tmp/srt-http.sock
  --bind <socksSocketPath> /tmp/srt-socks.sock
  --setenv PATH <slimmed_PATH>       # 沙箱内使用清理过的 PATH
  --setenv HOME <cwd>                # 工具需要的合理 HOME
  --setenv USER <username>
  --setenv TMPDIR /tmp
  --setenv HTTP_PROXY http://srt:<tok>@127.0.0.1:3128
  --setenv HTTPS_PROXY http://srt:<tok>@127.0.0.1:3128
  --setenv ALL_PROXY socks://srt:<tok>@127.0.0.1:1080
  --setenv SRT_DEBUG <if enabled>
  --setenv GIT_SSH_COMMAND "socat - PROXY:127.0.0.1:1080:%h:%p"   # SSH 通过 SOCKS5
  --unsetenv <credentialDenyEnvVars> ...
  --setenv <SENT_NAME> <SENTINEL> ... # 掩码 env 变量
  --apply-seccomp <shell> -c <innerScript>
```

### 决策说明

- `--ro-bind /` 然后用户可写 `--bind` 覆盖是典型模式。
- 必拒文件用 `--ro-bind /dev/null <p>`。绑定源为空文件。
- 必拒目录用 `--tmpfs <p>`。
- 不存在的必拒路径:跳过(当绑定挂载目标不存在时,父隐式被拒)**并注册以供清理**。

实际上,bwrap 的 `--ro-bind` 覆盖不存在的路径 *会创建* 宿主页上的空文件(以便挂载)。我们通过 Set 跟踪这些文件,在每个命令后清理。见 `cleanupBwrapMountPoints`。

### 为何 `--ro-bind /`

这让沙箱在 fork 时获得宿主文件系统的就地镜像;然后你可以用 `--bind` 切出可读可写区,用 `--tmpfs` / `--ro-bind /dev/null` 切出读 deny 区。另一种做法(bwrap 每个文件/目录的 `--bind`)在实用系统上不切实际:像 `npm install` 这样的工具触及很多路径。

## 6.3 必拒路径解析(Linux)

必拒集合在文档 03 §3.3 中有文档。在 Linux 上,它通过以下方式找到:

1. 构造静态 deny 路径列表,锚定在 cwd(与 macOS 相同):`.bashrc`、`.zshrc`、`.gitconfig`、`.mcp.json` 等,相对于 `process.cwd()` 解析。
2. 添加 `dangerousDirectories`(`.git/hooks/`、`.claude/commands/` 等),条件是 `.git` 作为目录存在(不是 symlink、不是文件——git worktree 中 `.git` 是文件,指向真实 `.git` 目录)。
3. 运行 **一次 ripgrep 调用**,`--files --hidden --max-depth <N> --iglob <每个模式>`,在子目录中枚举匹配项。
4. 对每个匹配:
    - 判断匹配是否在危险目录内 → 添加目录路径(而不是文件)。
    - 否则匹配是危险文件 → 添加绝对路径。
5. 对每个调用 `findSymlinkInPath(<path>, allowWritePaths)`(如果路径通过 symlink 越过写允许目录——`realpathSync` 显示宿主目标,`isSymlinkOutsideBoundary` 判定)。
6. 对每个调用 `hasFileAncestor(<path>)`(如果父级是文件则跳过,例如 git-worktree `.git`)。
7. 对每个调用 `findFirstNonExistentComponent(<path>)`——注册已解析组件以供 bwrap mount-point 清理。

`mandatoryDenySearchDepth` 默认 **3**,范围 1..10。Depth 0(`./.bashrc`)上的文件始终被保护。深度越大保护越彻底,但更慢。

### Depth 0 保护

步骤 1 中的静态列表始终覆盖 depth 0,与 rg flag 无关。所以即使 `mandatoryDenySearchDepth: 0`(Schema 强制 ≥1),`srt 'echo "malicious" >> .bashrc'` 仍然被拒。

## 6.4 Symlink 边界检查(`isSymlinkOutsideBoundary`)

如果 `allowWrite` 路径通过 symlink 解析到任一允许边界之外的位置,我们跳过该绑定。原因:

```
mkdir -p /tmp/project
ln -s /etc /tmp/project/etc
allowWrite: ['/tmp/project']
```

朴素的 `--bind /tmp/project /tmp/project` 会通过 `/tmp/project/etc` 让 `/etc` 可写。所以我们对每个 `allowWrite` 路径调用 `realpathSync`,要求已解析路径停留在某条 `allowWrite` 边界之内——否则以 debug 日志跳过,然后依赖 ro-bind 也拒绝。

读 deny 的 symlink 解析(`resolveSymlinkDenyDest`)做相反的事:一个 read-deny 在 `~/.netrc → /somewhere/.netrc` 的 symlink 上被重写为拒绝 `/somewhere/.netrc`(因为 bwrap 不能在一个 symlink 上 bind /dev/null;它报"Can't create file at <path>"错误)。

## 6.5 网络桥

### 宿主侧(`initializeLinuxNetworkBridge`)

```
socat UNIX-LISTEN:/tmp/claude-http-<rand>.sock,fork,reuseaddr TCP:127.0.0.1:<httpProxyPort>,keepalive,...
socat UNIX-LISTEN:/tmp/claude-socks-<rand>.sock,fork,reuseaddr TCP:127.0.0.1:<socksProxyPort>,keepalive,...
```

两个桥接进程运行在宿主命名空间中。它们连接到 `127.0.0.1:<port>`(JS 代理)。然后这些 socket 被 bind-mount 到沙箱内。

### 沙箱内(`buildSandboxCommand`)

```bash
socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:/tmp/srt-http.sock >/dev/null 2>&1 &
socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:/tmp/srt-socks.sock >/dev/null 2>&1 &
trap "kill %1 %2 2>/dev/null; exit" EXIT
ARGV0=<argv0_value> /path/to/apply-seccomp bash -c '<userCommand>'
```

两个 socat 监听器作为后台任务运行;trap 确保它们在沙箱退出时死亡。然后 `apply-seccomp` 作为前台进程被 exec——先装 seccomp,再 exec 用户的 `bash -c`。

### socat 路径解析

如果 `config.socatPath` 被设置(必须绝对),直接使用。否则 `whichSync("socat")`。沙箱内使用解析后的绝对路径,因为 bwrap 把 `/usr` 镜像到沙箱内。

### 处理 `socksProxyPort === httpProxyPort`

如果用户(或 mux)对两个协议报告相同端口,socks 侧复用 http 侧的 unix socket 与桥接进程。沙箱内的 SOCKS 监听器仍然使用端口 1080——两个不同的监听器,两个不同的桥,但当它们指向同一 TCP 时只有一个桥进程。

### 到 glibc/musl 的路径

`apply-seccomp` 是静态链接的,libc 无关。在 glibc 与 musl 发行版上都测试过。

## 6.6 `--unshare-net` 的依据

没有 `--unshare-net`,沙箱进程仍能通过宿主 NIC 直接做任意 TCP/UDP(bwrap 只沙箱化文件系统)。沙箱内路由表不变。所以 `--unshare-net` 是强制的;唯一的逃逸是通过 socat 桥。

## 6.7 Apply-Seccomp(`vendor/seccomp-src/apply-seccomp.c`)

这个 600 行的二进制是沙箱的 Linux 心脏。关键职责:

```
main(argc, argv):
    if SRT_OBSERVE_SOCK 设置: 创建预 fork socketpair 用于监控
    在 unshare 之前打开 /proc(unshare 后的 /proc 是沙箱的)

    直接尝试 unshare(CLONE_NEWPID|CLONE_NEWNS):
        EPERM? -> 尝试 user-namespace 回退路径
                 (CLONE_NEWUSER → setgroups:deny → uid_map → gid_map → unshare)
    fork():
        child1: outer stub
              install_forwarders(child3)        # SIGTERM/SIGINT/SIGHUP/etc. to inner init
              recv fd from socketpair           # 通知 fd
              supervise(child3, notify_fd, out_sock, enc, host_proc_fd)
              waitpid(child3)
              _exit(status)
        child1 的孙子进程(=原始进程的曾孙进程): inner init
              prctl(PR_SET_DUMPABLE, 0)
              mount(MS_PRIVATE|MS_REC, /)
              mount("proc", "/proc", ...)      # 可能因 EPERM 失败 -> 继续
              prctl(PR_CAP_AMBIENT, CLEAR_ALL)
              fork():
                  child2: worker
                          unsetenv("SRT_*")
                          prctl(PR_SET_NO_NEW_PRIVS, 1)
                          install_observe_filter(sp[1])
                          prctl(PR_SET_SECCOMP, BPF)   # unix_block_bpf
                          execvp(command_argv[0], command_argv)
              → _exit(reap_until(child2))
        child1 的孙子进程(=inner init):
              install_forwarders(child2)
              → reap_until(child2)
```

### BPF 过滤器

`unix-block-bpf.c`(单独编译并作为 `unix_block_bpf[]` 嵌入到 `apply-seccomp`)是 `struct sock_filter` 指令数组。语义:

```
arch != AUDIT_ARCH_X86_64 (或 AARCH64) → SECCOMP_RET_ALLOW (compat)
nr >= 0x40000000 (x32)            → SECCOMP_RET_ALLOW
nr == __NR_socket:
    args[0] == AF_UNIX (或 IPv4/IPv6 映射) → SECCOMP_RET_ERRNO|EPERM
    else                                       → SECCOMP_RET_ALLOW
nr ∈ { __NR_io_uring_setup,
        __NR_io_uring_enter,
        __NR_io_uring_register }    → SECCOMP_RET_ERRNO|EPERM
                                          (Linux 5.19+: IORING_OP_SOCKET 旁路)
default                              → SECCOMP_RET_ALLOW
```

监听器必须在构建时存在 `/usr/include/linux/seccomp.h`。生成的 BPF 在 npm 包构建阶段为每个架构(x64、arm64)编译一次(`npm run build:seccomp`)。

### 监控路径

当 `SRT_OBSERVE_SOCK` 被设置时,**第二个** BPF 过滤器被安装在 worker 侧,通过 `SECCOMP_RET_USER_NOTIF` 拦截写意图文件系统系统调用。外部 stub 用 `SECCOMP_USER_NOTIF_FLAG_CONTINUE` 处理每个通知(工作负载不变)。路径字节通过 `process_vm_readv` 从 worker 地址空间读取;相对路径针对 `/proc/<pid>/cwd` 或 `/proc/<pid>/fd/<n>` 解析。

然后 supervisor 写一条 JSON 行到由 `SRT_OBSERVE_SOCK` 命名的 unix socket。宿主侧的 Node `net.Server` 解析该流并送入 `SandboxViolationStore.addViolation`。

失败模式:内核太老 → 监控静默禁用。连到宿主 socket 失败 → 监控静默禁用。装过滤器前的任何错误 → fail-open(无监控,只有正常 seccomp)。装过滤器后任何错误 → 致命:不阻塞工作负载的唯一方法是用 CONTINUE 排空通知 fd。

## 6.8 必拒文件系统挂载

wrap 时 `generateFilesystemArgs` 的顺序:

```python
allowedWritePaths = []   # 处理 allowWrite 时填充
denyWriteArgs = []        # 缓冲,denyRead 循环后输出

if writeConfig:
    args += ['--ro-bind', '/', '/']
    for each allowWrite path P (解析后字面):
        if P 以 "/dev/" 开头: 跳过
        if 不存在: 跳过
        if 是 symlink-outside-boundary: 跳过
        args += ['--bind', P, P]
        allowedWritePaths.append(P)
    # 现在处理 deny
    denyPaths = denyWithinAllow + mandatoryDenyPaths(ripgrep, depth, allowGitConfig)
    for each P in denyPaths:
        if P 是目录:
            pushReadDenyDirMounts(args, P, allowedWritePaths, readAllowPaths)
        else:
            args += ['--ro-bind', '/dev/null', P]
    args.extend(denyWriteArgs)
    # 允许 git config 覆盖
    if .git/config 在必拒中,且 allowGitConfig=True,在这里通过 --bind 恢复
else:
    # 无写入限制:不拒绝任何内容
    args += ['--bind', '/', '/']  # 根可写;其他都必要
```

```python
def pushReadDenyDirMounts(args, deniedPath, allowedWritePaths, readAllowPaths):
    args += ['--tmpfs', deniedPath]
    # tmpfs 抹掉了任何先前对子路径的 --bind;恢复
    for wp in allowedWritePaths:
        if wp 以 deniedPath/+ 开头 或 wp == deniedPath:
            args += ['--bind', wp, wp]
    # 重新允许读访问:
    for rp in readAllowPaths:
        if rp 以 deniedPath/+ 开头 或 rp == deniedPath:
            # ... 与上面相同的逻辑,纯读加 '--ro-bind'
            if 某个写路径覆盖 rp,跳过(它刚被重新绑定)
            args += ['--ro-bind', rp, rp]
```

### 为何两遍

`--ro-bind /dev/null /home` 是错的(我们想要目录),而 `--tmpfs /home` 会抹掉之前发出的 `--bind /home/me/project`。所以我们缓冲 `denyWrite` 与 `pushReadDenyDirMounts` 中的重新绑定回步骤,直到写入允许循环之后。

## 6.9 环境变量接入

### 掩码环境变量

```
--setenv SENTINEL_FOO "<srt:FOO:abc>"     ← 真值在代理出口替换
```

### 被拒环境变量

```
--unsetenv SSH_AUTH_SOCK
```

### 信任库环境变量

如果打开了 `tlsTerminate`:

```
--setenv SSL_CERT_FILE <bundlePath>
--setenv CURL_CA_BUNDLE <bundlePath>
--setenv REQUESTS_CA_BUNDLE <bundlePath>
--setenv GIT_SSL_CAINFO <bundlePath>
--setenv NODE_EXTRA_CA_CERTS <bundlePath>
--setenv CARGO_HTTP_CAINFO <bundlePath>
```

bundle 必须可在沙箱内读取,所以它的父目录自动包含在 `allowRead` 中(管理器的 wrap 函数会做这件事)。

### 代理环境变量

```
--setenv HTTP_PROXY "http://srt:<token>@127.0.0.1:3128"
--setenv HTTPS_PROXY "http://srt:<token>@127.0.0.1:3128"
--setenv http_proxy "<same>"     ← 有些工具读小写
--setenv https_proxy "<same>"
--setenv ALL_PROXY "socks://srt:<token>@127.0.0.1:1080"
--setenv all_proxy "<same>"
--setenv NO_PROXY=127.0.0.1,localhost  ← 保持代理 loopback 在代理上
```

无凭证泄漏——只有会话级的鉴权 token。

### GIT_SSH_COMMAND

```
ssh → socat - PROXY:127.0.0.1:1080:%h:%p
```

`%h`/`%p` 是 git 的 SSHS 替换。该命令把 git 的 `ssh://` URL 通过 SOCKS5 代理路由到 TCP/1080。

## 6.10 PTY 处理

Linux 默认使用宿主 PTY(编排器的 stdio 被透传)。不需要沙箱端 PTY 基础设施。需要 TTY 的工具(npm、gh)通过父 shell 得到——意味着宿主用户的提示符可能泄漏。这对 Linux 是可接受的,因为替代方案(沙箱内 pty 读宿主终端)没有带来任何收益,反而增加复杂度。

## 6.11 清理(`cleanupBwrapMountPoints`)

当目标不存在时,bwrap 在宿主上创建空文件作为 bind-mount 目标(例如 `--ro-bind /dev/null ~/.bashrc` 在宿主上创建一个空的 `~/.bashrc`)。这些文件在沙箱调用之间保留,看起来像幽灵点文件。

跟踪:
- 在 Set `bwrapMountPoints` 中注册每个不存在的 deny 路径。
- Wrap 时 `activeSandboxCount` 递增,清理时递减。

清理:
- 命令之后:递减计数器;若为 0,删除 Set 中仍然为空的文件。
- 在 `reset()` 或进程退出时:无论计数器多少强制清理。
- 跳过已不再为空的文件(中间可能创建了真正的 shell-init 脚本,不要炸掉)。

## 6.12 Linux 路径仓库布局

```
src/sandbox/linux-sandbox-utils.ts
├── generateFilesystemArgs (async)
├── expandWriteAllowRebinds       ← 在 deny-tmpfs 后重新绑定写入
├── initializeLinuxNetworkBridge  ← 宿主侧 socat
├── buildSandboxCommand           ← 内部 `bash -c ...` 脚本
├── resolveApplySeccompPrefix
├── linuxGetMandatoryDenyPaths (async)
│    └── ripgrep 调用
├── cleanupBwrapMountPoints (引用计数,force-aware)
├── checkLinuxDependencies
└── wrapCommandWithSandboxLinux → 返回宿主 spawn 的 bwrap argv
```

```
vendor/seccomp-src/
├── apply-seccomp.c           ← 主二进制
├── seccomp-unix-block.c      ← BPF 过滤器源码(在构建时编译进二进制)
└── build.ts                  ← npm run build:seccomp 脚本,为 x64 与 arm64 调用 gcc
```
