# 06 — Filesystem Isolation — Linux

Linux uses **bubblewrap** (bwrap) for filesystem + namespace isolation, plus
an optional **seccomp BPF** filter for Unix-socket access control and
**SECCOMP_RET_USER_NOTIF** for violation observation. There are no globs in
the kernel — they're expanded at config- and wrap-time.

## 6.1 Architectural Pillars

1. **bubblewrap (`bwrap`)** — a small setuid-less binary that does its work via:
    - `--unshare-user-try` + explicit UID/GID setup.
    - `--unshare-pid` to make PID 1 a long-lived placeholder (helps with cleanup).
    - `--unshare-net` to remove the network namespace (mandatory; see §6.6).
    - Bind mounts (`--ro-bind / /` for a read-only root; `--bind <src> <dst>` for read-write).
    - `--tmpfs <path>` to deny a directory (read-deny for existing dirs).
    - `--ro-bind /dev/null <path>` to deny a single file (read-deny for non-existent or single-file paths).
    - `--proc`, `--dev`, `--tmpfs` for synthetic mounts.
2. **socat** — two bridges on host and two listeners inside the sandbox that
   tunnel TCP localhost → Unix socket on the host.
3. **apply-seccomp** — a small static ELF that:
    - Creates an outer user+pid+mount namespace (or piggybacks on bwrap's).
    - Forks an outer stub for signal/observation forwarding.
    - Forks an inner-init that mounts a fresh /proc.
    - Forks the actual worker, installs the BPF filter, and `execve`s.

The host Node process never sees the worker's PID. The worker sees only its
own PID and its children.

## 6.2 Bubblewrap Args Synthesized

### Top-level argv

```
bwrap
  --unshare-user-try                 # use CLONE_NEWUSER if permitted
  --unshare-pid                      # a placeholder is the new PID 1 (we don't exec it; we exec apply-seccomp)
  --unshare-net                      # remove network namespace
  --cap-add CAP_SYS_ADMIN            # needed for apply-seccomp's nested namespaces
  --die-with-parent                  # exit when srt exits (host PID trees get reaped on session end)
  --new-session                      # don't be in the caller's ctty
  --proc /proc
  --dev-bind /dev /dev
  --tmpfs /tmp                       # the only valid tmpfs for POSIX
  --tmpfs /run
  --tmpfs /var/tmp
  --ro-bind /usr /usr                # typically read-only system files
  --ro-bind /bin /bin
  --ro-bind /lib /lib
  --ro-bind /etc /etc                # entire /etc (configurable)
  --ro-bind /etc/resolv.conf /etc/resolv.conf   # network name resolution
  --ro-bind /etc/ssl /etc/ssl        # host CA roots unless tlsTerminate
  --ro-bind /etc/pki /etc/pki
  --ro-bind /nix/store /nix/store    # nix systems
  --ro-bind <allowReadMounts> ...    # user-requested read-only mounts
  --ro-bind /                        # the read-deny base
  --bind <allowWriteMounts> ...      # user-requested read-write mounts
  --bind <allowGitConfigMount> ...   # .git/config when allowGitConfig
  --ro-bind /dev/null <mandatoryDenyFile> ...  # mandatory deny (file)
  --tmpfs <mandatoryDenyDir> ...     # mandatory deny (dir)
  --bind <maskedFileBind> ...        # credential mask: read-only bind of fakePath over realPath
  --ro-bind <maskedFileStoreDir> /tmp/srt-mask   # read-only the store dir
  --bind <observeSocketPath> /tmp/srt-observe.sock
  --bind <httpSocketPath> /tmp/srt-http.sock
  --bind <socksSocketPath> /tmp/srt-socks.sock
  --setenv PATH <slimmed_PATH>       # use a sanitized PATH inside the sandbox
  --setenv HOME <cwd>                # sane HOME for tools that need it
  --setenv USER <username>
  --setenv TMPDIR /tmp
  --setenv HTTP_PROXY http://srt:<tok>@127.0.0.1:3128
  --setenv HTTPS_PROXY http://srt:<tok>@127.0.0.1:3128
  --setenv ALL_PROXY socks://srt:<tok>@127.0.0.1:1080
  --setenv SRT_DEBUG <if enabled>
  --setenv GIT_SSH_COMMAND "socat - PROXY:127.0.0.1:1080:%h:%p"   # SSH via SOCKS5
  --unsetenv <credentialDenyEnvVars> ...
  --setenv <SENT_NAME> <SENTINEL> ... # masked env vars
  --trust <SENT_NAME>=<SENTINEL> ...
  --apply-seccomp <shell> -c <innerScript>
```

### Decisions

- `--ro-bind /` then user-writable `--bind` overrides is the canonical pattern.
- Mandatory deny files use `--ro-bind /dev/null <p>`. Empty file at the bind source.
- Mandatory deny directories use `--tmpfs <p>`.
- Non-existent mandatory deny paths: skip (the parent is implicitly denied when the bind mount target doesn't exist) **and register for cleanup**.

Actually, bwrap's `--ro-bind` over a non-existent path *creates* an empty file
on the host (so it can mount). We track these via a Set and clean them up
after each command. See `cleanupBwrapMountPoints` in the linux-sandbox-utils.

### Why `--ro-bind /`?

This gives the sandbox an in-place image of the host filesystem at
fork-time; you can then carve out read-write regions with `--bind` and
read-deny regions with `--tmpfs` / `--ro-bind /dev/null`. The alternative
(bwrap `--bind` per file/directory you want accessible) is whack-a-mole on
practical systems: a tool like `npm install` touches dozens of paths.

## 6.3 Mandatory Deny Resolution (Linux)

The mandatory deny set is documented in Doc 03, §3.3. On Linux it is found by:

1. Build the static list of deny paths anchored at cwd (same as macOS):
   `.bashrc`, `.zshrc`, `.gitconfig`, `.mcp.json`, etc. resolved against `process.cwd()`.
2. Add `dangerousDirectories` (`.git/hooks/`, `.claude/commands/`, etc.) iff `.git` exists as a directory (not a symlink, not a file — git worktrees have `.git` as a file pointing at the real `.git` directory).
3. Run **one ripgrep invocation** with `--files --hidden --max-depth <N> --iglob <each pattern>` to enumerate matches in sub-directories.
4. For each match:
    - Determine if the match is inside a dangerous directory → add the directory path (not the file).
    - Otherwise the match is a dangerous file → add the absolute path.
5. Run `findSymlinkInPath(<path>, allowWritePaths)` for each (skip if the path crosses a write allowed dir via a symlink — realpathSync shows the host's target, then `isSymlinkOutsideBoundary` decides).
6. Run `hasFileAncestor(<path>)` for each (skip if a parent is a file, e.g. git-worktree `.git`).
7. Run `findFirstNonExistentComponent(<path>)` for each — register the resolved component for bwrap mount-point cleanup.

`mandatoryDenySearchDepth` defaults to **3**, range 1..10. Files at depth 0 (`./.bashrc`) are always protected. Higher depth = more thorough but slower.

### Depth 0 protection

The static list (Step 1 above) always covers depth 0 regardless of the rg flag. So `srt 'echo "malicious" >> .bashrc'` is denied even if `mandatoryDenySearchDepth: 0` is somehow set (the schema constrains it to ≥1 anyway).

## 6.4 Symlink Boundary Check (`isSymlinkOutsideBoundary`)

If an `allowWrite` path resolves through a symlink to a location outside any `allowWrite` boundary, we skip the bind. Rationale:

```
mkdir -p /tmp/project
ln -s /etc /tmp/project/etc
allowWrite: ['/tmp/project']
```

A naive `--bind /tmp/project /tmp/project` would make `/etc` writable via
`/tmp/project/etc`. So we `realpathSync` every allowWrite path and require
the resolved path to stay inside one of the allowWrite boundaries — else we
skip with a debug log and rely on the ro-bind to deny access anyway.

Read-deny symlink resolution (`resolveSymlinkDenyDest`) does the opposite: a symlink read-deny at `~/.netrc → /somewhere/.netrc` is rewritten to deny `/somewhere/.netrc` (because bwrap cannot bind /dev/null over a symlink; it errors with "Can't create file at <path>").

## 6.5 Network Bridge

### Host side (`initializeLinuxNetworkBridge`)

```
socat UNIX-LISTEN:/tmp/claude-http-<rand>.sock,fork,reuseaddr TCP:127.0.0.1:<httpProxyPort>,keepalive,...
socat UNIX-LISTEN:/tmp/claude-socks-<rand>.sock,fork,reuseaddr TCP:127.0.0.1:<socksProxyPort>,keepalive,...
```

Both bridged processes run in the host's namespace. They connect to `127.0.0.1:<port>` (the JS proxies). The sockets are then bind-mounted into the sandbox.

### Inside the sandbox (`buildSandboxCommand`)

```bash
socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:/tmp/srt-http.sock >/dev/null 2>&1 &
socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:/tmp/srt-socks.sock >/dev/null 2>&1 &
trap "kill %1 %2 2>/dev/null; exit" EXIT
ARGV0=<argv0_value> /path/to/apply-seccomp bash -c '<userCommand>'
```

The two socat listeners run as background jobs; the trap ensures they die on sandbox exit. Then `apply-seccomp` is exec'd as the foreground process — install-seccomp first, then exec the user's `bash -c`.

### socat path resolution

If `config.socatPath` is set (must be absolute), it's used directly. Else
`whichSync("socat")`. The resolved absolute path is used inside bwrap because
bwrap mirrors `/usr` into the sandbox.

### Handling `socksProxyPort === httpProxyPort`

If the user (or the mux) reports the same port for both protocols, the socks
side reuses the HTTP-side unix socket and bridge process. The SOCKS listener
inside the sandbox still uses port 1080 — two different listeners, two different bridges, but only one bridge process when they target the same TCP.

### Path to glibc/musl

`apply-seccomp` is statically linked, libc-independent. Tested on glibc and musl distros.

## 6.6 `--unshare-net` Rationale

Without `--unshare-net`, the sandboxed process can still do any TCP/UDP
directly through the host NIC (bwrap only sandboxes the filesystem). The
routing table inside the sandbox is unchanged. So `--unshare-net` is mandatory;
the only escape is via the socat bridge.

## 6.7 Apply-Seccomp (`vendor/seccomp-src/apply-seccomp.c`)

This 600-LOC binary is the Linux heart of the sandbox. Key responsibilities:

```
main(argc, argv):
    if SRT_OBSERVE_SOCK set: create a pre-fork socketpair for the observer
    open /proc before unsharing (the post-unshare /proc is the sandbox's)

    try unshare(CLONE_NEWPID|CLONE_NEWNS) directly:
        EPERM? -> try the user-namespace fallback path
                 (CLONE_NEWUSER → setgroups:deny → uid_map → gid_map → unshare)
    fork():
        child1: outer stub
              install_forwarders(child3)        # SIGTERM/SIGINT/SIGHUP/etc. to inner init
              recv fd from socketpair           # the notification fd
              supervise(child3, notify_fd, out_sock, enc, host_proc_fd)
              waitpid(child3)
              _exit(status)
        child1's grandchild (=original process's grand-grandchild): inner init
              prctl(PR_SET_DUMPABLE, 0)
              mount(MS_PRIVATE|MS_REC, /)
              mount("proc", "/proc", ...)      # may fail with EPERM -> continue
              prctl(PR_CAP_AMBIENT, CLEAR_ALL)
              fork():
                  child2: worker
                          unsetenv("SRT_*")
                          prctl(PR_SET_NO_NEW_PRIVS, 1)
                          install_observe_filter(sp[1])
                          prctl(PR_SET_SECCOMP, BPF)   # unix_block_bpf
                          execvp(command_argv[0], command_argv)
              → _exit(reap_until(child2))
        child1's grandchild (=inner init):
              install_forwarders(child2)
              → reap_until(child2)
```

### The BPF filter

`unix-block-bpf.c` (separately compiled and embedded into `apply-seccomp` as `unix_block_bpf[]`) is an array of `struct sock_filter` instructions. Semantics:

```
arch != AUDIT_ARCH_X86_64 (or AARCH64) → SECCOMP_RET_ALLOW (compat)
nr >= 0x40000000 (x32)            → SECCOMP_RET_ALLOW
nr == __NR_socket:
    args[0] == AF_UNIX (or IPv4/IPv6 mapped) → SECCOMP_RET_ERRNO|EPERM
    else                                       → SECCOMP_RET_ALLOW
nr in { __NR_io_uring_setup,
        __NR_io_uring_enter,
        __NR_io_uring_register }    → SECCOMP_RET_ERRNO|EPERM
                                          (Linux 5.19+: IORING_OP_SOCKET bypass)
default                              → SECCOMP_RET_ALLOW
```

The listener must be **/usr/include/linux/seccomp.h** at build time. The generated BPF is built once per architecture (x64 and arm64) at the npm package build phase (`npm run build:seccomp`).

### Observer path

When `SRT_OBSERVE_SOCK` is set, a **second** BPF filter is installed on the
worker side that traps write-intent filesystem syscalls via
`SECCOMP_RET_USER_NOTIF`. The outer stub services each notification with
`SECCOMP_USER_NOTIF_FLAG_CONTINUE` (the workload is unchanged). Path bytes are
read from the worker's address space with `process_vm_readv`; relative paths
are resolved against `/proc/<pid>/cwd` or `/proc/<pid>/fd/<n>`.

Then the supervisor writes a JSON line per event to the unix socket named by
`SRT_OBSERVE_SOCK`. A Node `net.Server` on the host side parses this stream
and feeds it into `SandboxViolationStore.addViolation`.

Failure modes: kernel too old → observer silently disabled. Connection failure to the host socket → observer silently disabled. Anything before the filter install → fail-open (no observer, normal seccomp only). Anything after the filter install → fatal: the only way to NOT wedge the workload is to drain the notification fd with CONTINUE.

## 6.8 Mandatory-Deny Filesystem Mounts

The wrap-time sequence in `generateFilesystemArgs`:

```python
allowedWritePaths = []   # populated as we process allowWrite
denyWriteArgs = []        # buffered, emitted after denyRead loop

if writeConfig:
    args += ['--ro-bind', '/', '/']
    for each allowWrite path P (resolved literal):
        if P startsWith "/dev/": skip
        if not exists: skip
        if is symlink-outside-boundary: skip
        args += ['--bind', P, P]
        allowedWritePaths.append(P)
    # Now process denials
    denyPaths = denyWithinAllow + mandatoryDenyPaths(ripgrep, depth, allowGitConfig)
    for each P in denyPaths:
        if P is a directory:
            pushReadDenyDirMounts(args, P, allowedWritePaths, readAllowPaths)
        else:
            args += ['--ro-bind', '/dev/null', P]
    args.extend(denyWriteArgs)
    # Allow git config override
    if .git/config is in mandatory deny, and allowGitConfig=True, restore via --bind here
else:
    # No write restrictions: deny nothing
    args += ['--bind', '/', '/']  # Root is writable; nothing else needed
```

```python
def pushReadDenyDirMounts(args, deniedPath, allowedWritePaths, readAllowPaths):
    args += ['--tmpfs', deniedPath]
    # tmpfs wiped any earlier --bind on subpaths; restore.
    for wp in allowedWritePaths:
        if wp startsWith deniedPath/+ OR wp == deniedPath:
            args += ['--bind', wp, wp]
    # Re-allow read access:
    for rp in readAllowPaths:
        if rp startsWith deniedPath/+ OR rp == deniedPath:
            # ... same logic as above, plus '--ro-bind' for pure-read
            if a write path covers rp, skip (it was re-bound)
            args += ['--ro-bind', rp, rp]
```

### Why two passes

`--ro-bind /dev/null /home` would be wrong (we want a directory) and `--tmpfs /home` would wipe out `--bind /home/me/project` that was emitted before the deny. So we buffer `denyWrite` and the re-bind-back step inside `pushReadDenyDirMounts` until after the write allow loop.

## 6.9 Env Wiring

### Masked env vars

```
--setenv SENTINEL_FOO "<srt:FOO:abc>"     ← real value substituted at proxy egress
```

### Denied env vars

```
--unsetenv SSH_AUTH_SOCK
```

### Trust store env vars

If `tlsTerminate` is on:

```
--setenv SSL_CERT_FILE <bundlePath>
--setenv CURL_CA_BUNDLE <bundlePath>
--setenv REQUESTS_CA_BUNDLE <bundlePath>
--setenv GIT_SSL_CAINFO <bundlePath>
--setenv NODE_EXTRA_CA_CERTS <bundlePath>
--setenv CARGO_HTTP_CAINFO <bundlePath>
```

The bundle must be readable inside the sandbox, so its parent directory is
included in `readAllow` automatically (the manager's wrap function does
this).

### Proxy env vars

```
--setenv HTTP_PROXY "http://srt:<token>@127.0.0.1:3128"
--setenv HTTPS_PROXY "http://srt:<token>@127.0.0.1:3128"
--setenv http_proxy "<same>"     ← some tools read lowercase
--setenv https_proxy "<same>"
--setenv ALL_PROXY "socks://srt:<token>@127.0.0.1:1080"
--setenv all_proxy "<same>"
--setenv NO_PROXY=127.0.0.1,localhost  ← keep the proxy loopback on the proxy
```

No credential leaking — just the auth token, which is per-session.

### GIT_SSH_COMMAND

```
ssh → socat - PROXY:127.0.0.1:1080:%h:%p
```

The `%h`/`%p` are git's SSHS substring substitution. This routes git's `ssh://` URLs through the SOCKS5 proxy on TCP/1080.

## 6.10 PTY Handling

Linux uses host PTY by default (the orchestrator's stdio is forwarded). No
sandbox-side PTY infrastructure needed. Tools that need a TTY (npm, gh) get
one via the parent shell, which means the host user's prompts can leak. This
is acceptable for Linux because the alternative is a pty in the sandbox that
reads the host's terminal; there is no benefit to that complexity.

## 6.11 Cleanup (`cleanupBwrapMountPoints`)

bwrap creates empty files on the host as bind-mount targets when the target
doesn't exist (e.g., `--ro-bind /dev/null ~/.bashrc` creates an empty `~/.bashrc`
on the host). These are persisted across sandboxed invocations and look like
ghost dotfiles.

Tracking:
- Every non-existent deny path registered (in the Set `bwrapMountPoints`).
- Active-sandbox counter incremented at wrap-time, decremented at cleanup.

Cleanup:
- After a command: decrement counter; if zero, delete any still-empty files in the Set.
- On `reset()` or process exit: force cleanup regardless of counter.
- Skip files that are no longer empty (a real shell-init script may have been created since — don't blow it away).

## 6.12 Repo Layout of the Linux Path

```
src/sandbox/linux-sandbox-utils.ts
├── generateFilesystemArgs (async)
├── expandWriteAllowRebinds       ← re-bind writes after deny-tmpfs
├── initializeLinuxNetworkBridge  ← host-side socat
├── buildSandboxCommand           ← the inner `bash -c ...` script
├── resolveApplySeccompPrefix
├── linuxGetMandatoryDenyPaths (async)
│    └── ripgrep invocation
├── cleanupBwrapMountPoints (ref-counted, force-aware)
├── checkLinuxDependencies
└── wrapCommandWithSandboxLinux → returns the bwrap argv the host spawns
```

```
vendor/seccomp-src/
├── apply-seccomp.c           ← main binary
├── seccomp-unix-block.c      ← the BPF filter source (compiled into the binary at build time)
└── build.ts                  ← npm run build:seccomp script, runs gcc for x64 and arm64
```
