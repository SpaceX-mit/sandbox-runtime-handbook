# 11 — Violation Monitoring

When a sandboxed process attempts a denied operation, the system enforces
that denial *kernel-side*. But the embedder (e.g. `claude-code`) needs to
see those denials to either prompt the user for permission or surface an
explanation. This document covers the violation observability paths.

## 11.1 The Goal

A sandbox violation is the information that:
- A specific command (the child's executable + args) attempted
- A specific operation (open, write, connect)
- On a specific resource (a path or a network host:port)
- And was denied.

Embedders want this information to:
- Show a "this command tried to do X and was blocked" message.
- Pop a permission prompt ("do you want to allow this for next time?").
- Audit-log all denials.

## 11.2 macOS — System Log Monitor

### Where the events live

macOS `sandbox-exec` violations are written to the unified log under the
subsystem `com.apple.sandbox`. Each line carries an XPC-typed payload and a
textual message that includes the SBPL rule that fired (e.g. the
`(with message "CMD64_…")` annotation).

### Subscribing

```ts
function startMacOSSandboxLogMonitor(
  onViolation: (v: SandboxViolationEvent) => void,
  ignoreViolations?: IgnoreViolationsConfig
): () => void {
  const stream = execFile('log', ['stream', '--predicate', 'subsystem == "com.apple.sandbox"', '--style', 'syslog']);
  // line-by-line parser; filter by logTag; produce SandboxViolationEvent
}
```

(Since Node 20 added `os.unstable.log` on Darwin the implementation
intends to migrate to that surface; for now it shells out to `/usr/bin/log`.)

### Filter Logic

Each generated profile carries a unique `<logTag>` of the form
`CMD64_<base64(command)>_END_<session-random>_SBX`. The monitor keeps the
set of currently-active logTags in a `Set<string>`; it parses each
incoming log line and drops events whose message does not contain one of
those tags. This avoids getting flooded with sandbox events from other
apps on the same machine.

### Mapping back to the command

`onViolation` receives:

```ts
type SandboxViolationEvent = {
  line: string,                 // raw log line text
  command?: string,             // decoded command if we matched a known logTag
  encodedCommand?: string,      // base64-encoded command if we know it
  timestamp: Date,
}
```

The encoded command is the base64 form stored in the logTag; the decoded
one is what the user passed to `srt`.

### Ignore-violations Filter

```json
{
  "ignoreViolations": {
    "*": ["/usr/bin", "/System"],
    "git push": ["/usr/bin/nc"]
  }
}
```

`ignoreViolations[*]` is the global deny list: any command attempting
those paths is dropped from the violation feed without surfacing it. Per-
command entries are checked by regex.

## 11.3 Linux — SECCOMP_RET_USER_NOTIF Monitor

This is significantly more elegant than `strace`-based detection.

### Architecture

```
Host                                                  Worker (inside bwrap)
────                                                  ──────────────────
apply-seccomp (outer stub)
    │
    │ ←───(socketpair; outer holds one end)──────────────────────────┐
    │                                                               │
    │      ┌─────────────────────┐                                  │
    │      │ apply-seccomp       │                                  │
    │      │   main() (worker)   │  install_user_notif_filter()     │
    │      │                     │                                  │
    │      │                     │ ← PR_SET_NO_NEW_PRIVS done        │
    │      │                     │ ← unix-block-bpf applied          │
    │      │                     │ → send fd to outer stub via sp    │
    │      │                     │                                   │  user command runs
    │      │                     │                                   │  ───────────
    │      │                     │                                   │
    │      │  supervise(child,   │ ←── trap on write-intent syscall  │
    │      │   notify_fd,        │                                   │
    │      │   out_sock, …)      │                                   │
    │      └─────────────────────┘                                  │
    │         │ poll(notify_fd) → SECCOMP_IOCTL_NOTIF_RECV           │
    │         │ read_remote_cstr(workload_pid, path_arg, …)          │
    │         │ SECCOMP_IOCTL_NOTIF_SEND {flags: CONTINUE}           │
    │         │ emit JSON line on out_sock                            │
    │                                                               │
    ▼                                                               │
linux-violation-monitor.ts (Node)                                  
    net.createServer('/tmp/srt-observe.sock')                       
    on 'connection': readline → JSON.parse                          │
                       SandboxViolationStore.addViolation(…) ◀──────┘
```

### Why SECCOMP_RET_USER_NOTIF

It's the only kernel-blessed way to observe *every* attempt without
disturbing it. `strace` adds enormous overhead and is itself a sandbox
escape (ptrace attach). BPF with `SECCOMP_RET_LOG` only logs to dmesg and
overwhelms the kernel buffer. USER_NOTIF is the right primitive.

### What Gets Observed

`observe_calls[]` is the list:

```c
{ __NR_openat,    "openat",    …  },
{ __NR_openat2,   "openat2",   …  },
{ __NR_unlinkat,  "unlinkat",  …  },
{ __NR_mkdirat,   "mkdirat",   …  },
{ __NR_mknodat,   "mknodat",   …  },
{ __NR_symlinkat, "symlinkat", …  },
{ __NR_linkat,    "linkat",    …  },
{ __NR_renameat,  "renameat",  …  },
{ __NR_renameat2, "renameat2", …  },
{ __NR_fchmodat,  "fchmodat",  …  },
{ __NR_fchmodat2, "fchmodat2", …  },
{ __NR_fchownat,  "fchownat",  …  },
{ __NR_utimensat, "utimensat", …  },
#ifdef __x86_64__
{ __NR_open,      "open",      …  },
{ __NR_creat,     "creat",     …  },
{ __NR_unlink,    "unlink",    …  },
{ __NR_rmdir,     "rmdir",     …  },
… (legacy entry points on x86_64 only)
#endif
```

### Filter Shape

The BPF gates the trap on the *write intent*: for `openat` etc. it traps
when `args[flags] & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)` is non-zero.
That way, `cat /etc/passwd` (a denied read) doesn't generate a USER_NOTIF —
the kernel already denied it at bwrap's bind mount layer; `echo > /etc/passwd`
(also denied, but for write) **does** generate one because the bwrap layer
says nothing until the syscall is actually attempted.

The supervisor *always* replies with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` —
**never** denies the syscall. The kernel-level denial already happened
(bwrap's mount namespace blocked the access). The supervisor's job is to
record the attempt and let it fail naturally.

### Emit JSON Shape

```json
{
  "nr": 257,
  "syscall": "openat",
  "pid": 42,
  "path": "/etc/passwd",
  "encodedCommand": "Y3VybCBleGFtcGxlLmNvbQ"
}
```

The `encodedCommand` is set once via a separate JSON header line:
`{"encodedCommand":"Y3VybCBleGFtcGxlLmNvbQ"}` is sent on the observe socket
right after the connection is established, so every event line has the
encoded command available.

### Path Resolution

For absolute paths (e.g. `/etc/passwd`): copy into the event directly.

For relative paths (e.g. `foo.txt` from cwd or dirfd):

```
host_proc_fd = open("/proc", O_PATH | O_DIRECTORY | O_CLOEXEC)   // pinned BEFORE unsharing

// inside the supervisor:
snprintf(link, 64, "%d/cwd", req->pid)
// or:
snprintf(link, 64, "%d/fd/%d", req->pid, dirfd)

readlinkat(host_proc_fd, link, dst, dstcap)
memcpy(dst + blen + 1, relPath, relPathLen)
```

Failure paths produce `path` = ""; the node side drops the line.

### Important Caveats

- The workload's memory is **attacker-controlled**. `process_vm_readv` returns whatever the worker chose to put there. Path strings are read into a small fixed buffer (`OBS_PATH_MAX = 4096`).
- A racing sibling thread can `unlink()` the path between trap and read — `path` may be stale. We accept this: it's a diagnostics channel, not an enforcement channel.
- `kernel.yama.ptrace_scope=0` lets ptraced processes see each other. The user-notif scope `PR_SET_DUMPABLE=0` on inner init + nested PID namespace mitigate this.

## 11.4 Windows — No Violation Monitoring (v1)

`FWPM_LAYER_ALE_AUTH_CONNECT` doesn't carry a callout driver hook (it
requires a kernel driver for that). Blocked connections simply return
`WSAECONNABORTED`; the bearer-side app sees a connection error.

For filesystem violations, NTFS doesn't have an analogous per-operation
notification API from user mode (FileSystemWatcher is best-effort, and
misses EACCES).

This is a known limitation; the README mentions it under "Known
limitations" as future work.

## 11.5 `SandboxViolationStore` (in-process)

```ts
class SandboxViolationStore {
    violations = new Map<string /* b64(command) */, SandboxViolationEvent[]>()
    addViolation(v: SandboxViolationEvent) { … }
    getViolationsForCommand(command: string): SandboxViolationEvent[] { … }
    clear(): void
}
```

This is what cli-and-programmatic-api consumers use to surface violations
back to the user. Note it's *per-process* — multi-host scenarios (two
srt CLIs running simultaneously) each have their own store.

## 11.6 `annotateStderrWithSandboxFailures(command, stderr)`

When the orchestrator captures a child's stderr to show to the user, it
can append:

```
<sandbox_violations>
[time] [operation/path/host blocked]
</sandbox_violations>
```

This is opt-in via `SandboxManager.annotateStderrWithSandboxFailures(...)`;
it's how the embedder can include violations in the user-visible error
output without needing to query the store.

## 11.7 Ignore-violations Semantics Across Platforms

`ignoreViolations: { "*": [...], "<command regex>": [...] }`:

- `*` is a glob (matches anything; default-deny-this).
- Each entry is a list of `path`s (mac, Linux) or `host:port`s (network). For network denies, match by host or host:port.

Implementation: per-platform pre-filter.

- macOS: applied at the monitor-level. Log lines whose resource matches an entry are dropped.
- Linux: applied in the supervisor. JSON lines whose resource matches are dropped.
- Windows: not applicable (no monitor).

## 11.8 Turning Observability Off

`SandboxManager.initialize(config, askCb, /*enableLogMonitor=*/false)` skips
monitors entirely. This is the default. Embedders that don't need the
violation stream won't pay for the subscription overhead.
