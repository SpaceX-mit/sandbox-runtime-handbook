# 05 — Filesystem Isolation — macOS

This document covers the macOS implementation: how the Seatbelt profile is
generated and how the sandboxed command is launched through `sandbox-exec`.

## 5.1 OS Primitive

`/usr/bin/sandbox-exec -f <profile> -p <profile> <command>` runs `<command>` under
the supplied SBPL profile. The kernel evaluates every VFS, IPC, and signal
operation against the profile. Operations are evaluated **in profile order,
last-match-wins**.

Public reference: <https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf>.
Note that Apple marked the binary `__DebugSymbols` from the public SDK; the
grammar is stable but undocumented in headers.

## 5.2 Profile Skeleton

`generateSandboxProfile({...})` produces an SBPL string. The skeleton:

```sbpl
(version 1)
(deny default (with message "<logTag>"))

; ─── Process basics ───
(allow process-exec)
(allow process-fork)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
(allow mach-priv-task-port (target same-sandbox))

; ─── User prefs, IOKit minimal ───
(allow user-preference-read)
(allow iokit-open (iokit-registry-entry-class "IOSurfaceRootUserClient") … )
(allow iokit-get-properties)
(allow sysctl-read (sysctl-name "hw.activecpu") … )    ← explicit allowlist
(allow file-ioctl (literal "/dev/null") …)
(allow ipc-posix-shm) (allow ipc-posix-sem)            ← Python multiprocessing etc.

; ─── Mach lookup ───
(allow mach-lookup
  (global-name "com.apple.audio.systemsoundserver")
  (global-name "com.apple.distributed_notifications@Uv3")
  …)
; Optionally:
(allow mach-lookup (global-name "com.apple.trustd.agent"))   ← enableWeakerNetworkIsolation
(allow appleevent-send) (allow lsopen)                       ← allowAppleEvents

; ─── Network ───
(if needsNetworkRestriction:
   (allow network-bind (local ip "*:*"))            ← allowLocalBinding
   (allow network-inbound (local ip "*:*"))
   (allow network-outbound (remote ip "localhost:*"))
   (allow system-socket (socket-domain AF_UNIX))    ← allowAllUnixSockets / allowUnixSockets
   (allow network-outbound (remote ip "localhost:<HTTP_PORT>"))
   (allow network-outbound (remote ip "localhost:<SOCKS_PORT>"))
)

; ─── Filesystem ───
<read rules>     ← deny-then-allow
<write rules>    ← allow-then-deny
```

`logTag` is `CMD64_<base64(command)>_END_<sessionSuffix>_SBX`. The system log shows it for every denied operation, letting the violation monitor filter to the specific command.

## 5.3 Read Rules (`generateReadRules`)

```
(allow file-read*)                                     ← default

for each pathPattern in denyOnly:
    if containsGlobChars(pathPattern):
        (deny file-read* (regex "<globToRegex(path)>"))
    else:
        (deny file-read* (subpath "<path>"))

if deniesRoot:
    (allow file-read* (literal "/"))                  ← ls / works

for each pathPattern in allowWithinDeny:
    if containsGlobChars(pathPattern):
        (allow file-read* (regex "<globToRegex(path)>"))
    else:
        (allow file-read* (subpath "<path>"))

<re-emit denied subpaths nested under allowedSubpaths> ← last-match-wins

if denyOnly.length > 0:
    (allow file-read-metadata (vnode-type DIRECTORY))  ← realpath() can lstat

<move-blocking denies for each denyOnly path>

<file-write-unlink/file-write-create reallows for each writeAllowPaths>
```

### Why the re-allowance of file-write-unlink

`generateMoveBlockingRules(denyOnly)` denies `file-write-unlink` and
`file-write-create` on each deny path AND on its ancestor directories. The
intent: stop `mv ~/.config/foo ~/.config/bar` then `cat ~/.config/bar`.

But this also kills file deletions inside write-allowed dirs because Seatbelt
evaluates specific denials before generic allows. So we explicitly re-allow
those two operations for every path in `writeConfig.allowOnly` after the
move-blocking deny emission. The `denyWrite` rules re-deny these two
operations *again* (later), so the precedence is:

```
net effect per writeAllowPath:
    1. allow file-write*
    2. deny file-write-unlink/file-write-create (deny-then-allow)
    3. allow file-write-unlink/file-write-create (this re-allow)
    4. deny file-write* (denyWrite)
    5. deny file-write-unlink/file-write-create (denyWrite move)
⇒ deletions are allowed (3 wins over 2 for paths not in denyWrite)
⇒ a file in denyWrite can never be unlinked (5 wins over 3)
```

## 5.4 Write Rules (`generateWriteRules`)

```
for each pathPattern in allowOnly:
    (allow file-write* (subpath "<path>"))     or (regex "<globToRegex>")

denyPaths = denyWithinAllow ∪ macGetMandatoryDenyPatterns(allowGitConfig)

for each pathPattern in denyPaths:
    (deny file-write* (subpath "<path>"))     or (regex)

<move-blocking denies for each denyPath>
```

`macGetMandatoryDenyPatterns` is a *static* globs compilation (no ripgrep needed):

```
cwd-anchored deny paths:
    .bashrc, .bash_profile, .zshrc, .zprofile, .profile, .zshenv, .bash_login, .zlogout, .bash_logout
    .gitconfig, .gitmodules, .ripgreprc, .mcp.json
    .git/hooks/        (.git/config excluded when allowGitConfig)
recursive globs:
    **/.bashrc, **/.zshrc, **/.git/hooks/**, **/.git/config, etc.
    **/.vscode/**, **/.idea/**
    **/.claude/commands/**, **/.claude/agents/**
```

### Move-blocking rules

For every protected path (read or write):

```
(deny file-write-unlink (subpath "<p>") (with message "<logTag>"))
(deny file-write-unlink (literal "<ancestorOf_p>") (with message "<logTag>"))   ← for every ancestor up to /
(deny file-write-create (subpath "<p>") (with message "<logTag>"))
(deny file-write-create (literal "<ancestorOf_p>") (with message "<logTag>"))
```

The ancestor denies stop `mv /a/secret /a/innocent && rm /a/innocent && rm /a/secret` style attacks. For glob paths the first ancestor that's a *literal* directory prefix is also denied; deeper ancestors are derived from that.

### Why this is necessary

macOS VFS allows `rename(2)` and `unlink(2)` operations to touch any directory the process has *some* right on — including via a parent that was allowed earlier and then deleted. Denying `file-write-unlink` and `file-write-create` on the path AND its ancestors guarantees the file (and the directory that contains it) cannot disappear via a side-door.

The price: `rm -rf ~` is impossible. That's by design.

## 5.5 Glob Handling

macOS SBPL has no native glob. We compile `*.ext`, `**/foo`, `dir/*`, etc. into ECMAScript-style regexes using `globToRegex`:

| Glob       | Regex (anchored)               |
| ---------- | ------------------------------ |
| `*`        | `[^/]*`                        |
| `**`       | `.*`                           |
| `?`        | `[^/]`                         |
| `[abc]`    | `[abc]`                        |
| Trailing `/**` | stripped (treated as directory) |

A path with metadata wildcards like `**` is matched with `(regex "<…>")` in SBPL. Plain paths use `(subpath "<p>")` because `subpath` is faster (kernel VFS lookup) and more precise.

## 5.6 Normalization

```
normalizePathForSandbox("/some/path/"):
    resolve ~ to user home
    resolve symlinks where possible
    remove trailing / (unless the path is just "/")
    collapse ".." where resolvable; otherwise leave for the kernel
    on macOS also resolve /private/tmp → /tmp etc. (but keep the public path; the kernel handles the symlinks at the VFS layer)
```

The result is the path string we emit into the profile.

## 5.7 Network Rule Generation

| Config                        | Emitted rules                                                                                                |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `needsNetworkRestriction: false` | `(allow network*)` — no proxy needed.                                                                  |
| `needsNetworkRestriction: true` + `allowLocalBinding: false` | `(allow network-bind (local ip "localhost:<HTTP_PORT>"))`, same for SOCKS. No local-bind allow. |
| `...` + `allowLocalBinding: true` | also `(allow network-bind (local ip "*:*"))` and `(allow network-inbound (local ip "*:*"))` and `(allow network-outbound (remote ip "localhost:*"))`. |
| `allowAllUnixSockets: true`   | `(allow system-socket (socket-domain AF_UNIX))`, plus `(allow network-bind (local unix-socket (path-regex #"^/")))`, plus `(allow network-outbound (remote unix-socket (path-regex #"^/")))`. |
| `allowUnixSockets: [...]`     | same as above, but with explicit `(subpath "<sock>")` per entry.                                          |
| `httpProxyPort` set           | `(allow network-outbound (remote ip "localhost:<port>"))`                                                  |
| `socksProxyPort !== httpProxyPort` | also `(allow network-outbound (remote ip "localhost:<SOCKS_PORT>"))`                                  |

### IPv4-mapped IPv6 quirk

Java/AArch64 runtimes default to AF_INET6 dual-stack. A `connect(127.0.0.1)` shows up as a `::ffff:127.0.0.1` packet. Seatbelt's `localhost` keyword matches `127.0.0.1` and `::1` but **not** `::ffff:127.0.0.1`. We force the IPv4 stack inside the sandbox by appending `-Djava.net.preferIPv4Stack=true` to `JAVA_TOOL_OPTIONS` (preserving the inherited value if it doesn't already include it, but discarding inheritance entirely if `JAVA_TOOL_OPTIONS` is on the credential-deny env list).

## 5.8 Wrap Glue

After profile + env are generated, `wrapCommandWithSandboxMacOS()` returns:

```
env -u ENV_A -u ENV_B ENV_C=val JAVA_TOOL_OPTIONS=... \
  sandbox-exec -p '<profile>' <shell> -c <userCommand>
```

- `env -u` strips credential-denied env vars (whose mode=deny).
- `env NAME=val` injects credential-masked vars (mode=mask returns the sentinel).
- Profile is passed via the `-p` flag (or `-f <file>` if too long; we always use `-p`).
- The shell wrapper preserves aliases/snapshots/init scripts.

The orchestrator outer-spawns this with `shell: true` so the shell parses it.

## 5.9 Resolving `binShell`

`binShell` defaults to `"bash"`. `whichSync()` resolves it to an absolute path; SBPL uses the path string verbatim because sandbox-exec loads the binary into the sandbox with its real path.

If the resolution fails the wrap is aborted with a hard error.

## 5.10 PTY Support (`allowPty: true`)

When set, profile gains:

```
(allow pseudo-tty)
(allow file-ioctl (literal "/dev/ptmx") (regex #"^/dev/ttys"))
(allow file-read* file-write* (literal "/dev/ptmx") (regex #"^/dev/ttys"))
```

This lets the sandboxed process open `/dev/ptmx` and use the BSD-style pseudoterminal API. Sandbox still denies opening other `/dev/*` unless they're in `allowWrite`.

PTY is the only path where macOS uses a real PTY in user mode; otherwise the orchestrator's stdio is the host's.

## 5.11 Launch From `cli.ts`

```
spawn(wrappedCommand, { shell: true, stdio: 'inherit' })
```

Signals (`SIGINT`, `SIGTERM`) are forwarded to the child:

```
process.on('SIGINT',  () => child.kill('SIGINT'))
process.on('SIGTERM', () => child.kill('SIGTERM'))
```

The wrap command is one logical entity to the parent shell; signals flow through naturally.

## 5.12 Sandbox Violation Log Monitor (`macos-sandbox-utils.ts` > `startMacOSSandboxLogMonitor`)

Optional via `SandboxManager.initialize(cfg, askCb, /*enableLogMonitor=*/ true)`.

Implementation:

1. Subscribe to `os_log` via `os.unstable.log subscribe` (Node ≥ 20 has the
   `node:os` `log` namespace on Darwin).
2. Filter events with: `subsystem == "com.apple.sandbox" AND composedMessage CONTAINS[c] "<logTag>"`.
3. Push matching events to the supplied callback (`(violation: SandboxViolationEvent) => void`).
4. Store each violation in the `SandboxViolationStore`, keyed by the base64-encoded command.
5. Surface to the host via `getSandboxViolationStore().getViolationsForCommand(command)` and an optional stderr annotation (`<sandbox_violations>...` block at the end of the child's stderr).

The monitor only runs when the host process explicitly opts in. The default is to NOT enable it (avoids pulling `os.unstable` into the stable surface).

## 5.13 Recap: Precedence Pitfalls

| Pitfall                                                   | Mitigation                                                         |
| --------------------------------------------------------- | ------------------------------------------------------------------ |
| `(subpath "/")` denies everything not a subpath of itself | re-allow `(literal "/")` if root was denied                        |
| Trailing `/**` would otherwise never match anything       | `removeTrailingGlobSuffix` strips it before profile emit            |
| Read deny path inside read allow path                     | re-emit the deny *after* the allow                                  |
| Write allow path with a deny inside                       | denyWrite is emitted AFTER allowWrite (last-match-wins)             |
| `mv foo bar` removing the parent directory                | move-blocking deny on the parent's literal path                    |
| `ln -s /etc/passwd /tmp/symlink && cat /tmp/symlink`       | symlink resolution is unchanged; `subpath` matches `cat`'s target  |

The macOS implementation rests on **profile ordering**. Last-match-wins is the
contract — every code path must be profiled in the right sequence, and the
tests verify the exact ordering (`test/sandbox/macos-seatbelt.test.ts`,
`macos-pty.test.ts`).

## 5.14 Things Out of Scope (for Mac)

- **Kernel extensions, sandbox extensions, container technologies** — not used.
- **Code-signing enforcement** — the sandbox applies to any binary that gets exec'd; code-sign checks happen at process launch in macOS outside our path.
- **Hardware-level I/O isolation (USB etc.)** — no profile rule for this; we accept that a sandboxed process can talk to allowed IOKit clients only.
- **Firewall on the host** — out of scope; if you need that, run inside a VM.
