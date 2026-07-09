# 13 — Security Model

This document is the threat model and the security invariants. It enumerates
what the runtime defends against, what it doesn't, and how the defenses are
layered.

## 13.1 Threat Model

### In-Scope Adversaries

1. **A compromised sandboxed tool** — the tool that's wrapped by `srt`. The tool may:
    - Read files it shouldn't (`~/.ssh`, `/etc/shadow`, etc.).
    - Write files it shouldn't (`.git/hooks/pre-commit`, shell rc files).
    - Open arbitrary TCP connections (DNS rebinding, exfil).
    - Spawn subprocesses that try to inherit the tool's powers.
    - Attempt to bypass domain-pattern checks (`*.attacker.com\x00.example.com`).
    - Try to escape via symlinks, race conditions, fd-passing.

2. **A passive observer on the same host machine** — another process that can read `/proc`, see the orchestrator's stdout, or dial `127.0.0.1:<port>`.
   - We defend by **authenticating the proxy** with a 16-byte token.
   - We defend by **state.db DACL** on Windows.
   - We defend by **Unix-domain sockets only** for the proxy on Linux.

3. **A network attacker on the path** — anyone between the host and the upstream:
   - Causing TLS MITM if the SRT already terminates TLS.
   - Reading TLS bytes (only if the SRT terminates upstream of the attacker; we always re-originate with `rejectUnauthorized:true` and the host's bundled roots or extras).
   - Forging DNS responses to a destination allow-listed hostname.

### Out-of-Scope Adversaries

1. **A user with `root`/`admin` on the host** — they can dump `/proc/<pid>/mem` or attach a debugger to the orchestrator. We cannot help here. The install/uninstall elevation step is the user's own choice.
2. **A kernel-level compromise** — rootkits, BPF-program abuse, side-channel attacks. Out of scope.
3. **Coercion of the orchestrator's operator** — the user themselves running the tool. Social-engineering the user is a different problem.

## 13.2 Defenses In Depth

The defenses are **layered**. An attacker has to break more than one:

| Layer                         | What it does                                       | What it defends against                                       |
| ----------------------------- | -------------------------------------------------- | ------------------------------------------------------------- |
| **Filesystem isolation**      | Read/write deny via OS primitive.                  | Read/write leak of source code/keys.                          |
| **Network isolation**         | All egress through a local proxy.                  | Direct TCP/UDS to internet.                                   |
| **Proxy filter**              | Domain allow/deny + per-request filter callback.   | Allowed hosts that need finer rules (e.g. `PUT` to GitHub).   |
| **Proxy auth**                | 16-byte hex token required on every request.       | Host processes dialing the loopback proxy.                    |
| **Mandatory deny**            | Always-block dangerous files (`.git/hooks`, `.bashrc`, etc.). | Hacks that allow-write a sensitive file.                  |
| **Move-blocking denies**      | Deny `file-write-unlink` and `file-write-create` on protected paths and ancestors. | `mv foo bar && rm foo` style escapes.                |
| **TPM/DPAPI** (Windows only)  | `state.db` credential encrypted at rest.            | Disk theft / cold-boot.                                       |
| **Sandbox user** (Windows only) | Sandboxed child runs as a dedicated SID.            | Cross-session SID hijacking via task schedulers / COM.        |
| **WFP fence** (Windows only)  | Kernel filters outbound by SID.                     | Token hijacking within the sandbox user.                      |
| **TLS termination**           | Optional in-process TLS termination + signed leaves. | Server-pinning / mTLS upstreams.                          |
| **Sentinel substitution**     | Hidden real secret values, substituted only at egress. | Tool exfiltrating secrets at runtime.                  |
| **Violation feed**            | Logs every denied attempt (mac, Linux).            | Internal monitoring / user prompts.                           |

## 13.3 Critical Invariants

These invariants hold when the implementation is correct. Bypassing any
single one is a CVE.

### Network Invariants

1. **The sandboxed process cannot reach the internet without going through the proxy.**
   - macOS: SBPL `(allow network-outbound (remote ip "localhost:<port>"))` is the only egress rule.
   - Linux: `--unshare-net` plus `socat` bridge means there is no NIC.
   - Windows: WFP filter `(allow) 127/8:[lo..hi]` plus `(block) <sandbox SID>` is exhaustive.

2. **The proxy authenticates every request.**
   - HTTP: `Proxy-Authorization: Basic srt:<token>`.
   - SOCKS5: RFC 1929 USER/PASS `srt:<token>`.

3. **The denial list is checked before the allow list.**
   - `filterNetworkRequest` order: `deniedDomains` first, then `allowedDomains`, then optional callback.

4. **Hostname canonicalization happens before matching.**
   - `canonicalizeHost` runs before `matchesDomainPattern` to defeat IPv4/integer ambiguity, trailing dots, etc.

5. **The proxy validates that hostnames don't contain control bytes.**
   - `isValidHost` rejects NUL, `%`, etc.

### Filesystem Invariants

1. **All file paths emitted to the OS primitive are normalized.**
   - `~` expansion is applied consistently across platforms.
   - Trailing `/**` is stripped (`removeTrailingGlobSuffix`).
   - Glob characters are expanded (Linux) or converted to regex (macOS).

2. **Mandatory denies always win.**
   - `.git/hooks/pre-commit` cannot be written even if the user has `allowWrite: ['.']`.
   - The macOS profile emits them last; the Linux wrapper emits them after the bind loop; Windows stamps them before granting allow.

3. **Move-blocks protect against `mv` and `unlink` of denied paths.**
   - Both macOS SBPL and Linux bwrap prevent unlinking the parent directory.
   - On Windows, ACE `FILE_DELETE_CHILD` DENY on the parent.

4. **Read-deny paths inside read-allow paths are explicitly re-denied.**
   - Last-match-wins is the macOS rule; the algorithm tracks this.
   - On Linux, bind-mount semantics handle re-allows correctly.

5. **Symlink-write-traversal is detected.**
   - `realpathSync` + `isSymlinkOutsideBoundary` rejects `allowWrite: ['/tmp/link']` if the link points outside any allowed region.

### Credential Invariants

1. **Real credentials never enter the sandboxed process's address space.**
   - Except: mode='mask' with `allowPlaintextInject` is an explicit opt-in.

2. **Real credentials only leave the host via TLS-terminated connections.**
   - To the allow-listed hosts in `injectHosts`.

3. **Sentinels are unique per session.**
   - `<srt:NAME:32-hex>` — random nonce prevents cross-session correlation.

4. **TLS-terminated leaves are minted by the same CA trusted by the sandboxed child.**
   - `state.db` thumbprint check on every `initialize()`.
   - CRL Distribution Point served from the loopback proxy.

### Process-Level Invariants

1. **The orchestrator is the only host-side process.**
   - All sandboxed children are spawned from it.

2. **The orchestrator's cleanup is fail-safe.**
   - `reset` is registered for exit, SIGINT, SIGTERM.

3. **The Linux isolation layer cannot be re-attached.**
   - Inner PID namespace; `PR_SET_DUMPABLE=0` on inner init; `ptrace_scope=0` doesn't help (we're in a different PID ns).

4. **The Windows sandbox user has no inherent rights on real-user files.**
   - ACE writes are additive and the only path to access.

## 13.4 Known Limitations

These are documented in the README and must be understood by embedders.

### Allow a broad domain risks exfiltration

Allowing `github.com` lets the sandboxed tool push to any repository. The
proxy does not inspect outbound HTTPS body content for legitimate-looking
HTTP requests. Custom plugin policy is recommended.

### Domain fronting

A tool can present TLS SNI=`example.com` to a CDN and tunnel to a different backend. `srt` does not defend against this unless `tlsTerminate` is enabled (in which case the proxy sees the negotiated HTTP/2 stream and can apply `filterRequest`). Embedders targeting trust-sensitive deployments should enable TLS termination.

### Unix domain sockets on Linux

The seccomp filter blocks `socket(AF_UNIX, ...)` and `io_uring_*`. It does **not** block operations on an inherited FD. Tools that receive a Unix socket FD from a parent are out of scope — there's no useful way to stop them.

### Linux proxy bypass

Tools that ignore `HTTP_PROXY` env vars (notably some old Python, some hand-rolled Go, certain routers) cannot reach the proxy. Future improvement: `proxychains` style `LD_PRELOAD` injection.

### macOS mandatory deny on non-existent files

SBPL evaluates a glob at exec-time; if a file path matches `**/foo` but the file doesn't exist when the rule is loaded, the file is still created-under-deny: the kernel evaluates the syscall against the profile and denies. macOS handles this correctly; Linux's mandatory deny is point-in-time (rg only finds existing matches).

### Windows registry / service configurations

The SID-fence doesn't reach `HKLM` or Windows services. A sandboxed process that creates a service running as a different user could… not, because the sandbox user cannot create services (its token is restricted, and no other service is in that SID's group by default).

### Windows `proxyAuthToken` exposure

For ~150ms, the token is in the runner's cmdline and a sibling host process
with `PROCESS_QUERY_LIMITED_INFORMATION` can read it. The token is also in
the env of the child, so the runner's cmdline exposure is a transitive
factor. On a single-user development machine this is acceptable; on a
shared host it's a consideration.

### Windows TLS CRL fetch

We serve an empty CRL from the loopback proxy to keep schannel happy. A
tool that doesn't use schannel-but-still-checks-revocation (e.g. Python's
`verify_mode=CERT_REQUIRED` + `revocation_mode=REVOKE_CHECK`) may still
hard-fail on the first CRL fetch.

### macOS DNS

The DNS resolver runs as `netd` / `systemd-resolved` outside the sandbox.
DNS rebinding is partially mitigated by `canonicalizeHost`. If the upstream
DNS is hijacked, the resolved IP can still be in `allowedDomains`. Tools
that verify TLS certificates (which check CN/SAN, not IP) are protected.

## 13.5 Defence-in-Depth Patterns

### Pre-spawn Validation

`SandboxManager.checkDependencies()` runs in `initialize()` — never deferred
to a per-command check. Missing dependencies fail at the beginning of the
process, not on the first user command.

### No Silent Fallback to Defaults

`--settings <path>` with a missing file is a hard error. The CLI never
runs without explicit config unless `~/.srt-settings.json` is missing AND
no `--settings` was provided.

### Structured Logging

`logForDebugging(msg, {level: 'warn'|'error'})` are visible at `SRT_DEBUG=1`.
The library never emits stdout unless the user opted in.

### Tokens Are Tokens

`proxyAuthToken` is regenerated every session. Even if leaked, it's per-run.

## 13.6 What the Layering Does NOT Defend

**The orchestrator itself.** If an attacker can compromise the orchestrator
process (e.g. by reading `~/.srt-settings.json` and writing their own
`network.allowedDomains: ['*']`), they win. The defense is at the
filesystem-protection layer of the host (file ACLs on the user's home
directory), not in srt.

**Credential disclosure by accident.** A credential that is masked in
env-vars might also be pasted into a config file that srt cannot see (e.g.
a tool that decodes the credential out-of-band). srt can mask the env var
but cannot mask the tool's own internal storage unless that storage is in
a directory that srt knows is credential-bearing.

**Supply chain attacks on the orchestrator.** If `npm install -g
@anthropic-ai/sandbox-runtime` is itself compromised, srt is compromised.
Standard npm/PyPI threat model applies.

## 13.7 Why the Design Holds

The Linux sandbox holds because:
- `bwrap` is widely deployed, audited, and used by Flatpak/Podman.
- `apply-seccomp` is ~600 LOC, fully audited, and the security-critical parts (BPF program) are reviewed.
- `--unshare-net` removes the network card.

The macOS sandbox holds because:
- Apple has shipped `sandbox-exec` since 10.5 with very few CVEs.
- The `(with message "<logTag>")` emission covers every operation.
- Dynamic profile generation is safer than sandbox profiles written once per app.

The Windows sandbox holds because:
- `WFP` is a kernel primitive evaluated in the same code path as the IP stack.
- `NTFS DACL` is the same code path every other app uses — no new attack surface.
- Sandboxed child runs as a different user, so any escape attempt is now in the sandbox-user's context, which has no inherent rights.

The credential injection layer holds because:
- The sentinel is opaque and per-session.
- The substitution happens in JS, after `filter()` approval and TLS validation.
- The TLS trust chain is anchored at the CA managed by srt and the CA's CRL is served by srt.
