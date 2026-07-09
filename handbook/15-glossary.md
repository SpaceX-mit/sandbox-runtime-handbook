# 15 — Glossary

A short alphabetical reference of terms used throughout this handbook.

| Term                    | Meaning                                                                                                                                  |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **ACD**                 | Access Control Entry — a single allow/deny rule inside an NTFS ACL.                                                                     |
| **ACE**                 | Access Control Entry — same as ACD (Windows jargon).                                                                                     |
| **audit arch**          | The kernel's per-arch identifier in `seccomp_data.arch` (e.g. `AUDIT_ARCH_X86_64`). Used to gate BPF programs per arch.                |
| **ask callback**        | The user-supplied `(host,port) => boolean` invoked by the proxy when no rule matches. Programmatic form of "permission prompt".        |
| **agent**               | A higher-level tool (often an LLM) that wraps arbitrary commands; `srt` is one of the layers an agent uses to be safer.                |
| **ale_user_id**         | WFP condition that keys on the user SID in the bearer token of an outbound connection.                                                    |
| **ambient capability**  | A Linux capability that survives `execve`. srt's `apply-seccomp` clears them all before the worker `execve`s.                            |
| **apparmor_restrict_unprivileged_userns** | Ubuntu 24.04 sysctl that strips caps from `CLONE_NEWUSER`. Disabling recommended.                                          |
| **bwrap**               | bubblewrap — a small setuid-less binary that creates user/pid/net/mount namespaces and binds mounts.                                    |
| **bfe**                 | Base Filtering Engine — the Windows service that runs WFP.                                                                              |
| **bind mount**          | A mount(2) invocation that makes a directory appear at another path. `--bind <src> <dst>`.                                               |
| **bp filter / bpf**     | Berkeley Packet Filter — the Linux in-kernel VM used by seccomp.                                                                         |
| **cdp**                 | CRL Distribution Point — an extension in an X.509 cert pointing to the URL where the CRL lives.                                          |
| **canonical host**      | The canonicalized form of a hostname (lowercase, no trailing dot, decimal IPv4 → dotted form, etc.).                                     |
| **cert store**          | Windows-specific certificate repository. `CurrentUser\Root` is where schannel looks for trust anchors.                                   |
| **cli**                 | Command-line interface. The `srt` binary.                                                                                                |
| **cll (cap list)**      | Capability list of a process token.                                                                                                      |
| **connector**           | The macOS `sandbox-exec` profile operation that allows network-bind/inbound/outbound to a specific remote.                                |
| **container inherit (CI)** / **object inherit (OI)** | NTFS ACE flags that make the rule propagate to new files/subdirs inside the protected directory.                                |
| **coredump / dumpable** | A process's "may-be-ptraced" flag. `PR_SET_DUMPABLE=0` makes a process non-traceable.                                                     |
| **connect (SOCKS5)**    | The SOCKS5 verb `0x01` — proxy initiates a TCP connect to the requested remote.                                                          |
| **cpuid**               | Identifier for a CPU architecture, used in trusted-code identification.                                                                 |
| **cre (CredentialEnforcer)** | Doesn't apply; `cre` is shorthand used elsewhere.                                                                                  |
| **crl**                 | Certificate Revocation List. Used to communicate that no certificate in a chain has been revoked.                                        |
| **cwd**                 | Current working directory.                                                                                                               |
| **dacl**                | Discretionary Access Control List — the part of an NTFS security descriptor that holds ACEs.                                              |
| **dispatcher**          | In multicall-binary mode, the binary's argv\[1] is `--srt-win` and the binary's main() routes to the right subcommand.                   |
| **dmr / dms**           | Doesn't apply here. (WFP-era abbreviation for data model/manager.)                                                                       |
| **dpapi**               | Windows Data Protection API. Encrypts data tied to a user or machine scope. Used to encrypt the sandbox user's password at rest.        |
| **dynamic plist**       | A `.sb` profile file fed to `sandbox-exec -f` per invocation, vs. -p embedded in argv.                                                   |
| **epem (Ephemeral)**    | A short-lived CA generated at session start. Lives in `state.db` (Windows) or temp dir (everywhere else) and is destroyed on reset.    |
| **epoll**               | Linux scalable I/O polling mechanism. Mentioned for completeness only.                                                                   |
| **execve**              | The Linux `execve(2)` syscall — replaces the current process with a new image.                                                           |
| **filesystem disable**  | `filesystem.disabled: true` — bypasses ALL filesystem rule generation. Documented escape hatch.                                            |
| **filesystem.disabled** | Same as above.                                                                                                                           |
| **filter callback**     | `network.filterRequest` — programmatic fine-grained HTTP-level filter, runs after allow/deny decide.                                     |
| **fwpm**                | The C-style Windows Filtering Platform API (`Fwpm*` functions).                                                                          |
| **fwp_value0**          | The variant struct that holds a single WFP condition value.                                                                              |
| **gbnf / grammar**      | Not used here.                                                                                                                           |
| **host**                | The host OS + host user, from the orchestrator's perspective.                                                                            |
| **hw.aes / hw.sha**     | Apple hw capabilities; typically allow-listed in sysctl-read section.                                                                    |
| **hostname canonicalization** | Making hostnames consistent before pattern matching (e.g. trailing dot, lowercase).                                               |
| **hw.bus / etc.**       | sysctl names — allowlisted in the SBPL profile's `(allow sysctl-read)`.                                                                  |
| **idempotent install**  | Running `install` again doesn't break; rather, it rotates password + reconciles filters.                                                  |
| **impersonate**         | Acquire a thread token for another user (used to install the CA in the sandbox user's registry).                                         |
| **io_uring**            | Async-IO kernel API; can also do socket ops (Linux 5.19+) so we block it.                                                                |
| **ipc-posix-shm / sem** | SBPL permission for POSIX shared memory / semaphores. Python multiprocessing needs `sem`.                                                |
| **job object**          | Windows kernel object; aggregating process kill + memory limits. Used as the sandbox boundary on Windows.                                  |
| **js proxy**            | The Node-side HTTP/SOCKS forward proxies that enforce allow/deny.                                                                         |
| **juggle / jumble**     | Doesn't apply. (Internal node-forge artifact.)                                                                                           |
| **kdump**               | Linux kernel crash dump. srt doesn't trigger this but appliers should know it can be triggered by BPF bugs.                              |
| **last-match-wins**     | SBPL rule ordering — later emitted rules in the profile override earlier ones for the same operation/path.                                |
| **leaf cert**           | A per-hostname X.509 certificate signed by the MITM CA, served to sandboxed tools that talk to the proxy.                                 |
| **listen-in-range**     | Binds the mux-proxy front-end to a free TCP port within `[low, high]`. Used on Windows where WFP fences a range.                         |
| **log monitor**         | Sandbox violation feed — macOS unified-log subscription or Linux SECCOMP_RET_USER_NOTIF supervisor.                                       |
| **logTag**              | Unique identifier embedded in every SBPL `(with message ...)`, used to filter macOS log lines per-command.                                 |
| **look-up**             | mach-lookup — the XPC service naming system on macOS; profiled explicitly.                                                                |
| **luid**                | Logon ID — Windows-specific identifier of a session.                                                                                     |
| **mitm_ca / mitm_ca**   | The MITM CA (an X.509 certificate + private key) used to mint leaves for terminated TLS connections.                                       |
| **macos seatbelt**      | Apple's sandbox profile language (SBPL).                                                                                                 |
| **mcp**                 | Model Context Protocol — a common embedding context for srt; not specifically depended on.                                                |
| **metric ton / metric** | Doesn't apply.                                                                                                                           |
| **mscorlib / .NET**     | The Windows .NET runtime; relies on schannel. Mentioned in the trust env var section.                                                     |
| **mux proxy**           | Single TCP port that dispatches incoming connections to either HTTP or SOCKS5 handler based on first byte.                                |
| **namespace**           | Linux kernel concept: a separate mapping of identifiers (mount, PID, network, user). bwrap does the unsharing.                           |
| **node-forge**          | A pure-JS implementation of X.509 + RSA used in srt's MITM path.                                                                         |
| **notify fd**           | The kernel-side listener FD returned by `SECCOMP_FILTER_FLAG_NEW_LISTENER`. Lets the supervisor receive USER_NOTIF callback requests.    |
| **observability**       | Compliance-jargon; in this context, the violation store and the monitors.                                                                |
| **openat**              | The Linux `openat(2)` syscall — the *at family variant of `open(2)`.                                                                      |
| **openssh**             | Doesn't apply.                                                                                                                           |
| **osquery**             | Doesn't apply.                                                                                                                           |
| **parent proxy**        | An HTTP/SOCKS proxy the orchestrator itself uses to reach the internet. Used when the host is behind a corporate proxy.                   |
| **pbac (per-exec)**     | A custom config passed to `wrapWithSandbox(...)` that overrides only the fields you specify.                                              |
| **pidfd**               | A Linux FD that refers to a process — used to await `pid_exit` without polling.                                                          |
| **policy engine**       | Hypothetical PEP; not part of srt. (Mentioned as a non-goal.)                                                                            |
| **posix sem / shm**     | POSIX semaphores / shared memory. Used by Python multiprocessing; SBPL allows them.                                                      |
| **profile**             | An SBPL text string; sometimes called `.sb` syntax.                                                                                      |
| **proxyAuthToken**      | A 16-byte hex random string generated per session; required by HTTP/SOCKS5 auth.                                                          |
| **ptrace_scope**        | Yama sysctl — controls which processes can ptrace each other. srt depends on being in a separate PID namespace, not on ptrace_scope.    |
| **qdisc / netem**       | Doesn't apply.                                                                                                                           |
| **rbac**                | Role-based access control — a different NTFS concept (privileges, not DACL).                                                              |
| **registry (HKU)**      | Per-user hive in the Windows Registry; the sandbox user's `CurrentUser\Root` cert store lives under `HKEY_USERS\<sid>\…\Root`.            |
| **revocation checking** | Schannel's online CRL/OCSP fetch — a sandbox whose CDP is unreachable fails TLS. We serve an empty CRL to keep it alive.                 |
| **ripgrep**             | A search tool used to find mandatory-deny files in subdirectories on Linux.                                                              |
| **rune**                | Don't confuse with Go's `rune`. Here it means "credential sentinel".                                                                      |
| **sandbox-exec**        | Apple's user-space sandbox engine. Receives an SBPL profile as input.                                                                    |
| **sbpl**                | Sandbox Profile Language — the SBPL grammar for Seatbelt.                                                                                |
| **seatbelt**            | Apple's sandbox kernel subsystem (also: a generic term for the entire family). srt's SBPL profile targets the kernel Seatbelt.           |
| **seccomp**             | Linux kernel feature that uses a BPF program to filter syscalls.                                                                         |
| **SECCOMP_RET_USER_NOTIF** | seccomp return code that traps the syscall into a userspace listener (the supervisor).                                                |
| **SECCOMP_IOCTL_NOTIF_*_RECV/SEND** | The two ioctls the supervisor uses to read notifications and reply.                                                       |
| **schannel**            | Windows' TLS implementation; trusts only the OS cert store.                                                                              |
| **sentinel**            | A placeholder string used to mask a real credential inside the sandbox. Format: `<srt:NAME:32-hex>`.                                       |
| **session**             | One process invocation of the orchestrator (from `initialize` to `reset`/exit).                                                          |
| **sha1 / sha256**       | Hash functions used in thumbprint / tree-commit style comparisons.                                                                        |
| **shell-quote**         | POSIX shell quoting utility in `utils/shell-quote.ts`.                                                                                   |
| **signal forwarding**   | The orchestrator forwards SIGINT/SIGTERM to the sandboxed child via `child.kill`.                                                        |
| **signup / register**   | The orchestrator's `initialize()` is also called `signup` in some embedding contexts.                                                    |
| **state.db**            | The Windows-side SQLite database at `%LOCALAPPDATA%\sandbox-runtime\state.db` storing the DPAPI credential, ACE records, CA cert.       |
| **stripHopByHop**       | RFC 7230 hop-by-hop header removal applied in proxy forwarding.                                                                          |
| **subprocess**          | A child process spawned by the orchestrator with `spawn()`.                                                                              |
| **sudo**                | Linux privilege escalation; not used by srt (bwrap is setuid-free).                                                                      |
| **symlink outside boundary** | Path that resolves through a symlink to an out-of-allowWrite location.                                                               |
| **sysctl**              | Linux kernel tunable (e.g. `kernel.yama.ptrace_scope`). SBPL allowlists specific sysctl reads/writes.                                    |
| **tcsd / tcsm**         | Apple-specific sysctl-related terms used in the SBPL sysctl-read allowlist.                                                              |
| **tee (body tee)**      | The `Readable.toWeb(req).tee()` split in the HTTP proxy that gives one stream to the filter callback and another to the upstream forward.|
| **tls-terminate-proxy** | The CONNECT handler that upgrades a TCP socket to TLS using a freshly minted leaf.                                                       |
| **tmpfs**               | A RAM-backed filesystem; used inside bwrap for `/tmp`, `/run`, etc., and as a deny mechanism (`--tmpfs <deny>`).                          |
| **token (Windows)**     | The security token attached to a process; `CreateRestrictedToken` removes rights.                                                         |
| **trust bundle**        | A PEM file the sandboxed child reads as its CA roots; combines the MITM CA + host's regular roots + extras.                                |
| **trustd.agent**        | macOS service that verifies TLS certificates; gated by `enableWeakerNetworkIsolation`.                                                  |
| **unshare**             | The Linux `unshare(2)` syscall; bwrap's backbone for namespaces.                                                                         |
| **user-notif**          | SECCOMP_RET_USER_NOTIF. Used in the Linux violation monitor.                                                                             |
| **veneer**              | Internal name for the trust-store env-var set wrapper. (Not an official term; mentioned in some test file names.)                        |
| **violation event**     | A single record in `SandboxViolationStore`.                                                                                              |
| **violation store**     | `SandboxViolationStore` instance.                                                                                                        |
| **vnode-type**          | The Seatbelt filter on file type (e.g. `CHARACTER-DEVICE`, `DIRECTORY`).                                                                |
| **wfp**                 | Windows Filtering Platform.                                                                                                              |
| **wfp / wfpStatus**     | A submodule of `windows-sandbox-utils.ts` returning the current WFP filter state (admin-only).                                           |
| **workspace**           | The user's working directory (`process.cwd()`) at the time of `wrapWithSandbox(...)`.                                                    |
| **x32**                 | The ILP32 calling convention under x86_64. Blocked by the BPF filter.                                                                    |
| **zero-runtime-deps**   | A milestone: pre-built binaries shipped in the package; no `gcc`/`cargo` at install time.                                                |

### Acronym Index

| Acronym          | Meaning                                                      |
| ---------------- | ------------------------------------------------------------ |
| ACL              | Access Control List (Windows)                                |
| ACE              | Access Control Entry                                          |
| AKI              | Authority Key Identifier (X.509)                              |
| AU               | Audit (e.g. AUDIT_ARCH_X86_64)                                |
| BFE              | Base Filtering Engine                                         |
| BPF              | Berkeley Packet Filter                                       |
| CA               | Certificate Authority                                         |
| CDP              | CRL Distribution Point                                         |
| CRL              | Certificate Revocation List                                    |
| DACL             | Discretionary Access Control List                              |
| EOF              | End of File                                                   |
| IPC              | Inter-Process Communication                                    |
| LSA              | Local Security Authority (Windows)                            |
| MITM             | Man-In-The-Middle                                              |
| NS / NS          | Namespace                                                      |
| OS               | Operating System                                                |
| PCI              | (Not used here.)                                              |
| PDB              | (Not used here.)                                              |
| PTY              | Pseudo-Terminal                                                 |
| RD               | (Not used here.)                                              |
| RPC              | Remote Procedure Call                                          |
| SBPL             | Sandbox Profile Language                                        |
| SID              | Security Identifier                                             |
| SKI              | Subject Key Identifier                                          |
| SSH              | Secure Shell                                                    |
| TCC              | Transparency, Consent, and Control (macOS)                     |
| TCP              | Transmission Control Protocol                                    |
| TLS              | Transport Layer Security                                         |
| URI / URL        | Uniform Resource Identifier / Locator                           |
| XPC              | Inter-process communication on macOS                            |
| ZSH / BASH       | Shells                                                          |
