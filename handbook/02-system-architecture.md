# 02 — System Architecture

## 2.1 Process Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                  HOST                                       │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                srt (Node ≥ 20 orchestrator process)                │    │
│  │                                                                     │    │
│  │  ┌──────────────────┐    ┌────────────────────┐  ┌─────────────┐    │    │
│  │  │  SandboxManager  │───▶│  HTTP forward proxy│  │ SOCKS proxy │    │    │
│  │  │   (singleton)    │    │   (mux front-end   │  │  (backend   │    │    │
│  │  │                  │    │    on one TCP port)│  │   only on   │    │    │
│  │  │                  │    │                    │  │  the mux)   │    │    │
│  │  │                  │    │  - CONNECT: TLS    │  │             │    │    │
│  │  │                  │    │    termination     │  │  - SOCKS5   │    │    │
│  │  │                  │    │  - filterRequest   │  │  - filters  │    │    │
│  │  │                  │    │  - sentinel inject │  │  - parent   │    │    │
│  │  │                  │    │  - parent proxy    │  │    proxy    │    │    │
│  │  └──────────────────┘    └────────────────────┘  └─────────────┘    │    │
│  │            │                       │                                 │    │
│  │            │                       │                                 │    │
│  │  ┌─────────▼───────────┐  ┌────────▼────────────┐                  │    │
│  │  │ linux-violation-    │  │ credential sentinel │                  │    │
│  │  │ monitor (SECCOMP_   │  │ registry + masked   │                  │    │
│  │  │ RET_USER_NOTIF)     │  │ file store          │                  │    │
│  │  └─────────────────────┘  └─────────────────────┘                  │    │
│  │            │                                                       │    │
│  │  ┌─────────▼─────────────────────────────────────────────────────┐  │    │
│  │  │              SandboxViolationStore (in-process)                │  │    │
│  │  └───────────────────────────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│       ┌──────────────┐          ┌──────────────────────────────────┐         │
│       │ socat bridge │◀─────────│ bwrap sandbox (Linux)            │         │
│       │ (Unix sock→  │ Unix     │  --unshare-net, --unshare-pid,   │         │
│       │  TCP→proxy)  │ socket   │  --unshare-user, bind-mount       │         │
│       └──────────────┘          │  ─────────────────────────────── │         │
│                                 │  apply-seccomp (PID 1)           │         │
│                                 │  │                               │         │
│                                 │  ├─ socat 3128 → Unix            │         │
│                                 │  ├─ socat 1080 → Unix            │         │
│                                 │  └─ user command (BPF applied)   │         │
│                                 └──────────────────────────────────┘         │
│                                                                             │
│       ┌──────────────────────────────────────────────────────────────┐      │
│       │ sandbox-exec (macOS)                                          │      │
│       │   one Seatbelt profile generated at wrap time                 │      │
│       │   ──────────────────────────────────────────────              │      │
│       │   <user command>                                              │      │
│       └──────────────────────────────────────────────────────────────┘      │
│                                                                             │
│       ┌──────────────────────────────────────────────────────────────┐      │
│       │ srt-win.exe runner → Token-restricted child (Windows)         │      │
│       │   (broker → CreateProcessWithLogonW → runner as srt-sandbox    │      │
│       │    → restricted token + job → <user command>)                  │      │
│       └──────────────────────────────────────────────────────────────┘      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Boundary Truths

1. **The orchestrator (Node process) is always outside any sandbox.** It owns the proxies, the violation store, and the lifecycle.
2. **The sandboxed process is always a child of the orchestrator.** Wrapping uses `spawn` with arguments emitted by `wrapWithSandbox(Argv)()`.
3. **Proxies never run inside the sandbox.** They live on the host. The orchestrator's `proxyAuthToken` (16-byte random hex string) gates access so a peer host process cannot dial the loopback port and reach `filterNetworkRequest`.
4. **Native helpers (`apply-seccomp`, `srt-win.exe`) sit at the boundary.** They are the smallest possible shim that holds the OS primitive the orchestrator needs.

## 2.2 Module Map

| Module                                | Responsibility                                                                                                  | Lines (approx) |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------- | -------------- |
| `cli.ts`                              | commander-driven `srt` command. Default subcommand → run a command; `windows-install`/`windows-uninstall` self-elevating one-shots. | 285 |
| `sandbox/sandbox-manager.ts`          | Singleton orchestrator. Owns proxies, ACEs, seccomp monitor, MITM CA, sentinel registry. Public surface behind a const object. | 2000 |
| `sandbox/sandbox-config.ts`           | Zod schemas; superRefinement for cross-field validity (injectHosts ⊆ allowedDomains, no tlsTerminate+mitmProxy, etc.). | 850 |
| `sandbox/sandbox-schemas.ts`          | Internal TS types (FsReadRestrictionConfig, FsWriteRestrictionConfig, NetworkRestrictionConfig).                | 80 |
| `sandbox/sandbox-violation-store.ts`  | In-memory event store keyed by encoded command. Append-only, public read API.                                    | 150 |
| `sandbox/http-proxy.ts`               | HTTP forward proxy: CONNECT handling, TLS termination, MITM unix-socket routing, per-request filter, header mutation, parent proxy. | 1100 |
| `sandbox/socks-proxy.ts`              | SOCKS5 forward proxy: ADDRESS parsing, canonicalizeHost, host filter callback, parent proxy.                      | 350 |
| `sandbox/mux-proxy.ts`                | Front-end on a single TCP port that dispatches by ClientHello-style first-byte to either HTTP or SOCKS5 backend. | 350 |
| `sandbox/mitm-ca.ts`                  | Ephemeral or user-supplied CA. Builds a trust bundle (CA + host roots + extraCaCertPaths). CRL generation.      | 380 |
| `sandbox/mitm-leaf.ts`                | Per-hostname leaf signed by the CA (with SKI matched from the CA's).                                             | 250 |
| `sandbox/tls-terminate-proxy.ts`      | Peek for ClientHello, then upgrade the socket to TLS using the minted leaf; forward the decrypted bytes upstream over real TLS. | 350 |
| `sandbox/parent-proxy.ts`             | Dial-direct vs. parent-proxy helpers. NO_PROXY parsing and CIDR matching.                                       | 220 |
| `sandbox/request-filter.ts`           | Web-standard `Request` adapter for `IncomingMessage`; tee body for filter inspection; failure-as-deny.            | 170 |
| `sandbox/credential-sentinel.ts`      | Symbol-keyed map: sentinel string ↔ real secret. injectHosts gating.                                           | 110 |
| `sandbox/credential-mask-files.ts`    | Read real file, register sentinel, write fake file in a managed temp dir. Whole-file and regex-extract modes.   | 280 |
| `sandbox/macos-sandbox-utils.ts`      | Build SBPL profile text; emit `(allow/deny file-read*|file-write*|network-*)` rules; `wrapCommandWithSandboxMacOS` -> `sandbox-exec -f <(echo) -- <cmd>`. | 1100 |
| `sandbox/linux-sandbox-utils.ts`      | `bwrap` argv synthesis (mount namespaces, --unshare-net, bind mounts), dangerous-path detection via ripgrep, seccomp integration, network bridge via socat. | 1500 |
| `sandbox/windows-sandbox-utils.ts`    | Spawn `srt-win` argv synthesis (`acl grant/stamp/revoke/restore`), `wfp status|verify`, ACE expansion, install/uninstall self-elevation. | 2500 |
| `sandbox/linux-violation-monitor.ts`  | `SECCOMP_RET_USER_NOTIF` filter (`apply-seccomp` side) + JSON-line receiver on a Unix socket. Path resolution via `/proc/<pid>/{cwd,fd/N}`. | 250 |
| `sandbox/sandbox-utils.ts`            | Cross-OS utilities: path normalization, glob-to-regex, default write paths, dangerous-files/dirs lists.          | 450 |
| `sandbox/domain-pattern.ts`           | Wildcard suffix matching with IP-literal refusal. Used by both config validation and runtime host filtering.    | 80 |
| `sandbox/listen-in-range.ts`          | Bind the front-end to a free TCP port in `[low, high]` (used on Windows to land inside the WFP PERMIT range).    | 60 |
| `sandbox/generate-seccomp-filter.ts`  | Locate (`apply-seccomp-x64` / `apply-seccomp-arm64`) for the current architecture. Build-time pre-generated filters are pre-baked into the binary via `vendor/seccomp-src/seccomp-unix-block.c`. | 80 |
| `utils/config-loader.ts`              | Read/parse `~/.srt-settings.json` (zod-validated). Supports control-fd live updates via newline-delimited JSON. | 90 |
| `utils/debug.ts`                      | `logForDebugging(msg)` gated on `SRT_DEBUG=1`.                                                                              | 30 |
| `utils/platform.ts`                   | `getPlatform()` → `'darwin'|'linux'|'win32'|'wsl'` (via `/proc/version`).                                                | 30 |
| `utils/shell-quote.ts`                | POSIX shell-quoting (`'a b' → "'a b'"`).                                                                                       | 50 |
| `utils/which.ts`                      | PATH lookup (Node no longer ships a `which`).                                                                                  | 30 |
| `utils/ripgrep.ts`                    | Async rg subprocess with depth/glob flags.                                                                                      | 50 |
| `vendor/seccomp-src/apply-seccomp.c`  | Single static binary, ~600 LOC. Unshare(pid+mounts(+user fallback)), fork outer stub, fork inner init, fork worker; worker installs BPF + execs.    | 600 |
| `vendor/srt-win-src/src/*.rs`         | Rust helper exposing one CLI: `install`, `uninstall`, `exec`, `wfp status|verify`, `acl grant|revoke|recover|stamp|restore`, `user status|trust-ca`. ~20 kLOC.     | — |

## 2.3 OS-Primitive Boundary Choices

| OS      | Filesystem enforcement | Network enforcement | Unix sockets | PTY | Violation feed |
| ------- | ---------------------- | ------------------- | ------------ | --- | -------------- |
| macOS   | Seatbelt (`sandbox-exec -f <(echo)`) emitted at wrap time; glob patterns via `regex` matcher; file-write-create / file-write-unlink denied to block symlink-replacement attacks. | Proxy at localhost:<port> only; `(allow network-outbound (remote ip "localhost:PORT"))` | `allowUnixSockets` / `allowAllUnixSockets` | `allowPty: true` → `(allow pseudo-tty)` and `/dev/ptmx`+`/dev/ttys*` | `log stream --predicate 'message CONTAINS "<logTag>"'` parsed via `os.unstable` `log subscribe`/`log show` |
| Linux   | `bwrap --unshare-{net,pid,user}` + recursive bind mounts `--ro-bind / /` then `--bind <allow> <allow>` for writes, `--ro-bind /dev/null <deny>` for non-existent denies, `--tmpfs <deny>` for existing dirs; mandatory-deny files mounted the same way | `bwrap --unshare-net` + 2× `socat TCP-LISTEN:<port>,fork UNIX-CONNECT:<unix-sock>`; host proxies at fixed TCP ports; ip-removal means only the loopback bridge is reachable | `socket(AF_UNIX)` is intercepted by seccomp BPF (`SECCOMP_RET_ERRNO|EPERM`) when `network.allowAllUnixSockets === false`. Plus `io_uring_setup/enter/register` blocked (5.19+ `IORING_OP_SOCKET` bypass). | n/a (no native helper, PTY is host-side) | `SECCOMP_RET_USER_NOTIF` filter on write-intent fs syscalls; observer reports every attempt (allow or deny); store dedupes against `allowWrite`/`denyWrite` |
| Windows | NTFS ACLs stamped onto the **config-defined** paths at `initialize()`: `allowWrite` → `(OI)(CI) MODIFY_NO_FDC` ALLOW; `allowRead` → `(OI)(CI) READ|EXECUTE`; `denyRead`/`denyWrite` → explicit DENY on target + `(OI)(CI) FILE_DELETE_CHILD` DENY on parent. ACE cleanup at `reset()` (best-effort) or `srt-win acl recover` | `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` filter set at install: BLOCK by `ALE_USER_ID==<sandbox SID>`; PERMIT `(127.0.0.0/8 OR ::1) AND remote port ∈ [lo, hi]`. Proxies bind inside `[lo, hi]`. | Not enforced at OS level by srt; default-deny for outbound is enforced via the WFP BLOCK on the sandbox SID. | n/a | n/a in v1; reserved for the next milestone. |

## 2.4 Lifecycle (CLI)

```
              ┌────────┐
              │ argv   │
              └───┬────┘
                  │  commander parse
                  ▼
         ┌────────────────────┐
         │  load config       │  from $HOME/.srt-settings.json OR --settings OR default
         │  (zod-validate)    │
         └────────┬───────────┘
                  │
                  ▼
         ┌────────────────────┐
         │ SandboxManager.    │  starts: HTTP proxy, SOCKS proxy, mux front-end
         │  initialize(cfg)   │  optional: macOS log monitor, Linux SECCOMP_RET_USER_NOTIF monitor
         └────────┬───────────┘
                  │
                  ▼   (per command)
         ┌─────────────────────────┐
         │ wrapWithSandbox(argv)   │  emits a shell string the host can run;
         │  or wrapWithSandboxArgv │  on Windows returns argv[] + env for {shell: false}
         └────────┬────────────────┘
                  │
                  ▼
         ┌────────────────┐
         │ spawn(...)     │  stdio: inherit, signal forwarding, abort handling
         └────────┬───────┘
                  │
                  ▼  (child exits)
         ┌──────────────────────────────┐
         │ cleanupAfterCommand()        │  Linux only: rm bwrap empty mount points
         │                              │  decrement activeSandboxCount
         │ reset() on exit/SIGINT/SIGTERM│
         └──────────────────────────────┘
```

## 2.5 Cross-Cutting Concerns

| Concern            | Pattern                                                                                                                                                                                                                                  |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Idempotency        | Both `initialize` and `reset` are re-entrant; cleanup is reference-counted for bwrap mount points; ACE revoke at `reset()` is best-effort with warning logs only.                                                                       |
| Concurrency        | The orchestrator process is single-threaded for the manager state (config, proxy handles); the proxies themselves are async (Node net.Server / Bun). Cross-process safety is via WFP persistence and DPAPI machine scope on Windows.   |
| Error handling     | Failures during `initialize` throw synchronously (caller never sees a half-initialized sandbox). Failures during `wrapWithSandbox` propagate; the platform builder returns an error string the user sees at runtime.                |
| Configuration reload | Network rules are hot-swappable (`updateConfig`). Filesystem rules require `reset()` + `initialize()`. On Windows the user is warned at `updateConfig` time when the file-access set would change.                                |
| Logging            | `logForDebugging(msg, {level})` (debug/info/warn/error), gated on `SRT_DEBUG=1`. Logs are NEVER printed by default to keep stdout clean for embedding as a library.                                                                       |
| Tracing            | Sandbox profiles embed a unique `logTag` (`CMD64_<base64-encoded-command>_END_<random>_SBX`) so macOS log streams and the Linux observer JSON feed can be filtered by exact subprocess.                                                  |
