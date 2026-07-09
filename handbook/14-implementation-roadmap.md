# 14 — Implementation Roadmap

A pragmatic order for re-implementing this project in another language. Each
milestone is self-contained and testable.

## 14.1 Suggested Stack

| Concern            | Go                                    | Rust                                   | Python                              |
| ------------------ | ------------------------------------- | -------------------------------------- | ----------------------------------- |
| CLI                | `cobra` + `urfave/cli`                | `clap`                                 | `click` or `typer`                  |
| Config validation  | hand-rolled + validator codegen       | `validator` derive + custom            | `pydantic` v2                       |
| HTTP server        | `net/http` + `httputil.ReverseProxy`  | `axum` + `tokio`                       | `aiohttp`                           |
| TLS termination    | `crypto/tls` + custom                 | `rustls` / `native-tls`                | `ssl` + custom                      |
| macOS sandbox      | CGo + `sandbox-exec`                  | Objective-C rs + `sandbox-exec`        | PyObjC + `sandbox-exec`             |
| Linux bwrap        | `os/exec`                             | `std::process::Command`                | `subprocess`                        |
| Linux seccomp      | CGo + libseccomp                      | `libseccomp-rs` / raw syscall          | CFFI + libseccomp / ctypes          |
| Windows WFP/ACL    | Win32 API via `golang.org/x/sys/windows` | `windows` crate                      | pywin32 / `ctypes`                  |
| Build              | `mage` or plain `Makefile`            | `cargo`                                | `hatch`                             |
| Tests              | `testing` + stretchr/testify          | `cargo test`                           | `pytest`                            |

This document assumes the re-implementer picks any of these and adapts
accordingly. The structure of the modules is language-agnostic.

## 14.2 Milestones

### M0 — Project Skeleton (1 week)

Deliverable: a binary that loads a JSON config and prints its parsed form.

Tasks:
1. Module layout (matching `02-system-architecture.md` §2.2).
2. CLI scaffold: `srt` command + version + help.
3. JSON-schema loader for `SandboxRuntimeConfig`-equivalent.
4. Lint + format + test runner wired.
5. README with usage examples.

Acceptance: `srt --help` works. `srt --version` returns the package version. Loading a valid JSON prints a parsed object; loading an invalid JSON errors with a structured message.

### M1 — Configuration Schema (1-2 weeks)

Deliverable: full configuration validation per `03-configuration-model.md`.

Tasks:
1. Re-implement `SandboxRuntimeConfig` schema and validator.
2. Domain-pattern validation:
    - Reject `*.com`, `*`, `*.foo.*`, etc.
    - Accept `example.com`, `*.foo.example.com`, `localhost`.
3. Path validation:
    - Reject empty strings.
    - Allow `~`, absolute, relative paths.
4. Cross-field validation:
    - `tlsTerminate.caCertPath ⇔ caKeyPath`.
    - Masked credentials require `tlsTerminate` or `allowPlaintextInject`.
    - `injectHosts ⊆ allowedDomains` semantically.
5. Test coverage ≥ 95% of validation rules.

Acceptance: every test in `config-validation.test.ts` passes when ported.

### M2 — Host-Side Network Proxy (3-4 weeks)

Deliverable: HTTP and SOCKS5 forward proxies with domain filter + auth.

Tasks:
1. Bind a TCP server (mux front-end optional, defer to M6).
2. Implement `parseConnectTarget("example.com:443")`.
3. Auth handshake (Basic for HTTP, USER/PASS for SOCKS5).
4. Filter pipeline:
    - `deniedDomains` check.
    - `allowedDomains` check.
    - Optional callback.
    - `canonicalizeHost` + `isValidHost`.
5. CONNECT handling:
    - Dial direct (TCP connect + 200 back).
    - Or, if `parentProxy` configured, tunnel through CONNECT.
6. Plain HTTP handling:
    - Detect absolute URI form.
    - Forward upstream.
    - Strip hop-by-hop headers.
7. SOCKS5:
    - Read greeting + select auth method.
    - Read request with IPv4/IPv6/domainname ATYP.
    - Dial direct or via parent.
8. Test: all unit tests in `mux-proxy`, `parent-proxy`, `request-filter`, `tls-terminate-proxy` (deferred parts OK).

Acceptance: `host:port` returns 403 for a denied domain; 200 for an allowed one. Auth fails with 407 on bad token.

### M3 — Sandbox Manager Lifecycle (1 week)

Deliverable: a singleton state machine that owns the proxies and exposes `initialize` / `reset` / `wrapWithSandbox` (returning a string for now).

Tasks:
1. Module-level state (`config`, proxy handles, auth token, mitm CA).
2. `initialize` is idempotent.
3. `reset` is best-effort cleanup.
4. `checkDependencies` per-platform scaffold.
5. Update + clone config; hot-reload applies network rules only.
6. Singleton exported via `SandboxManager.<method>` interface.

Acceptance: programmatic lifecycle works in unit tests.

### M4 — macOS Sandbox (2-3 weeks)

Deliverable: `wrapCommandWithSandbox` emits a valid `sandbox-exec` profile that enforces the configured rules.

Tasks:
1. Generate SBPL from read/write configs.
2. Handle glob patterns via regex conversion.
3. Read rules emit deny-then-allow; allow re-emit logic for deny-nested-in-allow.
4. Write rules emit allow-then-deny.
5. Move-blocking rules for every protected path + ancestors.
6. Mandatory deny patterns (rc files, git hooks, etc.).
7. Network rules (bind/inbound to localhost:proxy ports).
8. PTY passthrough.
9. `env -u/ENV=val` syntax with proper shell quoting.
10. Tests: `macos-seatbelt.test.ts`, `macos-pty.test.ts`, `macos-allow-local-binding.test.ts`.

Acceptance: a macOS smoke test (`srt 'cat /etc/hosts'` against `denyRead:['/etc']`) returns EPERM.

### M5 — Linux Sandbox (4-5 weeks)

Deliverable: `bwrap` argv synthesizer + `apply-seccomp` equivalent.

Tasks:
1. Mandatory deny resolution via ripgrep.
2. Symlink-boundary check on writes.
3. Bind-mount loop:
    - `--ro-bind / /` then `--bind` overrides.
    - `--tmpfs` for denied dirs; re-bind writes after deny tmpfs.
    - `--ro-bind /dev/null` for non-existent deny paths (with cleanup).
4. Network bridge (socat on host + bind into sandbox).
5. `apply-seccomp.c` port (or replace with a Rust implementation).
6. BPF filter:
    - Block `socket(AF_UNIX)`.
    - Block io_uring syscalls.
    - Allow `setuid/setgid` etc.
7. Env wiring (proxy vars, trust bundle vars, masked env vars, unset env vars).
8. `cleanupBwrapMountPoints` with ref-counting.
9. Tests: `linux-violation-monitor.test.ts`, `mandatory-deny-paths.test.ts`, `integration.test.ts`, `seccomp-filter.test.ts`, `symlink-boundary.test.ts`, `symlink-write-path.test.ts`, `pid-namespace-isolation.test.ts`.

Acceptance: a Linux smoke test (`srt 'cat /etc/passwd'` against `denyRead:['/etc']`) returns EPERM. seccomp blocks `socket(AF_UNIX)`.

### M6 — Mux Front-End (1 week)

Deliverable: single port serving both HTTP and SOCKS5.

Tasks:
1. Byte sniff on first packet (SOCKS greeting starts with `0x05`).
2. Dispatch to handlers.
3. Skip the mux when both external `httpProxyPort` and `socksProxyPort` are set.
4. On Windows, bind inside a configured port range.
5. Tests: `mux-proxy.test.ts`, `mux-proxy-e2e.test.ts`.

Acceptance: `srt 'curl -x http://127.0.0.1:<port> example.com'` and a SOCKS5 client both succeed against the same port.

### M7 — TLS Termination (3-4 weeks)

Deliverable: optional in-process TLS termination with synthetic leaf minting.

Tasks:
1. CA loader/generator.
2. Trust bundle composition (CA + host roots + extras).
3. Leaf minting with SKI/AKI matched.
4. SecureContext caching per hostname.
5. CONNECT path upgrade.
6. CRL generation.
7. Trust env vars in sandbox.
8. `filterRequest` invoked on terminated requests.
9. Mutate headers (sentinel injection).
10. Tests: `tls-terminate-proxy.test.ts`, `tls-terminate-trust-env.test.ts`, `mitm-ca.test.ts`, `mitm-leaf.test.ts`.

Acceptance: `curl --cacert ca.pem` against the proxy succeeds; the upstream sees the substituted sentinel for `Authorization` on the allow-listed host.

### M8 — Credential Masking (1-2 weeks)

Deliverable: `credentials` block honored end-to-end.

Tasks:
1. Sentinel registry (per-process map).
2. `register(name, real, injectHosts)` returns a sentinel.
3. `substituteInHeaders` (for the proxy path).
4. Mode=deny: env unset, file unreadable.
5. Mode=mask: env=sentinel; bind fake file over real; per-sentinel injectHosts gating.
6. Structured extraction (regex with capture group 1).
7. Validation cross-field (covered in M1).
8. Tests: `credential-deny.test.ts`, `credential-mask.test.ts`, `credential-mask-files.test.ts`.

Acceptance: a sandboxed process with `ANTHROPIC_API_KEY=<sentinel>` cannot extract the real value, but the proxy substitutes it on outbound requests to `*.anthropic.com`.

### M9 — Windows Path (4-6 weeks)

Deliverable: Windows sandbox with WFP + ACE isolation.

Tasks:
1. `windows-install`/`windows-uninstall` self-elevating entry points.
2. `srt-win` (or equivalent) helper:
    - WFP filter set install/uninstall/verify.
    - Sandbox user provisioning.
    - DPAPI-encrypted credential.
    - ACL stamp/revoke/restore/recover.
    - Two-hop launch with restricted token + job.
3. Win32 calls in your language of choice:
    - `CreateProcessWithLogonW`, `LogonUser`.
    - `FwpmFilterAdd0`, `FwpmSubLayerAdd0`.
    - `SetSecurityInfo`, `GetSecurityInfo`.
    - `CryptProtectData`, `CryptUnprotectData`.
4. `wrapWithSandboxArgv` (no shell string on Windows).
5. CRL distribution point (Windows-only).
6. CA install in sandbox user's `CurrentUser\Root` store.
7. Tests: `winsrt.test.ts`, `winsrt-paths.property.test.ts`, plus CI smoke.

Acceptance: an outbound TCP from the sandbox user to anything outside `127.0.0.1:[60080,60089]` is blocked. Read of a directory outside `allowRead` is denied.

### M10 — Sandbox Violation Monitoring (1-2 weeks)

Deliverable: violation store populated by mac and Linux.

Tasks:
1. `SandboxViolationStore` (in-process map).
2. macOS log subscription (or shelling out to `log stream`).
3. Linux SECCOMP_RET_USER_NOTIF listener.
4. Path resolution at the supervisor (relative paths via `/proc/<pid>/cwd`).
5. `encodedCommand` propagation.
6. `ignoreViolations` filter.
7. Tests: `linux-violation-monitor.test.ts`.

Acceptance: a denied operation emits a violation record into the store.

### M11 — Control FD + CLI Polish (1 week)

Deliverable: full CLI surface area.

Tasks:
1. `srt` default subcommand.
2. `--settings` (CLI flag with hard error on missing).
3. `-c` raw command string.
4. `--control-fd` live update.
5. `-d, --debug` for `SRT_DEBUG`.
6. Signal forwarding (SIGINT → child).
7. Cleanup on exit/SIGINT/SIGTERM.
8. Version string in `--version`.
9. Tests: `cli.test.ts`, `cli-config-loading.test.ts`, `control-fd.test.ts`.

Acceptance: the CLI passes every test in `cli.test.ts` and `cli-config-loading.test.ts` when ported.

## 14.3 Reusable Testing Invariants

The full test suite (≈500 tests) is the specification. Each milestone
above maps onto a set of ports:

| Milestone | Tests (when ported)                                                              |
| --------- | -------------------------------------------------------------------------------- |
| M0        | `platform.test.ts`, `shell-quote.test.ts`, `which.test.ts`                      |
| M1        | `config-validation.test.ts`                                                     |
| M2        | `parent-proxy.test.ts`, `request-filter.test.ts`, `mux-proxy.test.ts` (later)    |
| M3        | `domain-pattern.test.ts`, `ripgrep.test.ts`, `update-config.test.ts`            |
| M4        | `macos-*` integration suite                                                     |
| M5        | `linux-*` integration suite + `seccomp-filter.test.ts` + `pid-namespace-isolation.test.ts` |
| M7        | `tls-terminate-*`, `mitm-*`                                                     |
| M8        | `credential-*`                                                                  |
| M9        | `winsrt*.test.ts`                                                                |
| M10       | `linux-violation-monitor.test.ts`                                               |

## 14.4 Risks and Pivots

| Risk                                                                | Mitigation                                                                  |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| libseccomp unavailable on a target Linux distro                     | Bundle the static `apply-seccomp` binary like srt does.                    |
| macOS API drift (`os.unstable.log` not stable)                      | Shelling out to `/usr/bin/log stream` is a perfectly good fallback.        |
| Bubblewrap unavailable in a Docker environment                     | `enableWeakerNestedSandbox: true` opens a degraded path that uses less aggressive unsharing. Document it. |
| Windows install requires admin                                       | It does. Embedders can prompt the user once and ship.                       |
| Users with no CA rotation discipline                                | The CRL + thumbprint check at `initialize()` guards against stale installs. |
| New CVE in bubblewrap or sandbox-exec                               | Update dependency; reproduce tests; ship a patch.                          |

## 14.5 Reference Layout for a Re-Implementation

```
<project>/
├── cmd/srt/main.go             (or equivalent)
├── internal/
│   ├── cli/                    CLI parsing + signal forwarding
│   ├── config/                 Schema + validation
│   ├── manager/                SandboxManager state machine
│   ├── proxy/
│   │   ├── http.go
│   │   ├── socks.go
│   │   ├── mux.go
│   │   ├── parent.go
│   │   ├── filter.go
│   │   ├── mitm_ca.go
│   │   ├── mitm_leaf.go
│   │   └── terminate.go
│   ├── sandbox/
│   │   ├── macos/profile.go
│   │   ├── linux/bwrap.go
│   │   ├── linux/seccomp/      Rust crate or C shim
│   │   └── windows/
│   │       ├── wfp.go
│   │       ├── acl.go
│   │       ├── launch.go
│   │       └── trust.go
│   └── credentials/
├── shims/                      (compiled binaries, similar to vendor/ here)
├── testdata/                   TLS certs
├── tests/                      ports of the test files
├── README.md                   (uses the same examples as upstream)
├── LICENSE                     (Apache-2.0)
└── Cargo.toml / go.mod / pyproject.toml
```
