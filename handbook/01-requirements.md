# 01 — Requirements

## 1.1 Product Goals

The Sandbox Runtime (`srt`) is a research-preview tool whose purpose is to
**make arbitrary untrusted processes safer to run** by enforcing, at the
operating-system level, an explicit allow-list for filesystem and network
access. It is the smallest primitive that satisfies three properties:

| ID   | Goal                                                                                                                                                                                                                                |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| G-1  | **Filesystem isolation.** The child process may only read paths in the configured *deny-then-allow* read set and may only write paths in the configured *allow-then-deny* write set. |
| G-2  | **Network isolation.** By default, no outbound network traffic is permitted. Permitted traffic must match the configured allow-list and must not match the configured deny-list. |
| G-3  | **Cross-platform.** macOS, Linux, and Windows each get a native-enforced sandbox using the platform's *own* primitive — no Docker, no in-house kernel.                    |

Additional supporting goals:

| ID     | Goal                                                                                                                                                                                                            |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| G-4    | **Dual use.** Usable both as a CLI (`srt <command>`) and as a library (`SandboxManager.wrapWithSandbox` / `wrapWithSandboxArgv`).                                                                                  |
| G-5    | **Secure by default.** Empty allow-list ⇒ zero network access; empty write allow-list ⇒ no writes (except a small built-in set). Defaults require explicit opt-in to be useful.                                  |
| G-6    | **Transparent.** The sandboxed process sees the same OS view it would normally see, minus the restrictions. No LD_PRELOAD shim, no proxy auto-config magic for tools that ignore HTTP_PROXY.                      |
| G-7    | **Observable.** When a sandboxed process is denied, the violation can be surfaced to the host (subscriber callback + stderr tag). Used by `claude-code` to turn denials into permission prompts.                |
| G-8    | **Embeddable.** The orchestrator (`srt`) is a small Node ≥ 18 process that can be driven programmatically. Platform-native helpers (`apply-seccomp` for Linux, `srt-win` for Windows) are invoked as child binaries. |

## 1.2 Non-Goals

- **No complete container.** No image layering, no overlay fs, no cgroups/ulimits, no seccomp DSL, no Linux capability grant. srt uses bwrap *only* for `unshare-{net,pid,user}` and bind-mount surfaces.
- **No policy engine.** The library accepts a *configuration*, not a *policy*. Embedders (claude-code, MCP hosts) translate their policy into a configuration.
- **No multi-tenant scheduler.** One host process = one sandbox configuration = one set of proxies. Multiple concurrent hosts are not coordinated.
- **No file-recovery mode.** A sandboxed process that deletes files cannot undo it (the standard POSIX `unlink` semantics apply).
- **No TPM-attested boot.** Local trust assumed.

## 1.3 User Stories

1. *As an MCP host:* wrap `npx @modelcontextprotocol/server-filesystem` with `srt` as argv\[0] so the server may only read its working tree and write to a sandboxed dir.
2. *As a CLI user:* run `srt 'curl https://github.com'` with a config that allows `*.github.com`. Anything else is rejected.
3. *As an agent:* block reads of `~/.ssh` and writes to `.git/hooks` automatically. The "mandatory deny" set covers this without per-config effort.
4. *As an operator:* tighten the policy dynamically using a "control fd" — pipe JSON lines into fd 3 and the running CLI updates its rules live (network only, see §4.7).
5. *As a security reviewer:* trace what a sandboxed process attempted via the violation store, mapped to the tool that called it.

## 1.4 Success Criteria

| ID     | Criterion                                                                                                                                                                                                          | How it is verified                                       |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| S-1    | On macOS, `sandbox-exec -f <profile> <command>` blocks reads outside `allowRead` and writes outside `allowWrite` at the kernel layer (returns `EPERM`).                                                            | `test/sandbox/macos-seatbelt.test.ts`                    |
| S-2    | On Linux, `bwrap …` followed by `apply-seccomp …` blocks `socket(AF_UNIX, …)` with `EPERM`. The child process cannot see or ptrace anything outside its PID namespace.                                               | `test/sandbox/linux-violation-monitor.test.ts`           |
| S-3    | On Windows, an outbound TCP connect from the sandboxed process to anything except `127.0.0.1:[60080..60089]` is dropped by the WFP filter set before the kernel resolves the destination.                          | `verifyWindowsWfpEgress()` (run at `initialize()`)       |
| S-4    | The host proxy terminates HTTPS when `tlsTerminate` is configured; `network.filterRequest` can deny individual requests, with the upstream receiving a verified cert.                                                 | `test/sandbox/tls-terminate-proxy.test.ts`               |
| S-5    | `network.updateConfig` can permit a new domain for an already-running child without re-binding proxies.                                                                                                              | `test/sandbox/update-config.test.ts`                     |
| S-6    | `credentials.envVars[].mode == 'mask'` substitutes a sentinel for the real value in the env, then the proxy substitutes the real value into outbound HTTPS request headers when `tlsTerminate` is in scope.            | `test/sandbox/credential-mask.test.ts`                   |

## 1.5 Quality Goals (Non-Functional)

| NFR    | Target                                                                                                                              |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| NFR-1  | Sandbox bring-up ≤ 200ms P50 on macOS, ≤ 400ms on Linux (excluding the `srt-win install` step which is one-shot).                    |
| NFR-2  | Per-request overhead in the proxy ≤ 1ms P50. The proxies are on the loopback hot path; the user pays this on every socket.          |
| NFR-3  | Cleanup is **fail-safe**: even on `SIGKILL`, no host artifacts remain (verified for the Linux bwrap mount-point cleanup hook).        |
| NFR-4  | No silent fallback to insecure defaults. A missing dep or stale install must return a hard error.                                    |

## 1.6 Constraints

- License: **Apache-2.0** (see `LICENSE`). The C and Rust helpers are under the same license.
- Node engine: **>=20.11.0** (`engines.node` in `package.json`). CI uses Node 20 LTS.
- Rust toolchain (`srt-win`): edition 2021, MSRV pinned in `vendor/srt-win-src/Cargo.toml`.
- The library **never** depends on `npm install` at user runtime — all native artifacts (`apply-seccomp`, `srt-win.exe`) are pre-built and shipped in the package.

## 1.7 Definition of Done (per milestone)

| Milestone                                | Acceptance                                                                                                                                  |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Configuration schema + validation        | `SandboxRuntimeConfigSchema` accepts and rejects all fields per `sandbox-config.ts`; super-refinement catches injectHosts/excludeDomains conflicts. |
| macOS sandbox                            | `srt 'cat /etc/hosts'` against `denyRead: ['/etc']` returns `Operation not permitted`.                                                     |
| Linux sandbox                            | `srt --enable-seccomp curl example.com` works against allow-listed domain; `socket(AF_UNIX)` from inside returns `EPERM`.                    |
| Windows sandbox                          | Behavioural connect probe in `verifyWindowsWfpEgress()` returns success only when the filter set is present and matches the sandbox SID.   |
| Network proxy enforcement                | `deniedDomains` is checked *first*; `allowedDomains` is checked second; non-matching closes the connection with a 403 (HTTP) / no reply (SOCKS). |
| Per-request filter                       | `filterRequest` returning `{action:'deny'}` yields a 403 with `X-Proxy-Error: blocked-by-sandbox-runtime`.                                  |
| TLS termination + credential injection   | The sentinel appears *only* in headers destined for an `injectHosts` host, and only when that host's TLS was terminated in-process.       |
