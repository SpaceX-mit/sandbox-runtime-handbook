# Anthropic Sandbox Runtime (srt) — Re-Implementation Handbook

This handbook analyses `anthropic-experimental/sandbox-runtime` end-to-end and
provides a complete blueprint for re-implementing it in any language. Every
document states the *what* (functional contract), the *why* (security/UX
rationale), and the *how* (interfaces, algorithms, data shapes).

## Reading Order

| #  | Document                                    | What it covers                                                         |
| -- | ------------------------------------------- | ---------------------------------------------------------------------- |
| 01 | requirements.md                             | Product goals, non-goals, user stories, success criteria               |
| 02 | system-architecture.md                      | Process topology, module decomposition, OS-isolation boundary choices |
| 03 | configuration-model.md                      | JSON schema, semantics (allow/deny precedence), validation            |
| 04 | network-isolation-design.md                 | HTTP + SOCKS proxy, mux-front-end, TLS termination, parent proxy       |
| 05 | filesystem-isolation-macos.md               | Seatbelt (sandbox-exec) profile generation                             |
| 06 | filesystem-isolation-linux.md               | bubblewrap (bwrap) + seccomp BPF + mandatory deny paths                |
| 07 | filesystem-isolation-windows.md             | NTFS ACEs + WFP egress fence + srt-win helper                          |
| 08 | credential-masking.md                       | Sentinel-based masking for files and env-vars                          |
| 09 | cli-and-programmatic-api.md                 | Command surface, library surface, dynamic configuration               |
| 10 | platform-shim-and-build.md                  | Native helpers (apply-seccomp C, srt-win Rust), packaging              |
| 11 | violation-monitoring.md                     | macOS system log monitor, Linux SECCOMP_RET_USER_NOTIF monitor         |
| 12 | testing-strategy.md                         | Unit, integration, property, and platform-specific tests               |
| 13 | security-model.md                           | Threat model, security invariants, known limitations                   |
| 14 | implementation-roadmap.md                   | Phased plan for re-implementation                                      |
| 15 | glossary.md                                 | Terminology (SBPL, ACE, BPF, CRL, etc.)                                |

## Companion Files

These files in the repo back up the handbook:

- `src/index.ts` — public library exports
- `src/cli.ts` — CLI entry point (commander-based)
- `src/sandbox/sandbox-manager.ts` — central orchestrator (≈2,000 lines)
- `src/sandbox/sandbox-config.ts` — Zod-based schema for the runtime config
- `src/sandbox/{http,socks,mux,mux}-proxy.ts` — forward proxy servers
- `src/sandbox/{macos,linux,windows}-sandbox-utils.ts` — per-OS wrappers
- `src/sandbox/{mitm-ca,mitm-leaf,tls-terminate-proxy,parent-proxy}.ts` — TLS termination / upstream proxy plumbing
- `src/sandbox/credential-{sentinel,mask-files}.ts` — sentinel masking
- `src/sandbox/{sandbox-violation-store,linux-violation-monitor,sandbox-utils}.ts` — observability
- `vendor/seccomp-src/apply-seccomp.c` — ~600 LOC C helper that installs the BPF filter and forks the workload inside a nested PID namespace
- `vendor/srt-win-src/` — Rust helper (~20 kLOC) implementing WFP filters, ACL manipulation, sandbox-user provisioning, and the two-hop launch

## What This Project Does (One-Line)

It wraps a child process in a **kernel-enforced** sandbox: read/write paths and
network reachability are constrained per OS primitive (Seatbelt / bubblewrap +
seccomp / WFP + NTFS ACEs), and the sandboxed process is **force-routed**
through local HTTP+SOCKS5 forward proxies that enforce a domain allow/deny list
plus an optional per-request filter callback.

## What This Project Does NOT Do (Non-Goals)

- It is **not** a fully-fledged container runtime (no image management, no
  filesystem layering, no resource cgroups, no seccomp policy DSL).
- It does **not** attempt to be policy-aware about specific tools. Each
  embedder (`claude-code`, MCP servers, …) owns its own higher-level policy;
  srt is the OS-level enforcement primitive they all sit on.
- It does **not** provide a multi-tenant orchestrator. Each process gets its
  own sandbox; the manager is single-process and single-tenant.
- It does **not** ship its own seccomp policy language. `network.filterRequest`
  is the only escape hatch for per-request HTTP inspection, and library
  consumers own that policy.
