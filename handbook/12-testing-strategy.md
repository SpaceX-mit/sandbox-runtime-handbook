# 12 — Testing Strategy

The project ships a comprehensive test suite that walks all three platforms
plus the JS-side abstractions. Tests run under **Bun** (`bun test`), not the
default `npm test`. The repo exposes this through the `test` script in
`package.json`.

## 12.1 Test Layout

```
test/
├── cli-config-loading.test.ts        14 unit tests
├── cli.test.ts                        25 unit tests
├── config-validation.test.ts         ~290 unit tests (zod schema)
├── configurable-proxy-ports.test.ts   30 unit tests (mux and per-port overrides)
├── control-fd.test.ts                 8 unit tests (live config update)
├── docker-weak-sandbox.test.ts         5 unit tests
├── fixtures/
│   └── tls-terminate/                5 self-signed certificates
│       ├── ca.{cert,key}.pem
│       ├── leaf.example.com.{cert,key}.pem
│       ├── leaf.npmjs.org.{cert,key}.pem
│       └── leaf.test.local.{cert,key}.pem
├── helpers/
│   ├── platform.ts                   isLinux/isMacOS/isWindows
│   └── spawn.ts                      spawnAsync utilities
├── sandbox/                           ← integration tests, run per-platform
│   ├── allow-read.test.ts
│   ├── check-dependencies.test.ts
│   ├── connect-non-tls.test.ts
│   ├── credential-deny.test.ts
│   ├── credential-mask-files.test.ts
│   ├── credential-mask.test.ts
│   ├── domain-pattern.test.ts
│   ├── filesystem-disabled.test.ts
│   ├── glob-expand.test.ts
│   ├── integration.test.ts
│   ├── linux-bridge-spawn-error.test.ts
│   ├── linux-dependency-error.test.ts
│   ├── linux-violation-monitor.test.ts
│   ├── macos-allow-local-binding.test.ts
│   ├── macos-apple-events.test.ts
│   ├── macos-pty.test.ts
│   ├── macos-seatbelt.test.ts
│   ├── mandatory-deny-paths.test.ts
│   ├── mitm-ca.test.ts
│   ├── mitm-leaf.test.ts
│   ├── mux-proxy-e2e.test.ts
│   ├── mux-proxy.test.ts
│   ├── parent-proxy-tunnel.test.ts
│   ├── parent-proxy.test.ts
│   ├── pid-namespace-isolation.test.ts
│   ├── proxy-env-vars.test.ts
│   ├── request-filter.test.ts
│   ├── sandbox-env-tmpdir.test.ts
│   ├── seccomp-filter.test.ts
│   ├── symlink-boundary.test.ts
│   ├── symlink-write-path.test.ts
│   ├── tls-terminate-proxy.test.ts
│   ├── tls-terminate-trust-env.test.ts
│   ├── update-config.test.ts
│   ├── winsrt-paths.property.test.ts  (Windows-only, fast-check property tests)
│   ├── winsrt.test.ts                 (Windows-only, runs srt-win CLI)
│   └── wrap-with-sandbox.test.ts
└── utils/
    ├── platform.test.ts
    ├── ripgrep.test.ts
    ├── shell-quote.test.ts
    ├── which-node-test.mjs
    └── which.test.ts
```

Total: ~500 tests across unit, integration, and property-based (fast-check).

## 12.2 Test Categories

### Unit Tests (no OS primitive invoked)

`config-validation.test.ts` is the single largest: it covers every Zod refinement in `sandbox-config.ts` — domain patterns, glob patterns, mandatory-deny search depth bounds, Windows-only settings, superRefinement rules (injectHosts coverage, tlsTerminate/mitmProxy XOR, mask without tlsTerminate). Pure data, fast.

Other unit tests:
- `domain-pattern.test.ts` — hostname matching, wildcard semantics, IP-literal refusal.
- `shell-quote.test.ts` — POSIX quoting edge cases.
- `which.test.ts` — PATH lookup semantics.
- `platform.test.ts` — `getWslVersion` parsing.
- `ripgrep.test.ts` — rg subprocess driver.

### Component Tests

`http-proxy.test.ts` equivalent tests (`mux-proxy.test.ts`, `request-filter.test.ts`, `tls-terminate-proxy.test.ts`, `parent-proxy.test.ts`):
- Spin up the JS server in-process (`createServer()` with `127.0.0.1:0`).
- Issue HTTP / SOCKS requests with `node:http` / `node:net`.
- Assert response codes, body bytes, header mutations.
- Snapshot timing/sequencing with `bun:test`.

### Integration Tests (per-platform)

Each platform has dedicated integration tests that actually invoke the
OS primitive. They run only on that platform; on other OSes `it.skip(...)`.

#### macOS

```
macos-seatbelt.test.ts          ← real sandbox-exec; cat /etc/hosts blocked under denyRead
macos-allow-local-binding.test.ts ← real network-bind tests
macos-pty.test.ts               ← real PTY allocation
macos-apple-events.test.ts      ← (allow appleevent-send) works for osascript/open
```

#### Linux

```
integration.test.ts             ← spawns curl/python inside bwrap; checks egress through proxies
linux-bridge-spawn-error.test.ts← bad socat path → graceful failure
linux-dependency-error.test.ts  ← missing bwrap/socat → actionable error
linux-violation-monitor.test.ts ← SECCOMP_RET_USER_NOTIF → JSON feed → store
seccomp-filter.test.ts          ← direct binary invocation, verify BPF behavior
pid-namespace-isolation.test.ts ← /proc/<pid>/mem ptrace impossible from inside worker
symlink-boundary.test.ts        ← allow-write through symlinks is rejected
symlink-write-path.test.ts      ← same as above for reads
mandatory-deny-paths.test.ts    ← ripgrep finds + denies
```

#### Windows

```
winsrt.test.ts                  ← runs `srt-win` subprocess for install/uninstall/exec/acl/wfp
winsrt-paths.property.test.ts   ← fast-check generates random path sets, runs `srt-win acl stamp`
```

#### Cross-Platform Abstraction Tests

```
mitm-ca.test.ts                ← CA generation, bundle composition, CRL
mitm-leaf.test.ts               ← leaf minting, AKI matching
credential-deny.test.ts        ← mode='deny' for files and env (degrades on mac)
credential-mask.test.ts        ← mode='mask' on Linux: bind fake over real
credential-mask-files.test.ts  ← whole-file and structured extraction
proxy-env-vars.test.ts         ← HTTP_PROXY/HTTPS_PROXY/NO_PROXY bake-in
sandbox-env-tmpdir.test.ts     ← /tmp inside sandbox is fresh tmpfs
filesystem-disabled.test.ts    ← disabled:true bypasses all fs rules
allow-read.test.ts             ← allowRead within denyRead works
update-config.test.ts          ← hot-reload semantics
mux-proxy-e2e.test.ts          ← both protocols through one port
connect-non-tls.test.ts        ← CONNECT over plain stream (SSH) still allowlisted
```

### Property Tests (fast-check)

`winsrt-paths.property.test.ts` generates random path sets and ensures the
`expandWindowsFsPaths` function is total — no set of paths crashes the
expansion.

## 12.3 Test Execution

```bash
# Run all tests
bun test

# Run only the platform-relevant subset
bun test --testPathPattern=sandbox
bun test test/sandbox/seccomp-filter.test.ts   # Linux only
```

CI (`.github/workflows/integration-tests.yml`) matrix:

| OS       | Arch       | Runner                    |
| -------- | ---------- | ------------------------- |
| Linux    | x86_64     | ubuntu-latest             |
| Linux    | arm64      | ubuntu-24.04-arm          |
| macOS    | x86_64     | macos-15-large            |
| macOS    | arm64      | macos-14                  |
| Windows  | x86_64     | windows-latest            |
| Windows  | arm64      | windows-11-arm            |

All six run on every PR and on every push to `main`. The `release.yml`
workflow additionally builds and publishes the npm package.

## 12.4 Fixtures

`test/fixtures/tls-terminate/` contains:
- `ca.cert.pem`, `ca.key.pem` — self-signed MITM CA.
- `leaf.example.com.{cert,key}.pem` — leaf CN=`example.com`.
- `leaf.npmjs.org.{cert,key}.pem` — leaf CN=`npmjs.org`.
- `leaf.test.local.{cert,key}.pem` — leaf CN=`test.local`.

These are used by `tls-terminate-proxy.test.ts` to verify the proxy terminates TLS, exchanges a verifiable leaf, and the upstream cert-validates correctly.

## 12.5 Mocking Strategy

The project **does not mock** the OS primitive. Tests run real commands
in real sandboxes:

- `bwrap …` invokes bubblewrap for real.
- `sandbox-exec -p ...` invokes Apple's binary for real.
- `srt-win install` invokes the bundled Rust helper.

This is the discipline. The only mocking is at the network level — tests
that need a particular TCP service point at `127.0.0.1:<port>` start a
small Node `http.Server` or `net.Server` in the same test process.

## 12.6 Slow Tests

A few tests take 5-10 seconds:
- `linux-violation-monitor.test.ts` — spawns `apply-seccomp` and waits for `pidfd` to close.
- `pid-namespace-isolation.test.ts` — exercises the full `apply-seccomp` lifecycle.
- `integration.test.ts` — multiple `child_process.spawn` per test case.

The CI timeout per job is 30 minutes; per-test, the default is 5 seconds, but slow ones override:

```ts
it('does X', async () => {
  // ...
}, /* timeout */ 30_000)
```

The bridge-process exit timeout in `sandbox-manager.ts` is 1500 ms — sized to win the race against the test runner's 5s hook timeout.

## 12.7 Test Helpers

```ts
// test/helpers/platform.ts
export function isLinux(): boolean { return process.platform === 'linux' }
export function isMacOS(): boolean { return process.platform === 'darwin' }
export function isWindows(): boolean { return process.platform === 'win32' }

// test/helpers/spawn.ts
export async function spawnAsync(
  cmd: string,
  args: string[],
  opts: { timeoutMs?: number; env?: NodeJS.ProcessEnv } = {}
): Promise<{ stdout: string; stderr: string; code: number }>
```

`spawnAsync` is a thin wrapper around `child_process.spawn` with a 5-second
default timeout and full stdout/stderr capture. Used everywhere.

## 12.8 Test Configuration Patterns

```ts
function createTestConfig(testDir: string): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: ['example.com'],
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowRead: [],
      allowWrite: [testDir],
      denyWrite: [],
    },
  }
}
```

This minimum viable config lets tests focus on one behavior at a time.

## 12.9 Test-Based Bugs Caught (Notable)

These are some bug classes the test suite defends against:

1. **Profile-ordering bugs in macOS** (`macos-seatbelt.test.ts`).
   - `(subpath "/")` denies root and breaks path resolution → re-allow `(literal "/")`.
   - Read deny inside read allow → re-emit deny.
2. **BPF filter drift** (`apply-seccomp.c` + `seccomp-filter.test.ts`).
   - Wrong arch check → wrong syscall IDs.
   - x32 ABI byte range missing.
3. **Symlink boundary** (`symlink-boundary.test.ts`).
   - `realpathSync` not called → allowed write follows symlink to /etc.
4. **NUL byte in hostname** (`matchesDomainPattern` + `isValidHost`).
   - `evil.com\x00.allowed.com` slips past endsWith.
5. **IPv6 in canonicalize** (`parent-proxy.test.ts`).
   - `127.1` should match `127.0.0.1`.
   - Trailing-dot FQDNs stripped.
6. **io_uring bypass** (Linux 5.19+ IORING_OP_SOCKET).
   - bp filter must also block the `io_uring_setup/enter/register` syscalls.
7. **Token math** (`sandbox-env-tmpdir.test.ts`).
   - Inside bwrap, `$TMPDIR` must be the bwrap tmpfs, not the host's.

## 12.10 Test Conventions

- Use `describe` blocks grouped by feature, not by file.
- Use `it.skip(...)` to skip platform-specific tests on the wrong OS.
- Use `beforeEach` to create fresh temp directories under `/tmp/srt-test-<rand>/`.
- Use `afterEach` to clean them up; not relying on `process.exit()` to GC them.
- All tests are flat — no nested `describe`s except for grouping by feature.
- Tests run in **parallel** — Bun forks by default; integration tests use distinct port ranges to avoid collisions.

## 12.11 Coverage

The project does not run a coverage tool in CI. Coverage is conceptual; the
suite is structured to exercise every code path:

- Schema refinements → exhaustive table-driven config-validation.
- Platform wrappers → at least one test per behavioral dimension.
- Proxy pipeline → both control plane (auth, filter) and data plane (CONNECT, MITM, mutate headers).
- Native shims → unit + integration.

Any non-trivial code change is expected to come with a test that exercises it.
