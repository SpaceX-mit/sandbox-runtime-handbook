# 03 — Configuration Model

## 3.1 Where the Config Lives

| Source                                              | Used by                  | Notes                                                                                                                                |
| --------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| `~/.srt-settings.json`                              | `srt` CLI                | Default file. Missing → default config (full network block, full read, no writes except a small built-in set).                       |
| `--settings /path/to/settings.json`                 | `srt` CLI                | Missing file with explicit `--settings` is a **hard error** (silent fallback would run unhardened).                                  |
| The program's process environment (HTTP_PROXY etc.) | sandbox-manager         | `parentProxy` is resolved from `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` env vars when the config omits them.                           |
| The `--control-fd <fd>` file descriptor              | sandbox-manager         | A second input channel delivering newline-delimited JSON config updates while the CLI is alive (network hot-reload).                  |
| Library call                                       | embedding                | `SandboxManager.initialize(cfg, askCb, enableLogMonitor)`. Re-call allowed; second call returns the cached promise of the first.    |

## 3.2 Schema (TS-Zod Style)

The configuration is a single object validated by a Zod schema in
`sandbox/sandbox-config.ts`. The schema is the canonical machine-readable
contract; everything in this document is a re-expression of it.

```text
SandboxRuntimeConfig
├── network: NetworkConfig
│     ├── allowedDomains: DomainPattern[]                    required, may be [] (=> block all)
│     ├── deniedDomains : (DomainPattern | "*")[]           required, may be []
│     ├── strictAllowlist?: boolean
│     ├── allowUnixSockets?: string[]                       macOS path allowlist; ignored on Linux
│     ├── allowAllUnixSockets?: boolean
│     ├── allowLocalBinding?: boolean                       default false
│     ├── allowMachLookup?: string[]                        trailing-`*` wildcard prefix allowed
│     ├── httpProxyPort?  : 1..65535                        external proxy override
│     ├── socksProxyPort? : 1..65535
│     ├── mitmProxy?: { socketPath, domains: DomainPattern[] }
│     ├── filterRequest?: (req: Request) => {action,reason?}
│     ├── tlsTerminate?: {
│     │       caCertPath? / caKeyPath?
│     │       excludeDomains?: DomainPattern[]
│     │       extraCaCertPaths?: string[]                    }   # caCertPath ↔ caKeyPath must be set together
│     └── parentProxy?: { http?, https?, noProxy? }
├── filesystem: FilesystemConfig
│     ├── disabled?: boolean                                 (escape hatch; default false)
│     ├── denyRead   : path[]   required
│     ├── allowRead  : path[]   optional (carved out *within* denyRead; takes precedence)
│     ├── allowWrite : path[]   required
│     ├── denyWrite  : path[]   required (carved out *within* allowWrite; takes precedence)
│     └── allowGitConfig?: boolean                           default false
├── credentials?: CredentialsConfig                         (optional; see Doc 08)
│     ├── files?     : { path, mode, extract?, onExtractNoMatch?, maskDuplicates?, injectHosts? }[]
│     ├── envVars?   : { name, mode, injectHosts? }[]
│     └── allowPlaintextInject?: boolean                    default false; gate on no-tlsTerminate
├── ignoreViolations?: Record<commandPattern, path[]>
├── ripgrep?: { command, args?, argv0? }
├── mandatoryDenySearchDepth?: 1..10                        default 3 (Linux only)
├── allowPty?: boolean                                      macOS only
├── enableWeakerNestedSandbox?: boolean                     Linux only
├── enableWeakerNetworkIsolation?: boolean                  macOS only (trustd); weakens network fence
├── allowAppleEvents?: boolean                              macOS only; *removes code-execution isolation*
├── seccomp?: { applyPath?, argv0? }                        Linux only
├── bwrapPath?: absolute path                               Linux only
├── socatPath?: absolute path                               Linux only
└── windows?: WindowsConfig                                 Windows only
      ├── sandboxUser?: string (≤ 20 chars)
      ├── sublayerGuid?: UUID (canonical) / wfpSublayerGuid? (alias)
      ├── proxyPortRange?: [lo, hi]                         width ≤ 64
      └── srtWin?: { path? }
```

### Domain-Pattern Lexicon

| Pattern         | Meaning                                                   | Example matches                      |
| --------------- | --------------------------------------------------------- | ------------------------------------ |
| `example.com`   | Exact host (case-insensitive).                            | `EXAMPLE.com`                        |
| `*.example.com` | Strict subdomain only (`sub.example.com`, `a.b.example.com`). | not `example.com`, not `a.example.co` |
| `*`             | Wildcard (allowed **only** in `deniedDomains`).            | everything                           |
| `localhost`     | Literal allowed (no wildcards in plain entries).           | `localhost`                          |
| Anything else   | Rejected at config time (e.g. `*.com`, `*`, `https://x`). |                                      |

### Path Lexicon

| Form                            | Behaviour                                                                                       |
| ------------------------------- | ----------------------------------------------------------------------------------------------- |
| `/abs/path`                     | Resolved literal path.                                                                        |
| `~/x`                           | `os/user/home/x`; `~` is the only shell feature accepted.                                     |
| `name/` or `name`               | Relative to `process.cwd()`.                                                                  |
| `dir/**`                        | Trailing `**` is *stripped* during resolution (treated as `dir/` on macOS, see Doc 05).        |
| `dir/**/*.ext`                  | Full glob. On macOS: regex-match via `globToRegex`. On Linux: ripgrep-expanded to literal paths. |
| `dir/*`, `dir/?`, `dir/[abc]`   | macOS: regex-match. Linux: rejected (with a warning), since `bwrap` only knows literal paths. |

## 3.3 Default Values and Built-ins

| Default write path (always allowed) | Why                                              |
| ----------------------------------- | ------------------------------------------------ |
| `/dev/null`                         | Many tools redirect output to it.                |
| `/dev/zero`, `/dev/random`, `/dev/urandom` | Random data sources.                       |
| `/dev/tty`                          | Interactive TTY access.                          |
| `/dev/dtracehelper`                 | DTrace support on macOS.                         |
| `/tmp`, `/dev/shm`                  | POSIX-required scratch.                           |
| macOS: `/private/tmp`, `/private/var/folders/...` | `os.tmpdir()` symlinks to those. |
| `/dev/stdout`, `/dev/stderr`        | Useful for wrappers forwarding stdio.             |
| Linux: `/dev/` (tmpfs replacement)  | Required by `bwrap` and most CLIs.                |

| Mandatory deny writes (added by every platform builder)                                                                                                                     |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Shell rc files: `.bashrc`, `.bash_profile`, `.zshrc`, `.zprofile`, `.profile`, `.zshenv`, `.bash_login`, `.zlogout`, `.bash_logout`.                                          |
| Git files: `.gitconfig`, `.gitmodules`; `.git/hooks/` (entire directory); `.git/config` (unless `allowGitConfig: true`).                                                     |
| IDE dirs: `.vscode/`, `.idea/`.                                                                                                                                              |
| Tool dirs: `.claude/commands/`, `.claude/agents/`.                                                                                                                           |
| Tool files: `.ripgreprc`, `.mcp.json`.                                                                                                                                       |
| macOS-only (regex): equivalent recursive glob patterns (`**/.*rc`, etc.).                                                                                                    |
| Linux: ripgrep finds any of the above up to `mandatoryDenySearchDepth` levels deep, then bwrap mounts `/dev/null` (or the file itself) at every match.                       |

## 3.4 Precedence Rules

### Filesystem Reads (deny-then-allow)

```
(allow file-read*)                                ← default: read everywhere
(deny  file-read* (subpath /Users))               ← broad region denied
(allow file-read* (subpath /Users/me/project))    ← specific path re-allowed
```

- `denyRead` lists are evaluated first; matches **deny**.
- `allowRead` matches **re-allow** even within a denied parent (this is the opposite of writes; see below).
- macOS Seatbelt uses last-match-wins, so re-allow rules MUST be emitted *after* the deny rules.
- Linux: deny directories become `--tmpfs`; allowRead paths inside them are explicitly `--ro-bind`'d back.
- Mandatory deny writes ALWAYS take precedence over user-allowed writes (even `allowWrite:['.']` cannot override).

### Filesystem Writes (allow-then-deny)

```
(allow file-write* (subpath /Users/me/project))
(deny  file-write* (subpath /Users/me/project/.env))
```

- `allowWrite` is the only thing that lets writes happen. Empty ⇒ no writes.
- `denyWrite` within an allowed path **always wins** over the allow.
- `denyWrite: []` + `allowWrite: []` is the most locked-down posture; only the default write paths remain.

### Network (allow-then-deny, with optional callback)

```
deniedDomains checked first   ⇒ if matches:        deny
else  allowedDomains checked  ⇒ if matches:        allow
else  if strictAllowlist=true ⇒ deny (never callback)
else  if askCallback defined  ⇒ await askCallback({host, port})
else                          ⇒ deny
```

- The callback **never** fires for non-network-protocol decisions or for hosts rejected by `deniedDomains`.
- `strictAllowlist: true` short-circuits the callback entirely; used when `allowedDomains` is policy, not hint.

## 3.5 Validation Surface (Super-Refinements)

| Cross-field constraint                                                                                                                          | Where enforced                       |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `tlsTerminate.caCertPath` set ⇔ `caKeyPath` set                                                                                                  | `tlsTerminate.refine()`              |
| `network.tlsTerminate` XOR `network.mitmProxy` (setting both is an error)                                                                        | `SandboxManager.initialize()`        |
| For every masked credential, at least one of `{tlsTerminate, allowPlaintextInject}` must be set                                                  | schema `superRefine`                 |
| Every explicit `injectHosts` entry must be reachable via `allowedDomains` (semantic, not literal — `*.foo.com` covers `bar.foo.com`)            | schema `superRefine`                 |
| Every explicit `injectHosts` entry must NOT be entirely covered by `tlsTerminate.excludeDomains` (would never get the real value)              | schema `superRefine`                 |
| Wildcards only allowed as a single trailing `*` in `allowMachLookup`                                                                             | `NetworkConfigSchema.refine`         |
| `proxyPortRange[0] ≤ proxyPortRange[1]` and width ≤ 64                                                                                          | `WindowsConfigSchema`                |
| `mandatoryDenySearchDepth` ∈ [1, 10]                                                                                                              | `SandboxRuntimeConfigSchema`         |
| `windows.sandboxUser` ≤ 20 chars                                                                                                                  | `WindowsConfigSchema`                |
| `bwrapPath` / `socatPath` must be **absolute**                                                                                                   | `binaryPathSchema`                   |
| `windows.srtWin.path`: when set, the binary is spawned with `--srt-win argv[1]` (multicall routing)                                              | used in `wrapCommandWithSandboxWindows` |

## 3.6 Hot-Reload (`updateConfig`)

`updateConfig(newConfig)` swaps the global `config` reference. Differences
between platform behaviour:

| Aspect                | macOS              | Linux              | Windows            |
| --------------------- | ------------------ | ------------------ | ------------------ |
| `network.*`           | hot (next request) | hot (next request) | hot (next request) |
| `filesystem.*`        | apply-at-wrap only | apply-at-wrap only | warn; needs reset+init |
| `credentials.*`       | apply-at-wrap only | apply-at-wrap only | warn; needs reset+init |
| `proxyPorts`          | rebind required    | rebind required    | rebind required    |
| MITM CA identity      | rebind required    | rebind required    | rebind required    |

The implementation uses `structuredClone` to clone the config, peels off the
function-valued `filterRequest` (which can't be cloned), and reassigns. The
proxy servers **do not** rebind; they read `config.network.*` per request via
the closure captured at construction (`filterNetworkRequest(port, host, cb)`).

## 3.7 Filesystem Disabled (Escape Hatch)

`filesystem.disabled: true` causes **every** filesystem restriction (read deny,
read allow, write allow, write deny) to be ignored. The mandatory deny list is
also skipped. Credential ENV restrictions still apply (the env vars are unset
or sentinels substituted). Credential FILE restrictions are dropped along with
all other fs rules. The user is responsible for whatever security boundary
substitutes for srt's filesystem controls when this is enabled.

The setting is **session-level** in the global config and is also overridable
per-call via `customConfig.filesystem.disabled` in `wrapWithSandbox(customConfig)`.
Per-call `disabled` defaults to `false` *unless the key is omitted*, in which
case the session value applies.
