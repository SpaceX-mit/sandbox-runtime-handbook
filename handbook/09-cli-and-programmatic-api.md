# 09 — CLI and Programmatic API

## 9.1 CLI Surface (`srt`)

The CLI is a `commander` invocation in `src/cli.ts`. Subcommands:

| Subcommand             | Arguments                                                                  | Effect                                                              |
| ---------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| (default)              | `[command...]`, `-d, --debug`, `-s, --settings <path>`, `-c <cmd>`, `--control-fd <fd>` | Run `<command>` in the sandbox.                                    |
| `windows-install`      | `--sublayer-guid`, `--proxy-port-range`, `--sandbox-user`, `--force`       | Self-elevating install (one UAC prompt).                            |
| `windows-uninstall`    | `--sublayer-guid`                                                          | Self-elevating uninstall (one UAC prompt).                         |

### Default subcommand

```
srt [-d] [-s PATH] [-c "command string"] [--control-fd N] [-- ... arbitrary]
```

Examples:

```bash
# Direct invocation (each token shell-quoted into a `bash -c`):
srt curl https://example.com

# Run shell-piped commands without quoting headaches:
srt -c "for f in *.txt; do echo \$f; done"

# Dynamic config updates via fd 3:
srt --control-fd 3 curl https://github.com
# (the parent process writes JSON lines to fd 3; config updates live)
```

### Behaviour

1. Resolve the config path (default `~/.srt-settings.json`, or override).
2. Load + zod-validate the JSON. **Missing config with explicit `--settings` is a hard error**, never a silent fallback.
3. `SandboxManager.initialize(config)`.
4. If `--control-fd` is set, attach a `readline` interface to read newline-delimited JSON updates (network only — filesystem changes are warned at runtime on Windows, ignored on macOS/Linux).
5. Compute the wrapped command (shell string on POSIX; `{argv, env}` on Windows).
6. `spawn(...)`, inheriting stdio; forwarding SIGINT/SIGTERM to the child.
7. On exit: `cleanupAfterCommand()` (Linux-specific), `process.exit(code)`.
8. On process exit / SIGINT / SIGTERM: `reset()` (registered via `registerCleanup()`).

### Return Codes

| Cause                                 | Exit code                              |
| ------------------------------------- | -------------------------------------- |
| Sandbox violation (network blocked)   | child process's normal exit (e.g. 7 for curl) |
| Missing/invalid `~/.srt-settings.json` (with `--settings`) | 1 |
| Missing dependencies                  | 1 (stderr message)                     |
| User cancelled UAC at install/uninstall | 2                                     |
| Wrapper failure                       | 1 |

### Internals Notes

- `quote(commandArgs)` from `utils/shell-quote.ts` joins argv-style args into a shell-safe string (e.g. `'foo bar'`, `'a "b"'`).
- On Windows, the orchestrator uses `spawn(argv[0], argv.slice(1), { shell: false })` so the user-provided bytes never hit `cmd.exe`.
- `process.on('exit', cleanup)` plus `process.on('SIGINT', cleanup)` etc.

## 9.2 Programmatic Surface (`SandboxManager`)

Public type:

```ts
export const SandboxManager: ISandboxManager = {
  initialize,
  isSupportedPlatform,
  isSandboxingEnabled,
  checkDependencies,
  getFsReadConfig,
  getFsWriteConfig,
  getNetworkRestrictionConfig,
  getAllowUnixSockets,
  getAllowLocalBinding,
  getAllowMachLookup,
  getIgnoreViolations,
  getEnableWeakerNestedSandbox,
  getProxyPort,
  getProxyAuthToken,
  getSocksProxyPort,
  getLinuxHttpSocketPath,
  getLinuxSocksSocketPath,
  waitForNetworkInitialization,
  wrapWithSandbox,
  wrapWithSandboxArgv,
  cleanupAfterCommand,
  reset,
  getMitmCA,
  getSentinelRegistry,
  getMaskedFileStore,
  getSandboxViolationStore,
  annotateStderrWithSandboxFailures,
  getLinuxGlobPatternWarnings,
  getConfig,
  updateConfig,
} as const
```

`SandboxManager` is a **singleton** — one process, one config, one set of proxies.

### Lifecycle Methods

```ts
// Initialize with config; second call no-ops (returns the cached init promise).
await SandboxManager.initialize(config, askCallback?, enableLogMonitor?)

// Check if current OS is supported (returns false on WSL1, etc.).
SandboxManager.isSupportedPlatform()

// True if initialize() ran at least once.
SandboxManager.isSandboxingEnabled()

// Probe the deps. Errors = can't run; warnings = degraded.
const { errors, warnings } = SandboxManager.checkDependencies()
```

### Wrap Methods

```ts
// POSIX return: a shell command string. Wrap in `spawn(..., { shell: true })`.
const wrapped: string = await SandboxManager.wrapWithSandbox(
  'curl https://example.com',
  binShell?: string,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal
)

// Windows return: argv+env for { shell: false } spawn.
const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
  'curl https://example.com',
  binShell?: string,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal,
  cwd?: string
)
```

`customConfig` is *merged* into the session config in the following precedence:

- Each present key in `customConfig` overrides the session config.
- `customConfig.filesystem` is treated as a *single unit*: if the key is present at all (even `{disabled: false}`), it replaces the session's filesystem config entirely.
- `customConfig.network.allowedDomains !== undefined` triggers proxy use for this exec (even if the session's `allowedDomains` was `[]`).

### Live-Reload & Reset

```ts
// Hot-swap network rules. Filesystem rules on Windows WARN; otherwise ignored.
SandboxManager.updateConfig(newConfig)

// Full teardown — call before re-initialize.
await SandboxManager.reset()
```

### Observability Methods

```ts
// Get the violation store (keyed by encoded-command-b64).
const store = SandboxManager.getSandboxViolationStore()
for (const v of store.getViolationsForCommand(encodedCommand)) {
  console.error(v.line)
}

// Annotate a child's stderr with the violations captured during it.
const annotated = SandboxManager.annotateStderrWithSandboxFailures(command, stderr)

// The Linux-only "patterns in your config that won't be honored" warning.
const unsupportedGlobs = SandboxManager.getLinuxGlobPatternWarnings()

// Useful integration points
const token      = SandboxManager.getProxyAuthToken()
const muxPort    = SandboxManager.getProxyPort()
const socksPort  = SandboxManager.getSocksProxyPort()
const linuxHttpSock  = SandboxManager.getLinuxHttpSocketPath()
const linuxSocksSock = SandboxManager.getLinuxSocksSocketPath()
```

## 9.3 Type Exports

```ts
// Configuration types
export type {
  SandboxRuntimeConfig,
  NetworkConfig,
  FilesystemConfig,
  CredentialsConfig,
  CredentialFileConfig,
  CredentialEnvVarConfig,
  CredentialMode,
  IgnoreViolationsConfig,
  WindowsConfig,
  SrtWinConfig,
}

// Runtime helpers
export type {
  SandboxAskCallback,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  CredentialRestrictionConfig,
  NetworkRestrictionConfig,
  NetworkHostPattern,
  FilterRequestCallback,
  RequestDecision,
  MutateForwardedHeaders,
  SandboxViolationEvent,
}

// Schemas (zod)
export {
  SandboxRuntimeConfigSchema,
  NetworkConfigSchema,
  FilesystemConfigSchema,
  CredentialsConfigSchema,
  IgnoreViolationsConfigSchema,
  RipgrepConfigSchema,
  WindowsConfigSchema,
  SrtWinConfigSchema,
}

// Helpers
export { getDefaultWritePaths }
export { getWslVersion }
```

## 9.4 Schema Exports — Why?

Embedding a fresh `ZodObject` lets consumers reuse the validation:

```ts
import {
  SandboxRuntimeConfigSchema,
  type SandboxRuntimeConfig
} from '@anthropic-ai/sandbox-runtime'

const userConfig = JSON.parse(fs.readFileSync('user.json', 'utf8'))
const parsed: SandboxRuntimeConfig = SandboxRuntimeConfigSchema.parse(userConfig)
```

This means the embedder never has to duplicate validation logic; they get the same error messages we do.

## 9.5 Dynamic Config Updates via `--control-fd`

A second input channel that lets the parent process push config snapshots
into a running CLI while it's blocking on `spawn`. Wire protocol:

- One full JSON object per line (no pretty-printing, no arrays-of-configs).
- Same shape as `SandboxRuntimeConfigSchema`.
- Network changes apply on next request.
- Filesystem changes apply on next `wrapWithSandbox(...)` call.
- On Windows, a filesystem-shape change triggers a stderr warning and is ignored.
- Malformed lines are logged at debug level and dropped; valid lines trigger `SandboxManager.updateConfig(line)`.

Typical use:

```bash
# Make a sandboxed CLI run forever; a daemon watches something and pushes updates
srt --control-fd 3 daemon &
exec 3>#   # write end of pipe
# Later: write JSON to fd 3:
echo '{"network":{"allowedDomains":["github.com"],"deniedDomains":[]}, …}' >&3
```

## 9.6 Synchronous Primitive (`sandbox-exec` / `bwrap` / `srt-win exec`)

Each platform wrapper ultimately produces a string the host can spawn:

| OS      | Return path                                         | Run via                                  |
| ------- | --------------------------------------------------- | ---------------------------------------- |
| macOS   | `env -u… ENV=… sandbox-exec -p '<profile>' bash -c '<cmd>'` | `spawn(cmd, { shell: true })`     |
| Linux   | `bwrap … apply-seccomp bash -c '<cmd>'` argv form | `spawn(argv, { shell: false })`         |
| Windows | `srt-win exec … <shell> -c <cmd>` argv array        | `spawn(argv, { shell: false })`         |

Note Windows uses `cmd.exe` as the inner shell (or whatever `binShell`
specifies — `pwsh`, `bash` from WSL, etc.). Whatever the inner shell is,
it runs under the sandbox user (srt-win runs the runner as the sandbox
user → the inner shell sees the sandbox user's env).

## 9.7 Adding the Library as a Dependency

```bash
npm install @anthropic-ai/sandbox-runtime
```

Then:

```ts
import { SandboxManager } from '@anthropic-ai/sandbox-runtime'
import type { SandboxRuntimeConfig } from '@anthropic-ai/sandbox-runtime'
```

The README provides the exact usage snippet under "As a library".

## 9.8 Things Library Consumers Typically Want

### Want a sandbox-exec failure to fall back gracefully

`SandboxManager.checkDependencies()` is the right pre-check. Errors there mean `wrapWithSandbox()` will throw; the consumer can fall back to running unsandboxed (with a logged warning).

### Want to ask the user about out-of-policy network requests

```ts
await SandboxManager.initialize(config, async ({ host, port }) => {
  return await confirmDialog(`Allow ${host}:${port}?`)
}, /* enableLogMonitor */ true)
```

The callback is invoked per request from the proxy. Returning `false` ⇒ 403; returning `true` ⇒ request proceeds (within the existing allow-list semantics for plain-HTTP).

### Want hot config updates

Call `updateConfig(newConfig)` at any time. Network updates apply on next
request. Filesystem updates apply on next `wrapWithSandbox()` call.

### Want per-exec override (POSIX)

```ts
const wrapped = await SandboxManager.wrapWithSandbox(cmd, undefined, {
  filesystem: {
    denyRead: ['/extra'],
    allowWrite: ['/extra'],
    denyWrite: [],
  },
  network: {
    allowedDomains: ['api.example.org'],
    deniedDomains: [],
  },
})
```

### Want per-exec override (Windows)

Per-exec `allowRead`/`allowWrite` throws at `wrapWithSandboxArgv()` time.
Use `denyRead`/`denyWrite` only.

## 9.9 CLI Debugging Surface

- `SRT_DEBUG=1` (also `-d, --debug`) → set in `process.env` before `initialize()`. Surfaces every log to stderr.
- `which srt` / `srt --version` — confirm the installed version.
- `srt --settings /dev/null` — force a hard-error if your config is unloaded.
- `srt 'cat /etc/hosts'` against `denyRead: ['/etc']` — quick functional smoke.
- The sandboxed command's `$HTTP_PROXY` is inspectable with `srt 'env | grep -i proxy'`.

## 9.10 The Library-versus-CLI Distinction

The library surface is a strict subset of what the CLI does. The CLI does:
- Read/write `~/.srt-settings.json`.
- Handle `--control-fd`.
- Forward signals.
- Translate argv → shell-string.
- Print version/help.

The library does none of those — it is a stateful object that wraps a
single process. Embedders that need the CLI-like behaviour should *invoke*
the CLI as a subprocess, not use the library; embedders that need only the
wrap + spawn should use the library.
