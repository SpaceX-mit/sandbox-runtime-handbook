# 07 — Filesystem & Network Isolation — Windows

Windows is the most architecturally distinct platform in srt. There is no
Seatbelt or bubblewrap equivalent. The implementation reuses **two stock
Windows primitives**:

1. **NTFS discretionary ACLs (`DACL`s)** — every filesystem permission decision (read, write, modify, delete-child) is enforced by the kernel via DACLs.
2. **Windows Filtering Platform (`WFP`)** — the kernel's networking policy layer; we add filter conditions to `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`.

The trick: **the sandboxed process doesn't run as the calling user.** It runs
under a dedicated, machine-local user `srt-sandbox`, with a random DPAPI-encrypted
password. That user has *no* inherent rights on the calling user's files
(unlike the calling user, who has its own profile tree). We then **stam**
additive ACEs for the `srt-sandbox` SID onto the paths the user wants
accessible.

Everything else — WFP filters, ACL stamp/revoke, sandbox-user provisioning,
CA trust installation, the two-hop launch — lives in the bundled `srt-win`
helper (a Rust binary, ~20 kLOC).

## 7.1 One-time Install (`srt-windows-install`)

A self-elevating CLI invocation that runs once per host. Sequence:

```
srt → Spawn elevated `srt-win install` via ShellExecuteEx(runas) + UAC
srt-win install (elevated):
    1. Create local user `srt-sandbox`
         net user srt-sandbox <random-pw> /add
       Refuse if a user by that name exists but is NOT our previous install.
    2. Add it to group `sandbox-runtime-users`
       This group can read state.db but not decrypt the DPAPI blob.
    3. DPAPI-encrypt the random password (machine scope)
       Write to %LOCALAPPDATA%\sandbox-runtime\state.db (DACL-stamped broker-only)
    4. Open BFE (Base Filtering Engine); we are admin via the elevation
    5. Provision WFP sublayer + 4 filters (PERMIT loopback + BLOCK sandbox SID at each layer v4/v6)
    6. If interactive: confirm to user the filters are live
```

### Install Idempotency

A second `install` run:
- Re-uses the same SID if the user already exists with the same marker.
- Rotates the password (writes a new DPAPI blob).
- Reconciles WFP filters via `wfp filter enum` → delete-and-replace.

### Files Left on Disk

- `%LOCALAPPDATA%\sandbox-runtime\state.db` — DACL-stamped; never carries a cleartext credential.
- `HKLM\…\srt-sandbox-profile` keys.
- The sandbox-user profile dir under `C:\Users\srt-sandbox`.

## 7.2 The Per-Init Stamp (`SandboxManager.initialize` on Windows)

When `initialize` runs against Windows, the manager:

1. Resolves `srt-win` (default: `vendor/srt-win/<arch>/srt-win.exe`).
2. Runs `srt-win user status` → ensures the user is provisioned AND a credential is present.
3. Runs `srt-win wfp verify` → behavioural connect probe (more on this below).
4. If `tlsTerminate` → runs `srt-win user status ca-cert` and compares thumbprints.
5. Computes the access set from the config:
    - `grantRead` = expanded `filesystem.allowRead`.
    - `grantWrite` = expanded `filesystem.allowWrite`.
    - `denyRead` = expanded `filesystem.denyRead ∪ credential-deny-file-paths`.
    - `denyWrite` = expanded `filesystem.denyWrite`.
6. Calls `srt-win acl grant` → writes `(OI)(CI)` ACEs for `<sandbox SID>` on each grant path.
7. Calls `srt-win acl stamp` → writes explicit DENY ACEs on deny paths and `(OI)(CI) FILE_DELETE_CHILD` DENY on each deny path's parent.

The stamp set is module-state-tracked (`windowsFsStampedSet`) so `reset()` can revoke exactly what was added.

### Path Expansion (`expandWindowsFsPaths`)

Same semantics as the mac/linux glob expand, but:
- Glob expansion uses `rg --files` at `initialize` time.
- Symlinked paths are NOT followed; we stamp what the user gave us.
- Non-existent paths in `allowRead`/`allowWrite` are dropped with a debug log.

### Mandatory Deny Paths

The SDK does not have the same rc-file and git-config mandatory-deny list that mac/linux emits — Windows users use different tooling and the LibraryDirs pattern is different. Instead:
- The required `.git/hooks` block is the same.
- The rest of the mandatory deny is delegated to user configuration (the embedder typically denies `%USERPROFILE%` outright except for specific allow-listed paths).

### ACE Order

When two ACEs target the same trustee, the **more-specific** ACE wins (deny before allow). The SDK writes rules in:
1. `acl grant` first (so the sandbox user has working-tree access).
2. `acl stamp` second (so denies are explicit last).

If `initialize` throws after step 1 but before step 2, the catch block calls `acl revoke` and `acl restore` to release whatever ACEs landed.

## 7.3 File Read-Deny Stamp

For each `denyRead` path:

```
(grant) [sandbox SID]  R+X on <allowRead subpath>     ← emitted only if a subpath is allowRead-only

(deny)  [sandbox SID]  R+W+X+D  on <denyRead path>     ← full deny ACE

(parent of <denyRead path>)  (deny) [sandbox SID]  FILE_DELETE_CHILD
```

The `(OI)(CI)` flags ("object inherit, container inherit") make the ACE flow to all descendants; the parent's `FILE_DELETE_CHILD` deny prevents the sandboxed process from renaming or removing the denied subtree.

### ALLOW ACE for `allowRead`

The SDK reads `allowRead` as "re-allow within a broader deny", same as macOS. A path under `denyRead: ['/home']` that is `allowRead: ['/home/me/project']` produces:

1. DENY on `/home` for the sandbox SID.
2. ALLOW on `/home/me/project` for the sandbox SID.

ALLOW does not *override* DENY in the recompose order. So the order of ACL emission matters:

```
ACL on `/home`:
    DENY  sandbox-SID
ACL on `/home/me/project`:
    ALLOW sandbox-SID
```

ALLOW *does* override DENY when ACEs target the same file. To make `allowRead` paths actually readable, the SDK writes the ALLOW ACE directly on the path (not above), so they live on a different inode than the DENY on `/home`. The kernel evaluates ACEs in `lowest-priority-number-first` order, so the more-specific (innermost) ACE wins.

## 7.4 File Write-Deny Stamp

For each `denyWrite` path:

```
(deny)  [sandbox SID]  R+W+X+D  on <denyWrite path>
(parent) (deny) [sandbox SID]  FILE_DELETE_CHILD
```

And on every `allowWrite` path:

```
(allow) [sandbox SID]  MODIFY_NO_FDC  on <allowWrite path>     ← R+W+X+D minus FILE_DELETE_CHILD
```

The `MODIFY_NO_FDC` access mask grants `READ | WRITE | EXECUTE | DELETE` (and a few flags). We withhold `FILE_DELETE_CHILD` deliberately — without it, the sandboxed process could rename a denied file via `MoveFileEx` on the parent. The deny parent stamps ensure even that path is closed.

## 7.5 ACL Cleanup (`reset`)

At `reset()` the SDK walks `windowsFsStampedSet` and calls:

- `srt-win acl revoke <sb-SID>` — removes every ALLOW ACE the broker added.
- `srt-win acl restore <sb-SID>` — restores the originals recorded at stamp-time.

`srt-win` keeps a per-broker-PID refcount (in `state.db`), so concurrent hosts don't trample each other.

### Crash Recovery (`srt-win acl recover`)

If the broker process is killed before `reset()` runs, the state.db holds
the original ACE bytes. A subsequent `srt-win install` call (or
`acl recover`) walks the table, re-derives the original DACL, and writes
it back to disk. This re-stamps security on all paths.

## 7.6 WFP Egress Fence

### Filter Set at `install`

```
FWPM_SUBLAYER0
    key      = <sublayerGuid> (default constant; overridable via --sublayer-guid)
    flags    = PERSISTENT
    display  = "srt-sandbox ALE filter sublayer"

FWPM_FILTER0 (×4):
    layer       = FWPM_LAYER_ALE_AUTH_CONNECT_V4 (and V6)
    sublayerKey  = <sublayerGuid>
    action.type = FWP_ACTION_PERMIT  (weight 0)
    providerData= { tool:"srt", kind:"permit-loopback", port_range:[lo,hi] }
    conditions  = [
       IP_REMOTE_ADDRESS ∈ { 127.0.0.0/8  (v4) or ::1 (v6) }  using FWP_MATCH_EQUAL
       AND
       IP_REMOTE_PORT    ∈ [lo, hi]                           using FWP_MATCH_RANGE
    ]

FWPM_FILTER0 (×4):
    layer       = FWPM_LAYER_ALE_AUTH_CONNECT_V4 (and V6)
    sublayerKey = <sublayerGuid>
    action.type = FWP_ACTION_BLOCK   (weight 0xFFFFFFFF — high precedence)
    providerData= { tool:"srt", kind:"block-sandbox-user", user_sid:"<sandbox SID>" }
    conditions  = [
       ALE_USER_ID security descriptor matches if AccessCheck grants ← SD for sandbox SID
    ]
```

### Why Key on User SID

`FWPM_CONDITION_ALE_USER_ID` evaluates via `AccessCheck` against the supplied security descriptor. The kernel calls this for every outbound `connect()` whose bearer token is the sandbox user's. Other tokens (real user, SYSTEM, services) don't match → default-permit.

This makes several escapes impossible:
- **Surrogate spawn**: `schtasks /create /tn "x" /tr "..." /sc once` — task's token is in the sandbox user's SID → BLOCKED.
- `CreateProcess` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` onto a broker-owned process → still produces a token in the sandbox user's SID → BLOCKED.
- **BITS / RunAs "Interactive User"** COM → sandbox user SID → BLOCKED.

### Why `ALE_AUTH_CONNECT` (not `STREAM` or `DATAGRAM`)

The auth-connect layer runs **once** per `connect()` attempt, after name resolution. Blocking here means:

- Connection never reaches `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4` (where MITM could happen).
- DNS over UDP/53 still goes through the DNS service (which runs as `NETWORK SERVICE` → not the sandbox user → not matched by BLOCK). Modern schannel/OpenSSL tooling does its own resolution on TCP through the proxy, which doesn't reach DNS via UDP/53.

This **mirrors the macOS DNS-resolver exemption** (the README spells this out).

### Behavioral Verification (`srt-win wfp verify`)

Listing BFE filters via `FwpmFilterEnum0` is **admin-only**. Non-elevated
processes get `FWP_E_ACCESS_DENIED`. To verify a non-elevated install is
actually fencing, the SDK does:

1. Connect to `127.0.0.1:<port_inside_permit_range>` → expect success.
2. Connect to `127.0.0.1:<port_outside_range>` → expect `WSAECONNREFUSED` (no listener; that's the same outcome either way).
3. Connect to `127.0.0.1:0` (the only OUT-OF-RANGE port guaranteed unbound) → also `ECONNREFUSED`.
4. Use a WinAPI trick: `WSAGetLastError()` distinguishes "filters dropped" from "nothing listening". The BLOCK action causes `WSAECONNABORTED` from the kernel filter, NOT `WSAECONNREFUSED`.

If the trick returns `WSAECONNABORTED` on a blocked target, the fence is live. If it returns anything else, the SDK throws an actionable error and refuses to initialize.

This is **run once per process** (not per `initialize`). The fence is install-time; the manager caches `windowsWfpVerified = true`.

## 7.7 Trust-CA Lifecycle (`tlsTerminate` on Windows)

Modern Windows API expectations use **schannel**, which trusts only the OS cert store (env vars are ignored for tools built on schannel). To get a sandboxed `Invoke-WebRequest`, `curl.exe`, `git` (default backend) to verify proxy-minted leaves, the MITM CA must be installed in the **sandbox user's** `CurrentUser\Root` store.

### Install Step (manual, separate from `windows-install`)

```
srt-win user trust-ca <path-to-mitm-ca.crt>
    reads the cert
    acquires a token for the srt-sandbox user via LogonUser (uses the DPAPI-stored password)
    impersonates the user
    reads the sandbox-user's registry  (HKU\<sid>\…\Root\Certificates)
    adds the cert to it
```

The token is dropped as soon as the registry write returns.

### Per-Session Validation

`initialize()` compares the session's MITM CA thumbprint to the one in the registry:

```
sessionThumb = SHA1(certPem).toUpper()
installedThumb = read from registry
```

Mismatch → `tlsTerminate on Windows: the sandbox's installed CA (thumb=…) doesn't match this session's CA (thumb=…). Run \`srt-win user trust-ca …\` to update it.`

A stale install-time CA cannot silently break TLS — the gate fails closed.

### OpenSSL-tier tools (msys2 curl, git -c http.sslBackend=openssl, Node, Python, cargo)

These read env vars. The orchestrator sets:

```
NODE_EXTRA_CA_CERTS=<bundlePath>
SSL_CERT_FILE=<bundlePath>
CURL_CA_BUNDLE=<bundlePath>
GIT_SSL_CAINFO=<bundlePath>
CARGO_HTTP_CAINFO=<bundlePath>
```

The bundle is written into the broker's `%TEMP%`, which the sandbox user has no inherent right to read — so the manager adds the bundle path to the **session-level** `allowRead` grant set at `initialize()` time.

## 7.8 The Two-Hop Launch

`srt-win exec -- <user command>` runs:

```
broker (NT-process, real user)
    ↓ spawns (CreateProcessWithLogonW, --sandbox-user srt-sandbox, --password <pw>)
runner (NT-process, srt-sandbox user)
    ↓ spawns (CreateProcessWithRestrictedToken, -- jobObject, -- integrity-level medium)
child (NT-process, srt-sandbox user, restricted token)
    user command runs here
```

### Why Two Hops

A single hop means the broker holds the sandbox user's credential long enough to do `CreateProcessWithLogonW`. That's the credential-leak window. Two hops:

1. **Broker** reads the DPAPI blob, decrypts once per `wrapWithSandbox` call, passes plaintext to `runner` via `--password <pw>` argv argument on `runner`'s spawn.
2. **Runner** immediately constructs the restricted token + job, runs the child, and **never logs plaintext** afterwards.
3. **Runner exit**: token is destroyed; the password argument is on the runner's cmdline only briefly.

A `PROCESS_QUERY_LIMITED_INFORMATION` query against the runner reveals the
plaintext password for ~150ms. That's the documented limitation.

### Job Object

The child runs inside a `JOB_OBJECT` that:
- Limits `KILL_ON_JOB_CLOSE` so when the broker dies the child dies.
- Sets `JOB_OBJECT_LIMIT_PROCESS_MEMORY` to a configurable cap (default unlimited).
- Disallows nested job breakouts.

The job is closed at `reset()` time; the SDK keeps a per-broker handle in `state.db`.

### Token Restrictions

- `DISABLE_MAX_PRIVILEGE`
- `SANDBOX_INTEGRITY` (or low integrity, configurable) for AppContainer-like isolation if requested
- `NO_WRITE_UP` (medium→high denied)
- Specific SIDs removed from the default DACL group list

### Working Dir / Starting Path

The runner exe (`srt-win.exe`) is bind-mounted into a path under the sandbox user's `%APPDATA%` dir before exec (so the child can find its own helper if it needs to). The child inherits `%TEMP%`, `%APPDATA%`, etc. of the **sandbox user**, not the broker.

## 7.9 argv Construction (`wrapCommandWithSandboxArgv`)

The Windows path is fundamentally different. **There is no shell string returned.** Only `{ argv, env }`:

```ts
srt-win
  --srt-win                                 ← multicall dispatch (when path is customized)
  exec
  --binary <srtWinSpawn.path>
  --user  srt-sandbox
  --pw    <plaintext>
  --cwd   <cwd>
  --allow-write <grantWrite path>...        ← repeated
  --proxy   http://srt:<token>@127.0.0.1:<httpPort>
  --socks   socks://srt:<token>@127.0.0.1:<socksPort>
  --trust-bundle <mitmCA.trustBundlePath>
  --deny-read  <perExecDenyRead path>...
  --deny-write <perExecDenyWrite path>...
  --env <NAME>=<VAL>...
  --env NAME
  --
  <shell-path> -c <user-command>
```

Where:

- `<shell-path>` is parsed from `binShell` via `parseWindowsBinShell` (defaults to `cmd.exe /c` if not specified).
- The list of `--allow-write` is the **session-level** grant set (recorded at `initialize()`); per-call override not supported (throws).
- `--env NAME=` (no value) means "unset" — used for credential-mode=deny.
- `--env NAME=VAL` means set with sentinel — used for credential-mode=mask.

### Why the env has no Shell

`spawn([...], { shell: false })` is the security boundary on Windows. If
you go through `cmd.exe /c "..."`, you inherit:

- Command-line length limits (already painful, but not the issue).
- Shell parsing (which the user is trying to sandbox).
- Variable expansion that could resolve to the broker's values.
- The path-search order of the broker's `%PATH%`, not the sandbox user's.

Hence `wrapWithSandboxArgv()` is the only correct API on Windows, and `wrapWithSandbox()` is a no-op that throws.

## 7.10 Cleanup at `reset()`

`reset()` does:
- Call `srt-win acl revoke <sb-SID>` and `srt-win acl restore <sb-SID>` (only if `windowsFsStampedSet` is non-empty).
- Best-effort log any non-anomalous ACE states (the SDK accepts `revoked`, `restored`, `stillHeld`, `alreadyOriginal` as success).
- **Doesn't** clear `windowsWfpVerified` (the fence is install-time).
- **Doesn't** close the job object (the broker already has a single long-running job for the whole session; reset just stops spawning new children).

## 7.11 Known Limitations (README § "Windows (alpha)")

Read straight from the README; these are documented gaps in v1:

- **CRL fetch under schannel** is unblocked via the in-process CRL serving on loopback (see §7.12).
- **Per-user tool installs** (nvm, fnm, pip user, etc.) are unreachable since the sandbox user can't traverse your profile. Add them to `allowRead` or install machine-wide.
- **Per-exec `allowRead`/`allowWrite` overrides throw** — grants are session-wide; `srt-win exec` only accepts per-exec denies.
- **`proxyAuthToken` visible in runner cmdline** for ~150ms.
- **DNS via WinAPI** bypasses the fence (names resolve through the SYSTEM DNS service). TCP-level CONNECT still goes through the fence. Tools that bypass TCP (`nslookup`, `dig`) get fenced.

## 7.12 CRL Distribution Point (Windows-Only)

The Java code in `mitm-ca.ts` records `crlDer: Buffer` — an empty CRL signed by the MITM CA. The mux proxy serves it at `CRL_PATH == "/srt.crl"` on the mux-bound port.

Each leaf mint embeds `cRLDistributionPoints = http://127.0.0.1:<muxPort>/srt.crl`. Schannel fetches → "checked, not revoked" → TLS handshake proceeds.

> **Linux/macOS note:** the CDP URL is only set on Windows. On Linux the
> child runs under `bwrap --unshare-net` and the CDP would be unreachable
> anyway, so we omit it. macOS doesn't have a schannel-equivalent that does
> online revocation checks by default.

### Generating the Empty CRL

`genCRL(caCert, caKey)` (in `mitm-ca.ts`) creates an empty X.509 v2 CRL with the same issuer as the MITM CA, signed by the CA's RSA key. The DER encoding is precomputed once and stored on the `MitmCA` struct.

## 7.13 Boundary Truths Recap (Windows)

1. **Sandboxed process has a *different* SID** than any human user or system service. The fence keys on this.
2. **ACE writes are additive** — we never replace a path's existing DACL.
3. **The job object is owned by the broker**, not the runner. Closing the broker closes the job → kills all children.
4. **`state.db` is the only secret store.** The DPAPI blob is DPAPI-encrypted with machine scope + ACL-stamped so even the sandbox user can't decrypt it.
5. **No shell on the launch path.** argv is the contract.
