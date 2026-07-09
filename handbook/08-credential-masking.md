# 08 — Credential Masking

The credential system is a second layer on top of the usual deny-by-default
network and filesystem policy. It lets the operator say: *"this specific
secret is masked: it leaves this machine only when talking to this specific
host."*

## 8.1 Threat Model Assumptions

The masquerade scenario:
1. The sandboxed tool has a legitimate need to talk to `api.example.com`.
2. The tool was given an API key — `EXAMPLE_API_KEY=sk_live_abc123` — in its environment.
3. The operator wants to **revoke** that key for the duration of the sandbox session, but the tool *needs* a value to be present (some tools break with `unset EXAMPLE_API_KEY`).
4. **Either**: the operator wants the tool to call home only with the real key, only at `api.example.com`, never at any other host; or **alternatively**, the tool does its own plumbing and the operator wants to verify what's being sent.

The masking system gives both:
- The child sees a sentinel — a placeholder string with no useful value.
- The proxy substitutes the real value back on egress, **only** for the allow-listed hosts and **only** when the egress isTLS-terminated (so the operator can also inspect the request).

## 8.2 Sentinel Lifecycle

```
HOST                              CHILD                              UPSTREAM
─────                             ─────                              ───────
realValue = process.env.SECRET                                   
         │                                                        
         ▼                                                        
register("SECRET", realValue, [hosts])                            
         │                                                        
         ├── returns sentinel = "<srt:SECRET:<rand>>"             
         ▼                                                        
wrap-time: setEnvVars = { SECRET: sentinel }                      
         │                                                        
         ├── bwrap --setenv SECRET sentinel                        child sees SECRET=sentinel
         │                                                        
         ▼                                                        
HTTPS request to api.example.com                                  
         ├ Host: api.example.com                                  
         ├ X-Auth-Token: <srt:SECRET:<rand>>                      
         │                                                        
         ▼   (proxy connects to upstream with HTTPS, child cert-verified)
proxy intercepts:
    mutateHeaders(req, "api.example.com"):
        header["X-Auth-Token"] = <srt:SECRET:<rand>> → realValue
         │                                                        
         ▼                                                        
upstream sees X-Auth-Token: realValue                              ✓
```

## 8.3 Per-Credential Config

### File Credential

```json
{
  "path": "/home/me/.npmrc",
  "mode": "mask",
  "extract": "_authToken = \"([^\"]+)\"",
  "onExtractNoMatch": "warn",      // default; "deny" or "error" are options
  "maskDuplicates": false,         // scan non-matched spans too (risky for short values)
  "injectHosts": ["*.npmjs.org"]   // default: network.allowedDomains
}
```

| Field               | Meaning                                                                                              |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| `path`              | The credential file. Supported forms same as `filesystem.denyRead`.                                  |
| `mode`              | `"deny"` (unreadable) or `"mask"` (sentinel-content).                                                |
| `extract`           | Optional regex. Group 1 is replaced with the sentinel; the rest of the file is preserved byte-for-byte. |
| `onExtractNoMatch`  | `"warn"` / `"deny"` / `"error"` — see Doc 03.                                                        |
| `maskDuplicates`    | Also replace every verbatim occurrence outside the regex-matched spans.                              |
| `injectHosts`       | Where the proxy substitutes the real value back. Default = `network.allowedDomains`.                  |

### Env Credential

```json
{ "name": "ANTHROPIC_API_KEY", "mode": "mask", "injectHosts": ["api.anthropic.com"] }
```

| Field         | Meaning                                                                                                       |
| ------------- | ------------------------------------------------------------------------------------------------------------- |
| `name`        | POSIX env name (regex-validated so flags can't be parsed).                                                   |
| `mode`        | `"deny"` (unset inside sandbox) or `"mask"` (sentinel).                                                      |
| `injectHosts` | Same semantics as files.                                                                                     |

### Cross-field Validation

- `injectHosts` patterns must be reachable via `network.allowedDomains` (semantic — `*.github.com` covers `api.github.com`).
- `injectHosts` patterns must NOT be entirely covered by `network.tlsTerminate.excludeDomains` (would never inject anywhere).
- `injectHosts: []` (explicit empty) is rejected — self-contradictory.
- `mode: "mask"` requires either `network.tlsTerminate` set OR `credentials.allowPlaintextInject: true` (explicit opt-in to plaintext).
- File `path` ending with `/` is rejected for `mode: "mask"` (single-file masking isn't defined for directories).

## 8.4 The SentinelRegistry

Singleton inside the orchestrator process. Per-process Map:

```
sentinelRegistry = {
    nameToSentinel: Map<name, sentinelString>,
    sentinelToReal:  Map<sentinelString, realString>,
    sentinelToHosts: Map<sentinelString, string[]>   // injectHosts
}
```

`register(name, real, injectHosts)` returns the sentinel and stores both mappings. `clear()` drops everything (called from `reset()`).

### Format of the Sentinel

`<srt:NAME:RANDOM>` where:
- `<NAME>` is the env name or a sanitized file/path hash.
- `<RANDOM>` is 16 hex bytes (32 chars) per registration, generated with `crypto.randomBytes`.

A unique random suffix means the same credential masked in two different sessions produces a different sentinel — preventing cross-session correlation (an attacker holding bytes from one session cannot recognise the same value in a future session).

### Substitution Algorithm

`substituteInHeaders(headers, destHost, matchesDomainPattern)`:

```
for each [headerName, headerValue] in headers:
    for each (sentinel, real) in sentinelToReal:
        if destHost matches every host in sentinelToHosts[sentinel]:
            headerValue = headerValue.replace(sentinel, real)
    headers[headerName] = headerValue
```

Iterating headers (not building a new Headers object) keeps the mutation in-place — important because the headers back-references the Node `OutgoingMessage` directly.

### Sentinel lookup at TLD

`namesInjectableAt(host, matches)` returns the list of credential names
whose `injectHosts` would inject at this host. Used at network decision
time so we can log "this masked credential has its placeholder going
outbound because the host is excluded from TLS termination".

## 8.5 Masked File Store (`MaskedFileStore`)

A sandboxed process that *must* read a credential file (because the
unmasked tool fails without it) gets a managed fake.

### What the Store Does

`buildMaskedFileBinds(credentialFiles, allowedDomains, sentinelRegistry, store)`:

```
for each credentialFile in credentialFiles:
    skip if mode != "mask"
    realPath = expandUserPath(credentialFile.path)
    realBytes = readFileSync(realPath)             ← may throw; skipped if so
    extract = credentialFile.extract
    if extract:
        re = new RegExp(extract, 'g')
        sentinel = register(realPath, realBytes.match(re)?.[1] ?? "", allowedDomains)
        maskedBytes = realBytes.replace(re, m => m.replace(matchedValue, sentinel))
        if maskDuplicates:
            maskedBytes = maskedBytes.replace(sentinel, sentinel)   ← noop, plus original substitution
        if onExtractNoMatch == "warn":
            if no match found: console.warn("...")
        if onExtractNoMatch == "deny":
            downgrade to mode="deny"   ← fold into the file deny set
        if onExtractNoMatch == "error":
            throw
    else (whole-file masking):
        sentinel = register(realPath, realBytes, allowedDomains)
        maskedBytes = sentinel

    fakePath = store.write(realPath, maskedBytes)
    bind = { realPath, fakePath }
    maskedFileBinds.push(bind)

return { binds: maskedFileBinds, degradeToDenyPaths }
```

`MaskedFileStore` writes into a managed temp dir (created lazily on first call). All files in the dir are deleted at `reset()` time. The dir is bind-mounted RO into the sandbox (Linux/macOS) so the sandbox can read but not write.

### Whole-File vs Structured Masking

```
realFile:
    registry=https://registry.npmjs.org/
    _authToken = "abc123def456"

Whole file masked:
    <srt:/home/me/.npmrc:abc123def>
    (entire content replaced)

Structured masked (extract = '_authToken = "([^"]+)"'):
    registry=https://registry.npmjs.org/
    _authToken = "<srt:/home/me/.npmrc:abc123def>"
    (only the captured group is replaced)
```

Structured is preferred for tools that parse the file. Whole-file is for tools whose content IS the credential.

## 8.6 Mode Implications per OS

| OS      | mode = "deny"                                  | mode = "mask"                                                                |
| ------- | ---------------------------------------------- | ---------------------------------------------------------------------------- |
| macOS   | `readConfig.denyOnly.push(realPath)`           | `readConfig.denyOnly.push(realPath)` (degraded; SBPL can't redirect reads yet) |
| Linux   | bwrap `--ro-bind /dev/null <realPath>`          | `--ro-bind <fakePath> <realPath>` (read-only), with fakePath owned by host    |
| Windows | `acl grant` does not include; ALLOW-only adds the sandbox user a deny path effectively (the sandbox user has no rights anyway); the file becomes unreadable |
| Windows | Same as macOS — SBPL equivalent is the ACL stamp/grant; mask degrades to deny on Windows as well until DYLD-equivalent is built. |

## 8.7 Per-OS Injection Trigger

| OS      | Where the substitution happens                                                                                 |
| ------- | -------------------------------------------------------------------------------------------------------------- |
| macOS   | On the TLS-terminated path inside the JS HTTP proxy (`mutateHeaders` callback).                                |
| Linux   | Same as macOS.                                                                                                 |
| Windows | Same as macOS (Node ↔ Node in proxy). The leaf is minted in JS; substitution is JS-side.                       |
| Network request path (no termination) | `mutateHeadersPlaintext` callback IF the caller set `allowPlaintextInject: true`. Otherwise the sentinel is left in place. |
| Opaque-tunnel CONNECT (excluded host) | Not injected — the proxy can't see HTTPS bytes. The sentinel is *visible to the upstream* if the upstream IS the legitimate host, which is why `excludeDomains` is a per-host opt-out (mTLS / pinning), not a global thing. |

## 8.8 Cross-cutting: Schema Validation

`SandboxRuntimeConfigSchema` has a `superRefine` that walks `credentials.{files, envVars}` and:

1. Verifies `injectHosts[i]` is reachable via `network.allowedDomains` (semantic coverage).
2. Verifies `injectHosts[i]` is NOT entirely covered by `tlsTerminate.excludeDomains`.
3. Sets a `hasMasked` flag; if any credential has `mode == "mask"` and neither `tlsTerminate` nor `credentials.allowPlaintextInject` is set, the schema rejects the entire config.

## 8.9 Mental Model: Why This Is Strong

A naïve "mask the env var to a dummy value and the tool will leak it" defense is broken. The tool may extract the value from anywhere — its own binary, a config file, the in-memory cache of another process — and send it to a host of its choosing.

What `srt`'s model buys you is:

- The substitution happens at **last possible moment** (proxy egress), gated on
  cert-verification + domain allow-list + credential allow-list. The tool never
  holds the real value.
- The tool CAN'T reach any other host (the network fence is still on).
- The tool CAN'T exfiltrate via `~/.npmrc` either (the file is masked or denied).

A sandbox break has to circumvent all three: file isolation, network isolation, AND find a way past the TLS-termination endpoint. That's two primitives away from where most contemporary sandbox breaks happen.

## 8.10 Open Questions for v2

- **DYLD interposer** for macOS so `mode: "mask"` doesn't degrade to `mode: "deny"`.
- **Structured substitution in file content beyond headers** — currently we substitute in HTTP headers and proxy request bodies; substituted bytes inside the request body of an HTTPS POST require the proxy to actually inspect the body (it does, but only when `filterRequest` looks at it).
- **Per-write re-stamp on host** — currently the masked file store holds the masked bytes; the worker could write out a sentinel and then have the tool "see" the real bytes via a subsequent read. Not yet a concern because write-deny wins.
