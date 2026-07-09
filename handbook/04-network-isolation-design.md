# 04 — Network Isolation

This document covers the network half of the sandbox: the host proxies, their
filtering pipeline, the TLS-termination seam, the parent-proxy escape hatch,
and the host-routing chain inside the sandbox.

## 4.1 Goals

| ID  | Goal                                                                                                                       |
| --- | -------------------------------------------------------------------------------------------------------------------------- |
| N-1 | All outbound network traffic from the sandbox is **observable** by the host (for filtering, credential substitution, MITM). |
| N-2 | Domain allow-/deny-lists are enforced at the proxy boundary, not at the tool level.                                        |
| N-3 | The default posture is *no network at all* (empty `allowedDomains`). Adding a domain must be an explicit choice.            |
| N-4 | The proxy is **authenticated**: a 16-byte hex token gates every CONNECT / absolute-URI request.                            |
| N-5 | The HTTP proxy may optionally perform **in-process TLS termination** (`tlsTerminate`) so the host can see decrypted HTTPS.   |
| N-6 | Per-request body & header access is opt-in via `network.filterRequest`. Crashes or rejections in the callback **deny** the request. |

## 4.2 Host Architecture

```
                ┌─────────────────────────────────────────────────────────────┐
                │                       srt-host                              │
                │                                                             │
client ─── TCP ──▶ muxProxyServer (single port, dispatches by first byte)    │
                │     │                                                       │
                │     ├─[ HTTP method prefix ]─▶ createHttpProxyServer()      │
                │     │                          │                            │
                │     │                          ├▶ plain HTTP req ⇒ upstream │
                │     │                          ├▶ CONNECT + non-TLS = opaque tunnel
                │     │                          ├▶ CONNECT + TLS ⇒          │
                │     │                          │     terminateAndForward()  │
                │     │                          ├▶ GET/POST http://host ⇒     │
                │     │                          │     optional MITM via UDS  │
                │     │                          │     optional filterRequest │
                │     │                          │     optional mutateHeaders │
                │     │                          ├▶ cert+key override          │
                │     │                          └▶ tlsTerminateUpstreamCA     │
                │     │                                                       │
                │     └─[ SOCKS greeting ]────▶ createSocksProxyServer()      │
                │                                └▶ dialDirect / parent proxy │
                └─────────────────────────────────────────────────────────────┘
```

The mux (`sandbox/mux-proxy.ts`) is necessary because:

1. Some clients (Java's `Proxy.Type.HTTP` selector) hand out **one** proxy URL; tools that the user mixes in one shell shouldn't need two URLs.
2. The Windows WFP filter only PERMITs a small port range for loopback; sharing one port halves the range consumption.
3. There is no semantic difference to the user between "HTTP proxy on :N" and "SOCKS on :M" if both serve the same allow-list.

The mux dispatch is a trivial byte-sniff: any first byte in `{0x04,0x05}` (SOCKS4/5) and the first 4 bytes look like a SOCKS greeting → SOCKS handler. Anything else is sent to the HTTP handler.

## 4.3 HTTP Proxy Pipeline (`http-proxy.ts`)

### Step-by-step

1. **Accept TCP** on the bound loopback port.
2. **Auth** — if `proxyAuthToken` is set, validate `Proxy-Authorization: Basic base64("srt:<token>")`. A malformed header → `407 Proxy Authentication Required`.
3. **`CONNECT` method:**
    1. Parse `<host>:<port>` from the request URL.
    2. Run `filter(port, host)`. Block → `403 Forbidden` + `X-Proxy-Error: blocked-by-allowlist`.
    3. **Route decision** in priority order:
        1. `tlsTerminate` AND `shouldTerminateTLS(host, port) === true` ⇒ `terminateAndForward`.
        2. `mitmProxy?.domains` matches ⇒ tunnel through the configured Unix-domain-socket MITM proxy (`UNCONNECT` to `socketPath`).
        3. `parentProxy` resolves via `selectParentProxyUrl(host, port, noProxy)` ⇒ tunnel via HTTP CONNECT.
        4. Otherwise `dialDirect(host, port)`.
    4. Send `HTTP/1.1 200 Connection Established\r\n\r\n` back to the client.
4. **Plain HTTP** (absolute URI form: `GET http://example.com/foo HTTP/1.1`):
    1. Validate auth.
    2. `filter(port, host)`.
    3. If `tlsTerminate` AND host not excluded ⇒ upgrade to TLS via the CA's leaf and run the request as if it were HTTPS (this path is rarely used; `tlsTerminate` + plain-HTTP requests hits the same handler as the CONNECT path because we can read the bytes anyway).
    4. Call `decideAndRespond(filterRequest, req, res, url, signal)` if `filterRequest` is configured. Only **decryption-termination** path bodies are seen; **opaque-tunnel** CONNECTs are unreadable.
    5. `mutateHeaders` (the credential injector) runs after the allow decision and before outbound `http(s).request`.
    6. Forward via:
        - `parentProxy` if configured (tunnel through CONNECT);
        - else `dialDirect` and then `httpRequest` for HTTP, `httpsRequest` for HTTPS.
    7. Pipe the upstream response back to the client with `stripHopByHop` headers removed.

### Why `request.body` is teed

`filterRequest` is given a web-standard `Request` with a `.body` readable
stream. Body-less methods (GET/HEAD/OPTIONS) skip the tee — the bytes are
piped straight upstream. For PUT/POST/PATCH etc.:

```ts
const web = Readable.toWeb(req).tee()
const [forCallback, forUpstream] = web
// forCallback goes into `new Request(url, { body, signal })`
// forUpstream goes into the actual upstream pipe
```

If `filterRequest` never reads its branch (the common case — most filters
inspect URL/method/headers, not body bytes), we cancel it so the tee stops
buffering the upload.

## 4.4 SOCKS5 Proxy Pipeline (`socks-proxy.ts`)

### Method negotiation

```
client →  05 01 00      (greeting: SOCKS5, 1 method, "NO AUTH")
server ←  05 00         ("NO AUTH" selected; or 02 00 02 for password auth)
```

If `proxyAuthToken` is set, the server replies `02 00 02` (USER/PASS) and
validates `username:password === "srt:<token>"` (the same token used for HTTP
basic — keeps the client-side URL the same).

### Request phase

```
client →  05 01 00 01 7f 00 00 01 00 50  ...
          ver cmd rsv atyp addr            port
```

- `atyp=01` IPv4 ⇒ 4 bytes
- `atyp=03` DOMAINNAME ⇒ len byte + N bytes ⇒ run them through `canonicalizeHost` then through the same `filter(port, host)` used for HTTP.
- `atyp=04` IPv6 ⇒ 16 bytes

The host filter is identical to HTTP, so the embedder's allow/deny/ask logic
is single-source. **Authentication mismatch → 0x01 (general SOCKS failure)**.
Allow mismatch → `0x02` (connection not allowed by ruleset) so the client
sees a clean "no" without leaking whether the host is reachable.

### Upstream route

Same decision tree as HTTP CONNECT, but using SOCKS5 CONNECT against the
parent: `socks://user:token@host:port` (HTTP parent) or `socks://user:token@host:port` (SOCKS parent).

## 4.5 The Shared Filter Pipeline (`sandbox-manager.ts`)

`filterNetworkRequest(port, host, askCb)` is the single entry point. Implementation:

```
isValidHost(host)            // rejects NUL/control chars; IPv6 zone-id; brackets
canonicalHost = canonicalizeHost(host) ?? host   // inet_aton forms, trailing dot, etc.

for each deniedDomain in deniedDomains:
    if matchesDomainPattern(canonicalHost, deniedDomain):
        return false

for each allowedDomain in allowedDomains:
    if matchesDomainPattern(canonicalHost, allowedDomain):
        return true

if not askCb or strictAllowlist:
    return false

return askCb({host, port})
```

`isValidHost` and `canonicalizeHost` are critical defenses:

- `evil.com\x00.example.com` would pass naïve `endsWith` matching; `isValidHost` rejects every control byte.
- `2852039166` (=`169.254.169.254` in decimal) bypasses a denylist entry for `169.254.169.254`; `canonicalizeHost` resolves both to the same string before matching.
- Trailing-dot FQDNs (`example.com.`) bypass denylists if compared literally; canonicalization strips the dot.

## 4.6 Domain-Pattern Matching (`domain-pattern.ts`)

```
function matchesDomainPattern(hostname, pattern):
    h = lowercase(hostname)
    if pattern == "*": return true                              (deniedDomains only)
    if pattern startsWith "*.":
        if isIP(h): return false                                (refuse wildcard-suffix match for IP literals)
        return h endsWith "." + pattern[2..].lower()             (strict subdomain only)
    return h == pattern.lower()
```

Note: `*.example.com` does **not** match `example.com` itself. To include the apex you must also add the bare domain (`example.com`) — this matches what users actually intend.

## 4.7 Hot-Reload (`updateConfig`)

Network rules are hot: reassign `config` and the next request reads the new list. The proxy objects (`httpProxyServer`, `socksProxyServer`) capture `filterNetworkRequest` by closure, so the new closure sees the new `config` reference on the next call. No rebind; no port churn.

Windows hot-reload is the same — the JS proxies still close over `config`, the WFP layer does not see the new rules because Windows doesn't have a per-deny filter (it has a generic "BLOCK by sandbox SID"). The hot-reload only matters for `network.*`. Filesystem hot-reload on Windows is *warned* but not applied — reset+init is required.

## 4.8 TLS Termination (`tls-terminate-proxy.ts`, `mitm-ca.ts`, `mitm-leaf.ts`)

### Why a custom MITM

The library exposes an optional, in-process MITM path so a sandboxed tool can be inspected. Toolchains:

| User's tool | TLS validation source               | Trust bundle fed in                                                                                        |
| ----------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `curl`      | `SSL_CERT_FILE`, `CURL_CA_BUNDLE`   | set to the trust bundle path                                                                               |
| `git`       | `GIT_SSL_CAINFO` (per-system fallback to OpenSSL) | set to the trust bundle path                                                                       |
| `node`      | `NODE_EXTRA_CA_CERTS`               | set to the trust bundle path                                                                               |
| `python`    | `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` | set to the trust bundle path                                                                             |
| `cargo`     | `CARGO_HTTP_CAINFO`                 | set to the trust bundle path                                                                               |
| schannel (Windows `curl.exe`, `Invoke-WebRequest`, .NET, default-backend `git`) | OS cert store | the sandbox user's `CurrentUser\Root` is updated via `srt-win user trust-ca <path>` |
| msys2 / OpenSSL | env vars                       | same as curl/git                                                                                           |

### Trust Bundle Composition

`mitmCA.trustBundlePath` is a single PEM file written by `createMitmCA()`:

```
<MITM CA cert>
-----BEGIN CERTIFICATE-----
<Mozilla root store as concatenated PEMs>
-----BEGIN CERTIFICATE-----
<NODE_EXTRA_CA_CERTS contents (cleaned of non-CERTIFICATE blocks)>
<tlsTerminate.extraCaCertPaths files (cleaned similarly)>
```

The cleaning step (`PEM_CERT_BLOCK` regex) prevents a combined PEM file (e.g. a `cert+key.pem`) from leaking the private key into a world-readable bundle.

### Leaf-Mint Protocol

When a CONNECT arrives for a host the proxy decides to terminate:

1. Look up `(host:port)` in `mitmCA.leafCerts` cache; if hit, reuse.
2. Mint a fresh leaf:
    - Common Name = SAN = `<host>`.
    - SubjectAltName = `DNS:<host>, DNS:*.<host-base>` (single-label wildcard to admit `a.b.host`).
    - Sign with `mitmCA.key`. SKI of the leaf bytes = AKI key identifier (matching the CA's SKI; node-forge stores SKI as hex, AKI as bytes — convert before applying).
    - Validity 1 year (no, actually: **24 hours** to keep risk small).
3. Build a `tls.createSecureContext({cert, key})`. Cache by hostname.
4. `socket.once('data', sniff-for-ClientHello)` — actually done via `peekForClientHello` before writing `200 Connection Established` to the client.
5. Upgrade the socket to TLS using the cached context; the legacy HTTP request comes out of that upgraded stream.

### Excluded hosts (`tlsTerminate.excludeDomains`)

Some hosts must **not** be terminated:

- **mTLS upstreams** — only the in-sandbox client holds the client certificate. Terminating would re-originate the connect from the proxy and the upstream would reject.
- **Certificate-pinning clients** — they reject the MITM CA. e.g. parts of cloud CLIs that pin the API server's public cert.

For excluded hosts the proxy leaves the CONNECT as an opaque byte tunnel (still hostname-allowlisted via `filter`, but **not** seen by `filterRequest` and **not** subject to sentinel injection on HTTPS). Plain-HTTP requests to those hosts still go through the normal pipeline (they don't need TLS termination to be visible).

### CRL serving (Windows only)

Schannel performs online revocation checking when the leaf has a CRL Distribution Point. The chain fails with `CRYPT_E_REVOCATION_OFFLINE` if the URL is unreachable from the sandbox user (it usually will be — sandbox has only loopback egress).

`srt-win` therefore writes an empty CRL into `state.db` and the JS proxy serves it at `/srt.crl` (origin-form path `CRL_PATH`). The CRL is signed by the same MITM CA. Every leaf minted with `mitmCA` has a CDP extension pointing to `http://127.0.0.1:<muxPort>/srt.crl`. Schannel → "checked, not revoked" → sandbox survives.

> **Caveat**: this setting is only wired for Windows. On Linux the child runs under `bwrap --unshare-net` and the CDP URL would be unreachable from the host namespace. Linux tools that check revocation by default (none in the supported matrix) would hard-fail; we accept that because it's not the deployed platform.

## 4.9 Parent Proxy (`parent-proxy.ts`)

When the user's network only allows egress through a corporate proxy, the orchestrator itself must use that parent to reach the internet. `parentProxy` configuration:

```ts
{
  http?:  "http://user:pass@proxy.corp:8080",
  https?: "http://user:pass@proxy.corp:8443",   // optional, falls back to http
  noProxy: ".corp,10.0.0.0/8,127.0.0.0/8"      // comma list of suffixes or CIDRs
}
```

If both fields are unset, the manager falls back to the env vars (`HTTP_PROXY` etc.), but it does **not** echo the parent URL into the child env (we set `HTTP_PROXY=http://127.0.0.1:<port>` to point at ourselves).

The matching logic:

1. Parse `noProxy` once per init (lazy).
2. For each destination `(host, port)`:
    - If `host` matches any `noProxy` suffix or CIDR → **direct connect**.
    - Else → dial `selectParentProxyUrl(host, port, noProxy)` for the appropriate scheme.
3. For HTTPS upstreams: build a `CONNECT host:port` to the parent's HTTPS proxy URL via `http.request({host:parent, port:parentHttpsPort, method:'CONNECT'})`.
4. For HTTP upstreams: absolute-URI form on the proxy (`GET http://example.com/foo HTTP/1.1`).

The child **never** sees the parent credentials: only `HTTP_PROXY=http://127.0.0.1:<ourport>` is set in the sandbox env.

## 4.10 Routing Inside the Sandbox

| OS        | Mechanism                                                                                                                                                                                       |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| macOS     | `(allow network-outbound (remote ip "localhost:<httpProxyPort>"))` and the same for `<socksProxyPort>`. Tools that ignore `HTTP_PROXY` (rare) cannot reach the internet.                       |
| Linux     | `--unshare-net` + bind-mount two Unix sockets into the sandbox. Inside the sandbox, two `socat` listeners run on TCP `:3128` (HTTP) and `:1080` (SOCKS). Child tools see those two ports only. |
| Windows   | WFP filter set PERMITs `127.0.0.0/8:low..high` only. Sandbox account is BLOCKed for everything else. The JS proxies bind inside that range and the child env points `HTTP_PROXY`/`HTTPS_PROXY` at them. |

This is the dual-isolation guarantee from §1.3 G-3 of the requirements: a sandboxed process cannot reach the internet except via the audited proxies.

## 4.11 Per-Request Filter

`network.filterRequest` is the only allowed seam to add policy inside the proxy. The contract:

- **Input**: a web-standard `Request` object. Lazy body stream (a tee).
- **Output**: `{action: 'allow'} | {action: 'deny', reason?: string}`.
- **Failure mode**: throwing or rejecting → `deny` with reason = the error message (fail-closed).
- **Applies to**: plain HTTP via the proxy, AND any CONNECT that was terminated (`tlsTerminate`). Does NOT apply to opaque-tunnel CONNECTs (excluded hosts).

Common use cases:

- Body size caps (deny `>10MB` POST bodies).
- URL prefix restrictions (deny `PUT https://github.com/...` even though `github.com` is allow-listed).
- Method restrictions (deny PATCH on a read-only API).
- Audit (log the body bytes for compliance; then `allow`).

## 4.12 Credential Substituion (Sentinel Injection)

The sentinel registry holds a single string per masked credential:

```
sentinelRegistry.register("OPENAI_API_KEY", realValue, [allowedDomains])
   → returns "<srt:OPENAI_API_KEY:abc123...>"   (unique per registration)
   → stores realValue in a per-process Map
```

The child env gets `OPENAI_API_KEY="<srt:OPENAI_API_KEY:abc123...>"` (per `wrapCommandWithSandboxX`.`setEnvVars`). Inside the proxy's TLS-terminated path:

```
mutateHeaders = (headers, destHost) => sentinelRegistry.substituteInHeaders(headers, destHost, matchesDomainPattern)
```

For every header value, every occurrence of any sentinel `<srt:NAME:RAND>` that is allowed at `destHost` is replaced with the real bytes. Per-sentinel `injectHosts` ensures credential A's sentinel cannot be laundered through credential B's allowed host.

Substitution only happens on the TLS-terminated path (since upstream bytes are encrypted otherwise). For plain HTTP, `mutateHeadersPlaintext` is an opt-in via `credentials.allowPlaintextInject` (default false).

## 4.13 Proxy Auth Token

The token is a 16-byte hex string (`randomBytes(16).toString('hex')`), generated when the orchestrator spins up its proxies. It survives across `wrapWithSandbox(...)` calls in the same session.

Embedded in:

- `HTTP_PROXY=http://srt:<token>@127.0.0.1:<port>`
- `HTTPS_PROXY=http://srt:<token>@127.0.0.1:<port>`
- `ALL_PROXY=socks://srt:<token>@127.0.0.1:<port>` (where supported)

Validated by:

- HTTP: parsing `Proxy-Authorization` as Basic with username `srt` and password `<token>`.
- SOCKS: RFC 1929 USER/PASS sub-negotiation with the same pair.

External programs that ignore auth (some `curl --proxy-anyauth` overloads, or curl reading URL username/password) still work. Programs that follow the standard libraries also work. Programs that strip URL credentials: lose connectivity (intended — they aren't supposed to reach the proxy without authenticating).

The token is **not** a secret from the sandboxed process (it's in the URL the child sees). It's a barrier from other host processes dialing the loopback port.
