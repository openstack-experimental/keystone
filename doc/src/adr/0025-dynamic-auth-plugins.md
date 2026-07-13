# 25. Dynamic Auth Plugins via WebAssembly

**Date:** 2026-07-02

## Status

Proposed

## Reference

Contrasts with ADR 0018 (Plugin Linking - static, compile-time linking). Extends
ADR 0017 (Security Context), ADR 0023 (Audit). Reuses the resource-bound
patterns established in ADR 0020 §5.1 (regex evaluation timeout/size caps).
Amends ADR 0020 §2/§3 (`IdentitySource` gains a `WasmPlugin` variant;
`MappingContext` gains an optional plugin-hash field - §4 "`mapping` Mode").
Reuses ADR 0024 §3.B (`externalId` lookup index) for SCIM-aware identity linking

- §4 "Admin-Authorized External Identity Linking."

---

## 1. Context & Motivation

All extensibility in `keystone-rs` today is resolved at **compile time**:

- Backend drivers (SQL, Raft, etc.) are separate crates registered through
  `inventory::submit!` and forced into the link graph by the `anchor()` /
  `build.rs` convention (ADR 0018). Adding or changing a driver requires a new
  crate, a Cargo dependency edit, and a full rebuild + redeploy of the binary
  across the cluster.
- Authentication _methods_ are a closed Rust enum, `AuthenticationContext`
  (`crates/core-types/src/auth.rs:1169`), with variants `Password`, `Admin`,
  `Token`, `ApplicationCredential`, `Oidc`, `K8s`, `Trust`, `WebauthN`,
  `Mapping`. `crates/core/src/api/auth.rs` matches this enum exhaustively to
  build a `SecurityContext`. The `[auth] methods` config value
  (`crates/config/src/auth.rs:22-27`) is a `Vec<String>` allowlist, but every
  string in it must already correspond to a variant compiled into the binary.

This is the correct model for first-party backends (ADR 0018's stated goal: zero
manual maintenance, compile-time enforcement). It is the wrong model for
**operator- or customer-specific authentication logic**: a proprietary SSO
quirk, a legacy directory bridge, a step-up/MFA policy tied to an internal risk
service, or a one-off migration bridge that a specific deployment needs but that
has no place in the upstream `keystone-rs` tree. Today, satisfying any of these
requires either forking `keystone-rs` or waiting on a release that adds a
bespoke enum variant - in both cases a full recompile and coordinated
cluster-wide redeploy.

This ADR introduces a second, orthogonal extensibility mechanism: **dynamic auth
plugins**, compiled to WebAssembly, loaded from disk at process startup, and
invoked as first-class authentication methods - without touching `keystone-rs`
source or its build.

### Requirements

A plugin must be able to:

1. Act as a full authentication method: receive the raw login request and either
   accept it (producing an identity + claims) or reject it - not merely observe
   a decision made elsewhere.
2. Perform outbound HTTP calls (e.g. call a third-party risk API or legacy
   directory as part of the decision).
3. Call a curated set of internal Keystone operations when necessary - most
   importantly, provision a local user on first login.
4. Authenticate a user who already exists through some other channel (most
   notably SCIM provisioning, ADR 0024) - not only identities the plugin
   provisions itself. See §4 "Three Operating Modes" for how this is satisfied
   without weakening requirement 1's guarantees.
5. Redirect a request to a different, already-registered auth method based on
   inspecting the raw credential, for clients that cannot be made to request a
   custom method name themselves (`application_credential`-shaped auth for
   Terraform is the motivating case) - without that routing decision itself
   being able to authenticate anyone. See §4 "Guest Contract - `route` Mode."

### Non-goals

- Replacing the ADR 0018 static-driver model for first-party backends.
- Per-domain/multi-tenant plugin scoping (a domain admin installing their own
  plugin). See §8 (Open Questions) - this ADR restricts plugins to
  cluster-global, system-admin-installed only.
- Hot reload / upload-via-API. Plugins are loaded once at process startup from
  local disk (§5). A future ADR may revisit this (§8).
- General-purpose scripting for non-auth extension points (policy, mapping
  rules, etc.). Those already have dedicated mechanisms (OPA - ADR 0002; the
  Unified Mapping Engine - ADR 0020).

### Threat Model

Installing a plugin already requires filesystem and `keystone.conf` write access
on every node - operationally equivalent to root on the Keystone host. This ADR
therefore does **not** attempt to defend against an operator who deliberately
installs a plugin they wrote to be malicious; that is out of scope, the same way
a malicious `[database] connection` value is out of scope for any other ADR.

What it **does** defend against, because both are realistic even for a plugin
the operator trusts and reviewed:

1. **A buggy or exploited plugin** - third-party code, however well-reviewed,
   can have logic errors or be compromised via a supply-chain issue in its own
   dependencies (the plugin author's build, not `keystone-rs`'s). The blast
   radius of such a bug or compromise must be bounded to "this one auth method
   behaves incorrectly," not "arbitrary account takeover" or "arbitrary internal
   API access."
2. **An anonymous network attacker** - every plugin invocation is reachable
   pre-authentication (it _is_ the authentication step), so the design must
   assume a remote, unauthenticated party can trigger plugin execution and
   `http_fetch` calls at will, and bound the damage that's possible from that
   alone (resource exhaustion, SSRF, credential exposure).
3. **Widened credential exposure from `route` mode specifically** - a
   `full_auth`/`mapping` plugin is only invoked for requests already addressed
   to it by name, so a buggy or exploited one is exposed to at most the traffic
   an operator explicitly opted into routing there. A `route`-mode plugin breaks
   that property: it must run on every request whose `identity.methods` matches
   its `inspect_methods` list (§4 "Guest Contract - `route` Mode"), including
   ones it ultimately passes through unmodified, so it sees raw credential
   material (headers, method payloads) for a strictly larger slice of login
   traffic than any other plugin in this design - for example, every
   `application_credential` attempt in the cluster, not just ones actually meant
   for a custom handler. A bug or compromise here doesn't grant broader
   authentication power (§4's structural constraints - target-method allowlist,
   no identity resolution, no `scope` access - still bound that), but it does
   mean the plugin is a wider _observation_ surface: it is positioned to see,
   and potentially exfiltrate via a compromised `http_fetch` call, credential
   material belonging to logins it has no legitimate reason to act on.
   `inspect_methods` scoping (§4) and the `headers`/`payloads` allowlists are
   the load-bearing controls for this actor - narrowing what triggers invocation
   and what a triggered invocation can see is the only mitigation available,
   since the plugin must structurally be able to inspect _something_ about every
   matching request to decide whether to route it.

Every control in §4–§7 is sized against these three actors, not against a
deliberately hostile plugin author.

---

## 2. Decision Summary

| Axis                                                                                                                                                                                        | Decision                                                                                                                                                                                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WASM runtime                                                                                                                                                                                | [Extism](https://extism.org/) (host runtime built on `wasmtime`)                                                                                                                                                                                                                  |
| Hook point                                                                                                                                                                                  | Full custom auth method - a plugin is a peer of `password`/`openid`/`k8s`                                                                                                                                                                                                         |
| Tenancy / trust scope                                                                                                                                                                       | Cluster-global; installed only by system admins via `keystone.conf`                                                                                                                                                                                                               |
| Distribution                                                                                                                                                                                | Local filesystem path, pinned by a SHA-256 checksum in `keystone.conf`                                                                                                                                                                                                            |
| Failure handling                                                                                                                                                                            | Fail closed - any plugin error rejects the login attempt                                                                                                                                                                                                                          |
| Internal-call capability                                                                                                                                                                    | Curated, per-plugin host-function allowlist (no generic RPC)                                                                                                                                                                                                                      |
| Resource limits                                                                                                                                                                             | Fuel metering + wall-clock deadline + linear-memory cap, all configurable                                                                                                                                                                                                         |
| Identity binding                                                                                                                                                                            | Host-issued handles into a plugin-owned `(plugin_name, external_id)` namespace - never a raw `user_id`, never a lookup over existing accounts                                                                                                                                     |
| Provisioning domain scope                                                                                                                                                                   | Config-declared `provision_domain_id`; `create_user` rejects any other domain                                                                                                                                                                                                     |
| Claims                                                                                                                                                                                      | Reserved-key denylist + size/count caps, enforced by the host                                                                                                                                                                                                                     |
| Sensitive headers                                                                                                                                                                           | Hard denylist (`Authorization`, `Cookie`, ...) - never exposable via config                                                                                                                                                                                                       |
| Invocation rate limiting                                                                                                                                                                    | Per-source-IP token bucket fronting a per-plugin token bucket + global concurrency cap (mirrors ADR 0020 §7.2)                                                                                                                                                                    |
| Load-time checksum mismatch                                                                                                                                                                 | That plugin only is disabled + a critical alert is raised; the node and every other configured auth method still start                                                                                                                                                            |
| Plugin-compromise cleanup                                                                                                                                                                   | Bulk admin `revoke_all` endpoint, scoped per `plugin_name` - disables provisioned users, revokes granted roles, deletes identity links, revokes tokens                                                                                                                            |
| `http_fetch` SSRF policy                                                                                                                                                                    | Connect-time IP re-validation against `allowed_hosts`; no redirects by default                                                                                                                                                                                                    |
| Outbound secrets                                                                                                                                                                            | Host-injected from config/env; never placed in guest memory                                                                                                                                                                                                                       |
| `assign_role` scope                                                                                                                                                                         | Config-declared role allowlist; system-scope grants always forbidden                                                                                                                                                                                                              |
| WASI imports                                                                                                                                                                                | None registered - only the curated host functions in §6                                                                                                                                                                                                                           |
| Token/plugin-version binding                                                                                                                                                                | Per-plugin `valid_since` cutoff in config; verification rejects any token whose `issued_at` predates it (the fixed `FernetToken` payload cannot carry a per-plugin SHA-256). `full_auth` only - a `mapping`-mode token carries no plugin-recoverable field, see §4 caveat and §8. |
| Auth-method name collisions                                                                                                                                                                 | Plugin names reserved-word-checked against builtins at load time                                                                                                                                                                                                                  |
| Pre-existing (e.g. SCIM) users, low-privilege path                                                                                                                                          | `mapping` mode - plugin transforms claims; Mapping Engine (ADR 0020) remains the terminal identity authority, no binding needed                                                                                                                                                   |
| Pre-existing (e.g. SCIM) users, full-authority path                                                                                                                                         | `full_auth` mode + admin-authorized external identity linking - never plugin-self-service                                                                                                                                                                                         |
| Coarser "any user in my domain" resolution                                                                                                                                                  | Rejected - always requires explicit per-identity or per-SCIM-realm admin authorization (§4)                                                                                                                                                                                       |
| Routing ahead of method dispatch (e.g. a client that only ever sends a fixed method name, such as `application_credential`-shaped auth, but the real handler must vary by credential shape) | `route` mode - plugin sees the raw, pre-dispatch request and may relabel `identity.methods` + hand a payload to exactly one allowlisted target method; single-shot, never touches `scope`, target method still independently verifies the credential (§4)                         |

---

## 3. Runtime: Extism on wasmtime

No WASM runtime exists anywhere in the current dependency tree (`Cargo.lock`
only contains `wasm-bindgen`/`wasm-streams`, transitive browser-target deps of
an unrelated crate) - this is greenfield.

**Extism** is chosen over raw `wasmtime` or `wasmer` because it already solves
the three hardest parts of this problem as a framework, rather than requiring
`keystone-rs` to invent them:

- A stable, versioned **Plugin-Development-Kit (PDK)** ABI with official SDKs
  for the languages a third-party plugin author is likely to use (Rust, Go,
  JS/TS, Python, C, Zig, ...) - we do not have to design or document our own
  guest-side calling convention.
- A built-in **host-function** registration model (`extism::Function`) that maps
  directly onto the "curated allowlist" capability model this ADR requires (§6)
  - each host function is registered per-`Plugin` instance, so a plugin simply
    cannot see a host function it wasn't given.
- A built-in **HTTP allow-list** (`allowed_hosts` on `extism::Manifest`) for the
  guest-initiated HTTP use case (§6.A), instead of `keystone-rs` having to
  hand-roll a WASI-sockets bridge.
- It already wraps `wasmtime` for fuel metering, wall-clock timeouts
  (`Plugin::new` builder timeout), and linear-memory limits (§7) - the
  resource-bounding primitives this ADR needs are present, not something to
  build from scratch.

The trade-off is an additional framework dependency with its own release
cadence, on top of `wasmtime`. Given no existing runtime is present to reconcile
with, and the PDK ergonomics directly serve requirement 3 (guest-language
diversity for third-party plugin authors), this is judged worth it.

---

## 4. Hook Point: Plugins as a Full Auth Method

A plugin is registered under a **plugin name** that is used verbatim as an entry
in `[auth] methods` (`crates/config/src/auth.rs:22-27` already accepts arbitrary
strings - no config-schema change needed there). At authentication time, if the
requested method name does not match a builtin (`password`, `token`, `openid`,
...), it is looked up in a new `WasmPluginRegistry`, following the same "resolve
backend by string name" pattern already used by
`PluginManagerApi::get_x_backend` (`crates/core/src/plugin_manager.rs:56-120`).

```
[auth]
methods = password,token,openid,application_credential,acme_risk_sso
```

### Three Operating Modes: `full_auth` vs `mapping` vs `route`

The namespace-scoped identity binding in this ADR (below) is necessary to stop a
plugin from asserting an arbitrary pre-existing identity, but it has a direct
consequence: a plugin can, by construction, only ever authenticate users **it
itself provisioned**. That's correct for genuinely new external identities, but
it leaves no path for a plugin to serve as an auth method for users who already
exist through some other channel - most importantly, users provisioned via SCIM
(ADR 0024), which is an explicit, realistic requirement, not an edge case.

A separate, unrelated gap: some clients never let the operator choose which auth
method name is requested at all. Terraform's OpenStack provider, for example,
always use built-in auth method names - it has no concept of a custom method
name. A real-world pattern built around this constraint (and the direct
inspiration for `route` mode below) is `keystonemiddleware`-style request
rewriting: a component ahead of the auth logic inspects the incoming
`application_credential_id` and, based on its shape, rewrites the request so it
is dispatched to a different handler entirely - the _routing decision_ and the
_authentication decision_ are two separate concerns, made by two different
pieces of code, neither of which is the client. Neither `full_auth` nor
`mapping` mode can express this: both require the client to already know which
method name to ask for.

Rather than loosening the identity-binding namespace to cover the first gap
(which would reopen the account-takeover class this ADR exists to prevent - see
"Identity Binding" below), or collapsing the routing concern into an
authentication concern (which would let a request-shaping decision double as a
credential-verification decision - see "route" below), each plugin declares one
of three operating modes at config time (`mode = full_auth | mapping | route`,
§5; defaults to `full_auth` for everything already described in this ADR):

- **`full_auth`** (default, as designed above) - the plugin is the terminal
  identity authority for its method name. It calls `provision_user`/ `find_user`
  and returns `Allow`/`Deny` itself. Can reach pre-existing users only via an
  admin-authorized link (see "Admin-Authorized External Identity Linking" below)
  - never by unscoped lookup.
- **`mapping`** - the plugin has **no** authority to terminate authentication at
  all. It only transforms/normalizes the incoming request into a claims map,
  which is handed to the **existing, already-reviewed Unified Mapping Engine**
  (ADR 0020) to make the actual identity and authorization decision - exactly
  the same engine already trusted to resolve OIDC/K8s/SPIFFE claims to real or
  ephemeral users, including real, pre-existing local users via its
  `IdentityMode::Local` path. Because the plugin never asserts an identity
  itself, **no `ResolvedIdentityHandle`, no namespace, no binding of any kind is
  needed for this mode** - it's the direct, safe way to get the "simple auth
  request rewrite" behavior for users the plugin didn't provision, including
  SCIM-provisioned ones, without touching the account-takeover defense at all.
- **`route`** - the plugin has **no** authority to terminate authentication and
  **no** authority to decide identity at all; it only sees the raw, pre-dispatch
  request and decides which already-registered auth method should actually
  handle it, optionally relabeling that method's payload. This is a
  request-routing decision, not a credential-verification decision - the target
  method (builtin or another plugin) still performs its own full, unweakened
  verification. See "Guest Contract - `route` Mode" below.

`mapping` mode is the recommended default for plugins whose job is fundamentally
"translate a proprietary/legacy assertion into claims" (the SCIM-adjacent case).
`full_auth` mode remains available for plugins that must make a genuinely
custom, non-claims-matching judgment call - a real-time risk score, for instance

- that can't be expressed as a static mapping rule. `route` mode is for the
  narrower case where the client cannot be made to ask for a different method by
  name, but the credential it always sends is self-describing enough for a
  router to redirect it to the handler that actually knows how to verify it.

### Guest Contract - `full_auth` Mode

Each plugin exports a single Extism entry point:

```
authenticate(request: AuthPluginRequest) -> AuthPluginResponse
```

```rust
// Host <-> guest wire types (JSON over the Extism call boundary)
struct AuthPluginRequest {
    /// Raw credential payload from the identity.<method> block of the
    /// v3/v4 auth request, exactly as received.
    payload: serde_json::Value,
    /// Allowlisted subset of inbound HTTP headers - only headers the
    /// plugin's config explicitly opts into (`exposed_headers = ...`,
    /// §5) are forwarded. Everything else is never handed to the guest.
    /// This is an allowlist, not a denylist: a header added to Keystone in
    /// the future is excluded by default rather than silently exposed. A
    /// fixed set - `Authorization`, `Cookie`, `X-Auth-Token`,
    /// `X-Service-Token`, `X-Subject-Token`, `Proxy-Authorization` -
    /// additionally can **never** appear in
    /// `exposed_headers` regardless of what an operator configures; the
    /// config loader rejects any plugin config that lists one of them,
    /// the same fail-loud posture as §5. This is deliberate
    /// defense-in-depth: `exposed_headers` being operator-controlled makes
    /// it easy for a copy-pasted example config to silently re-expose
    /// exactly the headers this mechanism exists to protect.
    headers: HashMap<String, String>,
    /// The trusted transport peer address only. This is the socket peer
    /// Keystone actually accepted the connection from, **not** a value parsed
    /// from a forwarding header unless the public TCP peer is an explicitly
    /// configured trusted proxy. `[auth_plugins] trusted_header` selects
    /// exactly one header that those proxies must sanitize (`x_forwarded_for`
    /// by default, or `forwarded` by explicit opt-in). A plugin will predictably
    /// build IP
    /// allowlisting, geo, or step-up logic on this field; handing it a
    /// client-spoofable `X-Forwarded-For` value would let an anonymous caller
    /// (§1 Threat Model, actor 2) forge whatever source address defeats that
    /// logic. `None` when no trusted address can be established, rather than an
    /// untrusted guess.
    ///
    /// **Implementation note on a degenerate configuration.** The resolver
    /// (`crate::net::resolve_client_ip`) walks the configured header chain
    /// right-to-left looking for the first entry *not* in `trusted_proxies`,
    /// which is the actual, spoof-resistant client address. If every entry in
    /// the chain - including the raw TCP peer - is itself a configured
    /// trusted proxy (an operator misconfiguration: a trusted-proxy CIDR that
    /// also matches real client addresses, or a chain with no genuine client
    /// hop at all), the resolver falls back to the trusted peer's own
    /// address rather than `None`. This is still a real, non-spoofable,
    /// trusted address (never an unverified guess from the request itself),
    /// just not necessarily the true originating client - a narrower
    /// deviation from "`None` when no trusted address can be established"
    /// than it may first appear, but one worth operators being aware of if
    /// `trusted_proxies` is scoped too broadly.
    remote_addr: Option<String>,
}

/// Opaque, single-invocation, host-issued handle. Returned by the
/// `provision_user`/`find_user` host functions (§6.B, §6.C) and the only
/// thing a plugin can present back to the host to claim an identity - see
/// "Identity Binding" below. Not a `user_id`; has no meaning outside the
/// `Store` instance that issued it and expires with that invocation.
struct ResolvedIdentityHandle(String);

enum AuthPluginResponse {
    Allow {
        /// Must be a handle this exact invocation received from a
        /// `provision_user` or `find_user` call - never a plugin-supplied
        /// user_id. See "Identity Binding" below for why.
        resolved_identity: ResolvedIdentityHandle,
        /// Extra claims to attach to AuthenticationContext for downstream
        /// policy (OPA) visibility - analogous to OidcContext claims.
        /// Bounded and reserved-key-checked by the host; see §6.F.
        claims: HashMap<String, serde_json::Value>,
    },
    Deny {
        /// Operator-facing reason, CADF-audited; never shown to the client.
        reason: String,
    },
}
```

This makes the plugin a peer of the existing `Oidc`/`K8s` variants rather than a
request-mutation filter in front of them: it owns the full
credential-verification decision for its method name. `AuthenticationContext`
gains one variant:

```rust
WasmPlugin {
    plugin_name: String,
    claims: HashMap<String, serde_json::Value>,
    token: Option<FernetToken>,
},
```

The variant carries no `plugin_sha256`: the `FernetToken` payload is a fixed
enum with no plugin-bearing variant (a `WasmPlugin` login mints an ordinary
scoped token), so there is nowhere to embed and later re-compare a module hash.
Version binding is instead keyed on `plugin_name` at verification time against
the plugin's configured `valid_since` cutoff - see "Plugin Version Binding"
below.

which flows through the existing `ValidatedSecurityContext::new_for_scope()`
pipeline (`crates/core/src/auth.rs:79-181`) unchanged - a plugin-authenticated
principal is validated (enabled checks, expiry, effective-role calculation)
exactly like any other `IdentityInfo::User`.

### Guest Contract - `mapping` Mode

A `mapping`-mode plugin exports a different entry point, with no power to name
an identity:

```rust
mapping(request: AuthPluginRequest) -> MappingResponse
```

```rust
enum MappingResponse {
    /// Flattened claims map, handed verbatim to the Mapping Engine's rule
    /// evaluator (ADR 0020 §5) as if it came from an OIDC/K8s/SPIFFE
    /// ingress adapter. There is no Allow variant here - the plugin cannot
    /// terminate authentication, only feed the engine that does.
    Claims(HashMap<String, serde_json::Value>),
    Deny {
        reason: String,
    },
}
```

`AuthenticationContext` is not extended for this mode - a successful
`mapping`-mode login produces the existing `Mapping(MappingContext)` variant
(`crates/core-types/src/auth.rs:1200`), because the Mapping Engine, not the
plugin, made the decision. Mechanically:

1. ADR 0020's `IdentitySource` enum
   (`crates/core-types/src/mapping/resolution.rs`, per ADR 0020 §3) gains a
   variant: `WasmPlugin { plugin_name: String }`, alongside the existing
   `Federation`, `K8s`, `Spiffe`.
2. Each `mapping`-mode plugin is automatically assigned
   `provider_id = "wasm:<plugin_name>"` in the Mapping Engine's coordinate
   space. An operator writes ordinary `MappingRuleSet` rules under that
   `provider_id` (`POST /v4/mappings`, ADR 0020 §9.A) exactly as they would for
   a real OIDC provider - including `IdentityMode::Local` rules that resolve to
   real, pre-existing users (SCIM-provisioned or otherwise) by matching claims
   the plugin produced against whatever attributes identify that user.
3. The plugin's `Claims(...)` response is passed to the Mapping Engine's
   existing evaluator unmodified - the _same_ engine, the _same_ domain
   whitelist (0020 §3 `allowed_domains`), the _same_ regex/size bounds (0020
   §5.1), the _same_ TOCTOU `ruleset_version` check (0020 §5.5–§5.6). Nothing
   new is built; the plugin is just a new kind of ingress adapter feeding into
   infrastructure this codebase already trusts.
4. If no `MappingRuleSet` exists under `wasm:<plugin_name>` for the target
   domain, evaluation returns `MappingNotFound` (0020 §5.5) and the login is
   rejected - fail-closed by construction: a plugin can authenticate _no one_
   until an admin has explicitly authored rules for it.

**Why this needs no identity binding at all.** Two properties of the Mapping
Engine, both pre-existing and unmodified, do the work `ResolvedIdentityHandle`
does for `full_auth` mode:

- **Claims only ever drive rule _matching_, never become privilege directly.**
  `ClaimCondition`/`MatchCriteria` (0020 §5.1–§5.2) read claim values to decide
  which admin-authored rule fires; the rule's own hardcoded `identity`,
  `authorizations`, and `is_system` fields - not the raw claims - determine the
  outcome. A plugin cannot inject a claim that _becomes_ `is_system: true` the
  way an unbounded claims map could in `full_auth` mode (§7 "Response Payload
  Bounds" reserved-key denylist exists precisely because that mode lacks this
  property) - there is no rule-independent path from "plugin said X" to
  "principal has privilege Y."
- **Ruleset lookup is `provider_id`-isolated.** A `mapping`-mode plugin's claims
  are only ever evaluated against rules filed under its own `wasm:<plugin_name>`
  coordinate (0020 §8 keyspace:
  `data:mapping:v1:<domain_id>:wasm:<plugin_name>`) - never against the ruleset
  backing a real SPIFFE trust domain or OIDC IdP. A compromised or buggy plugin
  cannot forge claims that get matched against a _different_ source's rules; the
  worst it can do is cause a mismatch/no-match against rules an admin wrote
  specifically expecting its own output.

**Plugin-version binding for `mapping` mode - not enforceable at verification
today (implementation deviation, recorded here rather than left implicit).** The
original intent was the same `valid_since` cutoff as `full_auth`, recovering the
plugin name at verification time from the matched ruleset's
`IdentitySource::WasmPlugin { plugin_name }` via the token's `mapping_id`. That
requires the minted token to actually carry a `mapping_id` (or equivalent
plugin-recoverable linkage) - it does not: a successful `mapping`-mode login
mints an ordinary `DomainScope`/`ProjectScope`/... token
(`FernetToken::from_security_context`'s `AuthenticationContext::Mapping(_)` arm,
`crates/core-types/src/token.rs`) whose payload carries only
`methods = ["mapped"]`, the same as any OIDC/K8s/SPIFFE-sourced mapped login.
There is no `mapping_id` field anywhere in a `FernetToken` payload, so
verification (`TokenService::validate_to_context_impl`,
`crates/core/src/token/service.rs`) has nothing to recover a plugin name from

- widening the payload to carry one is exactly the kind of per-record
  bookkeeping this ADR otherwise avoids, and was judged not worth it for this
  first iteration.

Consequence: a token minted through a `mapping`-mode plugin is **not**
invalidated by bumping that plugin's `valid_since`, unlike a `full_auth` token
(whose `methods` does carry the plugin name and is checked at verification, see
"Plugin Version Binding" below). An operator responding to a compromised
`mapping`-mode plugin must fall back to the mechanisms every other token-holder
relies on: issue revocation events for the affected users, or rely on a short
token TTL. Closing this gap - by adding a plugin-recoverable field to the
relevant token payloads - is left as future work (§8), not required for this
ADR's threat model, since `mapping` mode's own structural constraint (the plugin
never asserts an identity - §4 "Why this needs no identity binding at all")
already bounds what a compromised `mapping`-mode plugin can do to "produce
claims the Mapping Engine's already-authored rules for it will match or reject,"
not "assert an identity directly."

**Capability restriction.** `provision_user`, `find_user`, and `assign_role`
(§6.B–D) are meaningless in `mapping` mode - the Mapping Engine owns
provisioning and role resolution instead. Granting any of them to a
`mode = mapping` plugin is a config-load-time error, the same fail-loud posture
used throughout §5, rather than a silent no-op. Only `http_fetch` (§6.A) applies
to both modes.

### Guest Contract - `route` Mode

`route` mode answers a narrower question than either mode above: not "who is
this?" but "which already-registered method should even attempt to answer that?"
It runs **before** method dispatch, on the raw v3/v4 auth request, and its only
power is to relabel which method handles the request and what payload that
method sees - it never resolves an identity, never returns `Allow`, and is not
itself subject to the namespace-scoped identity binding below (there is no
identity for it to bind).

```rust
route(request: RouteRequest) -> RouteResponse
```

```rust
struct RouteRequest {
    /// The `identity.methods` list exactly as the client sent it, before
    /// any method resolution has happened.
    requested_methods: Vec<String>,
    /// Allowlisted subset of inbound HTTP headers - same `exposed_headers`
    /// mechanism and same hard denylist (`Authorization`, `Cookie`, ...) as
    /// `full_auth`/`mapping` (§4 "Guest Contract - `full_auth` Mode").
    headers: HashMap<String, String>,
    /// Raw JSON payload for each `identity.<method>` block the plugin's
    /// config has declared it needs to inspect (`inspect_methods`, §5).
    /// Blocks for methods not in `inspect_methods` are never included -
    /// a router configured to look at `application_credential` never sees
    /// the body of an unrelated `password` block, even on a request that
    /// carries both.
    payloads: HashMap<String, serde_json::Value>,
    /// Trusted transport peer only - identical provenance rule and
    /// spoofing rationale as `AuthPluginRequest.remote_addr` above.
    remote_addr: Option<String>,
}

enum RouteResponse {
    /// Leave the request exactly as received; ordinary method resolution
    /// proceeds as if no router plugin were installed.
    Passthrough,
    /// Reroute to `target_method`, replacing the `identity.<target_method>`
    /// block with `payload` verbatim. `target_method` MUST be a member of
    /// this plugin's configured `route_targets` allowlist (§5) - a
    /// response naming any other method is rejected by the host as a
    /// malformed response (§7), not corrected or silently dropped.
    Route {
        target_method: String,
        payload: serde_json::Value,
    },
    Deny {
        reason: String,
    },
}
```

**Structural constraints, enforced host-side, not by convention:**

1. **Target-method allowlist.** A `route_targets` list (§5) is required at
   config load; a `Route` response naming a method outside it is treated as a
   malformed response under §7's failure semantics - the login is rejected, not
   redirected to an unintended handler. `route_targets` itself is subject to the
   same reserved-name check as plugin registration (§4 "Reserved Auth-Method
   Names") - a router can never be configured to target `admin`, `trust`, or any
   other method capable of reaching system scope.
2. **`scope` is immutable to the router.** The host constructs the re-dispatched
   request by replacing only the named `identity.<target_method>` block;
   `RouteResponse` carries no `scope` field at all, so there is no code path by
   which a router can widen or redirect the requested project/domain/system
   scope. Scope resolution remains entirely owned by whichever method (or the
   Mapping Engine, for a `mapping`-mode target) ultimately handles the rerouted
   request.
3. **Single-shot.** A request that has already been through one `route`-mode
   dispatch is not eligible for another - the host does not re-invoke any router
   (the same one or a different one) on a request it has already rewritten. This
   is enforced structurally (the rerouted request carries an internal flag no
   guest can set or clear), not left as an operator convention, and is what
   keeps this mechanism from degenerating into unbounded recursive rewriting.
4. **No identity, no claims, no credential synthesis.** The target method still
   performs its own complete, unweakened verification against whatever payload
   it receives - a router deciding "this looks like a credential for user X" is
   never treated as proof of that. `payload` may only carry values the plugin
   was actually able to read out of `payloads`/`headers` in this same invocation
   (the host does not prevent a plugin from fabricating an arbitrary JSON
   payload, since it cannot distinguish "reshaped" from "synthesized" at the
   type level - but the target method's own secret/ signature verification is
   exactly the backstop that makes fabrication harmless: a router can relabel
   which handler sees a credential, and can restructure the bytes it was given,
   but cannot manufacture a passing verification result for a credential it
   never actually possessed).
5. **Trigger scoping.** `inspect_methods` (§5) bounds not just what the plugin
   _sees_ but whether it is invoked _at all_: a request whose `identity.methods`
   contains none of the configured `inspect_methods` entries never reaches this
   plugin. This is the main lever for containing the router's blast radius -
   without it, a router would need to run on every login attempt for every
   method, including ones (`password`, `token`) it has no legitimate reason to
   ever see.
6. **Fail-closed, independent budget.** A `route`-mode failure (trap, timeout,
   fuel exhaustion, malformed response, off-allowlist target) rejects the login
   exactly like any other plugin failure (§7) - it never falls through to
   dispatching the original, un-routed request. Because a router is reachable by
   a strictly larger slice of traffic than a `full_auth`/`mapping` plugin (every
   request matching `inspect_methods`, not just requests already addressed to
   this plugin by name), its `invocation_rate_limit_per_minute`/
   `max_concurrent_invocations` budget (§7) is tracked independently of the
   target method's own budget - a saturated router degrades only routing
   decisions for its `inspect_methods`, never the target method's headroom for
   requests that reach it directly.

**Capability restriction.** `provision_user`, `find_user`, and `assign_role`
(§6.B–D) are config-load-time errors for `mode = route`, identically to
`mapping` - a router does not resolve or grant anything, only redirects.
`http_fetch` (§6.A) is permitted (a router may need to consult an external
service to decide a route) but its cost is paid on every matching request,
including ones that end up as `Passthrough`; operators should budget
`timeout_ms` accordingly given `route` mode sits ahead of, not instead of, the
target method's own processing time.

**Audit.** The mandatory audit wrapping (§6.E) records, for every `route`-mode
invocation, the client's originally-requested method list, the plugin's decision
(`Passthrough`/`Route`/`Deny`), and - for `Route` - the resulting
`target_method`. This is deliberate: without it, a CADF event for the
eventually-authenticated request would show only the routed-to method, making it
look as though the client had requested that method directly, which is exactly
the wrong picture for an operator investigating a routing plugin gone wrong.

**No router version binding on the issued token - by design.** A `route`-mode
plugin does not mint a token; the target method it routes to does, and that
token is subject to the _target's_ version binding (the target `plugin_name`'s
`valid_since` cutoff, for a `full_auth` or `mapping` target), not the router's.
This is intentional, not an oversight: the token-version-binding defense (§4
"Plugin Version Binding") exists to invalidate credentials a _vulnerable
authenticator_ minted, and a router never authenticates - it cannot mint a
credential for anyone the target method didn't independently verify (constraint
4 above). Patching a buggy router therefore has nothing to retroactively
invalidate: any token that exists was authorized by a target method's own
still-bound verification, and the router's fix takes effect on the next request
the instant its new module loads at startup (§5). The one thing a router bug
_does_ get bound into is the audit trail, which is where a routing bug actually
needs to be reconstructable.

### Identity Binding (`full_auth` Mode): Handles Into a Plugin-Owned Namespace, Not Raw `user_id`

A plugin is never given a channel to assert "bind this token to `user_id`
`<arbitrary-uuid>`." If it were, a single logic bug or malicious response from a
plugin would be a full authentication bypass - it could name any existing
account, including a cloud-admin's, without ever checking a credential for it.

It is not enough, however, to merely require the plugin to obtain a _handle_
before asserting an identity - a handle-issuing `find_user` that performs a
general, unscoped lookup ("does any user named `<x>` exist?") reopens exactly
the same bypass one function call later: a plugin (buggy, or simply never
implementing the credential check it's supposed to) could call
`find_user("admin")`, receive a valid handle for the real admin account, and
return `Allow` - never having verified anything. The host would then
correctly-but-uselessly confirm "yes, this handle was legitimately issued,"
because the lookup itself was the hole.

The actual control is **namespace scoping**, not merely indirection through a
handle. `provision_user` and `find_user` do not perform a general Keystone user
search at all - they operate exclusively against a federated-identity mapping
**private to that plugin**, keyed by `(plugin_name, external_id)`, where
`external_id` is a string the plugin's own guest logic derives (e.g. from a
verified external SSO subject or signed assertion) and has no relationship to a
Keystone username. This is the same pattern this codebase already uses for
OIDC/K8s/SPIFFE federation -
`find_federated_user(ctx, idp_id, unique_workload_id)`
(`crates/core/src/mapping/service.rs:374-433`) never searches local accounts by
name either; it only ever resolves `(idp_id, external_id)` pairs a prior
provisioning step created under that same source.

```rust
// Host functions §6.B / §6.C - signatures pinned here specifically so an
// implementer cannot accidentally build the unscoped version above.
fn provision_user(external_id: String, user: UserCreate) -> ResolvedIdentityHandle;
fn find_user(external_id: String) -> Option<ResolvedIdentityHandle>;
```

Mechanically:

1. `provision_user(external_id, user)` creates (or, on a repeat call with the
   same `external_id`, returns the existing) real `User` row via
   `IdentityBackend::create_user`, and records a mapping
   `(plugin_name, external_id) -> user_id` - separate storage from, and
   invisible to, any other plugin or auth method. `find_user(external_id)` looks
   up only within that same `(plugin_name, external_id)` mapping. **Neither
   function will ever resolve a `user_id` that this plugin did not itself
   provision** - a password-authenticated admin account, a user created via the
   API, or an identity provisioned by a _different_ plugin are all structurally
   unreachable, not merely policy-forbidden.
2. Both return an opaque `ResolvedIdentityHandle` unrelated to the real
   `user_id`, from which the host can recover `(user_id, domain_id)` on the
   `Allow.resolved_identity` echo below.

   **Implementation deviation: a signed token, not a per-`Store` map.** The
   original intent was an in-memory `handle -> (user_id, domain_id)` map scoped
   to the single `Store` created for that invocation - random, unguessable, and
   structurally impossible to reuse across invocations because the map itself
   doesn't outlive one. The actual implementation (`CoreHostFunctions` in
   `crates/core/src/auth_plugin.rs`) instead HMAC-signs
   `{plugin_name, user_id, domain_id, expires_at}` with a process-lifetime
   random key and hands the signed bytes back as the "handle." This is a
   consequence of how host functions are registered in this implementation (§6
   deviation, above): the `extism::Function` closures are shared across every
   concurrent invocation of a plugin's compiled module, not instantiated fresh
   per `Store`, so there is no per-invocation-scoped place left to keep an
   in-memory map safely isolated between concurrent requests. A signed, expiring
   token gives an equivalent security property - unforgeable without the key,
   and resolves only to exactly what a prior `provision_user`/`find_user` call
   in _this_ plugin's namespace actually returned - without relying on state
   scoped to a single invocation. The `expires_at` is set generously past a
   plugin's own `timeout_ms` budget (default 60 seconds) rather than truly
   one-shot: the trade-off is a small window in which a captured handle from one
   invocation could in principle be replayed into a later one, versus the ADR's
   original "expires with that invocation" property. This is bounded, not
   open-ended - `find_user`'s live-`domain_id` re-check (step 3,
   "Admin-Authorized External Identity Linking") still applies to a replayed
   handle exactly as it would to a fresh one - but it is a real, if narrow,
   deviation from a strictly per-invocation-scoped handle.

3. If the guest's `Allow.resolved_identity` verifies against the signing key
   (or, in the originally-intended design, matches an entry in that map), the
   host substitutes the real `(user_id, domain_id)` when constructing the token.
   If it does not verify - a fabricated handle, a tampered handle, one issued
   for a different plugin, an expired one, or no `provision_user`/`find_user`
   call was ever made - the request is rejected exactly like any other malformed
   response (§7), and the mismatch itself is audited as a suspicious event.
4. A plugin granted **neither** `provision_user` nor `find_user` (§6) has no way
   to produce a valid handle at all, and can therefore only ever `Deny` - this
   is enforced at config-load time: registering a plugin as an `[auth] methods`
   entry without at least one of those two capabilities is a startup
   configuration error, not a silent no-op.

This makes "which real accounts can this plugin authenticate as" a direct,
auditable, _structurally bounded_ function of what that specific plugin has
itself provisioned - never a lookup against the wider pool of existing Keystone
accounts, and never a free-form claim. What the host still cannot do - because
it's inherent to letting arbitrary code define an auth method - is verify that
the plugin performed a _correct_ credential check before calling
`provision_user`/`find_user` with a given `external_id`. Namespace scoping
bounds the failure mode to "this plugin's own provisioned identities might be
mis-authenticated," never "any account in the system might be."

### Admin-Authorized External Identity Linking (`full_auth` Mode)

For the case `mapping` mode doesn't cover - a `full_auth` plugin that must
remain the terminal identity authority, but needs to authenticate a pre-existing
user it did not itself provision (a SCIM-provisioned user, for instance, where
the login decision genuinely can't be expressed as a static mapping rule) - the
`(plugin_name, external_id) -> user_id` table `find_user` reads from (above) can
also be populated by an **administrator**, out of band, instead of only by the
plugin's own `provision_user` calls. The plugin side is unchanged:
`find_user(external_id)` still just resolves whatever is in that table today,
whether the entry came from the plugin provisioning it or from an admin linking
it.

**Domain restriction is re-checked at resolve time, not only at link time.** The
`provision_domain_id`/`allowed_provision_domains` bound (§6.B) is enforced both
when the link is created (below) **and** every time `find_user` resolves a
handle: the host re-reads the target user's current `domain_id` and rejects the
resolution (auditing it as a mismatch, §6.E) if that user has since moved
outside the plugin's configured domain set. A link-time-only check would leave a
stale window - an identity linked while in-domain, then administratively moved
to another domain, would otherwise remain authenticatable by a plugin that was
never granted reach into the user's new domain. Because the check rides on the
user's _live_ `domain_id`, a domain move closes that reach immediately without
needing a separate link-cleanup step.

**Why admin-authorized rather than plugin-self-service.** This is the one
mechanism in this ADR that intentionally lets a `full_auth` plugin reach an
identity it didn't create - so it has to be gated by something the plugin itself
cannot trigger. An admin action, taken once, out of band, requiring ordinary
Keystone RBAC (not the plugin's own runtime logic), is that gate. A coarser
alternative - letting a plugin resolve _any_ user within its configured domain
without a per-identity link - was considered and rejected: it would trade the
"only explicitly-authorized identities are reachable" guarantee for zero admin
overhead, and a buggy or exploited plugin (§1 Threat Model, actor 1) could then
authenticate as anyone in that domain, not just identities someone deliberately
opted in. The per-identity (or per-realm, below) authorization step is the
load-bearing control; nothing here is meant to be bypassable for convenience.

**API.** `POST /v4/auth_plugins/{plugin_name}/identity_links` with body
`{external_id, user_id}`. RBAC-tiered the same way ADR 0020 §9.A gates mapping
writes: system-admin authorization is required to link a user who holds any
system-scope role assignment; domain-admin authorization, scoped to the target
user's own domain, suffices otherwise. The endpoint additionally enforces the
plugin's `provision_domain_id`/`allowed_provision_domains` restriction (§6.B)
against the target user's domain - a link can never place a user outside the
domain(s) the plugin was already configured to reach, keeping that invariant
uniform regardless of whether an identity arrived via self-provisioning or
admin-linking. Re-linking an `external_id` that already has an entry is rejected
(`409 Conflict`); an admin must explicitly
`DELETE .../identity_links/{external_id}` first - no silent overwrite, so an
external_id can't be quietly reassigned to a different user by mistake or by a
compromised admin session skating past a diff review. Both create and delete are
CADF-audited via the same mandatory infrastructure as §6.E, and `DELETE`
additionally triggers the existing token-revocation pipeline for the unlinked
`user_id` (the same mechanism ADR 0020 §9.F uses when a virtual user is
disabled) - an unlinked identity can't keep using tokens issued while the link
was live.

**SCIM convenience.** Rather than requiring an admin to hand-copy internal
`user_id` UUIDs, the same endpoint accepts
`{scim_provider_id, scim_external_id}` in place of `{external_id, user_id}`: the
host resolves `user_id` via the **existing**
`index:scim:external_id:<domain_id>:<provider_id>:<type>:<external_id>` index
(ADR 0024 §3.B) instead of introducing parallel storage, and sets the plugin's
`external_id` to the SCIM `externalId` the IdP already assigned that user. This
is the direct answer to "users provisioned by SCIM need to be authenticatable
via a custom plugin": an admin pairs the plugin with the SCIM realm's
already-tracked identities, one link (or a small bulk batch) at a time, rather
than the plugin ever being able to decide that for itself.

### Plugin Version Binding & Token Invalidation (`full_auth` Mode)

Mirroring the `ruleset_version` TOCTOU defense in ADR 0020 §5.5–§5.6 (a token
issued under one mapping ruleset is rejected if the live ruleset has since
changed), a token minted via `WasmPlugin` is invalidated when the plugin behind
its `plugin_name` is patched. The mechanism is a **timestamp cutoff, not an
embedded hash**: the `FernetToken` payload is a fixed variant set with no
plugin-bearing case (a `WasmPlugin` login mints an ordinary scoped token that
already records its own `issued_at`), so there is no room to embed a
`plugin_sha256` in the token and re-compare it later. Instead, each plugin's
config carries an optional `valid_since` timestamp (§5). On every verification
of a `WasmPlugin`-authenticated token, the host compares the token's `issued_at`
against the `valid_since` configured for that `plugin_name`: if `issued_at`
predates `valid_since`, the token is rejected with a dedicated
`PluginVersionMismatch` error, forcing re-authentication against the current
plugin logic. An operator patching a plugin to fix a security bug bumps
`valid_since` (normally alongside the pinned `sha256`) to the cutover instant,
which invalidates every token the vulnerable version minted while leaving the
rest of the process running. This is verification-time only: a brand-new login
has no token yet (`issued_at` is set as the token is minted), so a past
`valid_since` never blocks fresh authentication - it only invalidates
already-outstanding tokens.

The trade-off relative to an automatic hash-drift check is that invalidation is
driven by an operator action (bumping `valid_since`) rather than falling out of
the `sha256` change itself: an operator who swaps the `.wasm` and updates
`sha256` but forgets to advance `valid_since` leaves the old version's tokens
valid until they expire naturally. Treating `valid_since` as a mandatory
companion to any `sha256` change - the same "plugin config change is a staged
rollout, not an ordinary edit" discipline §5 already calls for - is the
load-bearing operator convention here.

### Bulk Revocation on Plugin Compromise (`full_auth` Mode)

Version binding above stops a token minted under a since-patched plugin from
being _used_, but does nothing about the **persistent state** a plugin already
wrote while it was live and trusted - accounts it provisioned via
`provision_user`, role assignments it granted via `assign_role`, and identity
links an admin created for it ("Admin-Authorized External Identity Linking",
above). If an operator's response to a compromise is "patch the plugin and move
on," that state is exactly what an attacker who exploited it would want left
behind. Cleaning it up one `DELETE .../identity_links/{external_id}` at a time,
or by hand-querying the CADF audit trail (§6.E, which records `plugin_name` on
every such write) for everything to walk back, is only manual, error-prone
rollback under incident-response time pressure.

**API.** `POST /v4/auth_plugins/{plugin_name}/revoke_all`. System-admin only

- this is a cross-domain action by construction, since a plugin's
  `provision_domain_id`/`allowed_provision_domains` (§6.B) can span multiple
  domains and its role grants (§6.D) can land on any project within them, so no
  narrower RBAC tier is meaningful. Scoped entirely to the named plugin, in one
  call it:

1. **Disables** (does not delete) every `user_id` the plugin provisioned via
   `provision_user`, and every `user_id` reachable only through an
   admin-authorized identity link to it (above) - reusing the same disable path
   ADR 0020 §9.F already uses for a disabled virtual user, not a new deletion
   code path.
2. **Deletes** every remaining `identity_links` entry for that plugin - the
   batched equivalent of the existing per-`external_id` `DELETE`, above.
3. **Triggers the existing token-revocation pipeline** for every affected
   `user_id`, so a token minted before the operation ran cannot keep working on
   a since-disabled account - the same window the per-identity `DELETE` already
   closes for one identity at a time, now closed for all of them at once.

It deliberately does **not** revoke the role assignments the plugin granted via
`assign_role`. Attributing a stored assignment to the plugin that created it
would require every grant to carry a per-record origin marker - exactly the kind
of per-write bookkeeping this ADR rejects for version scoping (below), and which
the assignment store does not otherwise need. Because disabling the account
already denies all access, a leftover grant is inert unless an operator later
re-enables that user; at that point it is the operator's responsibility to
review the re-enabled user's assignments against the CADF audit trail (§6.E
records `plugin_name` on every `assign_role`) and revoke any they deem
compromised via the existing per-grant revocation API. This keeps "get
everything shut off fast" free of schema additions, and leaves selective
assignment cleanup - like the selective account reinstatement discussed below -
a deliberate manual step rather than an automatic one.

Each of the above is individually CADF-audited exactly as its single-record
equivalent already is (§6.E) - this endpoint is a bulk _driver_ of existing,
already-reviewed disable/revoke/unlink operations, not a new privileged code
path with its own semantics. It responds with a per-category count (users
disabled, links deleted) so the operator gets confirmation of blast radius
covered without a separate audit-trail query, and re-running it against a plugin
with no remaining state is a no-op (`200`, all-zero counts) - safe to include in
a standard incident-response runbook without first checking whether a prior run
already covered it.

**Why plugin-name-scoped, not version-scoped.** The action targets everything
attributable to `plugin_name`, not only writes made while one specific plugin
binary (`sha256`) was loaded. Scoping to a single vulnerable version would
require every provisioning/grant/link record to carry the `sha256` active at
write time - bookkeeping this ADR does not otherwise need (version binding,
above, is a single per-plugin `valid_since` timestamp compared to a token's
`issued_at`, and needs no per-record hash at all) - and would leave state from
_any other_ version of the same plugin untouched, the wrong default the moment
an operator's trust in a plugin binary has been broken. An operator confident
only one version is implicated can still hand-verify individual accounts against
the audit trail's `plugin_name` + timestamp before re-enabling them; this
endpoint optimizes for "get everything shut off fast," not selective
reinstatement.

### Reserved Auth-Method Names

At config load, a plugin's name is checked against the fixed set of builtin
method names (`password`, `token`, `openid`, `application_credential`, `trust`,
`webauthn`, `mapped`, `k8s`, `admin`, `totp`). A collision is a startup
configuration error - a plugin can never be registered under a name that would
shadow or be confused with a compiled-in auth method.

A `route`-mode plugin's `route_targets` (§5) list is checked against the same
set, minus the strictly reachable subset: `admin` and `trust` may never appear
in a `route_targets` list regardless of plugin, since neither is a method a
router's blast radius should ever be able to reach - this is a startup
configuration error, identical in posture to the name-collision check above.

---

## 5. Distribution & Loading

Plugin bytecode lives on the local filesystem. A new config section, one
sub-entry per plugin, follows the existing per-subsystem `[section] key = value`
convention (e.g. `crates/config/src/k8s_auth.rs`):

```
[auth_plugins]
plugins = acme_risk_sso,tf_appcred_router
# Header every trusted proxy sanitizes. Defaults to x_forwarded_for.
trusted_header = x_forwarded_for
# Comma-separated proxy CIDRs; empty trusts no forwarding header.
trusted_proxies =

[auth_plugin.acme_risk_sso]
path = /etc/keystone/plugins/acme_risk_sso.wasm
sha256 = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
# Plugin version binding (§4 "Plugin Version Binding"): any token whose
# issued_at predates this instant is rejected with PluginVersionMismatch,
# forcing re-auth against the current module. Bump this to "now" whenever
# `sha256` changes so tokens minted by the previous binary stop verifying.
# Optional - omit it and no token is ever rejected on version grounds.
valid_since = 2026-07-02T00:00:00Z
# full_auth (default): plugin is the terminal identity authority, may call
# provision_user/find_user/assign_role, can reach pre-existing users only
# via an admin-created identity_link (§4). mapping: plugin only produces
# claims for the Mapping Engine (ADR 0020) to evaluate; provision_user/
# find_user/assign_role are config-load errors in this mode (§4). route:
# plugin runs pre-dispatch and may only relabel identity.methods + hand a
# payload to one allowlisted target method - provision_user/find_user/
# assign_role are also config-load errors in this mode (§4).
mode = full_auth
# Capabilities are host functions this plugin may call (§6 A-D only -
# auditing is mandatory host-side infrastructure, not a capability; see §6.E).
capabilities = http_fetch,provision_user,find_user
exposed_headers = X-Acme-Session-Id
allowed_hosts = risk.acme.example.com
# Host injects this header on every http_fetch call; the value itself is
# read from the referenced environment variable and never enters guest
# memory (§6.A).
http_fetch_auth_header = Authorization
http_fetch_auth_secret_env = ACME_RISK_API_KEY
# provision_user (§6.B) may only create users in this domain; a UserCreate
# targeting any other domain_id is rejected before reaching IdentityBackend.
provision_domain_id = domain_acme_sso
assign_role_allowed = reader,member
timeout_ms = 750
fuel_limit = 50000000
memory_limit_mb = 32
# Per-(plugin, source-IP) bucket, checked before the plugin-wide bucket below
# (§7 "Invocation Rate Limiting & Concurrency") - keeps one anonymous caller
# from exhausting this method's shared budget for everyone else.
invocation_rate_limit_per_source_per_minute = 20
invocation_rate_limit_per_minute = 300
max_concurrent_invocations = 16

# route-mode example: Terraform's OpenStack provider always sends
# identity.methods = [application_credential]. This plugin inspects the
# application_credential_id shape and, for IDs matching its own convention,
# reroutes the request to a separately-registered full_auth plugin
# (hacked_appcred_handler, not shown) that performs the real verification;
# every other application_credential request passes through unmodified to
# the builtin handler.
[auth_plugin.tf_appcred_router]
path = /etc/keystone/plugins/tf_appcred_router.wasm
sha256 = 3b5d5c3712955042212316173ccf37be9de53d6c84a5c7c8e6e0e5e7f5f8a1b
mode = route
# Only requests whose identity.methods includes one of these entries ever
# invoke this plugin at all - a plain `password` login never reaches it.
inspect_methods = application_credential
# Methods this plugin is permitted to reroute a request to. A Route
# response naming anything else is rejected as malformed (§4 "Guest
# Contract - route Mode"), never dispatched.
route_targets = hacked_appcred_handler
capabilities =
timeout_ms = 200
fuel_limit = 5000000
memory_limit_mb = 8
invocation_rate_limit_per_minute = 6000
max_concurrent_invocations = 64
```

**Loading.** All configured plugins are loaded and their checksums verified
independently, once, at process startup. If a given plugin's file is missing or
its SHA-256 does not match the pinned value, **that plugin is disabled** - not
registered as an auth method, not reachable by any `identity.methods` entry -
and the host emits a `CRITICAL`-level structured log line plus a dedicated
metric/counter (e.g. `keystone_auth_plugin_load_failure{plugin_name}`) naming
the plugin and the mismatch, wired to whatever alerting an operator already has
on Keystone process health. The node itself, every other correctly verified
plugin, and every builtin auth method (`password`, `openid`, `k8s`, ...) start
and serve normally. This is a deliberate change from an earlier draft of this
ADR, which made a checksum mismatch a hard process-startup failure for the whole
node - rejected here because a plugin failing to load degrades availability of
exactly one auth method (fail-closed at the request level, identical to any
other plugin runtime failure, §7), and blocking every builtin method
cluster-wide over one misconfigured plugin was a disproportionate availability
cost for what is very often a copy-paste typo in `keystone.conf` rather than a
genuine tamper/corruption event.

**Cross-node divergence is the trade-off this creates, and it is accepted
explicitly rather than left implicit.** Because each node verifies its own copy
of the `.wasm` file independently, a node with a correct hash keeps a plugin
live while a sibling node with a typo'd or stale hash disables it - the cluster
can run with that auth method inconsistently available across nodes until an
operator acts on the alert. This is judged preferable to the previous
whole-cluster-down failure mode precisely because it is loud rather than silent:
the `CRITICAL` alert exists specifically to convert what would otherwise be an
unnoticed divergence into a paged one. Operators who need the stronger
all-or-nothing guarantee this ADR previously provided can still get it
operationally - verify the pinned hash against every node's `.wasm` file as a
pre-deploy gate in their rollout pipeline - and should continue to treat a
plugin config change with the same care as a schema migration, not an ordinary
config edit.

**Why filesystem, not Raft/FjallDB.** Given the cluster-global-only trust scope
(§8), there is no per-domain data to replicate, so the main advantage of storing
bytecode in the replicated log - automatic cross-node consistency for
tenant-authored content - does not apply. Filesystem distribution defers that
machinery until a per-tenant plugin model is actually needed.

---

## 6. Host Functions: Curated Capability Allowlist

A plugin can only call the host functions listed in its `capabilities` config
entry (§5). The security property is that an unlisted call can never be
successfully exercised, structurally or otherwise - not merely a permission
_check_ that could be bypassed by a bug in the check itself.

**Implementation deviation from "not registered at all."** The original intent
was that an ungranted function is absent from the guest's import table entirely.
The actual implementation registers all four host functions (§6 A-D) into every
plugin's compiled `extism::Plugin` module whenever _any_ `HostFunctions`
provider is configured, and each function's closure independently rejects a call
its plugin's `capabilities` didn't grant, before doing anything else. This is a
deliberate, documented substitution
(`crates/auth-plugin-runtime/src/host_functions.rs`), not an oversight:
`wasmtime` requires every guest-declared import to resolve at instantiation time
regardless of whether the compiled module actually calls it - an unresolved
import fails _every_ invocation of that module, not just the specific call that
would have used it - so selectively omitting a function's registration per
plugin is not viable for a single compiled module shared across
differently-configured invocations. From the guest's perspective the result is
identical either way: an ungranted capability structurally cannot be exercised,
since the closure's gate check runs before any host-side effect (DB write,
outbound HTTP call, etc.) and is not something plugin-supplied input can
influence or bypass.

### A. `http_fetch`

Backed by Extism's built-in HTTP bridge, restricted to the plugin's
`allowed_hosts` list (§5) - the same allow-list-of-hosts posture already
implicit in how `keystone-rs` talks to fixed external services (OPA base URL,
K8s API server). Unlike the existing `reqwest::Client` in
`crates/keystone/src/k8s_auth_client.rs:73-75`, which sets no per-request
timeout, the host-side bridge for `http_fetch` **must** enforce both a connect
and a total-request timeout derived from the plugin's `timeout_ms` budget -
closing a gap noted during this ADR's research rather than propagating it into a
new, more exposed (third-party-triggered) call path.

Because every `http_fetch` call is ultimately triggered by an anonymous,
pre-authentication caller (§1 Threat Model, actor 2), the bridge is an SSRF
surface and is hardened accordingly, as a hard requirement of this ADR rather
than an implementation detail:

- **Connect-time IP validation, not just hostname matching.** `allowed_hosts` is
  a hostname allowlist, but DNS is attacker-adjacent (a plugin's configured
  third-party host is not attacker-controlled, but its DNS resolution path is
  outside Keystone's control). The bridge re-resolves the hostname at connect
  time on every call (no long-lived resolution cache) and rejects the connection
  if the resolved address falls in a private, loopback, link-local, multicast,
  or cloud-metadata range (RFC 1918, RFC 4193, `127.0.0.0/8`, `169.254.0.0/16`
  including `169.254.169.254`, etc.) - regardless of what the configured
  hostname was. **The socket then connects to the exact `IpAddr` that was
  validated - the host does not hand the hostname back to the HTTP client to
  resolve a second time.** This distinction is load-bearing, not pedantic: a
  validate-then-re-resolve implementation reopens the exact DNS-rebinding TOCTOU
  this control exists to close, because the second lookup can return a private
  address the first one didn't. Validation and connection must observe the same
  resolved address. This closes the standard DNS-rebinding bypass of a
  hostname-only allowlist.
- **No automatic redirect following.** The bridge does not follow HTTP redirects
  by default; a 3xx response is returned to the guest as-is. An operator who
  needs redirect support opts in per-plugin
  (`http_fetch_follow_redirects = true`), and even then each redirect hop is
  re-validated against both `allowed_hosts` and the IP-range check above before
  being followed - a redirect is not permitted to silently escape the allowlist.
  The whole chain shares a single `timeout_ms` wall-clock budget, not one budget
  per hop: each hop's own request timeout is the _remaining_ time before that
  shared deadline, so a redirect chain cannot cost up to `MAX_REDIRECTS + 1`
  times the plugin's configured budget - the total wall-clock cost of a
  (possibly multi-hop) `http_fetch` call stays bounded to the same `timeout_ms`
  §7's per-invocation deadline is sized against.
- **Outbound secrets are host-injected, never guest-visible.** If a plugin needs
  to authenticate to its external service, the secret value (API key, bearer
  token) is **not** embedded in the `.wasm` binary and is **not** passed into
  guest memory. Instead, `http_fetch_auth_header` + `http_fetch_auth_secret_env`
  (§5) tell the host which header to attach and which host-side environment
  variable (or, in a future iteration, secret store reference) to read the value
  from; the host attaches it to the outbound request after the guest has already
  specified the rest of the request, so the plugin's WASM code and the `.wasm`
  file distributed to every node never contain the credential in any form.

This is a stricter posture than the existing `reqwest`-based clients elsewhere
in `keystone-rs` (OPA, K8s TokenReview) because those call fixed,
operator-configured single endpoints that are never influenced by an anonymous
caller's request; `http_fetch` is triggered by exactly such a caller on every
invocation.

### B. `provision_user`

`provision_user(external_id: String, user: UserCreate) -> ResolvedIdentityHandle`
(§4 "Identity Binding"). Wraps
`IdentityBackend::create_user(state: &ServiceState, user: UserCreate) -> Result<UserResponse, IdentityProviderError>`
(`crates/core/src/identity/backend.rs:119-123`) - the same call the Unified
Mapping Engine's `Local` identity mode uses today
(`find_or_create_federated_user`,
`crates/core/src/mapping/service.rs:374-433`) - but, critically, is namespaced
by `(plugin_name, external_id)` rather than performing a general
create-or-lookup by username: a repeat call with the same `external_id` returns
the same provisioned user rather than erroring or creating a duplicate, and no
other plugin or auth method can resolve a `user_id` through this mapping. This
idempotency must be **atomic** on the `(plugin_name, external_id)` mapping
(upsert / unique-constraint-backed insert-or-get), not a check-then-create: with
`max_concurrent_invocations > 1` two first-login requests for the same
`external_id` run in parallel `Store`s, and a non-atomic implementation races
into either a duplicate `User` row or a unique-constraint error surfaced as a
spurious auth failure. The mapping's own uniqueness on
`(plugin_name, external_id)` is the serialization point. This directly satisfies
requirement 3 ("provision user on first login"): the guest calls
`provision_user` with the external identifier and fields it has already verified
(federated attributes, username), and the host performs the actual DB-backed
creation under the existing identity backend - the plugin never gets raw DB or
`ServiceState` access, only this single narrow, namespace-scoped entry point.
The host does **not** return the real `user_id` to the guest - it returns a
`ResolvedIdentityHandle` that the guest can only use by echoing it back in
`Allow.resolved_identity`.

**Field sanitization.** The `UserCreate` handed to the host is **not** written
through verbatim. Identity-critical fields are host-controlled, not
guest-controlled:

- **`id`** - always host-generated. A guest-supplied `id` is rejected (not
  ignored), because a plugin that could name the new user's UUID could target an
  existing account's `id` - colliding with, or attempting to overwrite/alias, a
  password-authenticated admin - which is exactly the arbitrary-`user_id` claim
  the identity-namespace design (§4) exists to prevent, smuggled in one layer
  down through the create path.
- **`domain_id`** - see domain restriction below.
- Any privilege- or auth-relevant option field (e.g. federated-vs-local flags,
  password material, admin-ish user options) is either host-fixed or rejected;
  the guest may only supply the narrow set of descriptive attributes it has
  actually verified (external username, display attributes). The accepted-field
  set is an allowlist, so a field added to `UserCreate` in the future is
  excluded by default rather than silently passed through from the guest.

**Domain restriction.** `user.domain_id` is not accepted verbatim from the
guest. Each plugin's config declares `provision_domain_id` (§5) - a single fixed
domain (or, if genuinely needed, `allowed_provision_domains`, a small explicit
list) - and any `UserCreate` targeting a domain outside that set is rejected
before reaching `IdentityBackend`. This mirrors ADR 0020's `allowed_domains`
whitelist for federated provisioning (0020 §3, §7.3 `AllowedDomainsRequired`)
and bounds a buggy plugin (§1 Threat Model actor 1) to the domain(s) an operator
explicitly intended to hand it write access to, rather than "any domain in the
cluster."

### C. `find_user`

`find_user(external_id: String) -> Option<ResolvedIdentityHandle>` (§4 "Identity
Binding"). Read-only lookup within the same `(plugin_name, external_id)`
namespace `provision_user` writes to - used for idempotent "does this identity
already exist" checks before provisioning. This is **not** a general
username/attribute search over the Keystone user table: `find_user` structurally
cannot resolve a handle for any account it (or a prior invocation of the same
plugin) did not itself create via `provision_user`. This is the load-bearing
restriction that makes handle-based identity binding (§4) an actual
authentication-bypass defense rather than an extra function call in front of the
same bypass. For entries populated by admin-authorized linking rather than the
plugin's own provisioning, `find_user` additionally re-validates the resolved
user's live `domain_id` against the plugin's `provision_domain_id` /
`allowed_provision_domains` on every call (§4 "Admin-Authorized External
Identity Linking"), so a post-link domain move revokes reach immediately.

### D. `assign_role`

Grants a role assignment for the newly resolved principal (identified by a
`ResolvedIdentityHandle` from B/C - the same anti-impersonation constraint
applies here: a plugin cannot assign a role to an arbitrary `user_id` it merely
names). Kept as a separate, individually-grantable capability from
`provision_user` so a plugin can be scoped to "create users but never touch role
assignments" if an operator wants that split.

**Scope restriction.** A plugin's `assign_role` grant is bounded on three axes,
all enforced host-side:

- **Which role** - `assign_role_allowed` (§5): an explicit, per-plugin allowlist
  of role names it may assign.
- **Which target project/domain** - the assignment may only land on a project or
  domain **within the plugin's own `provision_domain_id` /
  `allowed_provision_domains` set** (§6.B). The role name allowlist alone does
  not bound _where_ the grant applies; without this, a plugin holding `member`
  in `assign_role_allowed` could grant its self-provisioned user `member` on an
  arbitrary project - including a sensitive one in another domain (e.g. the
  `admin` project). A grant whose target project/domain falls outside the
  configured provisioning domain(s) is rejected before reaching the assignment
  backend, the same fail-loud posture as the `provision_user` domain check.
- **Which scope type** - the load-bearing control against privilege escalation:
  `assign_role` only ever targets project/domain scope on the identity the same
  invocation resolved, and there is no code path by which a WASM plugin
  invocation can reach system scope - mirroring ADR 0020 §9.A's rule that
  `Authorization::System` requires `is_system: true` plus admin-level
  authorization, neither of which a plugin invocation ever carries. (An earlier
  draft of this ADR additionally proposed rejecting `assign_role_allowed`
  entries for roles that "carry admin privileges" - cut here because Keystone
  roles have no intrinsic, statically-inspectable privilege flag at config-load
  time; role semantics are policy-interpreted, e.g. `role:admin` in Rego, not a
  DB property queryable before OPA/the database are even necessarily reachable.
  Claiming that check existed would have been a control on paper only. The
  scope-type restriction above is the real, implementable defense and is
  sufficient given plugins never carry system scope regardless of which role
  name is assigned.)

### E. Mandatory Audit Wrapping (not a capability)

Unlike A–D, auditing is **not** something a plugin opts into or calls - it is
host-side infrastructure that unconditionally wraps every invocation of A–D and
the top-level `authenticate` outcome, regardless of what a plugin's
`capabilities` list contains. Each wrapped call emits a CADF-compatible event
via the existing `AuditHook` (`crates/core/src/events.rs:107-115`)
infrastructure (ADR 0023) - a dedicated `EventPayload` variant recording
`plugin_name`, the host function called (if any), and outcome. It is registered
as an inline, fail-closed hook (matching `AuditHook`'s existing semantics: if
the audit hook itself fails, the triggering call fails closed too), not the
fire-and-forget `ProviderHooks` pattern. Because this is infrastructure rather
than a capability, there is no `capabilities` entry that enables or disables it,
and no way for a plugin - buggy or otherwise - to provision a user or assign a
role without that action being recorded.

### F. Sandbox Baseline: No WASI

No WASI (preview1 or preview2) imports are registered into any plugin's
`extism::Plugin` instance - no ambient filesystem, clock, random, or environment
access beyond what A–D above explicitly provide. This is a hard requirement of
the host-function registration step (§3), not a follow-up item: a plugin's only
way to reach outside its own linear memory is through the capabilities in A–D
that its config explicitly grants.

Capabilities not listed above (arbitrary internal method invocation by name, raw
storage access, token minting) are intentionally **not exposed**. If a future
use case needs one, it is added to this fixed list explicitly, in a follow-up
ADR amendment - not opened up generically.

---

## 7. Resource Limits & Failure Semantics

Every `authenticate` invocation runs under three independent bounds, mirroring
the existing precedent of the mapping engine's regex evaluator (2-second
deadline, 4 KiB per-value cap - ADR 0020 §5.1), each configurable per-plugin
with cluster-wide defaults:

1. **Fuel metering** (`fuel_limit`) - bounds total instruction count,
   independent of wall-clock (protects against a plugin that spins without
   making forward progress on I/O, where a timer alone might not fire
   predictably under load).
2. **Wall-clock deadline** (`timeout_ms`) - bounds total invocation time
   including any `http_fetch` calls the guest makes.
3. **Linear memory cap** (`memory_limit_mb`) - bounds guest heap growth.

**On any failure** - a WASM trap, fuel exhaustion, timeout, an attempted call to
an undeclared host function, or a response that fails to deserialize as
`AuthPluginResponse` - the login attempt is **rejected** (generic
`401 Unauthorized`; no internal detail leaked to the client) and a CADF
`Failure` audit event is emitted with a sanitized reason (§6.E). There is no
automatic fallback to another `[auth] methods` entry: exactly as today, the
client selects which method(s) it is attempting via the `identity.methods` field
of the auth request, and a plugin failing its own method is not silently retried
as `password`. This fail-closed posture was chosen because an auth method is
exactly the kind of fail-closed-only inline hook `AuditHook` already models
(`crates/core/src/events.rs:102-106`) - a partially-failed authentication
decision must never be treated as an implicit "try something weaker instead."

**Isolation between requests.** One `wasmtime::Engine` and one compiled
`extism::Plugin` module are shared per process (compilation is expensive;
correctness of the compiled module is immutable), but each `authenticate` call
gets a fresh `Store`/plugin instance state - no mutable state persists across
invocations. This prevents one request's execution from leaking data into or
influencing another's, and means a fuel/memory exhaustion in one invocation
cannot degrade a concurrent one.

### Invocation Rate Limiting & Concurrency

Per-invocation resource bounds (fuel, wall-clock, memory) limit the cost of a
_single_ call, but every plugin invocation is reachable by an anonymous,
pre-authentication caller (§1 Threat Model, actor 2) - nothing above bounds how
_many_ invocations happen concurrently or per unit time. Left unbounded, this is
both a direct resource-exhaustion DoS against Keystone (unbounded parallel
`Store`/wasm instances) and an SSRF/DDoS amplification vector against whatever
host is in `allowed_hosts` (§6.A), since each anonymous login attempt can
trigger an outbound HTTP call.

Three bounds apply per plugin, mirroring the two-tier rate limiter the Unified
Mapping Engine already uses for its own externally-triggered shadow-registry
writes (`shadow_registry_creation_rate_limit`, `shadow_registry_auth_rate_limit`

- ADR 0020 §7.2), reusing the `governor` crate already a workspace dependency
  (`Cargo.toml:82`):

1. **Per-source rate limit** (`invocation_rate_limit_per_source_per_minute`,
   §5) - a sliding-window token bucket keyed on `(plugin_name, remote_addr)`,
   using the same trusted, non-spoofable `remote_addr` `AuthPluginRequest`
   carries (§4) - never a raw `X-Forwarded-For` value unless it arrived over a
   configured trusted-proxy hop. Checked **first**, in front of bound 2: a
   caller from a single source exceeding it is rejected with
   `429 Too Many Requests` before it can touch the plugin-wide budget at all,
   audited as a `RateLimited` outcome scoped to that source. This is what
   actually stops one anonymous attacker (§1 Threat Model, actor 2) from being
   the party who burns bound 2's shared budget for everyone else on that method.
2. **Invocation rate limit** (`invocation_rate_limit_per_minute`, §5) - a
   sliding-window token bucket per plugin, shared across all sources. Exceeding
   it rejects further `authenticate` calls for that plugin with
   `429 Too Many Requests` until the window clears, audited as a `RateLimited`
   outcome.
3. **Concurrency cap** (`max_concurrent_invocations`, §5) - a semaphore bounding
   how many `Store` instances (and therefore how many in-flight `http_fetch`
   calls) may execute simultaneously for that plugin. A request arriving when
   the cap is saturated is rejected the same way as (1)/(2) rather than queued,
   to avoid building an unbounded backlog of pending authentications under load.

Defaults are conservative and layered (§5 example: 20/min per source, 300/min
per plugin, 16 concurrent) and all three are per-plugin, not global, so one
plugin's traffic cannot starve another's budget.

**Bound 1's keyed store is shrunk on a periodic tick, not per-request.** Every
distinct source address bound 1 sees - necessarily including anonymous,
pre-authentication callers (§1 Threat Model, actor 2) - allocates an entry in
the underlying keyed rate-limit store, which is never freed on its own; left
unaddressed, a long-running process accumulates one entry per distinct source
address it has ever seen. The process's existing minute-scale background
maintenance tick evicts entries whose bucket has fully recovered (i.e. is
indistinguishable from a source never seen before) for every loaded plugin's
bound-1 store - a straightforward memory-bookkeeping fix, not a rate-limiting
behavior change: an evicted, truly-idle source's next request is treated exactly
as a first-ever request would be, which is already correct.

**Internal/admin interface behavior.** Bound 1 applies only to public ingress.
An unproxied public request is keyed by its raw TCP peer; a proxied public
request is keyed by the client resolved through `trusted_header`. Internal mTLS
and admin requests deliberately pass `remote_addr = None`, even though the mTLS
listener records its shared mesh peer for audit logging, so unrelated internal
services cannot exhaust one another's per-source bucket. Those requests retain
bounds 2 and 3.

### Response Payload Bounds

Fuel/memory/timeout bound what a plugin can do _internally_; they do not bound
the size or shape of the `AuthPluginResponse` JSON the host must deserialize
from the guest's output. Mirroring the caps ADR 0020 already applies to its own
claim-derived data (4 KiB per claim value, 256-char interpolation limit - 0020
§5.1, §5.4), the host enforces, before attempting to deserialize the response:

- A hard cap on total response size (default 64 KiB) - an oversized response is
  rejected without being parsed.
- A cap on the `claims` map: at most 64 entries, keys at most 256 bytes, values
  at most 4 KiB each (matching ADR 0020's existing claim-value limit).
- **Structural namespacing, not a denylist.** Every claim a plugin emits is
  carried under a single reserved envelope key and surfaced to downstream OPA /
  `SecurityContext` construction only as `plugin_claims.<plugin_name>.<key>` -
  never merged into the top-level claim namespace. A plugin therefore **cannot**
  set, shadow, or collide with any privilege-relevant top-level key regardless
  of what it names its own claims, because its keys structurally live in a
  sub-object no policy reads as authoritative identity/authorization input. This
  is deliberately a structural containment (like the
  `(plugin_name, external_id)` identity namespace in §4) rather than a
  blocklist: a denylist of forbidden keys (`is_system`, `is_admin`, `roles`,
  `effective_roles`, ...) can only ever enumerate the privilege-relevant keys
  known _today_ - the moment an operator writes a Rego policy or a future
  `SecurityContext` field that trusts a top-level claim not on the list (e.g.
  `groups` driving group→role mapping, `project_id`, `trust_id`), the denylist
  is silently incomplete and the plugin can inject it. Namespacing closes that
  entire class instead of chasing it key by key. As defense-in-depth the host
  additionally rejects (fails the whole `Allow` closed) any attempt by a plugin
  to emit the reserved envelope key itself or a claim key prefixed `__keystone`,
  the same fail-loud posture as ADR 0020's `SystemTokenShadowing` write-time
  check (0020 §7.3).

Any violation is treated as a malformed response under the failure semantics
above: the login is rejected, and the specific bound that was exceeded is
recorded in the audit event (§6.E) for operator diagnosis, without echoing
attacker-influenced content back into logs.

---

## 8. Open Questions / Future Work

- **`mapping`-mode version binding at verification - not implemented.** See §4
  "Plugin-version binding for `mapping` mode." A `mapping`-mode token has no
  plugin-recoverable field in its `FernetToken` payload, so bumping a
  `mapping`-mode plugin's `valid_since` does not invalidate outstanding tokens
  the way it does for `full_auth`. Closing this requires either widening a token
  payload to carry a plugin-recoverable linkage (the per-record bookkeeping this
  ADR otherwise avoids) or a different invalidation mechanism entirely. Until
  then, incident response for a compromised `mapping`-mode plugin relies on
  revocation events or short token TTLs, not `valid_since`.
- **Per-domain plugin scoping.** This ADR deliberately restricts plugins to
  cluster-global, system-admin-installed, to keep the trust model simple for a
  first iteration. Extending this to a `(domain_id, provider_id)`-scoped model -
  parallel to how OIDC/K8s/SPIFFE providers work today (ADR 0020 §2) - is
  plausible future work, but raises open questions this ADR does not answer:
  could a domain admin install a plugin that calls `provision_user` outside
  their own domain? Should `allowed_hosts` be domain-restricted too? A follow-up
  ADR should address this once there is a concrete multi-tenant use case.
- **Hot reload / upload API.** Startup-only loading (§5) is the simplest correct
  starting point. An admin API to upload new plugin versions without a process
  restart - likely backed by Raft/FjallDB replication once plugins are no longer
  purely cluster-global-static - is deferred.
- **Signing beyond a pinned checksum.** SHA-256 pinning (§5) catches corruption
  and accidental drift but is not a substitute for a real code-signing chain if
  plugins are ever sourced from outside the operator's own build pipeline. Not
  needed while distribution is "operator places the file themselves," but worth
  revisiting if plugins become installable from a registry.
- **Secret rotation.** `http_fetch_auth_secret_env` (§6.A) reads a secret from a
  host-side environment variable at call time, which is enough to keep the value
  out of guest memory and out of the distributed `.wasm` file, but rotating it
  still requires a process restart today, same as any other env-var-sourced
  Keystone secret. A dedicated secret-store integration (rotation without
  restart) is future work, not required for this ADR's threat model (§1).
- **Remediation after a plugin is pulled for a security bug - addressed.**
  Resolved by "Bulk Revocation on Plugin Compromise" (§4): a single
  `POST /v4/auth_plugins/{plugin_name}/revoke_all` disables everything the
  plugin provisioned/granted/was linked to and revokes affected tokens, on top
  of the token-level protection version binding (§4 "Plugin Version Binding")
  already provides. What remains genuinely open: that endpoint is deliberately
  `plugin_name`-scoped, not scoped to a single plugin binary version (see its
  "Why plugin-name-scoped" rationale) - an operator who wants to reinstate only
  the state attributable to a _different_, non-vulnerable version of the same
  plugin must still identify and re-enable that subset by hand against the audit
  trail.
- **Coarser domain-scoped resolution (considered, rejected).** An earlier draft
  of this ADR considered letting a `full_auth` plugin resolve any user within
  its `provision_domain_id` without a per-identity admin link, purely to reduce
  admin overhead for operators with many pre-existing users to onboard.
  Rejected: it would mean a buggy or exploited plugin (§1 Threat Model, actor 1)
  could authenticate as _anyone in that domain_, not just identities someone
  deliberately opted in - trading away the one guarantee ("only
  explicitly-authorized identities are reachable") this design is built around,
  for convenience. The SCIM bulk-linking convenience above (resolving via
  `scim_provider_id`/`scim_external_id`) covers the "many users to onboard" case
  without that trade-off - it's still one explicit link per identity, just
  without requiring the admin to already know the internal `user_id`.

---

## 9. Consequences

### Positive

- Operators can add custom authentication logic without forking `keystone-rs` or
  waiting on an upstream release - the stated requirement.
- The curated host-function allowlist (§6) means the security review surface for
  "what can a plugin actually do" is a fixed, auditable list per plugin, not
  "whatever Rust code can reach."
- Namespace-scoped identity binding (§4) structurally prevents a plugin from
  authenticating as an arbitrary existing account - not just by blocking a raw
  `user_id` claim, but by making `find_user`/`provision_user` incapable of
  resolving any identity outside that plugin's own `(plugin_name, external_id)`
  mappings. This is the strongest guarantee in this design: it bounds the blast
  radius of a buggy or exploited plugin (§1 Threat Model, actor 1) to "can
  authenticate as identities it itself provisioned," never "can authenticate as
  anyone already in the system."
- Fail-closed failure handling (§7) and mandatory, non-optional CADF auditing
  (§6.E) mean a misbehaving or exploited plugin cannot silently degrade into
  weaker-than-expected authentication or provision/grant without a trace.
- Per-source, per-plugin rate limiting and concurrency caps (§7) bound the
  damage an anonymous caller (§1 Threat Model, actor 2) can do simply by hitting
  the login endpoint, and specifically prevent a single bad actor from
  exhausting one auth method's shared budget for every legitimate user of it -
  extending the same two-tier pattern ADR 0020 already established for its own
  externally-triggered writes with a source-scoped front tier.
- A bulk `revoke_all` admin endpoint (§4 "Bulk Revocation on Plugin Compromise")
  turns "a plugin was compromised" from a manual, per-record cleanup exercise
  under incident-response pressure into a single audited call that disables
  everything the plugin ever provisioned, granted, or was linked to.
- `http_fetch`'s connect-time IP re-validation and host-injected secrets (§6.A)
  close the standard SSRF and credential-exposure pitfalls of an "allowed-hosts
  HTTP proxy" feature up front, rather than as a follow-up hardening pass.
- `mapping` mode (§4) lets a plugin serve pre-existing users - including
  SCIM-provisioned ones (ADR 0024) - without any identity-binding machinery at
  all, by delegating the actual decision to the already-reviewed Mapping Engine
  (ADR 0020). This is a strictly additive safety property: the plugin
  structurally cannot terminate authentication in this mode, so it inherits the
  Mapping Engine's existing guarantees rather than needing new ones.
- Admin-authorized external identity linking (§4) gives `full_auth` plugins a
  path to pre-existing users too, for cases `mapping` mode can't express,
  without ever letting the plugin itself decide who it can authenticate as - the
  gate is an ordinary RBAC-checked, audited, revocable admin action, not new
  plugin-facing trust.
- Reuses Extism's existing HTTP allow-list and resource-limiting primitives
  rather than hand-rolling a WASI-sockets bridge and a custom fuel/timeout
  system.
- Closes an existing gap (missing per-request HTTP timeout in
  `k8s_auth_client.rs`) for the new, more exposed call path, without needing to
  touch the existing K8s client itself.
- `route` mode (§4) lets a client that can only ever send a fixed method name -
  Terraform's `application_credential`-shaped auth is the motivating case - be
  transparently redirected to the handler that actually knows how to verify its
  credential, without collapsing the routing decision and the authentication
  decision into one piece of code. Because the target method still performs its
  own full verification and the router itself can never resolve or grant
  anything, this reuses the same "narrow, structurally-bounded capability"
  posture as the rest of this ADR rather than introducing a new trust model.

### Negative

- A new runtime dependency (`extism` + `wasmtime`) with its own release cadence,
  security-patch surface, and binary-size cost, orthogonal to the existing
  `inventory`-based plugin model (ADR 0018) - the codebase now has two distinct
  extensibility mechanisms, which must be kept clearly documented as serving
  different purposes (first-party static vs. third-party dynamic).
- Filesystem-based distribution (§5) means the operator, not `keystone-rs`, is
  responsible for keeping the `.wasm` file and its pinned hash consistent across
  every node; a mismatch on a given node - including a plain typo in the pinned
  hash, not just a genuine tamper/corruption case - disables only that plugin on
  that node (§5), which can leave one auth method inconsistently available
  across the cluster until an operator acts on the accompanying `CRITICAL`
  alert. This trades the previous design's stronger (whole-cluster-blocking)
  consistency guarantee for availability, and still raises the operational cost
  of a plugin update to that of a coordinated, carefully-staged rollout if an
  operator wants to avoid the divergence window entirely.
- Cluster-global-only scoping (§8) means this does not yet serve a multi-tenant
  "let domain admins bring their own auth plugin" use case - only system admins
  can install plugins.
- Guest-language plugin authors must target Extism's PDK ABI, which is a new
  toolchain requirement distinct from ordinary `keystone-rs` Rust development.
- The namespace-scoped identity model (§4) and mandatory audit wrapping (§6.E)
  add host-side bookkeeping (per-`Store` handle maps, a dedicated
  `(plugin_name, external_id)` mapping table, non-bypassable hook dispatch)
  beyond what a naive "trust the plugin's JSON" implementation would need - a
  deliberate complexity/safety trade-off given this is an authentication
  surface.
- Persistent state a plugin creates or is linked to (provisioned users, granted
  roles, admin-created identity links) is not automatically undone when the
  plugin is later patched or removed for a security issue - only future tokens
  are blocked (§4 "Plugin Version Binding"). Cleanup today is a manual,
  audit-log-driven operator task (§8).
- Three operating modes, a new admin API (`identity_links`), and an amendment to
  ADR 0020's `IdentitySource` enum and `MappingContext` payload (§4) widen this
  ADR's surface area beyond a single, self-contained mechanism - an operator now
  has to understand which mode a given plugin runs in to reason about what it
  can reach, and `mapping`-mode plugins depend on an admin having separately
  authored Mapping Engine rules for them (§4 step 4) or they authenticate no
  one.
- `route` mode is reachable by a strictly larger slice of traffic than
  `full_auth`/`mapping` plugins - every request whose `identity.methods` matches
  its `inspect_methods` list, not just requests already addressed to it by name
  - so it sees raw credential material (headers, payload fields) for logins it
    may ultimately have no involvement in beyond `Passthrough`. This is a real
    increase in what third-party WASM code is exposed to compared to the rest of
    this ADR's "opt-in by name" model, contained only by `inspect_methods`
    scoping and the payload/header allowlists already used elsewhere (§4).

## See Also

- `doc/src/adr/0018-plugin-linking.md` - the static/compile-time counterpart
  this ADR deliberately does not replace.
- `doc/src/adr/0017-security-context.md` - the validation pipeline a
  plugin-authenticated principal flows through unchanged.
- `doc/src/adr/0020-mapping-engine.md` §5.1 - precedent for bounded,
  timeout/size-capped evaluation of untrusted-shaped input.
- `doc/src/adr/0020-mapping-engine.md` §2, §3, §5.3, §9.A - `IdentitySource`,
  `MappingRuleSet`/`allowed_domains`, `MappingContext`, and admin-write RBAC
  tiering, all extended or reused by `mapping` mode and identity linking (§4).
- [`openstack_keystone_core_types::mapping::resolution::IdentitySource`] enum,
  gains the `WasmPlugin` variant for `mapping` mode.
- [`MappingContext`] - `mapping`-mode token invalidation reuses its existing
  `mapping_id` to recover the plugin's `valid_since` from the matched ruleset's
  `IdentitySource::WasmPlugin`; no new field is added.
- `doc/src/adr/0023-audit.md` - CADF audit event model reused for plugin
  invocation auditing.
- `doc/src/adr/0024-scim-v2-provisioning.md` §3.A–B - `ScimResourceIndex` and
  the `externalId` lookup index reused by the SCIM identity-linking convenience
  (§4).
- [`AuthenticationContext`] enum.
- [`AuthenticationContext::Mapping`], the variant a successful `mapping`-mode
  login produces.
- [`openstack_keystone_core::identity::backend::IdentityBackend::create_user`],
  the target of the `provision_user` host function.
