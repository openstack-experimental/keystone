# Authentication Plugin Development

This guide covers designing, building, and deploying dynamic authentication
plugins for Keystone using WebAssembly (WASM).

## Overview

Dynamic auth plugins extend Keystone's authentication without recompiling or
forking:

- **Compile once** to `.wasm`, distribute to every Keystone node
- **Three operating modes**: full authentication authority, claims transformer,
  or request router
- **Curated host functions** - plugins cannot access arbitrary storage or
  network, only what's explicitly granted
- **Namespace-scoped identity** - plugins can only authenticate users they
  themselves provision (except via admin-authorized linking)

All code in this guide is derived from the real, compiled reference plugin
fixture used by Keystone's own test suite
(`crates/auth-plugin-runtime/tests/fixtures/reference-plugin/src/lib.rs`) and
the actual wire contract types
(`crates/auth-plugin-runtime/src/{auth_contract,mapping_contract,route_contract}.rs`).
If your plugin's JSON doesn't round-trip against those types, the host rejects
it as malformed (ADR 0025 §7) - there is no leniency in the decoder.

See [ADR 0025](../adr/0025-dynamic-auth-plugins.md) for the complete threat
model and design rationale.

---

## Quick Start: Hello-World Plugin

Build and test a minimal `full_auth` plugin.

### 1. Setup

```bash
# Add Rust target for WebAssembly
rustup target add wasm32-unknown-unknown

# Create a new Rust library
cargo new --lib my_plugin
cd my_plugin
```

### 2. Dependencies

Edit `Cargo.toml`:

```toml
[package]
name = "my_plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]  # REQUIRED: produces .wasm, not .rlib

[dependencies]
extism-pdk = "1"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

### 3. Plugin Code

Every host function Keystone exposes takes exactly **one** JSON-encoded string
argument and returns exactly **one** JSON-encoded string - never multiple typed
arguments. The `#[host_fn] extern "ExtismHost"` block below is how you declare
that ABI to `extism-pdk`; you build/parse the JSON yourself with `serde_json`.

Edit `src/lib.rs`:

```rust
use extism_pdk::{host_fn, plugin_fn, FnResult, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Host functions Keystone registers for this plugin, gated by its
// `capabilities` config entry (ADR 0025 §6). One JSON string in, one JSON
// string out - this is the actual ABI, not the typed multi-arg signature a
// higher-level SDK might expose in other languages.
#[host_fn]
extern "ExtismHost" {
    fn provision_user(request_json: String) -> String;
    fn find_user(external_id_json: String) -> String;
}

// The `payload` shape is whatever your plugin's own config block declares
// under `identity.<method_name>` in the client's auth request - you define
// this struct to match what your clients will send.
#[derive(Debug, Deserialize)]
pub struct MyPayload {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthPluginRequest {
    pub payload: MyPayload,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub remote_addr: Option<String>,
}

// Wire-format requirement: internally tagged on "decision", snake_case.
// `{"decision":"allow","resolved_identity":"...","claims":{...}}` /
// `{"decision":"deny","reason":"..."}` - any other shape is rejected as
// malformed before your plugin's logic is even considered to have run.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum AuthPluginResponse {
    Allow {
        resolved_identity: String,
        claims: HashMap<String, serde_json::Value>,
    },
    Deny {
        reason: String,
    },
}

/// Authenticate a user (full_auth mode).
#[plugin_fn]
pub fn authenticate(req: Json<AuthPluginRequest>) -> FnResult<Json<AuthPluginResponse>> {
    let payload = req.0.payload;

    // Simple demo: accept any non-empty username. In a real plugin, verify
    // against an external service, check a signature, etc. *before* calling
    // provision_user - provision_user/find_user only bind an already-verified
    // external identity to a Keystone user, they perform no verification of
    // their own.
    if payload.username.is_empty() {
        return Ok(Json(AuthPluginResponse::Deny {
            reason: "empty username".to_string(),
        }));
    }

    // provision_user's request body: {"external_id": "...", "user": {...}}.
    // `user` accepts only `domain_id`, `name`, `enabled` (optional), `extra`
    // (optional map) - an intentionally narrow allowlist (ADR §6.B "Field
    // sanitization"); there is no `id`, `password`, or admin-ish option
    // field a plugin can set.
    let provision_request = serde_json::json!({
        "external_id": payload.username,
        "user": {
            "domain_id": "default",
            "name": payload.username,
        },
    });
    // The host function itself takes/returns a single JSON string - encode
    // the request, decode the response yourself.
    let handle_json = unsafe { provision_user(provision_request.to_string())? };
    // provision_user's success response is a bare JSON string (the opaque
    // handle) - NOT `{"handle": "..."}`.
    let resolved_identity: String = serde_json::from_str(&handle_json)?;

    let mut claims = HashMap::new();
    claims.insert(
        "external_username".to_string(),
        serde_json::Value::String(payload.username),
    );

    Ok(Json(AuthPluginResponse::Allow {
        resolved_identity,
        claims,
    }))
}
```

### 4. Build

```bash
cargo build --release --target wasm32-unknown-unknown
ls -la target/wasm32-unknown-unknown/release/my_plugin.wasm
```

### 5. Deploy

Compute the SHA-256 checksum:

```bash
sha256sum target/wasm32-unknown-unknown/release/my_plugin.wasm
# Output: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  my_plugin.wasm
```

Add to Keystone config:

```ini
[auth_plugins]
plugins = my_plugin

[auth_plugin.my_plugin]
path = /etc/keystone/plugins/my_plugin.wasm
sha256 = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
mode = full_auth
capabilities = provision_user,find_user
provision_domain_id = default
timeout_ms = 750
fuel_limit = 50000000
memory_limit_mb = 32

[auth]
methods = password,token,my_plugin
```

Copy the `.wasm` to every Keystone node and restart:

```bash
cp target/wasm32-unknown-unknown/release/my_plugin.wasm /etc/keystone/plugins/
systemctl restart keystone
```

### 6. Test

```bash
curl -X POST http://keystone:5000/v3/auth/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "auth": {
      "identity": {
        "methods": ["my_plugin"],
        "my_plugin": {
          "username": "alice"
        }
      }
    }
  }'

# On success: HTTP 201, X-Subject-Token header
```

---

## Operating Modes Deep Dive

### `full_auth`: Plugin Authenticates Users

Plugin is the terminal authentication authority. It decides who is allowed and
optionally provisions users.

**Entry point:** `authenticate(AuthPluginRequest) -> AuthPluginResponse`

**When to use:**

- Custom SSO bridges (proprietary token formats, legacy directory protocols)
- Real-time risk scoring or step-up decisions
- Non-standard credential verification (e.g., certificate chains)

**Capabilities available:**

- `http_fetch` - call external services
- `provision_user` - create new users (first login)
- `find_user` - look up provisioned users (idempotent login)
- `assign_role` - grant roles to users

**Identity binding (security):**

- Plugin cannot assert arbitrary `user_id` values
- `provision_user` and `find_user` operate on `(plugin_name, external_id)`
  namespace
- External ID must come from verified credential (not plugin-chosen)
- Only users the plugin itself provisioned are reachable
- Pre-existing users require admin-authorized linking (see "Admin Identity
  Linking" below)

**Example: OIDC-like SSO**

```rust
use extism_pdk::{host_fn, plugin_fn, FnResult, Json};
use std::collections::HashMap;

#[host_fn]
extern "ExtismHost" {
    fn http_fetch(request_json: String) -> String;
    fn provision_user(request_json: String) -> String;
}

#[plugin_fn]
pub fn authenticate(req: Json<AuthPluginRequest>) -> FnResult<Json<AuthPluginResponse>> {
    let token = req.0.payload.get("token").and_then(|v| v.as_str()).ok_or("No token")?;

    // http_fetch's request body: {"method": "GET", "url": "...", "headers": {...}, "body": null}.
    // Authentication to the upstream service (if any) is injected by the
    // host from `http_fetch_auth_header`/`http_fetch_auth_secret_env`
    // config - it is never something this plugin supplies itself.
    let fetch_request = serde_json::json!({
        "method": "GET",
        "url": "https://idp.example.com/userinfo",
        "headers": {"Authorization": format!("Bearer {token}")},
    });
    let response_json = unsafe { http_fetch(fetch_request.to_string())? };
    // http_fetch's response: {"status": 200, "headers": {...}, "body": "..."}
    // - body is the raw response text; parse it yourself.
    let response: serde_json::Value = serde_json::from_str(&response_json)?;
    let status = response.get("status").and_then(|v| v.as_u64()).unwrap_or(0);
    if status != 200 {
        return Ok(Json(AuthPluginResponse::Deny {
            reason: format!("IDP returned {status}"),
        }));
    }
    let body: serde_json::Value = serde_json::from_str(
        response.get("body").and_then(|v| v.as_str()).unwrap_or("{}"),
    )?;
    let sub = body.get("sub").and_then(|v| v.as_str()).ok_or("No 'sub' claim")?;

    let provision_request = serde_json::json!({
        "external_id": sub,
        "user": {
            "domain_id": "default",
            "name": body.get("name").and_then(|v| v.as_str()).unwrap_or(sub),
        },
    });
    let handle_json = unsafe { provision_user(provision_request.to_string())? };
    let resolved_identity: String = serde_json::from_str(&handle_json)?;

    let mut claims = HashMap::new();
    if let Some(email) = body.get("email") {
        claims.insert("email".to_string(), email.clone());
    }
    if let Some(groups) = body.get("groups") {
        claims.insert("groups".to_string(), groups.clone());
    }

    Ok(Json(AuthPluginResponse::Allow {
        resolved_identity,
        claims,
    }))
}
```

### `mapping`: Plugin Produces Claims, Mapping Engine Decides

Plugin generates claims; the **Mapping Engine** (not the plugin) makes the
identity decision via configured rules.

**Entry point:** `mapping(AuthPluginRequest) -> MappingResponse`

**When to use:**

- Plugins that transform existing credentials into claims (header/JWT parsing,
  protocol adapters)
- Authenticating pre-existing SCIM-provisioned users (no namespace scoping
  needed)
- Plugins that don't make terminal `Allow`/`Deny` decisions

**No identity binding:** Plugin cannot provision or name users. Mapping Engine
uses claims to match against `MappingRuleSet` rules, resolving to real users if
rules fire.

**A `__keystone_workload_id` claim is required.** Every `mapping`-mode
response's `claims` map must include a string-valued `__keystone_workload_id`
key - it is the Mapping Engine's `unique_workload_id` (ADR 0020 §3), which has
no dedicated field on `MappingResponse::Claims`. A response missing it, or where
it isn't a string, is rejected as malformed (`MissingWorkloadId`) before the
Mapping Engine ever sees it. Unlike every other `__keystone`-prefixed key, this
one is left in the claims map so mapping rules can also reference it directly.

**Admin setup required:**

1. Deploy plugin with `mode = mapping`
2. Create `MappingRuleSet` rules with `provider_id = "wasm:{plugin_name}"`
3. Rules decide identity resolution (e.g., match claims to existing user by
   email)
4. Plugin claims are namespaced: no risk of injecting privilege-relevant claims

**Example: Parse custom header and produce claims**

```rust
use extism_pdk::{plugin_fn, FnResult, Json};
use std::collections::HashMap;

// Wire shape mirrors AuthPluginResponse's tagging convention:
// {"decision":"claims","claims":{...}} / {"decision":"deny","reason":"..."}.
// There is no `Allow` variant - a mapping-mode plugin cannot terminate
// authentication, only feed the engine that does.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum MappingResponse {
    Claims { claims: HashMap<String, serde_json::Value> },
    Deny { reason: String },
}

#[plugin_fn]
pub fn mapping(req: Json<AuthPluginRequest>) -> FnResult<Json<MappingResponse>> {
    // Extract custom header (must be in this plugin's exposed_headers config
    // - anything not explicitly allowlisted there is simply absent here,
    // never silently forwarded).
    let header_value = req
        .0
        .headers
        .get("X-Custom-Auth")
        .ok_or("missing X-Custom-Auth header")?;

    let parts: Vec<&str> = header_value.split(':').collect();
    if parts.len() < 2 {
        return Ok(Json(MappingResponse::Deny {
            reason: "malformed header".to_string(),
        }));
    }

    let mut claims = HashMap::new();
    // Required on every mapping-mode response - see note above.
    claims.insert(
        "__keystone_workload_id".to_string(),
        serde_json::Value::String(parts[1].to_string()),
    );
    claims.insert("realm".to_string(), serde_json::Value::String(parts[0].to_string()));
    claims.insert(
        "email".to_string(),
        serde_json::Value::String(format!("{}@example.com", parts[1])),
    );

    Ok(Json(MappingResponse::Claims { claims }))
}
```

Corresponding Mapping Engine rule (`POST /v4/mappings`, ADR 0020 §9.A):

```json
{
  "mapping": {
    "domain_id": "default",
    "source": { "type": "wasm_plugin", "plugin_name": "my_mapping_plugin" },
    "domain_resolution_mode": { "type": "fixed" },
    "enabled": true,
    "rules": [
      {
        "name": "any-claim",
        "match": {
          "all_of": [
            {
              "type": "condition",
              "matches_regex": { "claim": "realm", "regex": ".*" }
            }
          ]
        },
        "identity": {
          "user_name": "{realm}-{email}",
          "user_domain_id": "default",
          "is_system": false
        },
        "authorizations": [],
        "groups": []
      }
    ]
  }
}
```

### `route`: Plugin Routes Requests Pre-Dispatch

Plugin sees the raw, pre-dispatch request before method dispatch; can redirect
to a different method or pass through unchanged. It never authenticates anyone.

**Entry point:** `route(RouteRequest) -> RouteResponse`

**When to use:**

- Clients that always send a fixed method name (can't be changed)
- Conditional routing based on credential content (e.g.,
  `application_credential` that might be different handler-specific formats)
- Credential-shape-based dispatching without authentication

**Important: Plugin does NOT authenticate.** Target method still performs full
verification against whatever payload it receives.

**Constraints (enforced by host):**

1. Cannot touch `scope` (project/domain/system) - `RouteResponse` carries no
   `scope` field at all, only relabels which method handles the request
2. Can only route to methods in this plugin's `route_targets` allowlist - a
   response naming any other method is rejected as malformed, not corrected
3. Can never target `admin` or `trust` methods, regardless of `route_targets`
4. Single-shot - a request already routed once is never re-routed, by the same
   router or a different one
5. Target method receives exactly the payload this plugin specifies -
   re-verification by the target is what makes that safe, not any assertion this
   plugin makes

**Example: application_credential routing**

```rust
use extism_pdk::{plugin_fn, FnResult, Json};
use std::collections::HashMap;

// `methods`, not `requested_methods` - the actual field name.
#[derive(Debug, serde::Deserialize)]
pub struct RouteRequest {
    pub methods: Vec<String>,
    #[serde(default)]
    pub payloads: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub remote_addr: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum RouteResponse {
    Passthrough,
    Route {
        target_method: String,
        payload: serde_json::Value,
    },
    Deny {
        reason: String,
    },
}

#[plugin_fn]
pub fn route(req: Json<RouteRequest>) -> FnResult<Json<RouteResponse>> {
    // `payloads` only ever contains blocks for methods this plugin's
    // `inspect_methods` config declared - a router configured to look at
    // `application_credential` never sees an unrelated `password` block,
    // even on a request carrying both.
    let Some(payload) = req.0.payloads.get("application_credential") else {
        return Ok(Json(RouteResponse::Passthrough));
    };
    let Some(cred_id) = payload.get("application_credential_id").and_then(|v| v.as_str()) else {
        return Ok(Json(RouteResponse::Passthrough));
    };

    if let Some(rest) = cred_id.strip_prefix("tf-") {
        return Ok(Json(RouteResponse::Route {
            target_method: "hacked_appcred_handler".to_string(),
            payload: serde_json::json!({ "external_id": rest }),
        }));
    }

    // Every other application_credential request passes through unmodified.
    Ok(Json(RouteResponse::Passthrough))
}
```

Config:

```ini
[auth_plugin.tf_router]
mode = route
inspect_methods = application_credential
route_targets = hacked_appcred_handler
capabilities =  # empty; add http_fetch if the router needs to query an external service
```

---

## Host Functions API

### Request Objects

Every entry point receives a request whose exact shape depends on the mode:

- `authenticate`/`mapping`:
  `AuthPluginRequest { payload, headers, remote_addr }`
  - `payload: serde_json::Value` - raw `identity.<method>` block from the
    client's auth request, exactly as received; deserialize it into whatever
    shape your plugin expects
  - `headers: HashMap<String, String>` - allowlisted subset of inbound HTTP
    headers (only names in this plugin's `exposed_headers` config; a fixed
    denylist - `Authorization`, `Cookie`, `X-Auth-Token`, `X-Service-Token`,
    `X-Subject-Token`, `Proxy-Authorization` - can never appear here regardless
    of config)
  - `remote_addr: Option<String>` - trusted client address (resolved via
    `[auth_plugins].trusted_proxies`), never a raw, spoofable `X-Forwarded-For`
    value; `None` if no trusted address could be established
- `route`: `RouteRequest { methods, payloads, headers, remote_addr }` - see the
  `route` mode section above; runs pre-dispatch on the client's full
  `identity.methods` list, not a single method's isolated payload

### HTTP Fetching

Capability: `http_fetch`.

**Request/response shape** (single JSON string in, single JSON string out, like
every host function):

```jsonc
// Request
{
  "method": "GET", // GET, POST, PUT, PATCH, DELETE, HEAD
  "url": "https://...", // host must be in this plugin's allowed_hosts
  "headers": { "Content-Type": "application/json" },
  "body": null, // UTF-8 string, or omit/null for no body
}
```

```jsonc
// Response
{
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body": "...", // UTF-8 (lossy) response body
}
```

**Constraints:**

- Only `allowed_hosts` are reachable (config-time allowlist)
- All resolved IPs are checked against private/loopback/link-local/multicast/
  cloud-metadata ranges (no SSRF), re-resolved at connect time (no DNS
  rebinding)
- Auth secrets are injected by the host from `http_fetch_auth_header` +
  `http_fetch_auth_secret_env` config, applied after your headers and replacing
  any header of the same name you supplied - the secret is never visible to your
  plugin's code or the distributed `.wasm` file
- No redirects by default; opt in per-plugin with
  `http_fetch_follow_redirects = true`, and even then the whole redirect chain
  shares one `timeout_ms` budget, not one budget per hop

**Example:**

```rust
let fetch_request = serde_json::json!({
    "method": "POST",
    "url": "https://idp.example.com/validate",
    "headers": {"Content-Type": "application/json"},
    "body": serde_json::json!({"token": token}).to_string(),
});
let response_json = unsafe { http_fetch(fetch_request.to_string())? };
let response: serde_json::Value = serde_json::from_str(&response_json)?;
let status = response.get("status").and_then(|v| v.as_u64()).unwrap_or(0);

if status != 200 {
    return Ok(Json(AuthPluginResponse::Deny {
        reason: format!("IDP returned {status}"),
    }));
}
```

### Provisioning Users

**`full_auth` mode only.**

**Request:**

```jsonc
{
  "external_id": "...", // plugin-derived identifier, never a Keystone user_id
  "user": {
    "domain_id": "...", // must be in provision_domain_id / allowed_provision_domains
    "name": "...",
    "enabled": true, // optional
    "extra": {}, // optional
  },
}
```

**Response:** a bare JSON string - the opaque handle. **Not**
`{"handle": "..."}`.

**Semantics:**

- Creates a new Keystone `User` (if not already created)
- Records mapping `(plugin_name, external_id) -> user_id`
- Returns opaque handle (not the real `user_id`) - present it back verbatim in
  `Allow.resolved_identity`
- **Idempotent:** same `external_id` on repeat calls returns a handle to the
  same user
- **Atomic:** race-safe with concurrent requests
- **Domain-scoped:** `user.domain_id` must be in this plugin's
  `provision_domain_id` or `allowed_provision_domains`; only `domain_id`,
  `name`, `enabled`, `extra` are accepted - there is no `id` or password field a
  plugin can set

**Use case:** First login for a new external identity

### Finding Users

**`full_auth` mode only.**

**Request:** a bare JSON string - the `external_id`.

**Response:** the handle as a JSON string, or `null` if not found.

**Semantics:**

- Looks up user by `(plugin_name, external_id)` only
- **Not** a general username search
- Cannot reach users provisioned by other plugins or via other methods
- For admin-linked identities: domain restriction is re-checked on every call
  (prevents stale links after a user is moved to a different domain)

**Use case:** Returning user login (idempotent after first provision)

### Assigning Roles

**`full_auth` mode only.**

**Request:**

```jsonc
{
  "resolved_identity": "...", // a handle THIS invocation's provision_user/find_user produced
  "role": "member",
  "target": { "scope": "project", "project_id": "..." },
  // or: { "scope": "domain", "domain_id": "..." }
}
```

**Response:** an empty JSON value on success (traps/errors on rejection - see
below).

**Constraints (host-enforced):**

- `role` must be in this plugin's `assign_role_allowed` list
- Target project/domain must be in `provision_domain_id` /
  `allowed_provision_domains`
- System scope is never allowed - there is no `system` variant of `target` at
  all, so a plugin has no way to even express that request
- `resolved_identity` must be a handle this exact invocation's own
  `provision_user`/`find_user` call produced - the same anti-impersonation
  constraint as identity binding itself

**Use case:** Grant initial roles on first user provisioning

---

## Error Handling

A host function call returns `Err` (traps the guest call via `?`) on any
violation of the constraints above - a disallowed domain, a role outside
`assign_role_allowed`, a host outside `allowed_hosts`, an invalid
`resolved_identity`, and so on. The failure reason is **not** returned to your
plugin in a structured, inspectable way - it fails the whole invocation closed
(ADR 0025 §7). Design your plugin to check what it can up front (e.g. only call
`assign_role` with roles you know are configured) rather than relying on host
errors for control flow.

---

## Admin Identity Linking

`full_auth` plugins can authenticate pre-existing users (e.g., SCIM-provisioned)
via admin-authorized linking, without the plugin provisioning them.

### API

**Create link:**

```bash
curl -X POST http://keystone:5000/v4/auth_plugins/{plugin_name}/identity_links \
  -H "X-Auth-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "identity_link": {
      "external_id": "sso_user_123",
      "user_id": "existing-keystone-uuid"
    }
  }'
```

RBAC-tiered (ADR §4): system-scope `admin` may link any user; a domain-scoped
`admin`/`manager` may link only a non-system user in their own domain.
Re-linking an `external_id` that already has an entry is rejected
(`409 Conflict`) - `DELETE` the existing link first.

> **Note:** SCIM convenience fields (`scim_provider_id`, `scim_external_id`) are
> documented in ADR 0025 §4 but not yet implemented. Only the direct
> `{external_id, user_id}` body is accepted today.

**Delete link:**

```bash
curl -X DELETE http://keystone:5000/v4/auth_plugins/{plugin_name}/identity_links/{external_id} \
  -H "X-Auth-Token: $ADMIN_TOKEN"
```

Also revokes the unlinked user's live tokens.

**Bulk revocation** (on plugin compromise):

```bash
curl -X POST http://keystone:5000/v4/auth_plugins/{plugin_name}/revoke_all \
  -H "X-Auth-Token: $ADMIN_TOKEN"
```

System-admin only. Disables every user the plugin provisioned or was linked to,
deletes those identity links, and revokes their tokens. It does **not** revoke
role assignments the plugin granted - review those separately against the CADF
audit trail before re-enabling any disabled account.

### Plugin Logic

No change needed in plugin code - `find_user(external_id)` works the same
whether the entry was created by `provision_user` or by an admin link.

---

## Response Bounds & Safety

### Claims Size

- Max 64 entries in the `claims` map
- Max 256 bytes per key
- Max 4 KiB per value
- Total response JSON capped at 64 KiB (rejected unparsed if exceeded)

### Claims Namespacing

All `full_auth`-mode plugin claims are automatically namespaced under
`plugin_claims.<plugin_name>.<key>` in the policy input - never merged into the
top level. This prevents injection of privilege-relevant top-level keys.

```rust
// Plugin returns (Allow.claims):
// {"email": "user@example.com", "groups": ["admin"]}

// OPA sees (input.credentials):
// {"plugin_claims": {"my_plugin": {"email": "...", "groups": ["admin"]}}}

// A policy can read: input.credentials.plugin_claims.my_plugin.email
// It cannot inject top-level keys like is_system, effective_roles, etc. -
// those simply aren't where plugin claims live.
```

`mapping`-mode claims are not namespaced this way - they flow into the Mapping
Engine's rule matching instead (ADR 0020), which has its own,
separately-reviewed guarantee that claim values only ever drive rule _matching_,
never become privilege directly.

### Reserved Keys

A claim key named exactly `plugin_claims`, or prefixed with `__keystone`, is
rejected (the whole response fails closed) - except `__keystone_workload_id` in
`mapping` mode, which is required (see the `mapping` mode section above).

---

## Testing & Debugging

### Local Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authenticate_valid() {
        let req = AuthPluginRequest {
            payload: MyPayload { username: "alice".to_string() },
            headers: Default::default(),
            remote_addr: Some("192.0.2.1".to_string()),
        };

        // Exercise your plugin's logic directly - `authenticate` itself
        // requires a live extism host context for its `unsafe { provision_user(..) }`
        // call, so unit-test the decision logic your plugin builds around it,
        // not the wasm entry point end to end. End-to-end coverage belongs in
        // integration tests (below) against a real Keystone instance.
        assert!(!req.payload.username.is_empty());
    }
}
```

### Integration Testing

Test against a real Keystone instance (see
[Administrator Plugin Operations](../admin/features/auth-plugins.md)):

```bash
# 1. Build and copy plugin
cargo build --release --target wasm32-unknown-unknown
SHA=$(sha256sum target/wasm32-unknown-unknown/release/my_plugin.wasm | cut -d' ' -f1)
cp target/wasm32-unknown-unknown/release/my_plugin.wasm /etc/keystone/plugins/

# 2. Update keystone.conf with plugin config and SHA
# 3. Restart Keystone
systemctl restart keystone

# 4. Test authentication
curl -X POST http://keystone:5000/v3/auth/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "auth": {
      "identity": {
        "methods": ["my_plugin"],
        "my_plugin": {"username": "test"}
      }
    }
  }'
```

### Debugging

**Plugin load failures** - `keystone_auth_plugin_load_failure{plugin_name}` on
`/metrics`, plus a `CRITICAL` log line naming the plugin and the mismatch:

```bash
grep "keystone_auth_plugin_load_failure" /var/log/keystone/keystone.log
```

**Rate limit hits** - check if the plugin is being rate-limited:

```bash
grep "rate_limited" /var/log/keystone/keystone.log
```

**Timeouts/fuel/memory** - a resource-bound violation fails the specific
invocation closed, audited via the plugin's CADF trail (`wasm_plugin.*` events,
ADR §6.E) rather than a distinct log grep target - check the audit event
outcome/reason for the plugin's `authenticate`/`mapping`/`route` calls.

---

## Real-World Example: OAuth2 Provider Validation

Complete plugin that validates tokens from an external OAuth2 provider,
provisioning a local user on first login and reusing it on subsequent ones.

```rust
use extism_pdk::{host_fn, plugin_fn, FnResult, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[host_fn]
extern "ExtismHost" {
    fn http_fetch(request_json: String) -> String;
    fn provision_user(request_json: String) -> String;
    fn find_user(external_id_json: String) -> String;
}

#[derive(Debug, Deserialize)]
pub struct OAuthPayload {
    pub access_token: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthPluginRequest {
    pub payload: OAuthPayload,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub remote_addr: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum AuthPluginResponse {
    Allow {
        resolved_identity: String,
        claims: HashMap<String, serde_json::Value>,
    },
    Deny { reason: String },
}

#[plugin_fn]
pub fn authenticate(req: Json<AuthPluginRequest>) -> FnResult<Json<AuthPluginResponse>> {
    let token = req.0.payload.access_token;

    let introspect_request = serde_json::json!({
        "method": "POST",
        "url": "https://oauth.example.com/introspect",
        "headers": {"Accept": "application/json"},
        "body": serde_json::json!({"token": token}).to_string(),
    });
    let fetch_response_json = unsafe { http_fetch(introspect_request.to_string())? };
    let fetch_response: serde_json::Value = serde_json::from_str(&fetch_response_json)?;
    let status = fetch_response.get("status").and_then(|v| v.as_u64()).unwrap_or(0);
    if status != 200 {
        return Ok(Json(AuthPluginResponse::Deny {
            reason: format!("introspect endpoint returned {status}"),
        }));
    }
    let body: serde_json::Value = serde_json::from_str(
        fetch_response.get("body").and_then(|v| v.as_str()).unwrap_or("{}"),
    )
    .map_err(|e| format!("failed to parse introspect response body: {e}"))?;

    let is_active = body.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
    if !is_active {
        return Ok(Json(AuthPluginResponse::Deny {
            reason: "token is not active".to_string(),
        }));
    }

    let sub = body
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or("no 'sub' claim in introspect response")?;

    // Idempotent lookup first - avoids re-provisioning on every login.
    let find_result_json = unsafe { find_user(serde_json::to_string(sub)?)? };
    let existing: Option<String> = serde_json::from_str(&find_result_json)?;

    let resolved_identity = if let Some(handle) = existing {
        handle
    } else {
        let username = body
            .get("preferred_username")
            .and_then(|v| v.as_str())
            .unwrap_or(sub);
        let provision_request = serde_json::json!({
            "external_id": sub,
            "user": { "domain_id": "default", "name": username },
        });
        let handle_json = unsafe { provision_user(provision_request.to_string())? };
        serde_json::from_str(&handle_json)?
    };

    Ok(Json(AuthPluginResponse::Allow {
        resolved_identity,
        claims: extract_claims(&body),
    }))
}

fn extract_claims(token_claims: &serde_json::Value) -> HashMap<String, serde_json::Value> {
    let mut claims = HashMap::new();
    for key in ["email", "groups", "realm_access"] {
        if let Some(value) = token_claims.get(key) {
            claims.insert(key.to_string(), value.clone());
        }
    }
    claims
}
```

---

## Best Practices

1. **Keep plugins single-purpose** - one auth logic, not multiple concerns
2. **Fail closed** - when in doubt, deny the login, log the reason
3. **Validate external data** - never trust HTTP responses or plugin input
4. **Use http_fetch carefully** - SSRF protection is automatic, but credential
   handling must be reviewed
5. **Set reasonable timeouts** - `timeout_ms` should be shorter than your
   external service's SLA + overhead, and covers the _whole_ invocation
   including any redirect chain
6. **Test failure paths** - network timeouts, malformed responses, slow services
7. **Document claims** - which external attributes map to which plugin claims
8. **Version plugins** - git tag releases, pin SHA-256 checksums in deployments,
   and bump `valid_since` alongside `sha256` when a change should invalidate
   outstanding tokens (`full_auth` mode only - see ADR §4 "Plugin Version
   Binding")
9. **Audit identity changes** - every host-function call and `authenticate`/
   `mapping`/`route` outcome is CADF-audited (`wasm_plugin.*` events, ADR §6.E)
10. **Monitor rate limits** - tune `invocation_rate_limit_per_minute` and
    `max_concurrent_invocations` based on load

---

## References

- [ADR 0025 - Dynamic Auth Plugins](../adr/0025-dynamic-auth-plugins.md) -
  Threat model, design rationale, all constraints
- [Administrator Plugin Operations](../admin/features/auth-plugins.md) - Deployment,
  configuration, operations
- `crates/auth-plugin-runtime/tests/fixtures/reference-plugin/src/lib.rs` - the
  real, compiled reference plugin this guide's examples are derived from
- [Extism PDK](https://github.com/extism/extism/wiki/Plugin-Development-Kit) -
  Language SDKs (Rust, Go, Python, JS, C, Zig, ...)
- [Security Model](security-model.md) - Authentication and authorization invariants
