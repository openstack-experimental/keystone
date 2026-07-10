# Auth Plugin Development Guide

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

See [ADR 0025](../adr/0025-dynamic-auth-plugins.md) for the complete threat
model and design rationale.

---

## Quick Start: Hello-World Plugin

Build and test a minimal plugin in 10 minutes.

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
extism-pdk = "0.3"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

### 3. Plugin Code

Edit `src/lib.rs`:

```rust
use extism_pdk::{plugin_fn, FnResult, Json};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct AuthRequest {
    pub payload: serde_json::Value,
    pub headers: std::collections::HashMap<String, String>,
    pub remote_addr: Option<String>,
}

#[derive(Serialize)]
pub struct UserCreate {
    pub name: String,
    pub domain_id: String,
}

#[derive(Serialize)]
pub struct ResolvedIdentityHandle(String);

#[derive(Serialize)]
pub enum AuthResponse {
    Allow {
        resolved_identity: ResolvedIdentityHandle,
        claims: std::collections::HashMap<String, serde_json::Value>,
    },
    Deny {
        reason: String,
    },
}

/// Authenticate a user (full_auth mode)
#[plugin_fn]
pub fn authenticate(req: Json<AuthRequest>) -> FnResult<Json<AuthResponse>> {
    // Extract credentials from req.payload
    let payload = &req.0.payload;
    let username = payload
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or("Missing username")?;

    // Simple demo: accept any non-empty username
    if username.is_empty() {
        return Ok(Json(AuthResponse::Deny {
            reason: "Empty username".to_string(),
        }));
    }

    // In real plugins: verify against external service, check password, etc.
    // For this demo, we'll skip that and just allow.

    // Call provision_user to create (or reuse) a local user for this external ID
    let user = UserCreate {
        name: username.to_string(),
        domain_id: "default".to_string(),
    };

    // (This is pseudocode - actual host function calls have a different shape,
    // shown in "Host Functions" section below)
    let handle = provision_user(username, user)?;

    // Optionally attach claims for downstream OPA policy
    let mut claims = std::collections::HashMap::new();
    claims.insert("external_username".to_string(), serde_json::Value::String(username.to_string()));

    Ok(Json(AuthResponse::Allow {
        resolved_identity: handle,
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
#[plugin_fn]
pub fn authenticate(req: Json<AuthRequest>) -> FnResult<Json<AuthResponse>> {
    let payload = &req.0.payload;
    let token = payload.get("token").and_then(|v| v.as_str()).ok_or("No token")?;

    // Verify token against external OIDC provider (HTTP call from host)
    let oidc_userinfo = http_fetch("https://idp.example.com/userinfo", token)?;
    let sub = oidc_userinfo.get("sub").ok_or("No 'sub' claim")?;

    // provision_user creates a local user linked to this external ID
    // (Real host function signature differs - see "Host Functions")
    let handle = provision_user(sub, UserCreate {
        name: oidc_userinfo.get("name").unwrap_or(&sub),
        domain_id: "default",
    })?;

    let mut claims = HashMap::new();
    claims.insert("email", oidc_userinfo.get("email")?);
    claims.insert("groups", oidc_userinfo.get("groups")?);

    Ok(Json(AuthResponse::Allow {
        resolved_identity: handle,
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

**Admin setup required:**

1. Deploy plugin with `mode = mapping`
2. Create `MappingRuleSet` rules with `provider_id = "wasm:{plugin_name}"`
3. Rules decide identity resolution (e.g., match claims to existing user by
   email)
4. Plugin claims are namespaced: no risk of injecting privilege-relevant claims

**Example: Parse custom header and produce claims**

```rust
#[plugin_fn]
pub fn mapping(req: Json<AuthRequest>) -> FnResult<Json<MappingResponse>> {
    // Extract custom header (must be in exposed_headers config)
    let header_value = req.0.headers.get("X-Custom-Auth")?;

    // Parse into claims (could also call external service via http_fetch)
    let parts: Vec<&str> = header_value.split(':').collect();
    if parts.len() < 2 {
        return Ok(Json(MappingResponse::Deny {
            reason: "Malformed header".to_string(),
        }));
    }

    // Return flattened claims dict
    let mut claims = HashMap::new();
    claims.insert("realm", serde_json::Value::String(parts[0]));
    claims.insert("user_id", serde_json::Value::String(parts[1]));
    claims.insert("email", serde_json::Value::String(format!("{}@example.com", parts[1])));

    Ok(Json(MappingResponse::Claims(claims)))
}
```

Corresponding Mapping Engine rule (OPA `MappingRuleSet`):

```json
{
  "mapping_ruleset": {
    "domain_id": "default",
    "rules": [
      {
        "provider_id": "wasm:my_mapping_plugin",
        "local": {
          "identity_provider": "local",
          "attributes": {
            "name": "{user_id}",
            "domain": "default"
          },
          "match_attributes": {
            "email": "{email}"
          }
        }
      }
    ]
  }
}
```

### `route`: Plugin Routes Requests Pre-Dispatch

Plugin sees raw request before method dispatch; can redirect to a different
method or pass through unchanged.

**Entry point:** `route(RouteRequest) -> RouteResponse`

**When to use:**

- Clients that always send a fixed method name (can't be changed)
- Conditional routing based on credential content (e.g.,
  `application_credential` that might be different handler-specific formats)
- Credential-shape-based dispatching without authentication

**Important: Plugin does NOT authenticate.** Target method still performs full
verification.

**Constraints (enforced by host):**

1. Cannot touch `scope` (project/domain/system) - only relabel method
2. Can only route to methods in `route_targets` allowlist
3. Can never target `admin` or `trust` methods
4. Single-shot - request is not re-routed if target is another router
5. Target method receives exact payload plugin specifies (re-verification
   required)

**Example: application_credential routing**

```rust
#[derive(Deserialize)]
pub struct RouteRequest {
    pub requested_methods: Vec<String>,
    pub payloads: HashMap<String, serde_json::Value>,
    pub headers: HashMap<String, String>,
    pub remote_addr: Option<String>,
}

#[derive(Serialize)]
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
    // Ignore if request doesn't include application_credential
    if !req.0.requested_methods.contains(&"application_credential".to_string()) {
        return Ok(Json(RouteResponse::Passthrough));
    }

    let payload = req.0.payloads
        .get("application_credential")?;

    let cred_id = payload
        .get("id")?
        .as_str()?;

    // Cloud IDs start with "custom-"; route to special handler
    if cred_id.starts_with("custom-") {
        return Ok(Json(RouteResponse::Route {
            target_method: "hacked_appcred_handler".to_string(),
            payload: payload.clone(),
        }));
    }

    // All other application_credential flow normally
    Ok(Json(RouteResponse::Passthrough))
}
```

Config:

```ini
[auth_plugin.tf_router]
mode = route
inspect_methods = application_credential
route_targets = hacked_appcred_handler,application_credential
capabilities = http_fetch  # optional; router may need to query external service
```

---

## Host Functions API

### Initialization & Context

Every entry point (`authenticate`, `mapping`, `route`) receives a request object
containing:

- `payload: serde_json::Value` - raw credential from `identity.<method>` block
- `headers: HashMap<String, String>` - allowlisted HTTP headers (never
  `Authorization`, `Cookie`, etc.)
- `remote_addr: Option<String>` - trusted peer IP (not spoofable
  `X-Forwarded-For`)

### HTTP Fetching

**Signature:**

```rust
// Pseudocode - actual calls via extism-pdk differ, shown in "Calling Host Functions" below
pub fn http_fetch(url: &str, options: HttpOptions) -> Result<HttpResponse>;

pub struct HttpOptions {
    pub method: String,  // "GET", "POST", etc.
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub timeout_ms: u32,
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}
```

**Constraints:**

- Only `allowed_hosts` are reachable (config-time allowlist)
- All resolved IPs are checked against private/loopback ranges (no SSRF)
- Second DNS resolution at connection time (prevents DNS rebinding)
- Auth secrets injected by host from environment variables (never in guest
  memory)
- No redirects by default (must opt-in per-plugin)

**Example:**

```rust
// In plugin code - this is pseudocode; real Extism calls differ
let response = http_fetch(
    "https://idp.example.com/validate",
    HttpOptions {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            // Authorization header injected by host from http_fetch_auth_secret_env
        },
        body: json!({"token": token}).to_string(),
        timeout_ms: 500,
    }
)?;

if response.status != 200 {
    return Ok(Json(AuthResponse::Deny {
        reason: format!("IDP returned {}", response.status),
    }));
}

let result: serde_json::Value = serde_json::from_slice(&response.body)?;
```

### Provisioning Users

**`full_auth` mode only.**

```rust
pub fn provision_user(
    external_id: String,
    user: UserCreate,
) -> Result<ResolvedIdentityHandle>;

pub struct UserCreate {
    pub name: String,
    pub domain_id: String,
    // Optional fields:
    pub email: Option<String>,
    pub description: Option<String>,
}

pub struct ResolvedIdentityHandle(String);  // Opaque handle for this invocation
```

**Semantics:**

- Creates a new Keystone `User` (if not already created)
- Records mapping `(plugin_name, external_id) -> user_id`
- Returns opaque `ResolvedIdentityHandle` (not the real `user_id`)
- **Idempotent:** same `external_id` on repeat calls returns handle to same user
- **Atomic:** race-safe with concurrent requests
- **Domain-scoped:** `domain_id` must be in plugin's `provision_domain_id` or
  `allowed_provision_domains`

**Use case:** First login for a new external identity

### Finding Users

**`full_auth` mode only.**

```rust
pub fn find_user(external_id: String) -> Result<Option<ResolvedIdentityHandle>>;
```

**Semantics:**

- Looks up user by `(plugin_name, external_id)` only
- Returns `Some(handle)` if found, `None` otherwise
- **Not** a general username search
- Cannot reach users provisioned by other plugins or via other methods
- For admin-linked identities: domain restriction is re-checked (prevents stale
  links)

**Use case:** Returning user login (idempotent after first provision)

### Assigning Roles

**`full_auth` mode only.**

```rust
pub fn assign_role(
    resolved_identity: &ResolvedIdentityHandle,
    role_name: &str,
    scope: RoleScope,
) -> Result<()>;

pub enum RoleScope {
    Project { project_id: String },
    Domain { domain_id: String },
}
```

**Constraints (host-enforced):**

- `role_name` must be in plugin's `assign_role_allowed` list
- Target project/domain must be in plugin's `provision_domain_id` /
  `allowed_provision_domains`
- System scope is never allowed (plugins cannot grant admin)
- Duplicate assignments are idempotent (not an error)

**Use case:** Grant initial roles on first user provisioning

---

## Calling Host Functions (Extism Mechanics)

Extism-PDK provides convenient wrappers. Here's a real example:

```rust
use extism_pdk::{host_fn, plugin_fn, FnResult, Json};
use serde::{Deserialize, Serialize};

// Host functions exported by Keystone (must be registered in plugin config)
#[host_fn]
extern "ExtismHost" {
    // HTTP fetching (simplified - real signature has more options)
    fn http_fetch(
        method: String,
        url: String,
        headers: String,  // JSON-encoded headers
        body: String,
    ) -> String;  // JSON response

    // User provisioning
    fn provision_user(external_id: String, user_json: String) -> String;  // Opaque handle JSON
    fn find_user(external_id: String) -> String;  // JSON: {"handle": "..."} or error
    fn assign_role(handle: String, role: String, scope_json: String) -> String;  // JSON result
}

#[plugin_fn]
pub fn authenticate(req: Json<AuthRequest>) -> FnResult<Json<AuthResponse>> {
    // Call http_fetch host function
    let headers = serde_json::json!({
        "Content-Type": "application/json",
    }).to_string();

    let response_json = http_fetch(
        "POST".to_string(),
        "https://idp.example.com/validate".to_string(),
        headers,
        req.0.payload.to_string(),
    );

    let response: serde_json::Value = serde_json::from_str(&response_json)?;
    if !response.get("valid").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Ok(Json(AuthResponse::Deny {
            reason: "IDP validation failed".to_string(),
        }));
    }

    // Provision user
    let external_id = response.get("sub").and_then(|v| v.as_str())?;
    let user_json = serde_json::json!({
        "name": response.get("name").and_then(|v| v.as_str()).unwrap_or(external_id),
        "domain_id": "default",
        "email": response.get("email"),
    }).to_string();

    let handle_json = provision_user(external_id.to_string(), user_json);
    let handle: serde_json::Value = serde_json::from_str(&handle_json)?;

    let mut claims = HashMap::new();
    claims.insert("email", response.get("email")?);

    Ok(Json(AuthResponse::Allow {
        resolved_identity: ResolvedIdentityHandle(handle.get("handle")?.to_string()),
        claims,
    }))
}
```

---

## Admin Identity Linking

`full_auth` plugins can authenticate pre-existing users (e.g., SCIM-provisioned)
via admin-authorized linking, without the plugin provisioning them.

### API

**Create link:**

```bash
POST /v4/auth_plugins/{plugin_name}/identity_links
Authorization: X-Auth-Token: $ADMIN_TOKEN

{
  "external_id": "sso_user_123",      # From plugin's verification
  "user_id": "existing-keystone-uuid"  # Pre-existing user
}
```

> **Note:** SCIM convenience fields (`scim_provider_id`, `scim_external_id`) are
> documented in ADR 0025 §4 but not yet implemented. Track as follow-up work.

**Delete link:**

```bash
DELETE /v4/auth_plugins/{plugin_name}/identity_links/{external_id}
```

**Bulk revocation** (on plugin compromise):

```bash
POST /v4/auth_plugins/{plugin_name}/revoke_all
```

### Plugin Logic

No change needed in plugin code - `find_user(external_id)` works the same
whether the entry was created by `provision_user` or by an admin link.

---

## Response Bounds & Safety

### Claims Size

- Max 64 entries in `claims` map
- Max 256 bytes per key
- Max 4 KiB per value

### Claims Namespacing

All plugin claims are automatically namespaced under
`plugin_claims.<plugin_name>.<key>`. This prevents injection of
privilege-relevant top-level keys.

```rust
// Plugin returns:
{
  "email": "user@example.com",
  "groups": ["admin"]
}

// Host transforms to (in SecurityContext):
{
  "plugin_claims": {
    "my_plugin": {
      "email": "user@example.com",
      "groups": ["admin"]
    }
  }
}

// OPA policy can read via: input.credentials.plugin_claims.my_plugin.email
// But cannot inject top-level keys like is_system, effective_roles, etc.
```

### Response Size Cap

Total response JSON is capped at 64 KiB. Oversized responses are rejected.

### Reserved Keys

Plugins cannot use reserved keys like `__keystone` prefix. These are rejected at
response validation.

---

## Testing & Debugging

### Local Unit Tests

Use `extism-pdk` test utilities:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authenticate_valid() {
        let req = AuthRequest {
            payload: serde_json::json!({
                "username": "alice",
                "password": "secret"
            }),
            headers: Default::default(),
            remote_addr: Some("192.0.2.1".to_string()),
        };

        let result = authenticate(Json(req)).unwrap();
        match result.0 {
            AuthResponse::Allow { .. } => {},
            _ => panic!("Expected Allow"),
        }
    }

    #[test]
    fn test_authenticate_missing_username() {
        let req = AuthRequest {
            payload: serde_json::json!({}),
            headers: Default::default(),
            remote_addr: None,
        };

        let result = authenticate(Json(req)).unwrap();
        match result.0 {
            AuthResponse::Deny { reason } => {
                assert!(reason.contains("username"));
            },
            _ => panic!("Expected Deny"),
        }
    }
}
```

### Integration Testing

Test against real Keystone instance (see
[Admin Guide - Plugins](../admin.md#plugin-operations)):

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

**Plugin logs** - HTTP calls and response handling appear in Keystone logs:

```bash
grep "auth_plugin" /var/log/keystone/keystone.log
```

**Rate limit hits** - Check if plugin is being rate-limited:

```bash
grep "429 Too Many Requests" /var/log/keystone/keystone.log
```

**Timeouts** - Plugin exceeded `timeout_ms`:

```bash
grep "timeout" /var/log/keystone/keystone.log
```

**Memory exhaustion** - Plugin exceeded `memory_limit_mb`:

```bash
grep "memory" /var/log/keystone/keystone.log
```

**Fuel exhaustion** - Plugin exceeded instruction budget (`fuel_limit`):

```bash
grep "fuel" /var/log/keystone/keystone.log
```

---

## Real-World Example: OAuth2 Provider Validation

Complete plugin that validates tokens from an external OAuth2 provider:

```rust
use extism_pdk::{host_fn, plugin_fn, FnResult, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[host_fn]
extern "ExtismHost" {
    fn http_fetch(method: String, url: String, headers: String, body: String) -> String;
    fn provision_user(external_id: String, user_json: String) -> String;
    fn find_user(external_id: String) -> String;
}

#[derive(Deserialize)]
pub struct OAuthRequest {
    pub access_token: String,
}

#[derive(Serialize)]
pub struct ResolvedHandle(String);

#[derive(Serialize)]
pub enum AuthResponse {
    Allow {
        resolved_identity: ResolvedHandle,
        claims: HashMap<String, serde_json::Value>,
    },
    Deny { reason: String },
}

#[derive(Deserialize)]
pub struct AuthPluginRequest {
    pub payload: serde_json::Value,
    pub headers: HashMap<String, String>,
    pub remote_addr: Option<String>,
}

#[plugin_fn]
pub fn authenticate(req: Json<AuthPluginRequest>) -> FnResult<Json<AuthResponse>> {
    // Extract token from payload
    let token = req.0.payload
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or("Missing access_token")?;

    // Validate token with OAuth2 provider
    let headers = serde_json::json!({
        "Accept": "application/json",
    }).to_string();

    let response_str = http_fetch(
        "POST".to_string(),
        "https://oauth.example.com/introspect".to_string(),
        headers,
        serde_json::json!({ "token": token }).to_string(),
    );

    let response: serde_json::Value = serde_json::from_str(&response_str)
        .map_err(|e| format!("Failed to parse introspect response: {}", e))?;

    let is_active = response
        .get("active")
        .and_then(|v| v.as_bool())
        .ok_or("Invalid introspect response")?;

    if !is_active {
        return Ok(Json(AuthResponse::Deny {
            reason: "Token is not active".to_string(),
        }));
    }

    // Extract user identifier from token claims
    let sub = response
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or("No 'sub' claim in token")?;

    // Check if user already exists
    let find_result = find_user(sub.to_string());
    if let Ok(existing_handle_json) = serde_json::from_str::<serde_json::Value>(&find_result) {
        // User exists, use existing handle
        return Ok(Json(AuthResponse::Allow {
            resolved_identity: ResolvedHandle(
                existing_handle_json
                    .get("handle")
                    .and_then(|v| v.as_str())
                    .ok_or("Invalid handle format")?
                    .to_string()
            ),
            claims: extract_claims(&response),
        }));
    }

    // New user - provision locally
    let username = response
        .get("preferred_username")
        .and_then(|v| v.as_str())
        .unwrap_or(sub);

    let user_create = serde_json::json!({
        "name": username,
        "domain_id": "default",
        "email": response.get("email"),
    }).to_string();

    let handle_json = provision_user(sub.to_string(), user_create);
    let handle_obj: serde_json::Value = serde_json::from_str(&handle_json)?;

    let handle = handle_obj
        .get("handle")
        .and_then(|v| v.as_str())
        .ok_or("Invalid handle format")?
        .to_string();

    Ok(Json(AuthResponse::Allow {
        resolved_identity: ResolvedHandle(handle),
        claims: extract_claims(&response),
    }))
}

fn extract_claims(token_claims: &serde_json::Value) -> HashMap<String, serde_json::Value> {
    let mut claims = HashMap::new();

    // Map token claims to plugin claims
    if let Some(email) = token_claims.get("email") {
        claims.insert("email".to_string(), email.clone());
    }
    if let Some(groups) = token_claims.get("groups") {
        claims.insert("groups".to_string(), groups.clone());
    }
    if let Some(realm) = token_claims.get("realm_access") {
        claims.insert("realm_access".to_string(), realm.clone());
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
   external service's SLA + overhead
6. **Test failure paths** - network timeouts, malformed responses, slow services
7. **Document claims** - which external attributes map to which plugin claims
8. **Version plugins** - git tag releases, pin SHA-256 checksums in deployments
9. **Audit identity changes** - `POST /v4/events` includes plugin operations
   (provision, link, revoke)
10. **Monitor rate limits** - tune `invocation_rate_limit_per_minute` and
    `max_concurrent_invocations` based on load

---

## References

- [ADR 0025 - Dynamic Auth Plugins](../adr/0025-dynamic-auth-plugins.md) -
  Threat model, design rationale, all constraints
- [Admin Guide - Plugins](../admin.md#dynamic-auth-plugins) - Deployment,
  configuration, operations
- [Extism PDK](https://github.com/extism/extism/wiki/Plugin-Development-Kit) -
  Language SDKs (Rust, Go, Python, JS, C, Zig, ...)
- [Security Model](../security.md) - Authentication and authorization invariants
