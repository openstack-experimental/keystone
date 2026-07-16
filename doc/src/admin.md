# Administrator Guide

This guide covers Keystone configuration, monitoring, operations, and how to add
custom authentication plugins.

## Configuration

Keystone configuration follows OpenStack conventions. The main configuration
file is `keystone.conf` in INI format.

### Core Sections

**`[DEFAULT]`** - Global settings

```ini
[DEFAULT]
use_stderr = false
debug = true
log_dir = /var/log/keystone
```

**`[database]`** - Backend persistence

```ini
[database]
# SQLite (dev only)
connection = sqlite:///var/lib/keystone/keystone.db

# PostgreSQL (production)
connection = postgresql://keystone:password@db.example.com/keystone
```

**`[distributed_storage]`** - OpenRaft cluster for high-availability replication

```ini
[distributed_storage]
# Local storage path (created if missing)
path = /var/lib/keystone/raft/db

# This node's cluster peer address (for replication)
node_cluster_addr = https://ks1.example.com:50051

# Address to listen on for incoming cluster replication
node_listener_addr = 0.0.0.0:50051

# Unique identifier for this node in the cluster
node_id = 0

# TLS for inter-node communication
tls_cert_file = /etc/keystone/tls/keystone.crt
tls_key_file = /etc/keystone/tls/keystone.key
tls_client_ca_file = /etc/keystone/tls/ca.crt

# Development mode - single-node cluster without strict consensus
# NEVER use in production
dev_mode = false
```

**`[api_policy]`** - Authorization via OPA (Open Policy Agent)

```ini
[api_policy]
enable = true
opa_base_url = http://opa.example.com:8181
opa_policies_path = policy/

# Optional: unix socket for local OPA
opa_base_url = unix:///var/run/opa.sock
```

**`[auth]`** - Available authentication methods

```ini
[auth]
# Built-in methods: password, token, openid, application_credential,
# x509, webauthn, k8s, trust, admin, mapped
# Plus any registered dynamic auth plugins (see "Dynamic Auth Plugins" below)
methods = password,token,openid,application_credential,my_custom_sso

# Optional: map method names to friendly display names for user-facing interfaces
method_display_names = password:Username/Password,openid:OIDC,my_custom_sso:Corporate SSO
```

**`[fernet_tokens]` / `[fernet_receipts]`** - Token encryption keys

```ini
[fernet_tokens]
key_repository = /etc/keystone/fernet-keys/tokens

[fernet_receipts]
key_repository = /etc/keystone/fernet-keys/receipts
```

**`[mapping]`** - Federation mapping engine (see ADR 0020)

```ini
[mapping]
# Cluster-wide salt for hashing external identities
cluster_salt = "fbb27433d07ab307cc1fc899d0e174cf197fd398fbcff7285a63fe2f94eec2fe"
```

**`[audit]`** - CADF audit logging

```ini
[audit]
spool_dir = /var/spool/keystone/audit
```

**`[local_emergency]`** - Node-local quorum-bypass emergency rotation (ADR 0028)

```ini
[local_emergency]
# Disabled by default. Must be explicitly opted in per-node.
enabled = false

# How long the Raft leader must be unknown before the guardrail unlocks
# local-only writes (avoids tripping on a transient election blip).
leaderless_grace_period_seconds = 30

# Interval between best-effort gossip fan-out attempts to reachable peers
# while partitioned.
gossip_interval_seconds = 10
```

See "Quorum-Bypass Emergency Rotation" below and
[OAuth2 admin guide](oauth2/admin.md#emergency-signing-key-rotation-during-quorum-loss)
for the operational procedure.

### Dynamic Auth Plugins

Register custom authentication plugins via `[auth_plugins]` and per-plugin
`[auth_plugin.NAME]` sections (see "Dynamic Auth Plugins" section below).

---

## Monitoring & Observability

### Health Checks

**Local health endpoint** (always available without authentication)

```bash
curl http://keystone:8080/health
# Returns: "OK"
```

**Admin socket health** (requires local socket access)

```bash
curl --unix-socket /var/run/keystone.sock http://localhost/health
```

### Logging

Keystone uses structured JSON logging. All logs include:

- `level`: `debug`, `info`, `warn`, `error`, `critical`
- `msg`: Human-readable message
- `time`: ISO 8601 timestamp
- Domain-specific fields (e.g., `user_id`, `req_id`, `req_method`,
  `resp_status`)

Log destinations controlled by `[DEFAULT]` section:

- `log_dir`: Write to files in this directory
- `use_stderr`: Also write to stderr

Example log filtering:

```bash
# Watch for errors in real-time
tail -f /var/log/keystone/keystone.log | grep '"level":"error"'

# Count 401 authentication failures
grep 'resp_status":401' /var/log/keystone/keystone.log | wc -l
```

### Metrics & Observability

Keystone emits structured metrics via hooks; integration with Prometheus,
Grafana, or similar is operator-configured.

Key metrics to alert on:

- `keystone_api_request_duration_seconds` - Request latency
- `keystone_auth_failure_total` - Auth failures (including rate limits)
- `keystone_auth_plugin_load_failure` - Plugin load failures (see "Plugin
  Errors" below)
- `keystone_audit_queue_depth` - Audit spool backlog

### Troubleshooting Common Issues

**Token validation failures**

- Check `[fernet_tokens] key_repository` - keys must be readable, not writable
  by others
- Verify all nodes share the same current key (key rotation must be coordinated)
- Check token expiry: `keystone token show <token>`

**Authentication method not available**

- Verify the method is listed in `[auth] methods`
- For OIDC/K8s: check provider configuration and connectivity
- For auth plugins: check logs for `keystone_auth_plugin_load_failure` alerts

**OPA policy failures**

- Verify `[api_policy] opa_base_url` is reachable
- Check OPA logs for policy compilation errors
- Confirm policy files exist under `[api_policy] opa_policies_path`

**Cluster consensus stuck**

- Check inter-node network connectivity (port 50051 by default)
- Verify TLS certificates in `[distributed_storage]`
- Review cluster membership: `keystone-manage cluster list`

---

## Cluster Operations

### Multi-Node Deployment

Keystone uses OpenRaft for distributed storage. Each node needs:

1. **Unique `node_id`** in `[distributed_storage]`
2. **Reachable cluster address** via `node_cluster_addr` (https only, TLS
   required)
3. **Synchronized time** (NTP) - consensus relies on clock accuracy
4. **Same fernet key repository** - keys must be identical across all nodes

Example 3-node cluster:

```ini
# Node 1: ks1.example.com
[distributed_storage]
node_id = 0
node_cluster_addr = https://ks1.example.com:50051
node_listener_addr = 0.0.0.0:50051
tls_cert_file = /etc/keystone/tls/ks1.crt
tls_key_file = /etc/keystone/tls/ks1.key
tls_client_ca_file = /etc/keystone/tls/ca.crt

# Node 2: ks2.example.com
[distributed_storage]
node_id = 1
node_cluster_addr = https://ks2.example.com:50051
node_listener_addr = 0.0.0.0:50051
tls_cert_file = /etc/keystone/tls/ks2.crt
tls_key_file = /etc/keystone/tls/ks2.key
tls_client_ca_file = /etc/keystone/tls/ca.crt

# Node 3: ks3.example.com
[distributed_storage]
node_id = 2
node_cluster_addr = https://ks3.example.com:50051
node_listener_addr = 0.0.0.0:50051
tls_cert_file = /etc/keystone/tls/ks3.crt
tls_key_file = /etc/keystone/tls/ks3.key
tls_client_ca_file = /etc/keystone/tls/ca.crt
```

### Node Management

**Add a new node:**

```bash
# 1. Generate TLS cert/key for the new node
# 2. Add to cluster configuration on existing nodes (restart required)
# 3. Start the new node with unique node_id
# 4. Verify it joined: keystone-manage cluster list
```

**Remove a node:**

```bash
# 1. Gracefully shut down the node
# 2. Remove from all peer configurations
# 3. Restart remaining nodes
```

**Cluster status:**

```bash
keystone-manage cluster status
keystone-manage cluster list
```

### Quorum-Bypass Emergency Rotation (ADR 0028)

When Raft has lost quorum, the ordinary emergency rotation paths (OAuth2
signing-key emergency rotation, DEK emergency rotation) cannot commit -- they're
themselves Raft proposals. `[local_emergency]` provides a node-local fallback:
an operator writes a rotation candidate straight to that node's local Fjall
keyspace (never touched by Raft's `apply()`), bypassing quorum entirely.
Guardrail: refused unless `[local_emergency] enabled = true` on that node
**and** the Raft leader has been unknown for at least
`leaderless_grace_period_seconds` -- this is not a general-purpose quorum-skip,
only a last resort while genuinely partitioned.

**Two subsystems use this path**: OAuth2 domain signing keys (see
[OAuth2 admin guide](oauth2/admin.md#emergency-signing-key-rotation-during-quorum-loss))
and the cluster DEK (below).

**Gossip.** A background sweep (every `gossip_interval_seconds`) best-effort
pushes each locally-originated candidate to every other reachable Raft peer over
the same inter-node mTLS channel Raft itself uses. This only makes candidates
_visible_ cluster-wide (`conflicted: true` if a peer reports a different active
candidate for the same subsystem/scope) -- it does not reconcile or auto-resolve
anything.

**Reconciliation.** Once quorum returns, an operator lists candidates on each
node that may have been reached during the outage and explicitly picks one
`rotation_id` to promote into Raft-replicated state. Reconciliation is strictly
per-node (run against the specific node holding the candidate, not cluster-wide)
and dual-control (confirming operator must differ from the one who staged it).

**DEK local-quorum-bypass rotation and reconciliation** (via
`ClusterAdminService` gRPC, same mTLS/operator-role boundary as `rotate-dek`):

```bash
# During quorum loss, on a guardrail-enabled node:
keystone-manage storage rotate-dek \
  --local-quorum-bypass --justification "suspected KEK compromise, quorum lost"

# After quorum returns, on every node possibly reached during the outage:
keystone-manage storage list-dek-local-emergency-candidates

# A different operator promotes the chosen candidate on the node that holds it:
keystone-manage storage reconcile-dek-local-emergency --rotation-id <id>
```

Reconciliation installs the DEK via the normal Raft transaction path and refuses
(`FailedPrecondition`) if the DEK version has advanced past what the candidate
expected -- i.e. another rotation already committed while this candidate sat
staged.

**Known scope limits** (deliberate, see ADR 0028 "Implementation Status"):

- No cross-node broadcast to clear a candidate once superseded elsewhere --
  gossip gives visibility, not cleanup.
- No automatic/unattended reconciliation sweep; an operator must pick a
  `rotation_id` explicitly, per node.
- Up to one `gossip_interval_seconds` of propagation delay after staging (no
  immediate post-stage push).

---

## Dynamic Auth Plugins

Custom authentication logic can be added without recompiling Keystone via
WebAssembly (WASM) plugins. See [Plugins: Auth](./plugins/auth.md) for the
developer guide.

**Requires distributed storage.** A `full_auth` plugin's
`(plugin_name, external_id) -> user_id` identity-binding index
(`[auth_plugin_identity] driver`, defaults to `raft`) is backed by
`[distributed_storage]`, decoupled from whichever `IdentityBackend` is
configured. There is currently no SQL driver alternative - `full_auth`-mode
plugins using `provision_user`/`find_user` are not available in a deployment
without distributed storage configured. `mapping`- and `route`-mode plugins have
no such requirement, since they never call those host functions.

### Plugin Configuration

Plugins are configured in `keystone.conf` under `[auth_plugins]` and per-plugin
sections.

**Minimal example** (full_auth mode - plugin authenticates users):

```ini
[auth_plugins]
plugins = my_plugin

[auth_plugin.my_plugin]
path = /etc/keystone/plugins/my_plugin.wasm
sha256 = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
mode = full_auth
capabilities = http_fetch,provision_user,find_user
provision_domain_id = default
timeout_ms = 750
fuel_limit = 50000000
memory_limit_mb = 32
invocation_rate_limit_per_source_per_minute = 20
invocation_rate_limit_per_minute = 300
max_concurrent_invocations = 16
```

Add to `[auth] methods`:

```ini
[auth]
methods = password,token,my_plugin
```

### Plugin Modes

**`full_auth`** (default) - Plugin is the authentication authority

- Can call `provision_user`, `find_user`, `assign_role`
- Suitable for custom SSO bridges, risk-scoring auth, proprietary protocols
- Must admin-link pre-existing users via
  `POST /v4/auth_plugins/{plugin_name}/identity_links`

**`mapping`** - Plugin produces claims; Mapping Engine decides identity

- Cannot call provisioning functions (config error if listed)
- Safe way to authenticate pre-existing (e.g., SCIM) users without special
  linking
- Plugin claims fed to `MappingRuleSet` rules for final identity resolution
- Requires `MappingRuleSet` rules exist under
  `provider_id = "wasm:{plugin_name}"`

**`route`** - Plugin redirects requests to other handlers (pre-dispatch)

- Runs before method dispatch; can rewrite method names and payloads
- Cannot call any identity/provisioning functions (config error if listed)
- Used for clients that always send a fixed method name (e.g.,
  `application_credential`)
- Does NOT authenticate; target method still performs full verification

### Plugin Capabilities

Plugins opt into capabilities; unlisted functions are not available to the
guest:

- **`http_fetch`** - Make HTTP calls to external services (SSRF-protected)
- **`provision_user`** - Create new users in the configured domain
- **`find_user`** - Look up existing provisioned users
- **`assign_role`** - Grant roles to provisioned users (config-bounded to
  `assign_role_allowed`)

Audit logging is always enabled; it cannot be disabled.

### Configuration Reference

| Key                                           | Mode        | Default                        | Description                                                                                                                                                                                                                        |
| --------------------------------------------- | ----------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `path`                                        | All         | Required                       | Filesystem path to `.wasm` plugin binary                                                                                                                                                                                           |
| `sha256`                                      | All         | Required                       | SHA-256 checksum of plugin file (verified at startup)                                                                                                                                                                              |
| `mode`                                        | All         | `full_auth`                    | Operating mode: `full_auth`, `mapping`, or `route`                                                                                                                                                                                 |
| `capabilities`                                | All         | Empty                          | Comma-separated host functions: `http_fetch`, `provision_user`, `find_user`, `assign_role`                                                                                                                                         |
| `exposed_headers`                             | All         | Empty                          | HTTP headers plugin may access (comma-separated); hard-denied: `Authorization`, `Cookie`, `X-Auth-Token`, `X-Subject-Token`, `Proxy-Authorization`                                                                                 |
| `allowed_hosts`                               | All         | Required if `http_fetch` used  | Hostname allowlist for `http_fetch` calls (comma-separated)                                                                                                                                                                        |
| `http_fetch_auth_header`                      | All         | Optional                       | Header name to attach auth secret (e.g., `Authorization`)                                                                                                                                                                          |
| `http_fetch_auth_secret_env`                  | All         | Optional                       | Environment variable containing auth secret (never enters guest memory)                                                                                                                                                            |
| `http_fetch_follow_redirects`                 | All         | `false`                        | Allow HTTP redirects (each hop re-validated against allowlist)                                                                                                                                                                     |
| `provision_domain_id`                         | `full_auth` | Required if provisioning       | Single domain where plugin may create users; `find_user` revalidates on every call                                                                                                                                                 |
| `allowed_provision_domains`                   | `full_auth` | Alternative                    | Comma-separated list of domains; use if plugin must span multiple domains                                                                                                                                                          |
| `assign_role_allowed`                         | `full_auth` | Required if `assign_role` used | Comma-separated role names plugin may grant (e.g., `member,reader`)                                                                                                                                                                |
| `inspect_methods`                             | `route`     | Required                       | Comma-separated identity methods that trigger this plugin (e.g., `application_credential`)                                                                                                                                         |
| `route_targets`                               | `route`     | Required                       | Comma-separated allowlist of methods this plugin may route to; `admin` and `trust` forbidden                                                                                                                                       |
| `timeout_ms`                                  | All         | 1000                           | Wall-clock timeout for plugin invocation, including any `http_fetch` calls (the whole redirect chain shares this one budget, not one per hop)                                                                                      |
| `fuel_limit`                                  | All         | 10000000                       | Instruction budget (protects against infinite loops)                                                                                                                                                                               |
| `memory_limit_mb`                             | All         | 16                             | Linear-memory limit for plugin heap                                                                                                                                                                                                |
| `invocation_rate_limit_per_source_per_minute` | All         | 20                             | Per-source-IP rate limit (sliding window)                                                                                                                                                                                          |
| `invocation_rate_limit_per_minute`            | All         | 300                            | Per-plugin global rate limit                                                                                                                                                                                                       |
| `max_concurrent_invocations`                  | All         | 16                             | Maximum simultaneous invocations                                                                                                                                                                                                   |
| `valid_since`                                 | `full_auth` | None (never rejects)           | RFC 3339 timestamp; a token whose `issued_at` predates this is rejected (`PluginVersionMismatch`) on re-verification. Bump alongside `sha256` for a security fix. Not enforceable for `mapping`-mode tokens today (ADR 0025 §4/§8) |

### Plugin Loading & Errors

Plugins are loaded at process startup. If a plugin's file is missing or its
SHA-256 does not match:

- **That plugin only** is disabled (not available for auth)
- A `CRITICAL`-level log and metric
  `keystone_auth_plugin_load_failure{plugin_name}` are emitted
- All other plugins and auth methods start normally

This is fail-closed-at-request-level: a load error for one plugin does not block
the cluster, but that specific auth method is unavailable on that node. A hash
mismatch across nodes creates temporary inconsistency until resolved.

**To fix:**

```bash
# 1. Verify the file exists and matches the pinned hash
sha256sum /etc/keystone/plugins/my_plugin.wasm

# 2. If hash is wrong, update keystone.conf with the correct hash
# 3. Restart Keystone
systemctl restart keystone
```

### Plugin Operations

**Admin-authorized identity linking** (`full_auth` mode only):

```bash
# Link a pre-existing (e.g., SCIM-provisioned) user to a plugin
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

RBAC-tiered: system-scope `admin` may link any user; a domain-scoped
`admin`/`manager` may link only a non-system user in their own domain.
Re-linking an already-linked `external_id` returns `409 Conflict` - `DELETE` the
existing link first.

> **Note:** SCIM convenience fields (`scim_provider_id`, `scim_external_id`) are
> documented in ADR 0025 §4 but not yet implemented. Track as follow-up work.

**Bulk revocation** (on plugin compromise or update):

```bash
# Disables all users provisioned by (or admin-linked to) the plugin, deletes
# identity links, and revokes tokens for every affected user. System-admin
# only. Idempotent - a second call against an already-cleaned-up plugin is a
# no-op (all-zero counts).
curl -X POST http://keystone:5000/v4/auth_plugins/{plugin_name}/revoke_all \
  -H "X-Auth-Token: $ADMIN_TOKEN"

# Response: { "revoke_all": { "users_disabled": N, "links_deleted": N } }
```

**This does NOT revoke role assignments** the plugin granted via `assign_role` -
attributing a stored grant to the plugin that created it would require
per-record origin bookkeeping this ADR deliberately avoids. Disabling the
account already denies all access; review a re-enabled user's remaining
assignments against the CADF audit trail (`plugin_name` recorded on every
`assign_role` event) and revoke any you deem compromised via the ordinary
per-grant revocation API before re-enabling.

### Plugin Errors & Troubleshooting

**Plugin fails to load**

- Check logs: `grep keystone_auth_plugin_load_failure /var/log/keystone.log`
- Verify file exists: `ls -la /etc/keystone/plugins/my_plugin.wasm`
- Check SHA-256: `sha256sum /etc/keystone/plugins/my_plugin.wasm`
- Update config and restart

**Plugin invocation fails (401 or 429)**

- `401`: Plugin denied the login or returned invalid response
  - Check plugin logs and external service logs (if using `http_fetch`)
  - Verify plugin logic matches expected credential format
  - Check the audit trail: CADF events (`wasm_plugin.*`, ADR 0025 §6.E) are
    spooled to `[audit] spool_dir`, not queryable via an HTTP API - grep the
    spool for the plugin's `Target.id` (the plugin name)

- `429`: Rate limit exceeded
  - Check configured limits: `invocation_rate_limit_per_source_per_minute`,
    `invocation_rate_limit_per_minute`, `max_concurrent_invocations`
  - Increase limits in config if legitimate traffic
  - Check for DDoS or misconfigured clients

**Plugin behavior unexpectedly changes**

- Plugin was patched and Keystone restarted with the new `sha256` - there is no
  hot reload (ADR 0025 §5); a running process never picks up a changed
  `.wasm`/`sha256` without a restart
- Mapping rules changed (for `mapping` mode) - verify `MappingRuleSet` config
- Identity links modified - check audit trail for admin changes

**Plugin consuming too much memory/CPU**

- Increase `fuel_limit` or `timeout_ms` if legitimate
- Check plugin code for memory leaks or inefficient algorithms
- Reduce `max_concurrent_invocations` if CPU-bound
- Review plugin logs and `http_fetch` external service performance

---

## Maintenance & Upgrades

### Keystone Upgrade

1. **Test in non-prod first** - authentication changes are high-risk
2. **Backup fernet keys** - `[fernet_tokens] key_repository`,
   `[fernet_receipts] key_repository`
3. **Stop all nodes** - graceful shutdown prevents data loss
4. **Upgrade binary** - pull new image or build from source
5. **Verify schema migrations** - `keystone-manage db upgrade`
6. **Start nodes one at a time** - wait for Raft consensus on each
7. **Monitor auth failures** - transient failures are normal for 1-2 minutes

### Plugin Update

When updating a plugin:

1. **Compute new SHA-256** of the updated `.wasm`
2. **Update config** with new hash and new `path` if needed
3. **If this update fixes a security issue, also bump `valid_since`** to the
   deployment instant. Updating `sha256` alone does **not** invalidate
   outstanding tokens - version binding is a separate, explicit `valid_since`
   cutoff compared against each token's `issued_at` (`full_auth` mode only; see
   the Configuration Reference table below). Forgetting this step leaves tokens
   minted by the previous (vulnerable) plugin version valid until they expire
   naturally.
4. **Restart Keystone** (all nodes, one at a time)
5. **Optional:** Run `POST .../revoke_all` if the plugin had a security fix, to
   also disable/unlink/revoke everything the compromised version provisioned or
   granted - `valid_since` alone only stops _new_ uses of already-issued tokens,
   not cleanup of persistent state

### Disaster Recovery

**Lost fernet keys?**

- All existing tokens are invalidated immediately
- Users must re-authenticate
- No data loss (keys are only for token encryption, not persistence)

**Database corruption?**

- From backup: Stop all nodes, restore DB, restart one node, let others rejoin
  Raft cluster
- Fresh start: Remove `[distributed_storage] path` directory, restart
  (single-node cluster forms)

**Cluster lost quorum?**

- For a 3-node cluster: can lose at most 1 node
- If 2+ nodes down: Raft cannot proceed; start any 1 node with `dev_mode = true`
  temporarily to unblock (high-risk, last resort)

---

## Security Best Practices

1. **Run Keystone as non-root** - separate unprivileged user
2. **Protect fernet keys** - restrictive file permissions (`0600`)
3. **TLS for cluster communication** - inter-node replication is encrypted
4. **Audit logging enabled** - retention policy required (compliance)
5. **Rate limiting tuned** - prevent brute force / DDoS
6. **Policy-driven authz** - OPA policies reviewed, tested, audited
7. **Plugin vetting** - review `capabilities` and `allowed_hosts` before loading
8. **Secret management** - `http_fetch_auth_secret_env` never hardcoded in
   config

See [Security Model](./security.md) for detailed threat model and invariants.
