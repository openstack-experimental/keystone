# 27. LDAP Identity Driver

**Date:** 2026-07-09

## Status

Proposed

## Context

LDAP is the most widely deployed identity backend across OpenStack clouds.
Organizations operate multi-thousand-user LDAP directories (FreeIPA, Active
Directory, OpenLDAP, JumpCloud, Azure AD) and rely on Keystone as the
authentication proxy, mapping external directory users and groups to local
authorization contexts.

The Python LDAP backend (`keystone/identity/backends/ldap/`) is a mature,
field-proven implementation with over two decades of production deployments.
Any Rust implementation must achieve configuration-compatible behavior with the
Python driver so that both can operate against the same directory server
returning identical results.

### Parallel Execution Requirement

The primary design goal is operational parity. A `keystone-rs` deployment must
behave identically to its Python counterpart when configured with the same LDAP
parameters, enabling:

1. **Rolling upgrades** -- mixed Python/Rust Keystone deployments querying the
   same directory without behavior divergence.
2. **Configuration portability** -- a `[ldap]` config section written for Python
   Keystone works unmodified in `keystone-rs`.
3. **Fallback capability** -- operators can switch between `driver = sql` and
   `driver = ldap` at the configuration level without code changes.

### Python LDAP Backend Architecture

The Python implementation spans four modules totaling ~2,823 lines:

| File | Lines | Purpose |
|------|-------|---------|
| `__init__.py` | 13 | Re-exports from `core.py` |
| `core.py` | 491 | `Identity`, `UserApi`, `GroupApi` classes |
| `models.py` | 75 | `User` and `Group` model definitions |
| `common.py` | 2,244 | `BaseLdap`, `EnabledEmuMixIn`, connection handlers, type conversions |

Key characteristics inherited from the Python design:

- **Not domain-aware** (`is_domain_aware() -> False`). All LDAP users occupy a
  single flat namespace.
- **Does not generate UUIDs** (`generates_uuids() -> False`). Identifiers come
  from the LDAP directory, not Keystone.
- **Read-only by default.** All mutating operations are gated behind
  `common_ldap.WRITABLE` (default `False`).
- **Two connection pools** -- a service pool for directory queries and a
  dedicated auth pool for end-user authentication.

### keystone-rs Identity Model Tension

`keystone-rs` `IdentityBackend` trait (27 methods) is designed around a
local-data, domain-aware SQL backend. LDAP operates under fundamentally
different constraints:

- Users are managed externally, not by Keystone.
- Authentication is an LDAP bind, not local password hash verification.
- Group membership lives in `member` DN attributes, not a local junction table.
- No local `domain_id` concept exists in LDAP.

This ADR reconciles these differences while maintaining the `IdentityBackend`
contract, ensuring both backends produce identical API responses.

---

## Decision

### 1. Crate Structure

Follow ADR-0018 naming convention:
`openstack-keystone-identity-driver-ldap`.

```
crates/
  openstack-keystone-identity-driver-ldap/
    Cargo.toml
    src/
      lib.rs          # LdapBackend, anchor(), inventory registration
      backend.rs      # IdentityBackend impl
      config.rs       # LdapConfig
      connection.rs   # Pool-managed LDAP connections
      user.rs         # UserApi: LDAP query builder and result mapper
      group.rs        # GroupApi: LDAP query builder and result mapper
      filter.rs       # Hints → LDAP filter translation
      enabled.rs      # Enabled emulation (bitmask, invert, group membership)
      models.rs       # LDAP entry → core-types conversion
```

The crate declares `inventory::submit!` registration and exposes a public
`#[allow(dead_code)] pub fn anchor() {}` for ADR-0018 linker anchor discovery.

### 2. Configuration Mapping

The `[ldap]` config section maps 1:1 with Python's `conf.ldap.*` option names.

```rust
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct LdapConfig {
    // --- Connection ---
    pub url: String,
    pub user: Option<String>,
    pub password: Option<SecretString>,
    pub use_tls: bool,
    pub tls_cacertfile: Option<String>,
    pub tls_cacertdir: Option<String>,
    pub tls_req_cert: String,          // "demand", "allow", "try", "never"
    pub connection_timeout: f64,
    pub randomize_urls: bool,
    pub pool: bool,                    // use_pool
    pub pool_size: i32,
    pub pool_retry_max: i32,
    pub pool_retry_delay: f64,
    pub pool_connection_timeout: f64,
    pub pool_connection_lifetime: f64,
    pub auth_pool: bool,               // use_auth_pool
    pub auth_pool_size: i32,
    pub auth_pool_connection_lifetime: f64,

    // --- Query ---
    pub query_scope: String,           // "one" or "sub"
    pub page_size: i32,
    pub alias_dereferencing: String,   // "never", "search", "always", "find"
    pub chase_referrals: bool,
    pub debug_level: i32,

    // --- User Mapping ---
    pub user_tree_dn: String,
    pub user_objectclass: String,
    pub user_id_attribute: String,
    pub user_name_attribute: String,
    pub user_mail_attribute: String,
    pub user_enabled_attribute: String,
    pub user_enabled_mask: Option<i32>,
    pub user_enabled_invert: bool,
    pub user_enabled_default: bool,
    pub user_additional_attribute_mapping: HashMap<String, String>,
    pub user_filter: Option<String>,
    pub user_attribute_ignore: HashSet<String>,
    pub user_enabled_emulation: bool,
    pub user_enabled_emulation_dn: Option<String>,
    pub user_enabled_emulation_use_group_config: bool,

    // --- Group Mapping ---
    pub group_tree_dn: String,
    pub group_objectclass: String,
    pub group_id_attribute: String,
    pub group_name_attribute: String,
    pub group_desc_attribute: String,
    pub group_member_attribute: String,
    pub group_additional_attribute_mapping: HashMap<String, String>,
    pub group_filter: Option<String>,
    pub group_ad_nesting: bool,

    // --- General ---
    pub suffix: String,
}
```

Environment variable override: `OS_LDAP__<KEY>`. Defaults mirror Python's
`DEFAULT_*` conventions (e.g., `user_objectclass = "inetOrgPerson"`,
`group_objectclass = "groupOfNames"`).

### 3. IdentityBackend Method Mapping

The `LdapBackend` struct implements `IdentityBackend`. Each of the 27 methods
maps to an LDAP operation, a read-only rejection, or a "not implemented"
response.

#### User CRUD

| Method | LDAP Operation |
|--------|----------------|
| `create_user` | Forbidden -- returns `IdentityProviderError::Readonly` |
| `get_user(user_id)` | `id_to_dn` → BASE search |
| `update_user` | Forbidden -- `Readonly` |
| `delete_user` | Forbidden -- `Readonly` |
| `list_users(params)` | Subtree paged search + hint filters |
| `find_federated_user` | Name-based search (maps `idp_id` → `domain_id`) |
| `get_user_domain_id` | Returns `default_domain_id` from config |

#### Authentication

| Method | LDAP Operation |
|--------|----------------|
| `authenticate_by_password` | Two-step: resolve user DN via service bind, then bind as user DN + password |

The authentication path is the primary function of an LDAP identity driver:
1. Resolve `user_id` or `name + domain_id` to the user's LDAP DN.
2. Attempt LDAP simple bind using the user DN and provided password.
3. On success, fetch full user attributes using the service bind pool.
4. Return `AuthenticationResult` with the mapped `UserResponse`.

Step 2 uses the dedicated `auth_pool` to prevent authentication storms from
exhausting the service query pool.

#### Group CRUD

| Method | LDAP Operation |
|--------|----------------|
| `create_group` | Forbidden -- `Readonly` |
| `get_group(group_id)` | `id_to_dn` → BASE search |
| `list_groups(params)` | Subtree search, filtered by `group_objectclass` |
| `delete_group` | Forbidden -- `Readonly` |

#### Membership

| Method | LDAP Operation |
|--------|----------------|
| `add_user_to_group` | Forbidden -- `Readonly` |
| `remove_user_from_group` | Forbidden -- `Readonly` |
| `list_groups_of_user(user_id)` | Reverse search: find groups where `member = user_dn`. When `group_ad_nesting`, uses LDAP_MATCHING_RULE_IN_CHAIN. |
| `list_users_of_group(group_id)` | Direct read of `member` attribute on group entry |
| `set_user_groups` | Forbidden -- `Readonly` |

All expiring-variant methods (`add_user_to_group_expiring`, etc.) return
`IdentityProviderError::NotImplemented`. Expiring membership is a federation
concept not applicable to LDAP.

#### Password and Service Accounts

| Method | Behavior |
|--------|----------|
| `update_user_password` | Forbidden -- `Readonly`. Passwords are LDAP-managed. |
| `create_service_account` | `NotImplemented`. LDAP has no service account concept. |
| `get_service_account` | Returns `None` always. |

### 4. ID-to-DN Mapping

Mirrors Python's `_id_to_dn` and `_dn_to_id` methods exactly.

#### `id_to_dn(object_id) → DN`

For `query_scope = "one"`: direct DN construction.
```
dn = "{id_attr}={object_id},{tree_dn}"
```

For `query_scope = "sub"`: subtree search then extract DN from single result.

#### `dn_to_id(dn) → object_id`

If `id_attr` matches the RDN attribute, extract from DN directly. Otherwise,
perform a BASE-scoped search on the DN and read the `id_attr` value.

### 5. Filter Translation (Hints → LDAP Filters)

Mirrors Python's `filter_query` method. Hints are translated to LDAP AND
clauses:

| Hint Comparator | LDAP Filter | Example |
|-----------------|-------------|---------|
| `equals` | `({attr}={value})` | `(uid=jdoe)` |
| `contains` | `({attr}=*{value}*)` | `(uid=*doe*)` |
| `startswith` | `({attr}={value}*)` | `(uid=j*)` |
| `endswith` | `({attr}=*{value})` | `(uid=*doe)` |

**Exclusion rules** (identical to Python):
- Case-sensitive filters (`equals_case`): skipped. Handled at controller level.
- `enabled` filter: skipped. Requires bitmask/emulation logic that doesn't
  compose into a simple AND clause.
- Unknown attributes: skipped silently.

**Filter escaping**: values must escape `*`, `(`, `)`, `\`, and NUL bytes
to prevent LDAP filter injection.

Combined filter structure:
```
(&{OBJCLASS}{USER_FILTER}{AND_ATTRIBUTE_FILTERS})
```

Satisfied filters are removed from hints; any remaining unsatisfied filters
are re-evaluated in-memory after LDAP returns results.

### 6. Result-to-Model Conversion

Mirrors Python's `_ldap_res_to_model`:

1. **Case-insensitive attribute matching** -- LDAP attribute names are lowercased
   before matching `attribute_mapping`.
2. **Bytes handling** -- Rust LDAP library (e.g., `ldap3`) handles UTF-8 natively.
3. **Multi-value ID attributes** -- fall back to DN as identifier.
4. **Additional attributes** -- `*_additional_attribute_mapping` entries are
   exposed as user/group `extras`.
5. **Private attribute filtering** -- matches Python's `filter_entity` (removes
   `dn`, `password` from results).

### 7. Enabled Emulation

Four strategies, all configurable per the Python `EnabledEmuMixIn`:

| Strategy | Config | Mechanism |
|----------|--------|-----------|
| Bitmask | `*_enabled_mask` | Read integer attribute, apply bit mask |
| Invert | `*_enabled_invert` | Invert boolean interpretation |
| Emulation | `*_enabled_emulation` | Group membership in `cn=enabled_us*rs,{tree_dn}` |
| Default | `*_enabled_default` | Fallback when attribute absent |

### 8. Connection Architecture

```
┌─────────────────────┐
│   LdapBackend       │  ← IdentityBackend impl
│   (query builder)   │
└────────┬────────────┘
         │
┌────────▼────────────┐
│   Connection Pools  │
│   ├── service_pool  │     service bind DN → all queries
│   └── auth_pool     │     user DN + password → auth only
└────────┬────────────┘
         │
┌────────▼────────────┐
│   LdapConnection    │  ← ldap3 crate
│   (TLS, bind, etc.) │
└─────────────────────┘
```

Paged search (RFC 2696) is used for all subtree operations to handle
directories with more than `page_size` results.

### 9. Active Directory Nested Groups

When `group_ad_nesting = true`, `list_groups_of_user` uses LDAP_MATCHING_RULE_IN_CHAIN:
```
FILTER: (&{OBJCLASS}{member_attr}={user_dn}:1.2.840.113556.1.4.1941)
```

Guarded behind the `group_ad_nesting` flag for non-AD compatibility.

### 10. LDAP Library Choice

| Library | Pool | TLS | Paged Search | Maturity |
|---------|------|-----|--------------|----------|
| `ldap3` | Yes | Full | RFC 2696 | Production |
| `slapd-rs` | No | No | No | Niche |

`ldap3` is selected for its complete operation set, native TLS support,
paged search, and async API compatibility.

### 11. No User Shadowing or ID Mapping

The `keystone-rs` SQL driver maintains three separate user storage
tables and two user-facing ID mapping layers:

| Table | Schema | Purpose |
|-------|--------|---------|
| `user` | `id`, `name`, `domain_id`, `enabled`, `extra`, ... | Main user record |
| `local_user` | `id`, `password` | Local user password data |
| `nonlocal_user` | `(domain_id, name, user_id)` FK | Federated user link |
| `federated_user` | `id`, `user_id`, `idp_id`, `protocol_id`, `unique_id` | IdP protocol binding |
| `idmapping` | `domain_id`, `entity_type`, `local_id`, `public_id` | Local ↔ public ID mapping |

The SQL `create` flow works as:
1. Insert `user` (main record)
2. If local user → insert `local_user` (with bcrypt password hash) + `password`
3. If federated user → insert `federated_user` (links to `idp_id` + `unique_id`)
4. The `idmapping` table maps the local user UUID to a public-facing ID

**The LDAP driver uses NONE of these tables.** LDAP users are not shadowed
into local storage. The authentication and lookup flow bypasses the SQL
identity tables entirely:

```
┌──────────────┐     LDAP bind     ┌──────────────┐
│              │ ────────────────→ │              │
│  Keystone    │                   │   LDAP       │
│  (read-only) │  ← user entry ←── │  Directory   │
│              │                   │              │
└──────────────┘                   └──────────────┘
```

When `driver = "ldap"`:
- `authenticate_by_password` → LDAP bind (no local password verification)
- `get_user`, `list_users` → LDAP subtree search → direct API response
- `get_group`, `list_groups` → LDAP subtree search → direct API response
- No local table writes occur at any point

The `idmapping` system is used by the SQL driver to map internal UUIDs
(public_id: local_id). LDAP uses the directory's native identifier
(`user_id_attribute`, default `cn`) as the `id` in the Keystone API
response. No additional ID mapping layer is needed because the LDAP
identifier IS the public identifier.

This is intentional and matches Python's behavior: the Python LDAP driver
sets `generates_uuids() -> False`, meaning it never creates local
identifiers. The `nonlocal_user` table is exclusively for federation
(OIDC/SAML/Passkey) where external IdP assertions are mapped to local
Keystone user records. The LDAP driver is a standalone identity backend,
not a federation endpoint.

### 12. Error Handling

`IdentityProviderError` gains new variants:

```rust
pub enum IdentityProviderError {
    // ... existing variants ...
    Readonly(String),         // Operation not permitted on read-only LDAP
    LdapConnection(String),   // Connection, bind, TLS, pool errors
    LdapFilterBuild(String),  // Filter construction failures
}
```

---

## Consequences

### Positive

1. **Configuration parity** -- An operator's `keystone.conf [ldap]` section
   works identically across Python and Rust deployments. No conversion tooling
   required.

2. **Auth storm isolation** -- The dedicated auth pool prevents a login storm
   from exhausting directory query capacity and breaking control-plane operations.

3. **Zero local data mutation** -- The read-only contract means `keystone-rs`
   cannot corrupt the LDAP directory. All write operations return clearly named
   errors.

4. **AD compatibility** -- `group_ad_nesting` with IN_CHAIN matching provides
   native AD nested group support, matching Python's behavior.

5. **Pagination safety** -- RFC 2696 paged search ensures large directories
   don't exceed LDAP server `sizelimit` and return incomplete result sets.

6. **Identity separation** -- LDAP, federation, and SQL identity data
   remain in separate storage layers. No cross-backend confusion.

### Negative

1. **Trait overhead** -- ~8 of 27 `IdentityBackend` methods are no-ops or
   return hardcoded errors. A more minimal trait (e.g.,
   `ReadonlyIdentityBackend`) could reduce this but would complicate the
   plugin registration model.

2. **No domain awareness** -- LDAP doesn't map to Keystone's multi-domain
   model. All users share `default_domain_id`. Operators needing multi-domain
   separation must use a local SQL backend or federation mappings.

3. **No write capability** -- Deferred write support means operators cannot
   use LDAP for user or group lifecycle management. If future work enables
   `WRITABLE` mode, the risk of directory corruption must be carefully managed.

4. **New dependency** -- `ldap3` adds an external LDAP protocol dependency
   to the Rust crate graph.

5. **No `idmapping` or `nonlocal_user`** -- LDAP users bypass the local
   identity shadowing layer entirely. This means LDAP users cannot be mixed
   with local SQL users in the same Keystone deployment. If an operator needs
   both LDAP users AND local service accounts, they must switch back to
   `driver = sql` or use federation to bridge the gap.

### Migration Path

The driver crate integrates via ADR-0018's automatic discovery:

1. Add `openstack-keystone-identity-driver-ldap` crate to workspace.
2. Add as dependency of `crates/keystone/Cargo.toml`.
3. `build.rs` discovers it automatically via the `driver` name filter.
4. Set `[identity] driver = "ldap"` in config to activate.

### Testing Strategy

1. **Config parity tests** -- Verify Rust `LdapConfig` deserializes identically
   to Python's `conf.ldap` for a set of representative config files.
2. **Filter translation tests** -- Unit tests verifying hint-to-filter mapping
   matches Python output for all comparator types.
3. **LDAP mock server tests** -- Integration tests against a controllable LDAP
   mock (e.g., `ldap-mock` or `slapd` in Docker) validating full query paths.
4. **Side-by-side validation** -- Smoke tests running Python and Rust backends
   against the same directory and comparing API responses.
