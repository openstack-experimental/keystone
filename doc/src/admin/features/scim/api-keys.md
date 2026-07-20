# SCIM API-Key Administration

API keys give Identity Providers (IdPs) doing SCIM provisioning a static,
long-lived bearer credential that authenticates in a single request, without a
prior `/v3/auth/tokens` exchange. See
[ADR 0021](../../../adr/0021-api-key-scim.md) for the full design and security
rationale; this page covers day-to-day usage.

API keys are **domain-owned machine identities**, not human user accounts.
They are only accepted on the SCIM sub-router — core `/v3`/`/v4` endpoints
reject them outright.

## Token format

A generated token looks like:

```
kscim_{43-char base62 entropy}_{crc32 checksum}
```

The token is shown to the administrator **once**, at creation time. Keystone
never stores it in recoverable form — only a `lookup_hash` (fast SHA-256, used
as the DB index) and a `secret_hash` (Argon2id, used for verification).

## Managing keys

All admin endpoints below require the `DomainManager` (or `SystemAdmin`) role
and are authenticated with a normal Fernet token, not an API key.

### Create a key

```
POST /v4/api-keys/
```

```json
{
  "api_key": {
    "domain_id": "d1",
    "provider_id": "entra-scim",
    "expires_at": 1798761600,
    "allowed_ips": ["198.51.100.0/24"],
    "description": "Entra ID SCIM provisioning"
  }
}
```

Response (`201`) — this is the only time the raw token is returned:

```json
{
  "api_key": { "client_id": "9f2c...", "domain_id": "d1", "provider_id": "entra-scim",
               "enabled": true, "created_at": 1751500000, "expires_at": 1798761600,
               "allowed_ips": ["198.51.100.0/24"], "description": "Entra ID SCIM provisioning" },
  "token": "kscim_9pQ...xz_1a2b3c4d"
}
```

### List / show

```
GET /v4/api-keys/?domain_id=d1[&enabled=true][&provider_id=entra-scim]
GET /v4/api-keys/{client_id}?domain_id=d1
```

Neither ever returns `secret_hash` or `lookup_hash`.

### Update

```
PUT /v4/api-keys/{client_id}?domain_id=d1
```

```json
{ "api_key": { "description": "renamed", "allowed_ips": null } }
```

Fields use nested-Option semantics: an absent field leaves the value
unchanged, `null` clears it. A revoked key cannot be re-enabled through this
endpoint (`409 Conflict` on `enabled: true`) — see Revocation below.

### Revoke

```
POST /v4/api-keys/{client_id}/revoke?domain_id=d1
```

Soft-revoke only: sets `enabled: false`, stamps `revoked_at`/`revoked_by`,
emits a CADF `revoke` event. Nothing is hard-deleted (needed for incident
audit trails). Revocation is permanent — the only way back into service is
creating a new key. Physical purge of revoked records happens later via the
janitor (see Configuration below).

### Zero-downtime rotation

Create a new key against the same `provider_id`, update the IdP with the new
token, then revoke the old key once traffic has moved. Both keys resolve
against the same mapping ruleset for `provider_id` in the interim.

### Dry-run: simulate access

```
POST /v4/api-keys/simulate-access
```

```json
{ "client_id": "9f2c...", "domain_id": "d1" }
```

`client_id` is passed in the body (not the URL) so it doesn't leak into proxy
access logs. Response shows what the key would resolve to without performing
real authentication:

```json
{
  "client_id": "9f2c...", "domain_id": "d1", "provider_id": "entra-scim",
  "matched": true,
  "scope": { "type": "domain", "domain_id": "d1" },
  "roles": ["member"],
  "reason": null
}
```

## Using a key

Only the SCIM sub-router accepts API keys, via `Authorization: Bearer`:

```
GET /SCIM/v2/{domain_id}/whoami
Authorization: Bearer kscim_9pQ...xz_1a2b3c4d
```

```json
{ "user_id": "...", "scope": { "type": "domain", "domain_id": "d1" } }
```

By design, SCIM API keys are **domain-scoped only** — a key authenticates
only if its mapping ruleset (ADR 0020) resolves to **exactly one**
domain-scoped authorization for the key's own `domain_id`. This is an
allowlist: only a domain scope is accepted, so zero matches, multiple
matches, or a match resolving to any other scope (project, system, or
otherwise) are all rejected.

## IP allow-listing

If `allowed_ips` is set, the request's effective client IP must fall inside
one of the listed CIDR blocks. The effective IP is the rightmost address in
`X-Forwarded-For` that isn't in the configured `trusted_proxies`, with the raw
TCP peer appended to the right of that chain first — this defeats
leftmost-entry XFF spoofing through an untrusted intermediate proxy. If
`allowed_ips` is unset, no IP restriction applies.

## Configuration (`[api_key]` in `keystone.conf`)

| Option | Default | Purpose |
| --- | --- | --- |
| `argon2_memory_kib` | 65536 | Argon2id memory cost |
| `argon2_time_cost` | 3 | Argon2id iterations |
| `argon2_parallelism` | 4 | Argon2id parallelism |
| `trusted_proxies` | (empty) | CSV of CIDRs, e.g. `10.0.0.0/8,192.168.1.0/24` |
| `rate_limit_burst_size` | 10 | Token-bucket burst, keyed on `lookup_hash` (or source IP for malformed tokens) |
| `rate_limit_replenish_per_minute` | 60 | Token-bucket refill rate |
| `janitor_inactive_days` | 90 | Auto-disable a key unused for this long |
| `janitor_grace_days` | 7 | Extra grace period absorbing async `last_used_at` write drift |
| `janitor_tombstone_retention_days` | 365 | Hard-purge revoked keys older than this |

Exceeding the rate limit returns `429 Too Many Requests`.

## Errors

| Condition | Response |
| --- | --- |
| Malformed token / bad CRC32 | request dropped |
| Unknown / disabled / expired key | `401` (dummy Argon2id hash computed regardless, to avoid timing-based lookup enumeration) |
| IP outside `allowed_ips` | `401` |
| Mapping resolves to zero authorizations | `401` |
| Mapping resolves to more than one authorization | `401` |
| Mapping resolves to any authorization other than a domain scope (project, system, ...) | `401` |
| Rate limit exceeded | `429` |
| Re-enabling a revoked key via `PUT` | `409` |
