# OAuth2 / OIDC Provider — Administrator Guide

This page covers day-to-day operation of the native OAuth2 Authorization Server
/ OpenID Connect Provider (OP): configuration, client registration, key rotation
(including emergency rotation), and the downstream middleware that lets
Nova/Neutron/etc. accept OP-issued JWTs directly. See
[ADR 0026](../../adr/0026-oauth2-oidc-provider.md) for the full design rationale
and threat model; this page is the operational surface on top of it.

For end-user/application-developer facing flows (login, token requests, device
code), see the [OAuth2 / OIDC user guide](../../user/features/oauth2.md).

## Concepts

- Every domain owns its own **independent signing keypair** — there is no
  cluster-wide key. Issuer, JWKS, and discovery are all per-domain:
  `GET /v4/oauth2/{domain_id}/jwks`,
  `GET /v4/oauth2/{domain_id}/.well-known/openid-configuration`.
- A domain created through `POST /v3/domains` gets its signing key automatically
  (provisioned by `Oauth2KeyHook` on the domain-create event). A domain
  provisioned any other way — most notably the `default` domain, which is seeded
  directly into the database at bootstrap and never fires that hook — has **no**
  signing key and `/jwks`/`/token`/discovery will fail for it until you
  provision one (see `ensure-signing-key` below).
- Tokens are stateless JWTs (`id_token`, `access_token`) signed ES256 by default
  (`RS256` configurable). Refresh tokens are the one stateful piece — rotating,
  family-tracked, stored in Raft + FjallDB.
- `OAuth2Client` registrations (relying parties / machine identities) are a
  fourth ADR 0020 provider resource, domain-owned, managed via the
  `/v4/oauth2/{domain_id}/clients` CRUD API below.

## Configuration (`[oauth2]` in `keystone.conf`)

| Option                                  | Default | Purpose                                                                                                                                          |
| --------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `signing_algorithm`                     | `ES256` | `ES256` or `RS256`. Governs both outbound signing and inbound verification — must match across a deployment.                                     |
| `signing_key_rotation_days`             | 90      | Automatic rotation cadence. Manual rotation via `keystone-manage oauth2 rotate-signing-key` is always available regardless of this value.        |
| `argon2_memory_kib`                     | 65536   | Argon2id memory cost for confidential-client secret hashing.                                                                                     |
| `argon2_time_cost`                      | 3       | Argon2id iterations.                                                                                                                             |
| `argon2_parallelism`                    | 4       | Argon2id lanes.                                                                                                                                  |
| `access_token_lifetime_minutes`         | 15      | `access_token` TTL.                                                                                                                              |
| `id_token_lifetime_minutes`             | 15      | `id_token` TTL.                                                                                                                                  |
| `authorization_code_lifetime_seconds`   | 60      | Single-use authorization code TTL.                                                                                                               |
| `refresh_token_lifetime_days`           | 30      | Idle lifetime of a refresh token family; reset on each rotation (never beyond the absolute lifetime).                                            |
| `refresh_token_absolute_lifetime_days`  | 90      | Absolute lifetime of a refresh token family from root issuance; rotation never extends it.                                                       |
| `refresh_token_reuse_grace_minutes`     | 10      | Grace window before a reused refresh token is treated as a breach (family revoked). `0` = tightest detection, most multi-device false positives. |
| `pre_auth_session_lifetime_minutes`     | 10      | Pre-authentication browser session TTL for the login/consent sequence.                                                                           |
| `device_code_lifetime_minutes`          | 10      | RFC 8628 `device_code`/`user_code` TTL.                                                                                                          |
| `device_code_poll_interval_seconds`     | 5       | Minimum interval between `/token` polls for a `device_code`.                                                                                     |
| `revoked_family_retention_days`         | 30      | Days a revoked-family refresh token tombstone is kept after its own expiry (forensics only) before the session janitor purges it.            |
| `session_janitor_interval_seconds`      | 300     | Interval of the leader-only janitor that purges expired pre-auth sessions, authorization codes, device grants and refresh tokens from Raft.      |
| `token_rate_limit_burst_size`           | 10      | `/token` rate-limit burst, keyed on unverified `client_id`.                                                                                      |
| `token_rate_limit_replenish_per_minute` | 60      | `/token` sustained rate after burst is exhausted.                                                                                                |

Exceeding a rate limit returns `429 Too Many Requests`.

## Provisioning a domain's signing key

```
keystone-manage oauth2 ensure-signing-key --domain <domain_id>
```

Idempotent — a no-op if the domain already has a key. Run this once for any
domain that did not go through `POST /v3/domains` (notably `default` after a
non-API bootstrap). Normal domain creation via the API does this automatically;
you only need the CLI for out-of-band-provisioned domains.

## Client registration (relying parties & machine identities)

All admin endpoints below require `SystemAdmin`/domain-manager Tier 1/Tier 2
gating per ADR 0020 §9.A and are authenticated with a normal Keystone token, not
an OAuth2 access token.

```
POST   /v4/oauth2/{domain_id}/clients
GET    /v4/oauth2/{domain_id}/clients
GET    /v4/oauth2/{domain_id}/clients/{provider_id}
PUT    /v4/oauth2/{domain_id}/clients/{provider_id}
POST   /v4/oauth2/{domain_id}/clients/{provider_id}/rotate-secret
DELETE /v4/oauth2/{domain_id}/clients/{provider_id}
```

- Confidential clients get a one-time plaintext `client_secret` in the
  `create`/`rotate-secret` response body — it is never stored or returned again,
  only its Argon2id hash.
- `provider_id` is unique within a domain; `client_id` is server-generated and
  globally unique (it's the sole key presented at `/token`, before `domain_id`
  is known).
- `client_id`, `provider_id`, `domain_id` are immutable after creation.
- Setting `pre_authorized: true` (skips user consent for trusted first-party
  device-code clients) requires `SystemAdmin` regardless of the Tier 2
  self-service path otherwise available on this endpoint, and is rejected
  together with `openstack:api` in `allowed_scopes` (a pre-authorized client
  cannot silently gain OpenStack authorization).
- `DELETE` soft-deletes the client and tombstones every refresh token family
  issued to it (revocation reason `client_revoked`) before returning. Setting
  `enabled: false` through `PATCH` does the same, since a disabled client must
  not keep live refresh families. Both emit an `oauth2/client_revoked` CADF
  event carrying the number of revoked families. Pending device grants and
  pre-auth sessions of the client are not purged eagerly: they are rejected at
  redemption because the client is disabled and are removed by the expired
  record janitor. Outstanding bearer access/id tokens remain valid until
  natural `exp` — for immediate access-token invalidation on a compromised
  client, use emergency signing-key rotation instead.
- Every create/update/delete/rotate-secret call emits a CADF audit event.

## Signing key rotation

### Normal rotation

```
keystone-manage oauth2 rotate-signing-key --domain <domain_id>
```

Generates a fresh keypair, commits it via Raft, promotes it to `Primary/Active`,
and demotes the prior `Primary` to `Previous`. The `Previous` key stays
published on JWKS for one full token max-lifetime after demotion so in-flight
tokens keep verifying, then a background janitor removes it. Also runs
automatically every `signing_key_rotation_days`.

### Emergency rotation (suspected/confirmed key compromise)

Emergency rotation requires **dual control**: the initiating operator stages the
rotation, and a _different_ operator must confirm it within 15 minutes or it
auto-aborts (recorded in the audit log either way).

```
# Operator A, over admin UDS + SPIFFE mTLS:
keystone-manage oauth2 rotate-signing-key --domain <domain_id> --emergency
```

This prints a `rotation_id` and `expires_at`. A second operator then runs:

```
keystone-manage oauth2 confirm-rotate-signing-key \
  --domain <domain_id> --rotation-id <rotation_id> \
  --revoke-jti <jti-1> --revoke-jti <jti-2> ...
```

What happens:

1. A fresh keypair is generated and committed via Raft, promoted directly to
   `Primary/Active` — no grace-window overlap with the compromised key.
2. The compromised key is marked `revoked`, not removed from JWKS outright
   (removing it would invalidate every outstanding token signed by it — a
   domain-wide denial of service). Instead its `jti`s are published on a
   dedicated revocation list: `GET /v4/oauth2/{domain_id}/jwks/revocation`.
3. `--revoke-jti` is how you seed that list: pass every `jti` you already know
   was minted during the compromise window. **This is currently manual** — the
   operator must supply known-suspect JTIs by hand; there is no automatic
   audit-log-derived backfill yet (see the companion ADR amendment tracking this
   gap).
4. The downstream middleware (below) checks this list on every token
   verification and fails closed if the endpoint is unreachable.
5. A distinct CADF event (`oauth2/emergency_key_rotation`) is recorded with
   `domain_id`, revoked `kid`, new `kid`, operator identity, and the full
   `revoked_jtis` list.

Normal rotation cadence resumes afterward; the `signing_key_rotation_days` timer
resets.

**Note:** the stage and confirm steps above go through the normal Raft-backed
HTTP path (admin UDS + SPIFFE mTLS to
`/v4/oauth2/{domain_id}/rotate-signing-key`), which requires Raft quorum to
commit. If the cluster has lost quorum at the same moment a key is compromised,
use the quorum-bypass path below instead.

### Emergency signing key rotation during quorum loss

See [ADR 0028](../../adr/0028-oauth2-quorum-bypass-emergency-rotation.md) for the
full node-local mechanism (guardrail, gossip, scope limits) shared with DEK
rotation. This section covers the OAuth2-specific commands.

Requires `[local_emergency] enabled = true` on the responding node, and the Raft
leader must have been unknown for at least `leaderless_grace_period_seconds`
(guardrail refuses otherwise).

**1. Stage** — during quorum loss, on a guardrail-enabled node:

```bash
keystone-manage oauth2 rotate-signing-key \
  --domain <domain_id> --local-quorum-bypass \
  --justification "suspected key compromise, quorum lost"
```

Writes a rotation candidate to that node's local Fjall keyspace only — never
touches Raft. A background sweep gossips it (best-effort) to reachable peers
every `gossip_interval_seconds`, marking it `conflicted: true` on any node where
a different active candidate already exists for the same domain.

**2. List candidates** — once quorum returns, on every node that may have been
reached during the outage:

```bash
curl -X GET https://keystone:5000/v4/oauth2/<domain_id>/local-emergency-candidates \
  -H "X-Auth-Token: $ADMIN_TOKEN"
```

CLI equivalent:
`keystone-manage oauth2 list-local-emergency-candidates --domain <domain_id>`.
Check `conflicted` before choosing a `rotation_id` — `true` means gossip saw a
different candidate elsewhere and you must decide deliberately which one wins.

**3. Reconcile** — a _different_ operator than the one who staged it, against
the specific node holding the chosen candidate (reconciliation does not fan out
cluster-wide):

```bash
keystone-manage oauth2 reconcile-local-emergency-key \
  --domain <domain_id> --rotation-id <rotation_id>
```

Promotes the candidate's key to `Primary` via the same Raft transaction path
normal rotation uses (requires quorum), demotes the prior `Primary` to
`Previous`, clears the candidate on this node, and revokes any other active
candidate for the domain on this node. Rejects if the confirming operator
matches the initiator (dual-control) or if the candidate was already revoked.
Emits `oauth2/local_emergency_key_reconciled` (CADF) with a
`_local:emergency:audit:<rotation_id>` pointer recorded in the local emergency
store back to the event — staging itself is **not** audited (consistent with the
ordinary emergency path's stage/confirm asymmetry); only reconciliation is.

## Downstream control-plane enforcement (Nova/Neutron/etc.)

A thin Python WSGI middleware (`KeystoneNativeJwtMiddleware`) drops into
existing Paste Deploy pipelines (e.g. `/etc/nova/api-paste.ini`) **in front of**
`keystonemiddleware.auth_token`. Requests without an OP-issued Bearer JWT fall
through unchanged to the existing Fernet filter chain, so rollout is incremental
per service/region with instant rollback (just remove the filter).

Required config per service:

```ini
keystone_jwks_url = https://keystone.example.com/v4/oauth2/<domain_id>/jwks
keystone_jwt_jti_revocation_url = https://keystone.example.com/v4/oauth2/<domain_id>/jwks/revocation
keystone_domain_id = <domain_id>
keystone_expected_issuers = https://keystone.example.com/v4/oauth2/<domain_id>
signing_algorithm = ES256
```

Operational notes:

- **Fail-closed.** Both the JWKS fetch and the JTI-revocation fetch reject the
  request on failure rather than serving stale data — a Keystone or network
  outage now also blocks OpenStack API calls, not just token issuance. This is
  deliberate: fail-open would let an attacker who can interfere with the
  middleware's connectivity keep an already-revoked compromised key validating
  for the outage's duration. Both endpoints must be treated as load-bearing for
  the whole control plane.
  - JWKS cache TTL: 300s (matches `Cache-Control: max-age=300` on `/jwks`).
  - Revocation list cache TTL: 60s.
- `aud` is domain-bound (`openstack-apis:{domain_id}`), never a flat
  cluster-wide value — a compromised domain key only forges tokens accepted
  within that domain's own blast radius.
- Set `keystone_expected_issuers` explicitly; claim presence of `iss` alone is
  not enough, the value is checked against this allowlist.

## Relying-party token revocation (RFC 7009)

`POST /v4/oauth2/{domain_id}/revoke` lets a client revoke its own refresh or
access tokens (see the user guide). Operationally:

- Refresh-token revocation tombstones the family with reason `rp_revoke` and
  emits `oauth2/refresh_family_revoked`; every request also emits a `revoke`
  session audit event whose initiator is the authenticated client. A client
  presenting another client's refresh token gets `200` (no oracle) but a
  `failure` audit event is recorded.
- Access-token revocation writes the `jti` to the same per-domain revocation
  list that emergency rotation uses (`/jwks/revocation`), so it is only
  enforced by services that fetch that list (see "Downstream control-plane
  enforcement"), after the list's 60s cache TTL. Entries are dropped once the
  token's `exp` passes.
- The endpoint is rate limited per client (`token_rate_limit_*`) and per source
  IP (global IP limiter) before any token lookup.
- OIDC access tokens carry a private `sid` claim (the refresh family id).
  Revoking such an access token also revokes that family. The reverse does not
  hold: revoking a refresh token does not revoke access tokens already minted
  from its family (the list is keyed by `jti`; the server does not track
  access tokens per family).
- Writes to the per-domain JTI list use optimistic concurrency with bounded
  retries, so concurrent revocations (or a revocation racing an emergency
  rotation) do not lose entries; under sustained contention the call fails with
  a 500 rather than silently dropping a revocation.

## Migration from Fernet

Everything here is additive — Fernet issuance/validation continues unchanged.
See ADR 0026 §13 for the staged migration path (Fernet interchangeability → JWS
format parity → OP goes live → machine identity migration → human flow migration
→ Fernet sunset). Key operational gate: a service may only prefer JWTs over
falling through to Fernet once its operator has explicitly accepted the
15-minute stateless revocation window (or wired back-channel introspection for
high-criticality operations) — record that acceptance in your deployment's
migration runbook.

## Upgrading to the absolute refresh-token lifetime

- **Existing refresh families** (issued before `refresh_token_absolute_lifetime_days`
  existed) carry no cap. On their first rotation after the upgrade they are
  backfilled with `now + refresh_token_absolute_lifetime_days`, so they are
  capped from then on rather than staying uncapped forever.
- **Rolling upgrades of a Raft cluster:** `create_refresh_token` commands now
  carry a `family_expires_at` field. Nodes still running the old version cannot
  apply them, so upgrade all nodes before serving refresh-token traffic from the
  new version (stored records stay readable in both directions).
- Revoking a family because its user or domain is no longer valid emits an
  `oauth2/refresh_family_revoked` audit event (family id and reason:
  `user_deleted`, `user_disabled`, `user_domain_changed`, `domain_disabled`).

## Known gaps

- **Audit-log-derived JTI backfill** — `--revoke-jti` is manual only.
  Auto-populating the revocation list from a time window against the audit trail
  needs a queryable audit-log store that does not exist yet.
- Quorum-bypass local-emergency rotation
  ([ADR 0028](../../adr/0028-oauth2-quorum-bypass-emergency-rotation.md), gap noted
  in ADR 0026 §3) is implemented — see "Emergency signing key rotation during
  quorum loss" above. Deliberate scope limits: no cross-node broadcast to clear
  a superseded candidate, no unattended reconciliation sweep, per-node (not
  cluster-wide) reconciliation.

## Troubleshooting

| Symptom                                                                       | Likely cause                                                                                                                     |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `/jwks` or `/.well-known/openid-configuration` returns 404                    | Domain has no signing key — run `keystone-manage oauth2 ensure-signing-key --domain <id>`                                        |
| `429` on `/token`                                                             | Rate limit hit — see `token_rate_limit_*` config                                                                                 |
| `429` on `/authorize`, `/device`, `/device/login`, or `/device_authorization` | Global per-IP limiter hit — see `[rate_limit_global_ip]`                                                                         |
| `confirm-rotate-signing-key` fails with "rotation not found/expired"          | The 15-minute confirmation window elapsed and the rotation auto-aborted; re-run `rotate-signing-key --emergency`                 |
| Downstream service rejects all OP tokens after Keystone/network blip          | Expected fail-closed behavior — check JWKS/revocation endpoint reachability from the service                                     |
| `rotate-signing-key --local-quorum-bypass` refused                            | `[local_emergency] enabled = false` on that node, or leader has not been unknown long enough (`leaderless_grace_period_seconds`) |
| `reconcile-local-emergency-key` fails with dual-control error                 | Confirming operator matches the one who staged the candidate — use a different operator                                          |
