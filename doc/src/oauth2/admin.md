# OAuth2 / OIDC Provider — Administrator Guide

This page covers day-to-day operation of the native OAuth2 Authorization
Server / OpenID Connect Provider (OP): configuration, client registration,
key rotation (including emergency rotation), and the downstream middleware
that lets Nova/Neutron/etc. accept OP-issued JWTs directly. See
[ADR 0026](../adr/0026-oauth2-oidc-provider.md) for the full design
rationale and threat model; this page is the operational surface on top of
it.

For end-user/application-developer facing flows (login, token requests,
device code), see the [OAuth2 / OIDC user guide](user.md).

## Concepts

- Every domain owns its own **independent signing keypair** — there is no
  cluster-wide key. Issuer, JWKS, and discovery are all per-domain:
  `GET /v4/oauth2/{domain_id}/jwks`,
  `GET /v4/oauth2/{domain_id}/.well-known/openid-configuration`.
- A domain created through `POST /v3/domains` gets its signing key
  automatically (provisioned by `Oauth2KeyHook` on the domain-create event).
  A domain provisioned any other way — most notably the `default` domain,
  which is seeded directly into the database at bootstrap and never fires
  that hook — has **no** signing key and `/jwks`/`/token`/discovery will
  fail for it until you provision one (see `ensure-signing-key` below).
- Tokens are stateless JWTs (`id_token`, `access_token`) signed ES256 by
  default (`RS256` configurable). Refresh tokens are the one stateful piece
  — rotating, family-tracked, stored in Raft + FjallDB.
- `OAuth2Client` registrations (relying parties / machine identities) are a
  fourth ADR 0020 provider resource, domain-owned, managed via the
  `/v4/oauth2/{domain_id}/clients` CRUD API below.

## Configuration (`[oauth2]` in `keystone.conf`)

| Option | Default | Purpose |
| --- | --- | --- |
| `signing_algorithm` | `ES256` | `ES256` or `RS256`. Governs both outbound signing and inbound verification — must match across a deployment. |
| `signing_key_rotation_days` | 90 | Automatic rotation cadence. Manual rotation via `keystone-manage oauth2 rotate-signing-key` is always available regardless of this value. |
| `argon2_memory_kib` | 65536 | Argon2id memory cost for confidential-client secret hashing. |
| `argon2_time_cost` | 3 | Argon2id iterations. |
| `argon2_parallelism` | 4 | Argon2id lanes. |
| `access_token_lifetime_minutes` | 15 | `access_token` TTL. |
| `id_token_lifetime_minutes` | 15 | `id_token` TTL. |
| `authorization_code_lifetime_seconds` | 60 | Single-use authorization code TTL. |
| `refresh_token_lifetime_days` | 30 | Idle lifetime of a refresh token family; reset on each rotation. |
| `refresh_token_reuse_grace_minutes` | 10 | Grace window before a reused refresh token is treated as a breach (family revoked). `0` = tightest detection, most multi-device false positives. |
| `pre_auth_session_lifetime_minutes` | 10 | Pre-authentication browser session TTL for the login/consent sequence. |
| `device_code_lifetime_minutes` | 10 | RFC 8628 `device_code`/`user_code` TTL. |
| `device_code_poll_interval_seconds` | 5 | Minimum interval between `/token` polls for a `device_code`. |
| `token_rate_limit_burst_size` | 10 | `/token` rate-limit burst, keyed on unverified `client_id`. |
| `token_rate_limit_replenish_per_minute` | 60 | `/token` sustained rate after burst is exhausted. |

Exceeding a rate limit returns `429 Too Many Requests`.

## Provisioning a domain's signing key

```
keystone-manage oauth2 ensure-signing-key --domain <domain_id>
```

Idempotent — a no-op if the domain already has a key. Run this once for any
domain that did not go through `POST /v3/domains` (notably `default` after
a legacy bootstrap). Normal domain creation via the API does this
automatically; you only need the CLI for out-of-band-provisioned domains.

## Client registration (relying parties & machine identities)

All admin endpoints below require `SystemAdmin`/domain-manager Tier 1/Tier
2 gating per ADR 0020 §9.A and are authenticated with a normal Keystone
token, not an OAuth2 access token.

```
POST   /v4/oauth2/{domain_id}/clients
GET    /v4/oauth2/{domain_id}/clients
GET    /v4/oauth2/{domain_id}/clients/{provider_id}
PUT    /v4/oauth2/{domain_id}/clients/{provider_id}
POST   /v4/oauth2/{domain_id}/clients/{provider_id}/rotate-secret
DELETE /v4/oauth2/{domain_id}/clients/{provider_id}
```

- Confidential clients get a one-time plaintext `client_secret` in the
  `create`/`rotate-secret` response body — it is never stored or returned
  again, only its Argon2id hash.
- `provider_id` is unique within a domain; `client_id` is server-generated
  and globally unique (it's the sole key presented at `/token`, before
  `domain_id` is known).
- `client_id`, `provider_id`, `domain_id` are immutable after creation.
- Setting `pre_authorized: true` (skips user consent for trusted
  first-party device-code clients) requires `SystemAdmin` regardless of
  the Tier 2 self-service path otherwise available on this endpoint, and
  is rejected together with `openstack:api` in `allowed_scopes` (a
  pre-authorized client cannot silently gain OpenStack authorization).
- `DELETE` revokes the client and immediately invalidates all refresh
  tokens in its family tree. Outstanding bearer access/id tokens remain
  valid until natural `exp` — for immediate access-token invalidation on
  a compromised client, use emergency signing-key rotation instead.
- Every create/update/delete/rotate-secret call emits a CADF audit event.

## Signing key rotation

### Normal rotation

```
keystone-manage oauth2 rotate-signing-key --domain <domain_id>
```

Generates a fresh keypair, commits it via Raft, promotes it to
`Primary/Active`, and demotes the prior `Primary` to `Previous`. The
`Previous` key stays published on JWKS for one full token max-lifetime
after demotion so in-flight tokens keep verifying, then a background
janitor removes it. Also runs automatically every
`signing_key_rotation_days`.

### Emergency rotation (suspected/confirmed key compromise)

Emergency rotation requires **dual control**: the initiating operator
stages the rotation, and a *different* operator must confirm it within 15
minutes or it auto-aborts (recorded in the audit log either way).

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

1. A fresh keypair is generated and committed via Raft, promoted directly
   to `Primary/Active` — no grace-window overlap with the compromised key.
2. The compromised key is marked `revoked`, not removed from JWKS
   outright (removing it would invalidate every outstanding token signed
   by it — a domain-wide denial of service). Instead its `jti`s are
   published on a dedicated revocation list:
   `GET /v4/oauth2/{domain_id}/jwks/revocation`.
3. `--revoke-jti` is how you seed that list: pass every `jti` you already
   know was minted during the compromise window. **This is currently
   manual** — the operator must supply known-suspect JTIs by hand; there
   is no automatic audit-log-derived backfill yet (see the companion ADR
   amendment tracking this gap).
4. The downstream middleware (below) checks this list on every token
   verification and fails closed if the endpoint is unreachable.
5. A distinct CADF event (`OAUTH2_EMERGENCY_KEY_ROTATION`) is recorded
   with `domain_id`, revoked `kid`, new `kid`, operator identity, and the
   full `revoked_jtis` list.

Normal rotation cadence resumes afterward; the `signing_key_rotation_days`
timer resets.

**Current limitation:** both the stage and confirm steps go through the
normal Raft-backed HTTP path (admin UDS + SPIFFE mTLS to
`/v4/oauth2/{domain_id}/rotate-signing-key`), which requires Raft quorum
to commit. If the cluster has lost quorum at the same moment a key is
compromised, there is currently no quorum-bypass fallback — see the
companion ADR amendment for this gap.

## Downstream control-plane enforcement (Nova/Neutron/etc.)

A thin Python WSGI middleware (`KeystoneNativeJwtMiddleware`) drops into
existing Paste Deploy pipelines (e.g. `/etc/nova/api-paste.ini`) **in
front of** `keystonemiddleware.auth_token`. Requests without an OP-issued
Bearer JWT fall through unchanged to the legacy Fernet filter chain, so
rollout is incremental per service/region with instant rollback (just
remove the filter).

Required config per service:

```ini
keystone_jwks_url = https://keystone.example.com/v4/oauth2/<domain_id>/jwks
keystone_jwt_jti_revocation_url = https://keystone.example.com/v4/oauth2/<domain_id>/jwks/revocation
keystone_domain_id = <domain_id>
keystone_expected_issuers = https://keystone.example.com/v4/oauth2/<domain_id>
signing_algorithm = ES256
```

Operational notes:

- **Fail-closed.** Both the JWKS fetch and the JTI-revocation fetch reject
  the request on failure rather than serving stale data — a Keystone or
  network outage now also blocks OpenStack API calls, not just token
  issuance. This is deliberate: fail-open would let an attacker who can
  interfere with the middleware's connectivity keep an already-revoked
  compromised key validating for the outage's duration.
  Both endpoints must be treated as load-bearing for the whole control
  plane.
  - JWKS cache TTL: 300s (matches `Cache-Control: max-age=300` on
    `/jwks`).
  - Revocation list cache TTL: 60s.
- `aud` is domain-bound (`openstack-apis:{domain_id}`), never a flat
  cluster-wide value — a compromised domain key only forges tokens
  accepted within that domain's own blast radius.
- Set `keystone_expected_issuers` explicitly; claim presence of `iss`
  alone is not enough, the value is checked against this allowlist.

## Migration from Fernet

Everything here is additive — Fernet issuance/validation continues
unchanged. See ADR 0026 §13 for the staged migration path (Fernet
interchangeability → JWS format parity → OP goes live → machine identity
migration → human flow migration → Fernet sunset). Key operational
gate: a service may only prefer JWTs over falling through to Fernet once
its operator has explicitly accepted the 15-minute stateless revocation
window (or wired back-channel introspection for high-criticality
operations) — record that acceptance in your deployment's migration
runbook.

## Known gaps

Two items from ADR 0026 §3 remain intentionally unbuilt; see the follow-up
ADR amendments for the design work required to close them:

- **UDS/loopback quorum-bypass emergency rotation** — today's emergency
  rotation still requires Raft quorum. There is no local-only fallback for
  the case where quorum is lost at the same time a key is compromised.
- **Audit-log-derived JTI backfill** — `--revoke-jti` is manual only.
  Auto-populating the revocation list from a time window against the
  audit trail needs a queryable audit-log store that does not exist yet.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `/jwks` or `/.well-known/openid-configuration` returns 404 | Domain has no signing key — run `keystone-manage oauth2 ensure-signing-key --domain <id>` |
| `429` on `/token` | Rate limit hit — see `token_rate_limit_*` config |
| `confirm-rotate-signing-key` fails with "rotation not found/expired" | The 15-minute confirmation window elapsed and the rotation auto-aborted; re-run `rotate-signing-key --emergency` |
| Downstream service rejects all OP tokens after Keystone/network blip | Expected fail-closed behavior — check JWKS/revocation endpoint reachability from the service |
