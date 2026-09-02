# 32. Vendor Data JWT Attestation (SPIRE Integration Plan, Phase 2)

**Date:** 2026-09-02

## Status

Proposed

## Reference

Phase 2 of `doc/plans/spire-integration.md`. Depends on Phase 1 (SPIRE
DevStack plugin, merged) for the per-host `nova-compute` SPIFFE identity
this endpoint authenticates its caller with, and on a minimal slice of
Phase 3 (the internal SPIFFE mTLS interface, already wired to the REST
router) for the interface this endpoint lives on.

---

## 1. Context

Nova injects a keystone-rs-signed JWT into a VM's `vendor_data.json` at
boot. A (future, Phase 5) custom SPIRE node attestor plugin running inside
the VM reads that JWT and presents it to the SPIRE server, which verifies
the signature and mints a project/instance-scoped SPIFFE SVID for the VM.
This ADR covers the keystone-rs side of that hand-off: the endpoint that
signs the JWT, and the key it is signed with.

## 2. Decision

- **`POST /v4/vendordata`** (internal SPIFFE mTLS interface, port 8444)
  signs a short-lived (60-600s, default 300s) attestation JWT scoped to a
  `project_id`/`instance_id` pair, requested by Nova-compute on the
  `vendor_data_url` boot hook.
- **`GET /v4/spiffe/{domain_id}/jwks`** publishes the public half of the
  signing key, unauthenticated, for the (Phase 5) SPIRE server plugin to
  fetch and cache.
- **Attestation key isolation**: the signing key is a second, independent
  per-domain asymmetric key
  (`openstack_keystone_core::spiffe_key`), never the OAuth2 access-token
  signing key (`openstack_keystone_core::oauth2_key`, ADR 0026 §3) and
  never published on the OAuth2 JWKS endpoint. An earlier draft considered
  publishing both keys in one JWKS set, distinguished by a `use` metadata
  tag; that was rejected because it would make a JWK metadata field (per
  RFC 7517, meant to distinguish signature vs. encryption keys, not
  application purpose) the actual security boundary between "can forge API
  tokens" and "can mint VM identities" -- a validator that mishandles `use`
  would silently accept the wrong key. Endpoint separation removes that
  failure mode: the SPIRE server plugin only ever fetches
  `/v4/spiffe/{domain}/jwks` and can never be tricked into trusting the
  OAuth2 key.
- **Ownership verification (Fix 1)**: before signing, and only when
  `[vendordata] verify_placement` is `true` (the default), the handler
  cross-checks the caller's claimed `project_id`/`instance_id` against
  Nova's own record for that instance, using keystone-rs's own
  admin-scoped Nova credentials. A mismatch is `403`; a Nova-side error or
  timeout is `503` (fail closed -- never a signed JWT on an unverifiable
  claim). Without this check, any compute host's SPIFFE SVID could request
  a signed attestation for an instance it does not run, since the SVID
  alone doesn't bind the caller to a specific host/instance pairing.

## 3. Key design decisions

- `aud` is fixed to `spiffe-attestation`, preventing reuse of an
  attestation JWT for any other purpose.
- `jti` is a freshly generated random identifier per issued JWT, never
  `instance_id` -- a legitimate re-attestation (VM rebuild) must produce a
  different `jti` from the original boot so the (Phase 5) SPIRE server
  plugin's anti-replay cache can tell fresh re-attestation apart from true
  replay.
- `ttl_seconds` is capped at `[oauth2] access_token_lifetime_minutes` as a
  safety bound, regardless of what the request asks for.
- The endpoint lives on the internal SPIFFE mTLS interface because
  Nova-compute authenticates with its per-host SPIFFE SVID
  (`spiffe://{trust_domain}/service/nova-compute/host/{hostname}`, Phase
  1) -- there is no other credential Nova-compute could plausibly present.

## 4. Known gaps and deviations from the plan doc (Phase 2 scope)

This phase intentionally trades some fidelity to the plan doc's original
design for a smaller, self-contained first implementation. Each item below
is a deliberate, flagged simplification -- not an oversight -- and a
natural next increment:

- **Attestation key storage is filesystem-backed, not Raft-backed.**
  `[oauth2]`'s signing key (ADR 0026 §3) is Raft + FjallDB replicated for
  HA; the attestation key reuses the same generic
  `AsymmetricKeyRepository`/`KeyMaterial` shape from `key-repository`, but
  through `FilesystemAsymmetricKeySource` (the same source the Phase 0 JWS
  token provider already uses in single-node deployments) rather than a
  new Raft-backed backend. A single-node keystone-rs deployment works
  unchanged; multi-node HA needs the same Raft generalization `[oauth2]`
  already has, tracked as follow-up work, not part of this ADR.
- **No emergency rotation or JTI revocation for the attestation key.**
  `[oauth2]`'s signing key has a two-phase emergency rotation and JTI
  revocation list (ADR 0026 §3, §11); the attestation key's provider trait
  (`SpiffeKeyApi`) is deliberately smaller -- `ensure_domain_keys`, `jwks`,
  `active_signing_key` only. Attestation JWTs are already short-lived
  (max 600s) and carry no long-lived session state to revoke, so the
  operational need is smaller than for OAuth2 access tokens; if it grows,
  the same rotation machinery `[oauth2]` uses can be generalized to a
  second purpose.
- **Nova ownership verification mints its own token per call** (resolved:
  originally a static, operator-provisioned admin token). `[vendordata]
  nova_auth_scope` (project or system) and `nova_auth_roles` (role names)
  configure the scope and effective roles of a token keystone-rs mints for
  itself on every ownership check, using the same "virtual identity with
  pre-populated roles" mechanism the SPIFFE/mapping engine (ADR 0020) uses
  for externally authenticated identities -- keystone-rs still has no real
  user account or role assignment for this identity, so the configured
  role names are set directly as the token's effective roles rather than
  resolved from an assignment lookup (each name must resolve to an
  existing role, or the check fails closed with `503`). This removes the
  long-lived static credential; nothing left to rotate manually.
- **The compute host is derived directly from the raw `SpiffeId` request
  extension**, not through Phase 3's generic SPIFFE claim-flattening
  (`spiffe.host` in `crates/core/src/api/auth.rs`) and the ADR 0020
  mapping engine. This endpoint parses
  `spiffe://{trust_domain}/service/nova-compute/host/{hostname}` itself,
  with the same strict path-segment validation the plan doc specifies
  (reject trailing slashes, extra segments, and any URI that doesn't match
  exactly) -- but that claim is not yet available to OPA policy or any
  other handler. Generalizing it into the mapping engine's claim
  flattening remains Phase 3 proper.

## 5. Security Considerations

See `doc/plans/spire-integration.md`'s "Security Considerations" table for
the full threat model this phase participates in
("Compute-host impersonation / unauthorized attestation minting",
"Attestation/OAuth2 key blast-radius coupling"). The devstack join-token
registration path from Phase 1 does not itself prove per-host identity the
way `x509pop` would in production -- this endpoint's ownership check
narrows, but does not eliminate, that gap in a devstack deployment.

## 6. Consequences

### Positive

- A key compromise no longer grants both API-token forgery and VM identity
  minting (separate keys, separate endpoints).
- A compromised or malicious compute host cannot mint attestations for
  instances it does not run, when `verify_placement` is enabled.
- Reuses the existing generic asymmetric key-repository machinery rather
  than inventing a new key storage format.

### Negative / Risks

- The filesystem-backed attestation key does not survive a single-node
  failure the way the Raft-backed OAuth2 key does; multi-node HA for this
  key is not yet implemented (see §4).
- `nova_auth_roles` is configured with broad (cross-project) read access
  via `os-extended-server-attributes` in mind; misconfiguring it with an
  over-broad role name grants every self-minted Nova-calling token that
  same access, so treat the role list with the same operational care as a
  policy file, not as an inert config value.
