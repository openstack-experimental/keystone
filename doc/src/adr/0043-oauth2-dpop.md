# 43. OAuth2 sender-constrained tokens with DPoP

**Date:** 2026-10-16

## Status

Proposed.

## Reference

Extends ADR 0026 (OAuth2/OIDC provider, "Token Replay Model" and the "DPoP
Deferred to v1.5" consequence). Related: ADR 0036 (service delegation, SPIFFE
binding for workloads), vision §4.3 (sender constraint gate) and open question
4 (DPoP versus mTLS-bound tokens for public clients). Standard: RFC 9449.

## Context

ADR 0026 issues pure bearer access tokens and refresh tokens. A stolen token
is usable until `exp`, and a stolen refresh token until its family is
revoked. The vision lists sender constraint as a gate for scope-less tokens.

Two constraint mechanisms exist:

- **Workloads with a SPIFFE SVID** are bound to the SPIFFE ID at the internal
  interface (ADR 0036). RFC 8705 thumbprint binding is not usable there
  because SVIDs rotate.
- **End users and public clients** (CLI, browser applications, desktop tools)
  have no certificate. Issuing one would need a CA, which the per-domain OAuth2
  signing keys are not (they are published in JWKS, rotated on a token
  lifetime and used for JWS only). DPoP needs no certificate: the client holds
  its own keypair and proves possession on each request.

This ADR specifies DPoP for the second group. It does not change workload
binding.

## Decision

### 1. Enforcement levels and discovery

Enforcement is configurable at three levels, each `disabled | optional |
required`:

- **Global:** `[oauth2] dpop` (default `disabled`).
- **Domain:** a per-domain setting, stored in Raft as
  `data:oauth2:domain_settings:<domain_id>` and managed through
  `GET/PUT /v4/oauth2/{domain_id}/settings`. No per-domain OAuth2 settings
  record exists today, so this record is new (trailing, defaulted, no
  migration). An unset domain value inherits the global one.
- **Client:** `OAuth2Client.dpop_bound_access_tokens: bool` (default `false`)
  is the narrowest level; `true` means `required` for that client.

The effective mode is the **strictest** of the three
(`disabled < optional < required`). The global value is therefore a floor: a
domain can raise `optional` to `required`, never weaken a global `required`.
A global `optional` with selected domains `required` is the intended
combination. The domain is the token's issuer (`iss` is
`/v4/oauth2/{domain_id}`), so the decision at `/token` is a lookup on the
client's domain.

- `required`: `/token` rejects requests without a valid proof
  (`invalid_dpop_proof`).
- `optional`: a token is bound whenever the client sends a proof.

Authorization for the domain setting:

- Raising the mode is allowed to a domain `manager` (self-service).
- Lowering it, or setting it below the global value, requires `admin`, so a
  compromised domain manager cannot disable DPoP. Because the global floor
  always applies, the stored value only ever matters when it is stricter.
- Every change emits a CADF event with the old and new mode.

Discovery advertises `dpop_signing_alg_values_supported` (`ES256`, `RS256`;
`none` and symmetric algorithms are never accepted) and, per issuer, a
`dpop_required` boolean for the effective domain mode. Public clients are
expected to use ES256.

Switching a domain to `required` does not end existing refresh families: the
next refresh without a proof is rejected and the client re-authenticates with
a bound key.

### 2. Proof validation (shared verifier)

A single proof verifier is used by Keystone and by the Python middleware. A
proof is a JWT in the `DPoP` header with:

- header `typ = dpop+jwt`, an allowed `alg`, and the public key as `jwk`.
  The `jwk` must be a public key only (any private member, and `x5c`/`x5u`,
  are rejected), its `kty`/`crv` must match `alg` (P-256 for `ES256`), and an
  RSA key must be at least 2048 bits;
- claims `jti`, `htm`, `htu`, `iat`, plus `ath` on resource requests and
  `nonce` when the server required one.

Checks, all fail-closed: signature against the embedded `jwk`; `htm` equals the
request method; `htu` equals the request URI without query and fragment,
compared after normalisation; `iat` within `[oauth2] dpop_proof_lifetime_seconds`
(default 60) of server time, in both directions; `jti` unseen within that
window; exactly one `DPoP` header. `htu` is compared against the external
URL of the endpoint, built from `[DEFAULT] public_endpoint` (the same value
used for `iss` and discovery) for Keystone endpoints, and from the service's
configured external base URL at resource servers; the internal listener
address is never used, so TLS-terminating proxies and load balancers do not
break matching. For `ath`, the value is the base64url
SHA-256 of the access token.

Replay protection is a bounded in-memory `jti` cache keyed by
`(jkt, jti)` and expiring with the proof window. It is per node and best
effort at resource servers, which is acceptable because a proof is already
bound to a method and URL. The cache is bounded per `jkt` and globally; when
full, new proofs from a key that exceeds its share are rejected
(`invalid_dpop_proof`) instead of evicting other keys' entries, so a flood of
fresh keys cannot push out entries and enable replay.

Keystone issues server nonces (`DPoP-Nonce` response header,
`use_dpop_nonce` error). A nonce is **mandatory on every `/token` request
that carries a proof** (a proof without a valid nonce is answered with
`use_dpop_nonce`). The nonce is an HMAC of a time slot under a key derived from
the cluster salt, identical on every node, so any node accepts nonces issued
by another. Slots last `[oauth2] dpop_nonce_lifetime_seconds` (default 300);
the current and the previous slot are accepted, so a nonce stays valid for up
to two slots. Resource servers do not use nonces in this version.

Proof verification costs a signature check before the client is
authenticated, so it runs behind the pre-hash rate limit of ADR 0022: the
limit is applied to the source and to the unverified `jkt` before the
signature is checked, and invalid proofs count against it.

### 3. Token endpoint

1. The client sends the proof with the grant (authorization code, device code,
   refresh token).
2. On success the access token response has `token_type = DPoP` and the access
   token carries `cnf = {"jkt": <RFC 7638 SHA-256 thumbprint of the proof key>}`.
   The token is signed with the domain signing key exactly as today; no
   signing key, `kid`, JWKS or rotation behaviour changes.
3. A refresh token issued to a DPoP-bound client records the `jkt` in its
   family. Every refresh request must carry a proof from that same key.
   A valid proof from a **different** key is a suspected theft: the request is
   rejected with `invalid_grant` and the family is revoked (same path as reuse
   detection, ADR 0026 §9). A missing, malformed, expired, replayed or
   nonce-less proof is only a bad request (`invalid_dpop_proof` or
   `use_dpop_nonce`) and never revokes the family, so clock skew or a lost
   nonce cannot be used to end a session.
4. The `jkt` is also stored with the authorization code (`dpop_jkt`
   authorization request parameter is accepted and must match the proof at
   `/token`), binding the code to the key before the redirect.
5. `client_credentials` is bound the same way for clients that send a proof
   (or are `required`); SVID-holding workloads keep the SPIFFE mechanism of
   ADR 0036 and do not use DPoP.
6. `OpenStackAccessTokenClaims` and `OidcAccessTokenClaims` gain
   `cnf: Option<Confirmation>`. `cnf` is added to the reserved claim set for
   `claims_template`. `id_token`s are not bound.

### 4. Resource side

- A bound token is accepted only as `Authorization: DPoP <token>` with a
  `DPoP` proof header. A bound token presented as `Bearer`, or a proof without
  a bound token, is rejected.
- After the existing signature, `aud`, `token_use` and revocation checks, the
  verifier validates the proof (section 2, with `ath`) and requires the proof
  key thumbprint to equal `cnf.jkt`.
- `/userinfo` and the other Keystone endpoints that take an access token apply
  the same rule. Unbound tokens keep working while `dpop = optional`.
- A verifier reads `dpop_required` from the issuer's discovery document
  (cached like JWKS) and, when `true`, rejects unbound access tokens from that
  issuer. Without this an unbound token issued before the switch would still
  be accepted as `Bearer` until its `exp` (at most one token lifetime).
- `/revoke` of a bound token needs no proof, as the client is authenticated
  by other means.
- **Token exchange (RFC 8693, ADR 0036).** A `subject_token` that carries
  `cnf.jkt` is accepted at `/token` only together with a proof from that key
  (`ath` = hash of the subject token), as for any other use of the token.
  Without it the exchange fails, so a stolen bound token cannot be traded for
  an unbound one. The exchanged token is bound to the same `jkt` when the
  requesting client uses DPoP, and is otherwise issued unbound only if the
  effective mode (section 1) is not `required`.
- The `dpop_required` lookup fails closed: if the discovery document cannot be
  fetched and the cached copy is older than its TTL (60 s, shorter than the
  discovery `Cache-Control`), the request is rejected, so interfering with the
  fetch cannot downgrade enforcement.

### 5. Client protocol

What a conforming client sends, step by step. `P(...)` below is a fresh proof
(section 2) signed with the client key; a proof is never reused, so every HTTP
request gets its own `jti` and `iat`.

**Authorization request (`/authorize`, browser redirect).** The browser leg
cannot carry a `DPoP` header, so the key is announced as a parameter:

```
GET /v4/oauth2/{domain}/authorize?response_type=code&client_id=...
    &redirect_uri=...&code_challenge=...&code_challenge_method=S256
    &state=...&dpop_jkt=<base64url SHA-256 JWK thumbprint of the client key>
```

`dpop_jkt` is optional in `optional` mode and recommended always; Keystone
stores it with the authorization code. In `required` mode a missing `dpop_jkt`
is accepted (the key is then taken from the token request, PKCE still binds the
code), but a present one must match. Authorization-request pushing (PAR) is not
supported.

**Token request (`/token`).** Every grant carries the proof in the `DPoP`
header, with `htm = POST` and `htu` the token endpoint URL:

```
POST /v4/oauth2/{domain}/token
DPoP: P(htm=POST, htu=https://ks.example/v4/oauth2/{domain}/token, nonce=?)
grant_type=authorization_code&code=...&code_verifier=...&client_id=...
```

- If Keystone requires a nonce it answers `400` with
  `error=use_dpop_nonce` and a `DPoP-Nonce` header. The client builds a new
  proof containing that `nonce` and retries once. The client stores the latest
  `DPoP-Nonce` per issuer and sends it on later token requests; a nonce may be
  returned on success as well and replaces the stored one.
- If `dpop_jkt` was sent at `/authorize`, the proof key must match it, else
  `invalid_grant`.
- The response has `token_type: "DPoP"`. Anything else means the token is
  unbound and is used as `Bearer`.
- The same applies to `device_code`. The key is fixed when the flow starts:
  the device authorization request carries the proof (or `dpop_jkt`) and the
  device code is bound to that key. Every poll must use it, and a poll with a
  different key is `invalid_grant`. Browser approval of the user code is
  unaffected. The same applies to
  `refresh_token` (proof from the family's key; a new refresh token in the
  response stays bound to it).

**Every use of the access token (any resource request, including `/userinfo`).**

```
GET /v2.1/servers HTTP/1.1
Authorization: DPoP <access_token>
DPoP: P(htm=GET, htu=https://nova.example/v2.1/servers, ath=b64url(SHA-256(access_token)))
```

- A new proof per request, signed with the same key as at `/token`.
- `htu` is the URL the client called, without query and fragment. A service
  behind a proxy or load balancer compares against its configured external
  base URL, not the internal one, so both sides agree.
- The scheme is `DPoP`, never `Bearer`, for a bound token.
- Failures return `401` with `WWW-Authenticate: DPoP error="invalid_token"`
  (or `invalid_dpop_proof`) and `algs="ES256 RS256"`. Resource servers do not
  require nonces in this version, so the client has no nonce to track there.
- Clients must not send a proof to a host they did not request: a proof is
  per URL by construction, but a client library must not attach one to
  redirects to another origin.

### 6. Clients and key management

- Clients generate the keypair locally and never send the private key.
  Browser applications should use non-extractable WebCrypto keys; CLI tools
  (`osc`, SDK) keep the key in the OS keystore or a file with owner-only
  permissions, one key per cloud profile and device.
- Losing the key means a new login; there is no recovery, by design.
- Keystone stores only the thumbprint, never the public key.

### 7. Out of scope

- Service-to-service hops: delegation tokens obtained by services use the
  SPIFFE ID mechanism of ADR 0036, not the end user's `jkt`. Accepting a
  bound subject token at the exchange endpoint is in scope (section 4).
- Binding of Fernet tokens and of Horizon cookie sessions.
- An X.509 CA for end users and RFC 8705 for them. If ever needed it would be a
  dedicated issuer with its own keys; the OAuth2 signing keys are not reused.

## Consequences

- A leaked access or refresh token is useless without the client key, closing
  the sender-constraint gate for public clients.
- Every `/token` request and every resource request from a bound client costs
  one signature verification and a cache lookup; clients pay one signature.
- Clients must carry a key and a DPoP-aware HTTP layer. OpenStack SDKs and
  `keystonemiddleware` need changes; until then deployments run in `optional`
  mode and bind only clients that opt in.
- The `jti` cache is not shared across nodes or resource servers, so a proof
  can be replayed against a different node inside its short window. The
  method/URL binding and short lifetime bound the impact; nonces protect
  `/token` only.
- Clock skew now matters for proofs; the window is configurable and the nonce
  flow lets a client recover from a skewed `iat`.
- Discovery and client schema change additively; no SQL migration. The
  per-domain settings record and its API are new surface to document and test.
- A domain-level `required` setting makes unbound tokens from that issuer
  unacceptable at verifiers that read `dpop_required`; verifiers that do not
  still accept them until `exp`.
