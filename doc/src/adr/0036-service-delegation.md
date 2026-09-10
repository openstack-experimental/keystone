# 36. Service Delegation: SVID-Bound Grants and On-Behalf-Of Exchange

**Date:** 2026-09-10

## Status

Proposed.

Supersedes the trust mechanism (`/v3/OS-TRUST`, `AuthenticationContext::Trust`,
`ScopeInfo::TrustProject`, `trust-driver-sql`) once the phases in §11 are
complete. Nothing changes for a deployment until it registers a delegatable
service (§3).

Related:

- [ADR 0014 — Application Credentials](0014-application-credentials.md): the
  lifecycle rules (frozen role subset, cascade on role loss) reused here.
- [ADR 0017 — Security Context](0017-security-context.md) and the
  [security model](../contributor/security-model.md): invariants I1–I5 that
  every mechanism in this ADR must satisfy.
- [ADR 0020 — Mapping Engine](0020-mapping-engine.md): how an SVID becomes a
  Keystone principal for plain service-to-service calls.
- [ADR 0026 — OAuth2/OIDC Provider](0026-oauth2-oidc-provider.md): the token
  endpoint, `DelegationContext`, the RFC 8693 grant (§12) and the reserved
  `tls_client_auth` / `private_key_jwt` client authentication methods.
- [SPIRE integration plan](../../plans/spire-integration.md): the internal
  SPIFFE mTLS interface and per-service / per-VM SVIDs.
- Issue #1018 (token exchange for external IdP JWTs via the mapping engine): the
  other extension of the same RFC 8693 grant, with the shared implementation
  surfaces listed in §6.4.

## Context

### What trusts are used for

OpenStack services use trusts in two distinct situations:

1. **Deferred authority with no user present.** Heat stores a trust at stack
   create and redeems it hours or months later for autoscaling, convergence, and
   stack delete. Magnum, Mistral, Senlin, Aodh, Sahara and Trove follow the same
   pattern. This is the only thing trusts do that nothing else in Keystone can
   do today.
2. **Continuation of a user-initiated operation past token expiry.** Glance
   image import into Swift (`swift_store_use_trusts`) uses a trust. Nova and
   Cinder solve the same problem differently, with `X-Service-Token` plus
   `allow_expired`, which `keystone-rs` already supports on
   `GET /v3/auth/tokens`.

### Why trusts must go

- **The trustee is a user with a secret.** A trust grants authority to a
  Keystone user account that authenticates with a password or an application
  credential. Magnum ships that credential into every cluster VM. The authority
  is only as safe as a long-lived bearer secret in a config file.
- **Impersonation, redelegation and `remaining_uses`** are three independent
  feature switches with their own validation rules. Most historical trust
  advisories and most of the special-casing in `validate_scope_boundaries()` and
  `calculate_effective_roles()` exist because of them (see the `OSSA-2026-005`
  and `OSSA-2026-015` notes in ADR 0017).
- **Trust tokens are a scope, not a chain.** `ScopeInfo::TrustProject` makes the
  delegation a property of the token's scope, the exact thing the security model
  says a delegation decision must never key on (I1). The Trust-on-`Project` path
  exists only to paper over that for EC2 redemption.
- **The `trust` table is Python-owned.** Every change is constrained by
  byte-compatibility with Python Keystone.
- **Users cannot see or reason about them.** Trusts are created by services on
  the user's behalf and are effectively invisible, so revocation in practice
  never happens.

### What already exists in `keystone-rs`

- An **internal SPIFFE mTLS interface** (`[interface_internal]`,
  `type = "spiffe"`) on which OpenStack services present X.509 SVIDs. The SVID
  is flattened to `spiffe.id`, `spiffe.trust_domain`, `spiffe.host`,
  `spiffe.project_id` / `spiffe.instance_id` claims
  (`crates/core/src/api/auth.rs`) and resolved through the mapping engine to an
  `IdentityInfo::Principal`, optionally `is_system`.
- An **OAuth2 provider** with a domain-bound token endpoint, a
  `client_credentials` grant, an RFC 8693 `token-exchange` grant that already
  re-expresses application-credential delegation as a JWT
  (`crates/core/src/oauth2_client/token_exchange.rs`), a `DelegationContext`
  claim enum reserved for exactly this extension, and
  `token_endpoint_auth_method` values `tls_client_auth` and `private_key_jwt`
  reserved for v2.
- **Application credentials** with the lifecycle semantics this ADR copies:
  roles frozen to a subset of the creator's roles, intersected with live
  assignments at use, deleted when the creator loses the roles.
- A **SPIRE plan** that gives every control-plane service a stable SPIFFE ID and
  every VM a project/instance SVID.

### Constraints

- **SPIFFE is not reachable from the public API.** OpenStack API users have no
  SVID and no route to the internal interface. Anything a user does (create,
  list, revoke a delegation) must work with an ordinary token on the public
  interface. Anything a service does (redeem a delegation) happens on the
  internal interface with an SVID, or, for workloads that cannot reach it, with
  a SPIRE-issued JWT-SVID presented on the public interface (§5.3).
- **Tokens will stop carrying scope.** A stated goal is to replace scope
  bindings in the token with runtime authorization resolution. This ADR
  therefore places every delegation fact in `delegation_context` (an
  authentication-chain fact) and treats the project/role projection into
  `openstack_context` as a transitional convenience that can be dropped without
  touching the design (§7).
- **Python coexistence.** Nothing here writes to Python-owned tables. New state
  lives in Raft-backed drivers like the OAuth2 resources.

## Decision

### 1. Two mechanisms, one token endpoint

| Need                                          | Mechanism                      | Grant type at `/v4/oauth2/{domain_id}/token`          | Token subject | Actor          |
| --------------------------------------------- | ------------------------------ | ----------------------------------------------------- | ------------- | -------------- |
| Deferred authority, no user token at run time | **Service grant** (§4, §5)     | `urn:openstack:params:oauth:grant-type:service-grant` | grantor user  | service client |
| Continue a user-initiated operation           | **On-behalf-of exchange** (§6) | `urn:ietf:params:oauth:grant-type:token-exchange`     | user          | service client |

Both mint an `OpenStackAccessTokenClaims` JWT (ADR 0026 §4). Both record the
service as an RFC 8693 `act` claim so audit never loses the acting party, and
both carry the delegation boundary in `delegation_context`. Neither creates a
Keystone user, a password, or a client-side secret. There is no impersonation
flag, no redelegation, and no use counter.

### 2. Vocabulary

| Term               | Meaning                                                                                                                                  |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **Grantor**        | The Keystone user whose authority is delegated. Always a real user (`IdentityInfo::User`).                                               |
| **Grantee**        | The party that may redeem the delegation: a registered service client (v1) or another user (§9, later phase).                            |
| **Service client** | An `OAuth2Client` with a `delegation` policy and a bound SPIFFE identity (§3). The operator-controlled registry of delegatable services. |
| **Actor**          | The authenticated grantee at redemption time, recorded in the `act` claim.                                                               |
| **Grant**          | The stored, user-visible, revocable delegation record (§4).                                                                              |

### 3. Delegatable service registry: `OAuth2Client` extension

The registry of services that may receive delegated authority is the existing
`OAuth2Client` resource. A client becomes delegatable when an operator sets:

```rust
pub struct OAuth2ClientResource {
    // existing fields (ADR 0026 §5) ...
    pub token_endpoint_auth_method: String,   // "tls_client_auth" or "private_key_jwt" for service clients
    pub spiffe_ids: Vec<String>,              // NEW: SVIDs accepted as this client. Exact IDs or a
                                              // per-host family such as
                                              // "spiffe://td/service/heat-engine/host/*" (last segment only)
    pub delegation: Option<DelegationPolicy>, // NEW
}

pub struct DelegationPolicy {
    pub service_grants: bool,               // may be a grantee of service grants (§4)
    pub on_behalf_of: bool,                 // may perform on-behalf-of exchange (§6)
    pub cross_domain: bool,                 // may hold grants from users of other domains; SystemAdmin-only
    pub max_role_ids: Vec<String>,          // ceiling on delegated role ids; empty = no ceiling beyond the grantor's own
    pub max_grant_lifetime: Option<Duration>,     // ceiling on grant `expires_at`; None = unbounded
    pub max_operation_lifetime: Duration,   // ceiling on on-behalf-of re-exchange chains (§6.3)
    pub max_grants_per_project: Option<u32>,// per-project grant cap for this grantee; None = no per-project cap (§4.1)
    pub display_name: String,               // what users see in GET /v4/delegatable-services
}
```

`max_role_ids` holds role **ids**, not names. Role names are not unique once
domain-specific roles exist (ADR 0034), so a name-based ceiling is ambiguous
across domains; the API accepts names on write only as a convenience and
resolves them, in the client's own domain, to ids that are what gets stored.

- Setting or changing `delegation` and `spiffe_ids` is gated by
  `policy/oauth2/client/update.rego` with the same SystemAdmin-only carve-out
  ADR 0026 uses for `pre_authorized`, and emits a high-severity CADF event.
- Control-plane services register once, in the operator's infrastructure domain,
  with `cross_domain: true`. Tenant-local automation registers in the tenant
  domain with `cross_domain: false`.
- **`GET /v4/delegatable-services`** (public interface, any authenticated user)
  lists the clients a caller may name as grantee: those in the caller's domain
  plus every `cross_domain` client. It returns `client_id`, `display_name`, and
  the `DelegationPolicy` ceilings, nothing else. Users never see or type a
  SPIFFE ID. This is an accepted disclosure: the existence and delegation
  ceilings of every `cross_domain` (i.e. control-plane) client are visible to
  every authenticated user in the cluster. That set is operator-curated, is
  already inferable from the service catalog, and a `client_id` is not a
  credential — nothing can be redeemed without an SVID that matches
  `spiffe_ids`, which is never returned here.

#### 3.1 SVID-to-client matching

Done by the token endpoint itself, never by the mapping engine: the redeemed
token's subject is the grantor, not the service, so there is no principal to
map. The match is normative, not "prefix-ish":

1. The presented SVID is parsed and normalized as a SPIFFE ID (scheme, trust
   domain, path); a value that does not parse is rejected before any comparison.
2. Comparison is on the **split path segments**, never on the raw string. A
   pattern matches only when it has the same segment count and every segment is
   equal, with the single exception below.
3. `*` is allowed **only as the entire final segment** of a pattern, matches
   exactly one non-empty segment, and never matches across a `/`. A bare `*`
   pattern, a `*` inside the trust domain, a `*` in any non-final segment, and a
   substring wildcard (`heat-*`) are all rejected at client-update time, not at
   match time.
4. Trust domains are compared for exact equality. A pattern whose trust domain
   is not the deployment's own is rejected on write.

So `spiffe://td/service/heat-engine/host/*` matches
`spiffe://td/service/heat-engine/host/compute-3` and does **not** match
`spiffe://td/service/heat-engine/host/a/b` or
`spiffe://other-td/service/heat-engine/host/x`.

#### 3.2 Cross-domain client resolution

`OAuth2Client` is a domain-bound resource (ADR 0026 §5), but a service grant is
redeemed at the **grantor's** domain token endpoint (§5.1), and a control-plane
client lives in the operator's infrastructure domain. Therefore:

- `client_id` is unique **cluster-wide**, not per domain. The Raft-backed
  `oauth2-client-driver-raft` keying already gives a global id space; this ADR
  makes that a guarantee rather than an accident, enforced at client create.
- `ServiceGrant.grantee` stores `Client { client_id, client_domain_id }`. The
  token endpoint resolves the client by that pair, so redemption never scans
  domains.
- Resolving a client from a domain other than `{domain_id}` in the request path
  is permitted **only** when `client.delegation.cross_domain == true`. Every
  other client authentication path at `/v4/oauth2/{domain_id}/token` keeps
  today's same-domain-only rule.
- The minted token is still signed by the **grantor's** domain key and carries
  `aud = openstack-apis:{grantor domain_id}` (ADR 0026 §5 domain key isolation).
  The grantee's own domain never appears in the token; it is a registry fact
  only.

### 4. Service grant resource

#### 4.1 Model

```rust
pub struct ServiceGrant {
    pub id: String,
    pub domain_id: String,             // grantor's domain; the token endpoint the grant is redeemed at
    pub grantor_user_id: String,
    pub grantee: Grantee,              // v1: Client { client_id, client_domain_id } (§3.2); later: User { user_id } (§9)
    pub target: GrantTarget,           // v1: Project { project_id }; the I2 delegation boundary
    pub role_ids: Vec<String>,         // subset of grantor's effective roles on target at creation
    pub expires_at: Option<DateTime<Utc>>,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_redeemed_at: Option<DateTime<Utc>>,
    pub disabled_reason: Option<DisabledReason>, // RoleLost | GrantorDisabled | GranteeRemoved | Revoked | Expired
}
```

Rules applied at creation:

- The caller is the grantor. A grant can only delegate the caller's own
  authority; `grantor_user_id` is never client-supplied.
- `role_ids` must be a non-empty subset of the caller's **effective** roles on
  `target` at creation — effective meaning direct, group-derived and inherited
  assignments alike, exactly what `calculate_effective_roles()` already returns
  for the caller's own scope — further capped by
  `DelegationPolicy.max_role_ids`. Omitting `roles` freezes the caller's current
  effective roles, as application credentials do.
- `expires_at` is capped by `max_grant_lifetime`.
- The caller's authentication chain must not itself be delegated: a request
  authenticated via a trust, a restricted application credential, a service
  grant, or an on-behalf-of token is rejected (`403`). An `unrestricted`
  application credential may create grants, matching the existing trust rule.
  This is what keeps chain depth at exactly one.
- One project per grant. A service that needs several projects holds several
  grants. Domain-scoped targets are a possible later extension; system scope is
  never delegatable.
- Grant count limits, configurable. Trusts have no such cap today and services
  hold **one grant per managed object** (§10.2: one per Heat stack), so a flat
  low cap would break the pilot at the 51st stack in a project. Therefore:
  - Grants whose grantee is a registered service client are counted per
    `(project, grantee client)` and bounded by that client's
    `max_grants_per_project`, which defaults to `None` (uncapped). An operator
    who registers a delegatable service is already deciding to trust it at
    project scale; a per-service knob is where that decision belongs.
  - Grants whose grantee is a **user** (§9) are capped per grantor, default 50,
    which is the case where an unbounded count is an abuse channel rather than a
    workload property.
  - A cluster-wide `[delegation] max_grants_per_project` backstop exists for
    storage protection, default 10000, and is a 429/`quota_exceeded`, not a
    security control.

#### 4.2 API

Public interface, ordinary user token:

| Method   | Path                                                         | Policy                                                                            |
| -------- | ------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| `POST`   | `/v4/service-grants`                                         | `policy/service_grant/create.rego` (owner only)                                   |
| `GET`    | `/v4/service-grants?user_id=&project_id=&grantee_client_id=` | `policy/service_grant/list.rego` (I8/I8a: `user_id` filter required unless admin) |
| `GET`    | `/v4/service-grants/{id}`                                    | `policy/service_grant/show.rego`                                                  |
| `DELETE` | `/v4/service-grants/{id}`                                    | `policy/service_grant/delete.rego`                                                |

Who may act:

- The grantor: create, list own, show own, delete own.
- Project admins and domain admins: list and delete grants targeting their
  project / domain. They cannot create grants on behalf of other users.
- The grantee service: show and delete grants where it is the grantee, so Heat
  can clean up at stack delete. It cannot list arbitrarily. The caller is
  identified by the **same `spiffe_ids` match as §3.1**, not through the mapping
  engine: a mapped principal is an identity in its own right with no link back
  to a `client_id`, and the policy has to compare against
  `grant.grantee.client_id`. The handler therefore resolves the presented SVID
  to a client exactly as the token endpoint does, and passes
  `credentials.actor.client_id` to OPA (§8). A service that has both a mapped
  principal identity and a delegatable client registration keeps them separate;
  only the client registration authorizes grant show/delete.

Grants are immutable except for `enabled` / `disabled_reason`, which only the
lifecycle hooks (§8) set. Rotation is create-new, switch, delete-old.

#### 4.3 Storage

New crate `service-grant-driver-raft`, keyed
`data:service_grant:<domain_id>:<id>` with secondary indexes by
`grantor_user_id`, `grantee_client_id`, and `target.project_id`. Backend trait
in `crates/core/src/backend.rs` following the CRUD naming convention
(`create_service_grant`, `get_service_grant`, `list_service_grants`,
`update_service_grant` for lifecycle flags only, `delete_service_grant`).

### 5. Redeeming a service grant

#### 5.1 Request

`POST /v4/oauth2/{domain_id}/token` where `domain_id` is the **grant's** domain
(the grantor's), authenticated as the service client:

```
grant_type=urn:openstack:params:oauth:grant-type:service-grant
grant_id=<id>
scope=<optional space-separated role names to narrow further>
audience=<optional; narrows aud, see §7>
```

Client authentication is one of:

- **`tls_client_auth`** on the internal interface: the SVID presented at the TLS
  layer must match one of the client's `spiffe_ids`. This is the normal
  control-plane path.
- **`private_key_jwt`** on the public interface: a SPIRE **JWT-SVID** as the
  `client_assertion` (RFC 7523). This is the path for grantees that cannot reach
  the internal interface, for example automation inside a tenant VM that holds a
  project/instance SVID from the SPIRE plan. No client secret exists in either
  case.

  RFC 7523 §3 requires `iss == sub == client_id` for client authentication. A
  SPIRE JWT-SVID carries the workload's SPIFFE ID in `sub` and the SPIRE server
  in `iss`, so this is a **deliberate deviation**, spelled out because a
  spec-literal implementation would reject every SVID:

  - `sub` MUST be a SPIFFE ID matching `spiffe_ids` per §3.1. That match, not
    `client_id`, identifies the client; a `client_id` form parameter, if sent,
    must agree with the result or the request is rejected.
  - The signature MUST verify against the trust domain's JWKS bundle for the
    trust domain named in `sub`, fetched from the SPIRE bundle endpoint and
    cached, never against Keystone's own domain keys.
  - `aud` MUST contain the exact token endpoint URL
    (`https://<host>/v4/oauth2/{domain_id}/token`). An assertion minted for any
    other audience is rejected, so a JWT-SVID obtained by some other Keystone-
    adjacent service cannot be replayed here.
  - `exp - iat` MUST be <= 300s and clock skew tolerance is 60s.
  - The assertion `jti` MUST be recorded in a replay cache for the remainder of
    its `exp` window, and a repeat is rejected (`invalid_client`). Without this
    a captured assertion is a reusable bearer credential for its whole TTL,
    which would undercut the "no delegated secret exists anywhere" property this
    ADR is built on. The cache is the per-domain Raft-backed store, so a replay
    cannot be laundered through a different API node.

The endpoint checks, in order:

1. Rate limiting, pre-hash, as for every other `/token` grant (ADR 0026 §7.A).
2. Client authentication (including the replay/audience checks above) and
   `DelegationPolicy.service_grants == true`.
3. `grant.domain_id == {domain_id}` from the request path — a grant is only ever
   redeemable at its own domain's token endpoint.
4. Grant exists, `enabled`, not expired, `grantee` is this client, and either
   `grant.grantee.client_domain_id == grant.domain_id` or
   `client.delegation.cross_domain` (§3.2).
5. Grantor is enabled and the grantor's domain is enabled.
6. Effective roles =
   `grant.role_ids ∩ grantor's live effective roles on target ∩ scope narrowing`.
   Empty → `403` and the grant is marked `RoleLost`. **This live intersection,
   re-run on every single redemption, is the primary role-loss control**; the
   lifecycle hooks in §8 are an optimisation that usually gets there first, not
   the thing the security property rests on.

Redemption load: with no refresh token and a 15-minute access token, each active
grant re-redeems roughly four times an hour, and a Heat-sized deployment holds
one grant per stack. Service clients are therefore given their own `/token`
rate-limit bucket, sized by the operator from the expected grant count rather
than sharing the per-client default meant for interactive clients; the §7.A
pre-hash limiter still applies first so an unauthenticated flood is dropped
before any grant lookup. Deployments that find this traffic material should
raise the access-token lifetime for service clients, which trades revocation
latency (§8) for request volume, in that direction only.

#### 5.2 Response and claims

A standard token response with `access_token` and `expires_in`. **No refresh
token.** The service re-redeems the grant when the access token nears expiry;
the grant record is the durable state, and every redemption re-runs the checks
above. This is what makes revocation effective (§8).

```json
{
  "iss": "https://keystone/v4/oauth2/{domain_id}",
  "sub": "<grantor user id>",
  "aud": "openstack-apis:{domain_id}",
  "client_id": "<service client id>",
  "act": {
    "client_id": "<service client id>",
    "sub_type": "spiffe",
    "sub": "spiffe://td/service/heat-engine"
  },
  "amr": ["service_grant"],
  "token_use": "access",
  "delegation_context": {
    "auth_method": "service_grant",
    "grant_id": "<id>",
    "delegated_project_id": "<target project>"
  },
  "openstack_context": { "...": "transitional projection, see §7" },
  "exp": 0,
  "iat": 0,
  "nbf": 0,
  "jti": "..."
}
```

`sub` is the grantor because downstream services key resource ownership on
`user_id`, which is why trusts were almost always created with
`impersonation=true`. Unlike trusts, the acting service is **always** present in
`act`; there is no way to mint a token that hides it.

`act.sub_type` is mandatory and disambiguates the namespace `act.sub` is drawn
from: `"spiffe"` for a service client (above), `"user_id"` for a human grantee
(§9). Consumers must branch on it rather than pattern-matching the value, so
adding a third grantee kind later is not a silent reinterpretation of an
existing claim.

`amr` is `["service_grant"]` and deliberately does **not** carry the grantor's
original authentication methods: no user authenticates at redemption time, and
the grantor's last login may be months in the past. Policies that key on `amr`
for MFA or PCI-DSS purposes (ADR 0010–0012) therefore never match a delegated
call. That is intended — an MFA assertion about an absent user would be a
fiction — and a deployment that wants to keep MFA-gated operations away from
delegated callers expresses that as `amr == ["service_grant"]` being denied by
the relevant rule, not as a stronger `amr` on the token.

#### 5.3 Why the token endpoint and not a new v3 auth method

Trusts were a v3 auth method with a dedicated scope. Putting delegation on the
OAuth2 token endpoint gives the RFC 8693 `act` semantics, the domain-bound
`aud`, the client registry, rate limiting, and `DelegationContext` for free, and
keeps every delegation fact in the chain (I1). It also means services need one
client library shape for both mechanisms in this ADR.

### 6. On-behalf-of exchange

#### 6.1 Request

`POST /v4/oauth2/{domain_id}/token`, authenticated as a service client with
`DelegationPolicy.on_behalf_of == true`:

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<the user's token as received by the service>
subject_token_type=urn:ietf:params:oauth:token-type:access_token   (JWT)
                 | urn:openstack:params:oauth:token-type:keystone   (Fernet / JWS v3 token)
audience=<optional>
```

The actor is the mTLS-authenticated client; no `actor_token` parameter is
accepted. This extends the existing `token-exchange` grant, which today only
accepts an application-credential subject and rejects everything else.

#### 6.2 Checks and claims

1. `subject_token` is validated through `TokenApi::validate_to_context` like any
   bearer token (expiry, revocation, user enabled). When the subject is itself
   an on-behalf-of token, its `delegation_context.root_jti` is checked against
   the revocation store as well (§6.3).
2. The subject's chain must be plain, application-credential, or an on-behalf-of
   token previously minted **for the same actor** (§6.3). A trust,
   service-grant, or on-behalf-of-for-another-actor subject is rejected: no
   re-delegation.
3. `sub` = the subject's user id; `act` = this client, with `sub_type: "spiffe"`
   as in §5.2; `amr` = the **set union** of the subject's `amr` and
   `on_behalf_of` — a union, not an append, so a chain re-exchanged twenty times
   does not accumulate twenty `on_behalf_of` entries.
4. `delegation_context`:

   ```json
   {
     "auth_method": "on_behalf_of",
     "actor_client_id": "<client id>",
     "auth_time": 1757500000,
     "root_jti": "<jti of the user token that started the chain>",
     "delegated_project_id": "<inherited from the subject's own delegation, if any>"
   }
   ```

   `delegated_project_id` is present only when the subject's chain was itself
   delegated (an application credential). A plain subject has no delegation
   boundary; its authority is whatever the user's live assignments say at run
   time, which is the point of §7.

5. `auth_time` and `root_jti` are taken from the subject on the first hop and
   preserved unchanged on every re-exchange (§6.3).

#### 6.3 Renewal without a stored record

Long operations outlive a fifteen-minute access token. The service presents the
previously exchanged token as `subject_token`; the endpoint accepts it if the
actor is unchanged and
`now < auth_time + DelegationPolicy.max_operation_lifetime`. The `act` claim is
not nested; depth stays at one.

**The chain is bound to the root token, not just to the last hop.** On the first
exchange the endpoint records `root_jti` — the subject token's `jti`, or its
`audit_id` when the subject is a v3 Fernet/JWS token — into
`delegation_context`, and every subsequent hop copies it forward unchanged. Each
hop then re-runs, against `keystone-rs`:

1. `root_jti` is not revoked (the ordinary revocation store, `revoke-driver-sql`
   / the `/v3/auth/tokens` revocation path — the same check a plain bearer token
   gets, applied to the _root_ identifier rather than to the hop token that was
   presented).
2. The user is enabled, the domain is enabled.
3. Live role and delegation-boundary checks, as on the first hop.

Without the `root_jti` binding, re-exchange would present a _different_ token
than the one the user handed over, with a different `jti`, and an explicit
"revoke my token" would have no effect after the first hop — the chain would be
a token-lifetime-extension primitive that outlives its own revocation, which is
precisely the class of behaviour §"Why trusts must go" objects to. Revoking the
root token now ends the chain at the next hop, and, because the hop tokens carry
`root_jti` as a claim, a deployment on the back-channel validation path rejects
already-issued hop tokens immediately as well.

No grant record exists for on-behalf-of exchange because the user's original
token, presented to the service, is the consent, and the user's ordinary
revocation controls — revocation of the root token, role removal, user disable —
all end the chain at the next hop. Offline JWT validators still honour an
already-issued hop token until its own `exp` (§8).

#### 6.4 Related work: external subject tokens (issue #1018)

Issue #1018 extends the _same_ grant type on the _same_ endpoint in the opposite
direction: an **external IdP JWT** as `subject_token`, verified against a
trusted issuer, flattened to claims and run through the mapping engine
(`evaluate_ruleset` → `authenticate_by_mapping`, with a new
`IdentitySource::TokenExchange { issuer }`) to establish a Keystone identity.
That is _ingress_ — deciding who the caller is. This ADR is _delegation_ — an
identity Keystone already established acting through a service, with the mapping
engine deliberately not involved (§3.1). The two are orthogonal in semantics and
can land in either order, but they share three implementation surfaces and must
not grow two answers to any of them:

- **One `subject_token_type` dispatch.** The parameter is accepted today but not
  branched on (`crates/keystone/src/api/v4/oauth2/token.rs`,
  `#[allow(dead_code)]`), because the shipped app-cred path is Keystone-native
  by assumption. This ADR adds `urn:openstack:params:oauth:token-type:keystone`
  (§6.1); #1018 adds `urn:ietf:params:oauth:token-type:jwt`. Whichever lands
  first builds the match; the second extends it rather than adding a parallel
  path.
- **`verify.rs` needs a validation profile, not a constant** — a shared
  prerequisite for both. Subject-token verification currently hardcodes
  `set_audience(&["openstack-apis:{domain_id}"])`. #1018 breaks on it because an
  external token's `aud` is never that value; this ADR breaks on it because §7.1
  narrowing mints `openstack-apis:{domain_id}:<service type>` and §6.3
  re-exchanges such a token as `subject_token`. One refactor to a
  per-subject-kind validation profile (expected issuers, accepted audiences,
  required claims) serves both; doing it twice guarantees divergence.
- **Confused-deputy replay gets one rule.** #1018's concern (an external token
  minted for someone else replayed at Keystone) is the same one §5.1 answers for
  JWT-SVID client assertions: pin `aud` to the exact token endpoint, bound the
  assertion lifetime, and cache the assertion `jti` against replay. §5.1's rule
  is the stricter of the two and generalises to the external-subject case.

Separately, if #1018 proceeds, ADR 0026 §1's "Circular Token Exchange Trap"
needs an amendment note: that section records
external-IdP-JWT-for-Keystone-token as eliminated by native OP issuance, which
reads as prohibiting exactly what #1018 schedules. The distinction is that #1018
mints a native JWT through a standards-compliant grant rather than trading an
external JWT for a Fernet token. Nothing in this ADR touches that boundary —
every subject here is Keystone-native.

### 7. Token content and runtime authorization

Every fact a policy needs to bound a delegated caller lives in
`delegation_context`, which is derived from the authentication chain and is
immutable across audience narrowing or re-exchange. Nothing in §4–§6 keys on the
token's scope.

`openstack_context` (project and roles, ADR 0026 §4) is still populated at mint
time as a projection of the grant for the benefit of today's
`keystonemiddleware` filters. When scope-less tokens land:

- `openstack_context` is dropped from delegated tokens exactly as from plain
  ones.
- The authorization resolver (back-channel `keystone-rs`, or the offline filter
  with a policy bundle) computes effective roles at request time as: live roles
  of `sub` on the request's target, intersected with `grant.role_ids` when
  `delegation_context.grant_id` is set, and the target must equal
  `delegated_project_id` when that field is set.
- The grant record therefore becomes runtime authorization input. `keystone-rs`
  exposes it to the resolver via `GET /v4/service-grants/{id}` on the internal
  interface, cacheable for the access-token lifetime, and any change to the
  grant bumps a version the resolver compares.

#### 7.1 `audience` narrowing

ADR 0026 §12 left audience-narrowing semantics explicitly unspecified and
needing their own design pass. This ADR does that pass, minimally:

- The request parameter is RFC 8693 `audience`, one or more values. `resource`
  (URI form) is **not** accepted in v1; it is reserved so that adding it later
  is additive.
- A valid value is an OpenStack **service type** from the catalog
  (`object-store`, `compute`, …). The endpoint validates each value against the
  catalog of `{domain_id}` and rejects unknown ones with `invalid_target` rather
  than minting a token nobody accepts.
- The resulting claim is
  `aud = ["openstack-apis:{domain_id}:<service type>", …]`, a narrowing of the
  default `openstack-apis:{domain_id}`. Requesting no `audience` keeps the
  default.
- Acceptance side: the ADR 0026 §6 middleware and the back-channel validation
  path accept a token when `aud` contains either the unnarrowed
  `openstack-apis:{domain_id}` or
  `openstack-apis:{domain_id}:<its own service type>`. A service that does not
  know its own service type accepts only the unnarrowed form, so narrowing is
  opt-in per deployment and cannot silently break an unupgraded service.
- Narrowing can only ever remove reach: an `audience` value is honoured only if
  the token would otherwise have been valid there.

The narrowed `aud` is a transport property; it never changes
`delegation_context`, and re-exchange (§6.3) may narrow further but never widen.

### 8. Keystone-side enforcement and lifecycle

New `AuthenticationContext` variants, with match arms added everywhere ADR
0017's checklist requires (`validate_scope_boundaries`, `new_for_scope`,
`calculate_effective_roles`, `fully_resolved`, `Credentials::try_from`,
`from_security_context`):

```rust
ServiceGrant { grant: ServiceGrant, actor: ActorInfo },
OnBehalfOf   {
    actor: ActorInfo,
    subject: Box<AuthenticationContext>,
    auth_time: DateTime<Utc>,
    root_jti: String,   // §6.3: the chain is revoked with the token that started it
},
```

Invariant mapping:

| Invariant        | How it holds                                                                                                                    |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| I1               | `is_delegated`, `delegated_project_id`, and the new `actor` fields on `Credentials` are read from the chain variants above.     |
| I2 / I3          | `delegated_project_id == grant.target.project_id`; the scope-drift tripwire in `policy.rs` and the rego helper apply unchanged. |
| I4               | Effective roles = grant roles ∩ grantor live roles, on every scope shape, including the interim scoped projection.              |
| I5               | `validate_scope_boundaries`: `ServiceGrant` permits only `Project == grant.target`; `OnBehalfOf` delegates to its `subject`.    |
| Token-from-token | Forbidden for both variants, as for trusts today. Renewal is re-redemption (§5) or re-exchange (§6.3).                          |

`Credentials` gains `actor: Option<ActorInfo { client_id, spiffe_id }>` so
policies can say, for example, that only `heat-engine` may call `stacks:signal`.

Lifecycle hooks (event bus, `crates/core/src/events.rs`), mirroring
application-credential cascade. **These hooks are an optimisation, not the
security control.** The control is the live intersection re-run on every
redemption (§5.1 check 6) and on every on-behalf-of hop (§6.3), which is why the
gaps below are tolerable rather than holes:

- `EventPayload::RoleAssignment` covers **direct** assignments only. Role loss
  through a **group membership** change needs its own arm on
  `EventPayload::GroupMembership`, and loss of an **inherited** domain
  assignment that projected onto the target project is only visible by
  recomputing effective roles, which the hook does not do.
- With an external assignment driver (ADR 0033 OpenFGA, ADR 0034 per-domain
  drivers), assignment changes made outside Keystone emit **no event at all**,
  so no hook fires.

In every one of those cases the grant stays `enabled` in the record while
already being unredeemable: the next redemption computes an empty role
intersection, returns `403`, and marks it `RoleLost` then. The user-visible
`enabled` flag is therefore "best known state", and `GET /v4/service-grants`
documents it as such.

| Event                                                                                        | Effect on grants                                                          |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Grantor loses a delegated role on the target (direct assignment, or group membership change) | `enabled=false`, `RoleLost`. Re-enable is not possible; create a new one. |
| Grantor disabled / deleted                                                                   | `GrantorDisabled` / hard delete                                           |
| Target project disabled / deleted                                                            | disabled / hard delete                                                    |
| Service client deleted or `delegation` removed                                               | `GranteeRemoved`                                                          |
| `expires_at` passed                                                                          | `Expired`; janitor deletes after a retention period                       |
| `DELETE /v4/service-grants/{id}`                                                             | `Revoked` and deleted; CADF event                                         |

Revocation latency: immediate for every path that hits `keystone-rs`
(redemption, re-exchange, Fernet/back-channel validation). **Offline JWT
validation is bounded by the access-token lifetime and nothing shortens it.**

Deleting a grant does **not** populate the jti revocation list of ADR 0026 §3.
That list is fed from the audit log during emergency signing-key rotation, and
ADR 0026 §5 already declines to populate it on client delete for the same
reason: nothing indexes minted `jti`s by the object that authorized them.
Building that index would mean a per-grant record of every token minted from it
— new write-heavy state on the redemption hot path, contradicting §5.2's "the
grant record is the durable state", and ADR 0026 §12's Phase 6 amendment
specifically avoided adding the audit-query capability that the alternative
needs. The 15-minute access-token lifetime is the accepted bound instead.

Deployments that need sub-lifetime revocation of already-minted delegated tokens
have two options, both pre-existing: keep the affected services on the
back-channel validation path (where a deleted grant fails immediately, since
§7's resolver reads the grant record), or trigger emergency key rotation (ADR
0026 §3) for the domain, which is a domain-wide action and priced accordingly.
This is called out again in the risks below.

CADF events: `service_grant.create`, `.redeem`, `.revoke`, `.disable`,
`on_behalf_of.exchange`; each carries `grant_id`, `grantor_user_id`,
`actor.client_id`, `actor.spiffe_id`, `delegated_project_id`.

### 9. Human-to-human delegation (later phase)

The same grant record with `grantee: User { user_id }`. The grantee redeems on
the public interface with its own bearer token as client authentication:

```
grant_type=urn:openstack:params:oauth:grant-type:service-grant
grant_id=<id>
```

The minted token has `sub` = grantor and
`act = { sub_type: "user_id", sub: <grantee user id> }` (§5.2). Enforcement is
identical to §5, including the depth-one rule: the redeeming grantee's own
authentication chain must be plain or `unrestricted` application credential,
exactly as §4.1 requires of a grantor, so a grantee's delegated token cannot
redeem another grant. This gives AWS `AssumeRole` / GCP
service-account-impersonation semantics with mandatory audit and no
impersonation-without-trace option, at almost no additional cost once §4–§8
exist. It is not required to retire trusts and is scheduled last.

### 10. How OpenStack services change

#### 10.1 Common prerequisites

- A SPIRE agent on every control-plane host with a registration entry per
  service (SPIRE plan Phase 1). Services fetch their X.509 SVID from the
  Workload API socket; `keystonemiddleware`'s SPIFFE transport (SPIRE plan Phase
  4.1) already does this for the back-channel.
- Each service registered once as an `OAuth2Client` with `spiffe_ids` and a
  `DelegationPolicy` (§3). This replaces the service user, its password, and its
  `admin` role assignment for delegation purposes; plain service-to-service
  calls keep using the mapping-engine identity.
- Two new `keystoneauth1` plugins (or one plugin with two modes):
  - `v4servicegrant`: inputs `auth_url` (internal interface), `grant_id`;
    authenticates with the SVID via `tls_client_auth`; caches the access token
    and re-redeems at `exp - margin`.
  - `v4onbehalfof`: inputs `auth_url`, the incoming user token; performs the
    exchange; re-exchanges its own output at `exp - margin` until
    `max_operation_lifetime`. Both present the result as
    `Authorization: Bearer <JWT>` to other services, which the ADR 0026 §6
    offline filter or the `auth_token` fall-through accepts.

#### 10.2 Heat (deferred authority)

1. **Stack create / adopt.** `heat-api` holds the user's token. Instead of
   `POST /v3/OS-TRUST/trusts` it calls `POST /v4/service-grants` with
   `grantee_client_id` = Heat's cluster-unique client id (§3.2; discovered once
   via `GET /v4/delegatable-services` or configured), `project_id` = the request
   context project, `roles` = `trusts_delegated_roles`, `description` = stack
   id. It stores `grant_id` on the stack where `trust_id` / `trustor_user_id`
   are stored today. `deferred_auth_method = service_grant`.
2. **Deferred operation** (autoscaling, convergence, timers, signals).
   `heat-engine` builds a session with `v4servicegrant(grant_id)`. Every request
   to Nova, Neutron, Cinder carries a token with `sub` = stack owner, `act` =
   `heat-engine`. Nothing else in the engine changes.
3. **Stack update by another user.** Create a new grant as the new user, swap
   `grant_id`, delete the old one, as Heat rotates trusts today.
4. **Stack delete.** After resources are gone, `heat-engine` deletes the grant
   with its own SVID (§4.2 grantee delete). If the grant is already disabled
   because the owner lost roles, delete still proceeds for the owner, admins, or
   the grantee.
5. **Grant disabled mid-life** (`RoleLost`). Redemption returns `403` with
   `error=grant_disabled`; Heat surfaces it as it surfaces a missing trust today
   and the stack owner creates a new grant via stack update.
6. Heat's stack-domain users for wait conditions are unchanged. They can later
   be replaced by the VM's project/instance SVID (SPIRE plan Phase 5/6)
   presented as a JWT-SVID on the public interface.

#### 10.3 Magnum

- `magnum-conductor` uses a service grant per cluster exactly like Heat (§10.2),
  created at cluster create, deleted at cluster delete.
- The trustee user, its password, and the trust that Magnum currently writes
  into cluster nodes are removed. In-cluster components (cloud-controller
  manager, CSI, autoscaler) obtain a project/instance SVID from SPIRE and
  authenticate with a JWT-SVID through the existing JWT federation flow
  (ADR 0008) or `client_credentials` with `private_key_jwt`, mapped to a
  project-scoped identity by a mapping rule on `spiffe.project_id`. No Keystone
  credential is ever stored in the cluster.

#### 10.4 Glance (continuation of a user operation)

- On `image import` / task creation, `glance-api` holds the user's token. It
  performs an on-behalf-of exchange (§6) with `audience` narrowed to the object
  store, and stores the exchanged token in the task context instead of a trust
  id. `swift_store_use_trusts` becomes `swift_store_on_behalf_of`.
- The task worker re-exchanges at `exp - margin` (§6.3) for as long as
  `max_operation_lifetime` allows; the operator sets that per the largest image
  they intend to support.
- Copy-image and web-download follow the same path. Scheduled or
  operator-initiated cross-store copies with no user present use a service grant
  instead.

#### 10.5 Nova and Cinder

Long operations (live migration, backups, volume retype) keep `X-Service-Token`
plus `allow_expired` until they opt into on-behalf-of exchange; the two coexist.
Migrating removes the need to honour expired user tokens at all, and gives the
same `act` audit trail as the rest of this ADR.

#### 10.6 Octavia, Nova-to-Neutron, and other pure service calls

No change and no delegation: these are the service acting as itself and are
already covered by the mapping-engine `is_system` identity (ADR 0020 §6 use case
1). Octavia's amphora certificates are out of scope.

#### 10.7 Mistral, Aodh, Senlin, Sahara, Trove

Same shape as Heat: a service grant created when the workflow / alarm / cluster
/ instance is created with the user's token, redeemed by the engine or conductor
when it fires, deleted when the object is deleted.

### 11. Migration and deprecation of trusts

1. **Phase 1 — registry and grants.** `OAuth2Client` extension (§3) including
   the normative SVID match (§3.1) and cluster-unique `client_id` / cross-domain
   resolution (§3.2), `ServiceGrant` resource, driver, API, policies (§4),
   redemption grant (§5), `AuthenticationContext::ServiceGrant` with the full
   ADR 0017 checklist and negative tests, lifecycle hooks and CADF events (§8),
   `v4servicegrant` plugin. Pilot: Heat.
2. **Phase 2 — on-behalf-of.** Extend `token_exchange.rs` for plain and chained
   subjects (§6), `AuthenticationContext::OnBehalfOf`, `v4onbehalfof` plugin.
   Pilot: Glance import.
3. **Phase 3 — JWT-SVID client authentication.** `private_key_jwt` with SPIRE
   JWT-SVIDs on the public interface (§5.1), including the RFC 7523 deviation,
   bundle verification, audience pinning and the assertion `jti` replay cache,
   for grantees outside the control plane. Pilot: Magnum in-cluster components.
4. **Phase 4 — trusts off by default.** New config `[trust] enabled` (default
   `true` in this phase, `false` in the next). When disabled:
   `POST /v3/OS-TRUST/trusts` returns `403`, existing trust tokens validate
   until they expire, and EC2 credentials whose blob carries `trust_id` are
   rejected at `/v3/ec2tokens`.

   **EC2 under a service grant is the OSSA-2026-005 shape and gets the full
   treatment, not just a blob field.** Storing `service_grant_id` is the smaller
   half:

   - **Mint.** An EC2 credential created while authenticated under a service
     grant records `service_grant_id` in its blob, server-managed and never
     client-settable, mutually exclusive with `trust_id` / `app_cred_id` /
     `access_token_id`, exactly as ADR 0019 §1 handles `trust_id`. A
     client-supplied `service_grant_id` is discarded on create.
   - **Redeem.** `/v3/ec2tokens` must reconstruct
     `AuthenticationContext::ServiceGrant` from `service_grant_id` rather than
     falling through to `AuthenticationContext::Ec2Credential`. This mirrors the
     `Trust` / `ApplicationCredential` passthrough already documented on the
     `Ec2Credential` variant in `crates/core-types/src/auth.rs`, and it is what
     makes `new_for_scope()`'s bounded-object validation, the I4 role bounding
     (`grant.role_ids ∩ grantor live roles`), and the I2/I3 scope-drift tripwire
     apply unchanged. Reconstructing it also re-runs the §5.1 checks, so a
     disabled or deleted grant kills the EC2 credential's authority immediately.
   - **Redemption of a credential whose grant is gone** is a `401`, not a
     fallback to the grantor's full roles. A missing grant must never widen
     authority.
   - **Tests.** Negative tests are required for: redeeming an EC2 credential
     whose grant was revoked; redeeming one whose grantor lost a delegated role
     (effective roles must be the intersection, never the grantor's live set); a
     client attempting to set `service_grant_id` at create; and I6's
     `sha256(access) == id` guard against a `service_grant_id`-bearing blob of
     the wrong type. This is the CVE-2026-33551 / OSSA-2026-005 regression set
     re-run against the new delegation kind.

5. **Phase 5 — human grantees** (§9).
6. **Phase 6 — removal.** Delete `AuthenticationContext::Trust`,
   `ScopeInfo::TrustProject`, `TrustPayload`, the Trust-on-`Project` special
   case, `trust-driver-sql`, `/v3/OS-TRUST`, and the trust arms of the
   `token-exchange` grant. Only after every deployment that shares a database
   with Python Keystone has moved trust creation off it.

## Consequences

### Positive

- **No delegated secret exists anywhere.** The grantee proves identity with an
  SVID that SPIRE rotates and that never leaves the workload. A leaked
  `grant_id` is inert.
- **Three trust feature switches and their vulnerability classes disappear**:
  impersonation, redelegation, `remaining_uses`. Chain depth is structurally
  one; the actor is structurally always recorded.
- **Users can see and revoke every standing delegation they hold**, and
  operators can see and cap which services may hold any. Today neither is
  practical.
- **The design survives scope-less tokens** because every delegation fact is a
  chain fact in `delegation_context` and the grant record is directly usable as
  runtime authorization input (§7).
- **All security-model invariants are reused, not re-derived.** The new variants
  slot into the same `new_for_scope()` pipeline, `Credentials` projection,
  tripwire, and rego helpers as application credentials.
- **Service migrations are mechanical**: replace the trust-creation call with a
  grant-creation call, replace the trust auth plugin with the grant plugin,
  store one id instead of three fields.
- No writes to Python-owned tables; Fernet and v3 continue to work alongside.

### Negative and risks

- **Bearer tokens remain bearer.** SPIRE rotates certificates, so RFC 8705
  certificate-thumbprint binding of the access token is not usable and the token
  is bound to the SPIFFE ID only through `act`. Mitigations: short TTL,
  `audience` narrowing, keeping redemption on the internal interface, and DPoP
  if ADR 0026 v1.5 lands.
- **A compromised service holds every grant it is grantee of** until the
  operator disables its `delegation` policy, which stops all redemptions at
  once. This is strictly narrower than today, where a compromised Heat holds a
  trustee password with the same reach and no single kill switch.
- **Offline JWT revocation latency** (ADR 0026 §11) applies to delegated tokens
  in full: deleting a grant does not shorten the life of tokens already minted
  from it, because nothing indexes minted `jti`s by grant (§8). The bound is the
  access-token lifetime. Deployments needing immediate revocation keep those
  services on the back-channel path, as the SPIRE plan already requires, or
  accept emergency key rotation as the only faster lever.
- **`max_operation_lifetime` is a tuning knob with security weight.** Too long
  and a leaked on-behalf-of token can be refreshed until the ceiling; too short
  and large image imports fail. It is per service client, not global. Since
  §6.3, a leaked hop token is at least killable by revoking the root token —
  before that binding it would not have been.
- **Redemption traffic replaces credential caching.** No refresh token means
  every active grant hits `/token` roughly four times an hour (§5.1). This is
  the deliberate price of making revocation effective, and it needs sizing at
  deployment time rather than discovery under load.
- **Upstream service patches** (Heat, Magnum, Glance, keystoneauth1) are
  required before trusts can be turned off; §11 phases are ordered so each
  service can migrate independently.
- **New state and a new driver crate**, plus one more `AuthenticationContext`
  pair to keep in every match arm. The ADR 0017 checklist and compile-time
  exhaustive matches make omissions a build error rather than a runtime hole.
