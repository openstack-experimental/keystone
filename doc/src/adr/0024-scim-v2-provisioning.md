# 24. SCIM v2 Resource Provisioning: Multi-Realm Identity Lifecycle per Domain

**Date:** 2026-07-01

**Last-revised:** 2026-07-08 (PR1+PR2+PR3+PR4+PR5 implementation note)

## Status

Proposed

**Implementation note (2026-07-06):** PR1 (Realm Foundation), PR2 (Users
vertical slice), PR3 (Groups + membership isolation), and PR4 (Protocol
Surface Completion — filter grammar, `PATCH`, ETags, discovery endpoints)
have landed. During implementation, the realm/user identity design was
refined beyond what this ADR originally specified: `ScimRealmResource` gained
a mandatory `idp_id` link to a federation `IdentityProvider`, and a
SCIM-provisioned `User`'s `id` is derived deterministically rather than
server-assigned, so it converges with a later federated JIT login for the
same person instead of producing a duplicate account. §2.A and §4 below have
been updated to match the as-built behavior; the "Rejected alternative"
callout in §4 is revised accordingly. `Group`, by contrast, keeps a normal
server-assigned `id` and an optional `externalId` — nothing federates in *as*
a Group, so there is no convergence hazard a deterministic id would solve.
§5's filter/PATCH/ETag design matches the as-built PR4 behavior as written,
with one addition worth noting here: closing the ETag CAS guarantee (§5.E)
required fixing a latent bug in the storage driver's compare-and-swap path
that predates PR4 (a concurrent-write violation was detected by the store but
never surfaced to the caller) — `ScimResourceIndex.version` now bumps on
every `PUT`/`PATCH`, not only ones that change `externalId`, so the ETag is
meaningful on every write.

**Implementation note (2026-07-08):** PR5 (Janitor Purge Phase, §6.C) has
landed, matching the as-written design with one naming deviation: the
retention config lives at `[scim_resource] janitor_deprovisioned_retention_days`
(default 365) rather than a top-level `[keystone] scim_deprovisioned_retention_days`
— this codebase nests janitor-tunable config on the owning provider's own
config struct throughout (see `[api_key] janitor_tombstone_retention_days`,
ADR 0021 §6.F), and PR5 follows that existing convention rather than
introducing a new top-level config table. The sweep itself is a
leader-gated hourly background task
(`crates/core/src/scim_resource/janitor.rs`), mirroring the API Key
janitor's structure exactly: for every tombstoned (`deprovisioned_at` set)
`ScimResourceIndex` older than the retention window, it hard-deletes the
underlying `User`/`Group` row via the existing `IdentityApi::delete_user`/
`delete_group`, purges the `ScimResourceIndex` anchor and its `externalId`
claim in one storage transaction, and emits a CADF `delete` event. Per-item
failures are isolated and retried on the next pass, exactly like the API
Key janitor. The operator-triggered `purge-now` erasure-request path (§6.C
last paragraph) is a new authenticated endpoint,
`DELETE /v4/scim-realms/{domain_id}/{provider_id}/purge/{resource_type}/{keystone_id}`,
gated by a new `identity/scim_realm/purge` OPA policy (admin, or manager
scoped to the realm's own domain — the same authorization boundary as
`identity/scim_realm/disable`, since purging a realm's resource is at least
as sensitive as disabling the realm). It refuses to purge a resource that
is not already deprovisioned, since that would silently skip the role-
stripping and session-revocation steps `DELETE /Users|Groups/{id}`
performs — an operator must soft-delete first, then purge. This is the
final phase in this ADR's implementation plan besides CLI parity (§12);
this ADR stays `Proposed` until that lands.

## Reference

Extends ADR 0002 (OPA), ADR 0017 (Security Context), ADR 0020 (Unified Mapping
Engine), ADR 0021 (Stateless API-Key Ingress), ADR 0023 (Audit). Amends ADR 0021
§3 Step 4 (see §2.C below).

---

## 1. Context & Motivation

Enterprise IdPs (Okta, Entra ID, Workday) push identity lifecycle events —
create, update, deactivate — for users and groups via SCIM, independently of
however those same users later authenticate (OIDC, SAML, or direct Keystone
credentials). Provisioning is therefore a distinct concern from authentication:
it manipulates **persistent** `User`/`Group` rows, not the ephemeral shadow
principals of ADR 0020's Unified Mapping Engine (UME).

A single Keystone domain frequently represents an organization boundary that
receives feeds from more than one authoritative source at once — for example, an
Okta tenant provisioning full-time employees and a Workday-driven system
provisioning contractors into the same domain. Both feeds must coexist without
either one able to see, rename, or delete the other's records, and without
either clobbering a human administrator's manually created accounts.

---

## 2. The Realm Model: Many Realms per Domain

A **SCIM realm** is the same tenant-local coordinate already used throughout ADR
0020/0021: the pair `(domain_id, provider_id)`. A domain MAY register any number
of independent, concurrently active realms. Each realm owns its own externalId
and userName namespace, its own API keys (per ADR 0021 §5.D, N keys may still
rotate under one `provider_id`), and its own provisioned resources. Realms
within the same domain are fully isolated from one another (§7).

### A. `ScimRealmResource`

Registering a realm is an explicit administrative act — creating an
`ApiClientResource` (ADR 0021) alone does **not** enable SCIM resource
provisioning for that `provider_id`. This separates "an API key that
authenticates" from "an API key permitted to provision identities," so API keys
minted for unrelated ABAC/system-integration mapping rulesets can never
accidentally provision Users/Groups.

```rust
pub struct ScimRealmResource {
    pub domain_id: String,
    pub provider_id: String,       // shared coordinate with ApiClientResource / MappingRuleSet
    pub idp_id: String,            // federation IdentityProvider this realm's users belong to
    pub display_name: String,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}
```

**Keyspace:** `data:scim_realm:v1:<domain_id>:<provider_id>`.

**`idp_id` is mandatory** and must resolve to an existing `IdentityProvider`
(checked at both realm create and update; an unresolvable `idp_id` is `404`).
This exists because of the identity-convergence scheme in §4: a SCIM-provisioned
`User`'s `id` is derived from `(domain_id, externalId)`, the same formula used
for a federation JIT shadow user's `id` — so the realm has to know, up front,
which `IdentityProvider`'s `sub` claims its `externalId`s are expected to equal
for that convergence to actually line up. A realm not bound to a real IdP would
still create syntactically valid `User` rows, but they'd never converge with
anything, silently defeating the point of §4's scheme.

Groups provisioned under a realm always inherit the realm's own `domain_id` — no
separate target-domain override is offered, keeping "one realm, one domain" the
literal ownership boundary even though a domain may host many realms.

### B. Realm Activation Gate

Every SCIM Users/Groups request first resolves the authenticated API key's
`provider_id` (already known to the ingress layer — it is a field on
`ApiClientResource`, ADR 0021 §2.B) and looks up
`data:scim_realm:v1:<domain_id>:<provider_id>`. If absent or `enabled: false`,
the request is rejected with `403 Forbidden` before touching any User/Group
storage.

### C. Amendment to ADR 0021: Realm-Aware Context Hydration

`hydrate_ephemeral_context` (ADR 0021 §3 Step 4) currently discards
`provider_id` once the UME match resolves authorizations — it is never carried
onto the `ValidatedSecurityContext`. This ADR amends that step: the resolved
`provider_id` MUST be threaded through into a
`ScimRealmContext { domain_id, provider_id }` available to a new `ScimRealmAuth`
extractor (parallel to `ApiKeyAuth`), used exclusively by the `/SCIM/v2`
resource handlers introduced here. This is additive to ADR 0021's payload and
does not change its authentication semantics.

**Scope restriction.** `ScimRealmAuth` requires `ScopeInfo::Domain` matching the
path's `{domain_id}`. Project-scoped API keys receive `403 Forbidden` on all
`/SCIM/v2/{domain_id}/Users` and `/Groups` routes — identity lifecycle
provisioning is a domain-level operation, never project-scoped. (The existing
diagnostic `whoami` route is unaffected and keeps accepting any scope.)

**Write-time ruleset constraint.** Because a realm's `provider_id` shares its
`MappingRuleSet` coordinate (ADR 0020 §3) with the general UME, nothing
inherently stops an operator from adding a rule to that same ruleset that
resolves `Authorization::Project` for some other, unrelated claim match — which
would make `ScopeInfo::Domain` above pass or fail per-request unpredictably for
what is nominally "the same realm." To close this structurally rather than leave
it as a runtime surprise, the Mapping Engine CRUD API (ADR 0020 §9.A) MUST
reject, with `422 Unprocessable Entity`, any attempt to write a rule containing
`Authorization::Project` into a `MappingRuleSet` whose `provider_id` has an
active `ScimRealmResource`. This mirrors the existing write-time `is_system`
prohibition for `ApiClient` sources (ADR 0021 §6.C): a SCIM realm's ruleset may
only ever resolve `Authorization::Domain` (matching its own `domain_id`) —
`System` is already forbidden for all API-key ingress.

---

## 3. Resource Ownership & the SCIM Index

### A. `ScimResourceIndex`

Every SCIM-provisioned `User` or `Group` is anchored by an ownership record kept
separate from the mutable resource itself (mirroring how ADR 0020 keeps
`VirtualUserMetadata` distinct from live claims) so that provenance cannot be
altered by the SCIM PATCH surface itself.

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScimResourceType { User, Group }

pub struct ScimResourceIndex {
    pub domain_id: String,
    pub provider_id: String,        // owning realm — the sole authority for §3.C
    pub resource_type: ScimResourceType,
    pub keystone_id: String,        // User.id or Group.id; also the SCIM "id"
    pub external_id: Option<String>,
    pub version: u64,               // monotonic; source of the SCIM ETag (§5.E)
    pub deprovisioned_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}
```

### B. Keyspace Summary

| Purpose                            | Key Pattern                                                             | Value               |
| ---------------------------------- | ----------------------------------------------------------------------- | ------------------- |
| SCIM Realm                         | `data:scim_realm:v1:<domain_id>:<provider_id>`                          | `ScimRealmResource` |
| Resource Ownership Anchor          | `data:scim_resource:v1:<domain_id>:<provider_id>:<type>:<keystone_id>`  | `ScimResourceIndex` |
| `externalId` Lookup (realm-scoped) | `index:scim:external_id:<domain_id>:<provider_id>:<type>:<external_id>` | `keystone_id`       |
| `userName`/`displayName` Lookup    | `index:scim:name:<domain_id>:<provider_id>:<type>:<lowercased_name>`    | `keystone_id`       |

The realm-scoped index in the table above exists for fast, realm-owned lookup
and version resolution (§3.C, §5.E) — it is deliberately **not** the sole
uniqueness check. See §3.D: `POST` (create) additionally performs a domain-wide
collision check against core Identity, independent of realm ownership.

### C. Ownership Fencing Algorithm

`GET`/`PUT`/`PATCH`/`DELETE /Users/{id}` (and `/Groups/{id}`) execute:

1. Fetch `data:scim_resource:v1:<domain_id>:<provider_id>:<type>:<id>` using the
   **caller's own** `provider_id` from `ScimRealmContext`.
2. If absent, return `404 Not Found` — indistinguishable from "the resource does
   not exist," even when a same-ID or same-`userName` resource exists under a
   different realm or was created manually. This prevents realm confusion / IDOR
   without leaking existence information across realms.
3. If `deprovisioned_at` is set, `GET`/list treat it as absent (`404`); repeat
   `DELETE` is idempotent (`404` per RFC 7644 guidance for re-delete).

`POST /Users` and `POST /Groups` (create) check the realm-scoped `externalId`
index **and** the domain-wide `userName`/`displayName` uniqueness check defined
in §3.D; either collision returns `409 Conflict` with `scimType: "uniqueness"`
(§10). Note the asymmetry with step 2 above: existence is hidden cross-realm for
ID-addressed reads/writes (IDOR protection), but is deliberately **not** hidden
for name collisions at create time (§3.D) — the two serve different goals.

### D. Domain-Wide Create-Time Uniqueness

§1 states that concurrent realms — or a realm and a human administrator — must
never silently produce two identities that collide on `userName` within one
domain. A check scoped only to the calling realm's own index (as in an earlier
draft of this ADR) cannot detect that: research into the existing schema
(`crates/identity-driver-sql`) found no pre-existing global unique constraint on
`(name, domain_id)` for users, so a second realm — or a manual `POST /v3/users`
— creating the same `userName` would otherwise succeed unnoticed, leaving two
`User` rows with identical `name`+`domain_id` and no way for a non-SCIM-aware
lookup (`openstack user show`, a UME rule matching on `user_name`) to
disambiguate them.

To close this, `POST /Users` and `POST /Groups` perform a **domain-wide**
existence check — a live query against core Identity for any existing
`User`/`Group` in `domain_id` whose `name` matches (case-insensitive),
regardless of which realm, or no realm, created it — in addition to the
realm-scoped `externalId` check. Any match, cross-realm or manual, rejects the
create with `409 Conflict` (`scimType: "uniqueness"`, §10). This uniqueness
check is deliberately not folded into the realm-scoped `ScimResourceIndex`
lookup used by §3.C for read/update/delete ownership fencing: the two checks
answer different questions — "does this name already exist anywhere in the
domain" (create-time, domain-wide) versus "do I own the resource at this ID"
(read/write-time, realm-scoped) — and conflating them would either leak
cross-realm existence on reads (weakening §3.C's IDOR protection) or fail to
catch cross-realm collisions on create (the gap being closed here).

**Race condition (TOCTOU).** A read-then-write existence check by itself is not
sufficient: two `POST`s for the same `(domain_id, name)` issued concurrently
(realistic under IdP-driven bulk onboarding, or two realms syncing the same
person independently) can both pass the check before either commits, producing
the exact duplicate this section exists to prevent. Since no unique constraint
on `(name, domain_id)` exists today (that's the gap this section opened with),
this ADR requires the check-and-insert to be closed by one of the two mechanisms
below, not by the live query alone:

- **Preferred:** a `UNIQUE(domain_id, LOWER(name))` constraint added to the core
  `User`/`Group` tables in `identity-driver-sql`, with the SCIM create path
  treating the resulting constraint-violation error as the `409 Conflict`
  trigger instead of (or in addition to) the pre-flight query. This makes
  uniqueness correct under concurrency by construction, at the cost of a schema
  migration shared with non-SCIM user/group creation.
- **Fallback**, if a schema-wide constraint is out of scope for this ADR's first
  cut: the existence check and the row insert execute inside a single
  serializable database transaction scoped to `(domain_id, name)`, so a second
  concurrent transaction targeting the same name blocks or fails at commit
  rather than at the earlier read.

Either way, the pre-flight query described above remains as a fast-path
rejection for the common (non-racing) case; it is the commit-time guarantee that
actually closes the race, and this ADR is not satisfied by the pre-flight check
alone.

---

## 4. Resource Schemas & Attribute Mapping

SCIM provisioning targets real, persistent Keystone `User`/`Group` rows — never
the ADR 0020 ephemeral shadow-registry path. A SCIM-provisioned user is expected
to authenticate later through an entirely separate channel (OIDC, password,
passkey); SCIM only manages the account's existence and attributes.

**Identity convergence with federation JIT (as-implemented).** `externalId` is
**mandatory** on `POST .../Users` (`400` if empty/absent), and the created
`User.id` is not server-assigned: it's derived deterministically as
`generate_public_id(domain_id, externalId, "user")` — the identical sha256-based
formula this codebase's ADR 0020 UME path already uses to derive a federation
JIT shadow user's `id`. The user row is created as `UserType::NonLocal` (no
password, no `local_user` row). The practical effect: a person provisioned
ahead of time via SCIM (`externalId` == the IdP's `sub` claim), who later
authenticates for the first time via that same realm's `idp_id` (§2.A),
converges onto the *same* `User` row a JIT login would otherwise have created
from scratch — rather than ending up with two accounts for one person, one
SCIM-managed and one federation-managed. `POST .../Users` additionally probes
for a user already occupying that deterministic id (e.g. one a federated JIT
login already created before SCIM provisioning caught up) and returns `409
Conflict` (`scimType: "uniqueness"`) rather than surfacing a raw
primary-key-collision error from the Identity driver.

**Rejected alternative:** reusing `User.federated: Option<Vec<Federation>>` (on
`UserResponse`/`UserCreate`/`UserUpdate`;
`Federation { idp_id, protocols, unique_id }`) to carry the SCIM `externalId`
directly. `Federation` is scoped to authentication-protocol linkage (`idp_id` +
`protocol_id`) and is not realm-fenced or version-tracked; overloading it would
conflate two different provenance concepts and bypass the ownership fencing in
§3.C. `ScimResourceIndex` is kept as a dedicated, parallel structure for
provenance/ownership instead — the convergence above is achieved purely through
the shared `id`-derivation formula, not by writing into `User.federated`.

| SCIM Attribute (User)                | Keystone `User` field                                    |
| ------------------------------------ | -------------------------------------------------------- |
| `id`                                 | `id` (`generate_public_id(domain_id, externalId, "user")`; deterministic, not server-random — see above) |
| `externalId`                         | `ScimResourceIndex.external_id` (mandatory on create — see above) |
| `userName`                           | `name`                                                   |
| `active`                             | `enabled`                                                |
| `name.givenName` / `name.familyName` | `extra["scim_given_name"]` / `extra["scim_family_name"]` |
| `emails[primary eq true].value`      | `extra["scim_primary_email"]`                            |
| `displayName`                        | `extra["scim_display_name"]`                             |

| SCIM Attribute (Group) | Keystone `Group` field                                                                                                                                                                                                                                                                        |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`                   | `id`                                                                                                                                                                                                                                                                                          |
| `externalId`           | `ScimResourceIndex.external_id`                                                                                                                                                                                                                                                               |
| `displayName`          | `name`                                                                                                                                                                                                                                                                                        |
| `members`              | resolved via the existing `user_group_membership` store (`crates/identity-driver-sql/src/user_group.rs`) already backing core group-membership CRUD, keyed to member `User.id`s owned by the **same realm** (§7); capped at 1000 entries per resource per the §11 membership-graph-bomb limit |

Attributes without a first-class Keystone field are namespaced under
`extra["scim_*"]` rather than added as new top-level `User` columns — avoiding a
core-identity schema migration for display-only SCIM metadata.

---

## 5. Protocol Surface (Pragmatic Subset)

Full RFC 7644 compliance (arbitrary filter expressions, arbitrary PATCH path
expressions, `/Bulk`) is explicitly **not** targeted for v1. This mirrors the
DoS-hardening posture already established elsewhere in the codebase (regex ReDoS
bounds and per-claim size caps in ADR 0020 §5.1, token-bucket rate limiting in
ADR 0021 §6.A).

### A. Endpoints

- `POST /SCIM/v2/{domain_id}/Users`, `GET .../Users`, `GET .../Users/{id}`,
  `PUT .../Users/{id}`, `PATCH .../Users/{id}`, `DELETE .../Users/{id}`
- `POST /SCIM/v2/{domain_id}/Groups`, `GET .../Groups`, `GET .../Groups/{id}`,
  `PUT .../Groups/{id}`, `PATCH .../Groups/{id}`, `DELETE .../Groups/{id}`
- `GET /SCIM/v2/{domain_id}/ServiceProviderConfig`, `GET .../Schemas`,
  `GET .../ResourceTypes` — static discovery documents, honestly advertising
  `bulk.supported: false`, `sort.supported: false`, and describing the
  restricted filter grammar below (Okta/Entra ID both tolerate a
  `filter.supported: true` with a narrower attribute set than the spec's
  maximum).

### B. Filter Grammar

```
filter     := term (LOGICAL_OP term)*      // homogeneous chain only — "and" and "or" MUST NOT be mixed in one filter string
term       := ATTR OP value
LOGICAL_OP := "and" | "or"
OP         := "eq" | "ne" | "co" | "sw" | "pr"
```

| Attribute (User) | Allowed operators    |
| ---------------- | -------------------- |
| `userName`       | `eq, ne, co, sw, pr` |
| `externalId`     | `eq, ne, pr`         |
| `id`             | `eq, pr`             |
| `active`         | `eq, pr`             |

| Attribute (Group) | Allowed operators    |
| ----------------- | -------------------- |
| `displayName`     | `eq, ne, co, sw, pr` |
| `externalId`      | `eq, ne, pr`         |
| `id`              | `eq, pr`             |

Any attribute or operator outside these tables, a mixed `and`/`or` chain,
nested/parenthesized expressions, or a filter string exceeding 512 bytes / 8
terms is rejected with `400 Bad Request` (`scimType: "invalidFilter"`).
`co`/`sw` are only evaluated against attributes that already carry a realm index
(§3.B), bounding worst-case cost to that index's range, never a full table scan.

### C. PATCH Operation Support

`Operations: [{op, path, value}]` is accepted only for these top-level, scalar
`path` targets: `active`, `userName`/`displayName`, `externalId`,
`name.givenName`, `name.familyName`, plus `members` (Group, `add`/`remove` only
— the common "push group" pattern). Any other `path` (complex filter expressions
like `emails[type eq "work"].value`, array-index paths) returns
`400 Bad Request` (`scimType: "invalidPath"`). `PUT` performs a full declarative
replace of all mapped attributes, including a full membership resync for Groups
(remove-then-add against the target member set).

### D. Pagination

`startIndex` (1-based, default 1), `count` (default 20, max 200). Listing and
`totalResults` are computed via a bounded prefix range-scan over the realm's own
`data:scim_resource:v1:<domain_id>:<provider_id>:<type>:*` keyspace, excluding
`deprovisioned_at`-set entries. This is a linear scan bounded to one realm's
resource count (consistent with existing janitor range-scans elsewhere); a
maintained counter is deferred as a future optimization if realm sizes prove
large enough to matter.

**Group listing cost.** The bound above covers the `scim_resource` index scan
itself, not `members` hydration. A `GET /Groups` page fans out into one
`user_group_membership` lookup per group on the page — bounded per-group by the
same 1000-member cap as §11, so a full page's worst case is `count × 1000`
membership rows (e.g. 200 × 1000 for a max-size page), not unbounded, but
materially larger than the resource-index scan alone. Clients needing cheaper
listing should page with a smaller `count` when membership detail isn't
required, or use `GET /Groups/{id}` for individual membership detail.

### E. ETags / Concurrency

`ScimResourceIndex.version` is a monotonic counter incremented on every
SCIM-driven `PUT`/`PATCH`, serialized as a weak ETag: `W/"<version>"`. `PUT` and
`PATCH` requests carrying `If-Match` are rejected with `412 Precondition Failed`
if the header value doesn't match the current version — closing the lost-update
race inherent to concurrent push-group syncs from a single IdP.

This guarantee only holds if the `If-Match` compare, the field write, and the
`version` increment happen as one atomic operation against the backing store — a
read-compare-then-write done as three separate calls reintroduces the same race
it's meant to close, just moved into the version counter itself. The handler
MUST perform this as a single compare-and-swap against the
`data:scim_resource:v1:...` row (or an equivalent single transaction against the
underlying `User`/`Group` table when the write also touches core Identity
fields), rejecting with `412` if the stored version has moved between the
initial read and the write. A high-frequency IdP sync burst is exactly the case
this is meant to survive, not merely the common case.

### F. Explicitly Out of Scope for v1

`/Bulk`, arbitrary filter path expressions, `sortBy`/`sortOrder`, and
multi-valued complex attribute PATCH addressing (`emails[type eq "work"]`).
Extending any of these later requires a ratifying revision to this ADR given
their DoS/complexity surface.

---

## 6. Deprovisioning Semantics

### A. `DELETE /Users/{id}` → Soft-Disable Only

Consistent with the retention pattern already used for API keys (ADR 0021 §5.C)
and the UME shadow registry (ADR 0020 §4.A), `DELETE` on a User **never
hard-deletes**. It:

1. Sets `User.enabled = false`.
2. Stamps `ScimResourceIndex.deprovisioned_at`.
3. Triggers the existing token revocation pipeline
   (`revocation:v1:user:<user_id>`, ADR 0020 §9.F) so live sessions die
   immediately.
4. Emits a CADF `disable` event (§9).

Subsequent `GET`/`PATCH`/`PUT` against the same `id` from the owning realm
return `404 Not Found` (tombstoned), matching RFC 7644's expectation that a
deleted resource is inaccessible, while the underlying row and its audit trail
survive for incident response.

### B. `DELETE /Groups/{id}` → Neutralize + Tombstone

`Group` has no `enabled` field in the current schema (unlike `User`), and RFC
7644's Group schema defines no `active` attribute either. Rather than adding a
new field to core `Group` for this single caller, or hard-deleting (which would
silently leave any inherited role grants dangling and does not match the
"preserve audit trail" rationale used everywhere else in this codebase), Group
deletion:

1. Immediately clears the group's role assignments (closing the live
   authorization surface — this is the security-relevant action, since a
   "deleted-looking" group that still grants roles would be a silent escalation
   path). A role-stripped group grants nothing regardless of who remains listed
   as a member, so this alone is sufficient to neutralize the group.
2. Stamps `ScimResourceIndex.deprovisioned_at` and hides the group from all SCIM
   `GET`/`List` responses (`404`), identically to a User tombstone. **Membership
   is deliberately left intact** at this point — clearing it would destroy
   exactly the forensic snapshot (who belonged to the group at the moment of
   deletion) that the "preserve audit trail" rationale for not hard-deleting is
   meant to protect, and retaining it poses no live authorization risk once step
   1 has stripped the group's roles.
3. Retains the `Group` shell and its membership snapshot for the same retention
   window as (C) below, then the janitor hard-deletes the row (and its
   membership records) together.

### C. Janitor Purge

A background janitor (extending the pattern of ADR 0020 §4.A's archive cleanup
and ADR 0021 §6.F's physical reclamation) permanently deletes User and Group
rows whose `ScimResourceIndex.deprovisioned_at` is older than
`[keystone] scim_deprovisioned_retention_days` (default: 365 days), removing the
`ScimResourceIndex` anchor and its `external_id`/name index entries in the same
transaction.

**Regulatory retention risk.** A fixed 365-day default of PII (`extra["scim_*"]`
fields, `external_id`) held in a soft-deleted-but-readable-by-operators state
purely to preserve an audit snapshot is a data-minimization / right-to-erasure
tension for deployments under GDPR or comparable regimes — a deployer cannot
justify a full year of retention against an erasure request just because this
ADR's default says so. This ADR treats `scim_deprovisioned_retention_days` as
deployer-controlled specifically so regulated deployments can set it far below
365 days (including near-zero, trading away most of the forensic window for
compliance), and additionally requires an operator-triggered `purge-now` path —
a janitor invocation scoped to a single `keystone_id` that ignores the retention
window — so a verified erasure request does not have to wait for the configured
period to elapse. Choosing the right default retention for a given jurisdiction
is a deployment/compliance decision this ADR deliberately leaves to the operator
rather than prescribing centrally.

---

## 7. Cross-Realm & Membership Isolation

Beyond the per-resource ownership fencing in §3.C, group membership writes are
fenced transitively: a `Group` `members` entry (add, via `PUT` or `PATCH`) MUST
reference a `User` owned by the **same realm** (same `provider_id`) as the group
itself. A membership reference to a user owned by a different realm, or to a
manually-created user with no `ScimResourceIndex` entry at all, is rejected with
`400 Bad Request` (`scimType: "invalidValue"`). This prevents one IdP
integration from reaching across realm boundaries — or into human-managed
accounts — merely by guessing or enumerating a Keystone user ID.

---

## 8. Authorization & OPA Policies

Realm CRUD (`POST/GET/PATCH /v4/scim-realms`) is invoked by a
Fernet-authenticated human operator, not a SCIM API key, so its authorization
reuses the actual, pre-existing `manager` role (this codebase's realization of
"DomainManager" — see ADR 0021 §5.A) or `admin`/`is_admin` (never
`DomainAdmin`), under new policies named per the slash-separated convention
actually used by every implemented policy call site in
`crates/keystone/src/api/v4/**` and the corresponding `.rego` packages (e.g.
`identity/user/create`) — **not** the colon-separated form
`identity:api_key:create` that ADR 0021 §5.A used only in prose and was never
implemented:

- `identity/scim_realm/create` / `identity/scim_realm/list` /
  `identity/scim_realm/show` / `identity/scim_realm/disable`

SCIM resource CRUD authorization is enforced exactly like any other v4 endpoint
per ADR 0002, but with one important distinction from realm CRUD above: SCIM
resource requests are authenticated exclusively via API-key ingress (ADR
0021), and `ApiClientResource` carries **no Role field and no
RoleAssignment at all**. The `roles` evaluated by these policies are therefore
never RBAC-assigned — they are entirely the `Authorization::Domain{roles}`
value produced by evaluating the realm's own `MappingRuleSet` (ADR 0020 UME /
ADR 0021 §3 Step 4 `hydrate_ephemeral_context`) at request time. An operator
grants access by authoring a mapping rule whose output includes the role
string `manager`, `admin`, or `scim_provisioner` onto the realm's
`provider_id` — not by assigning a Keystone `Role` to anything, since no such
assignment surface exists for API keys. These policies are evaluated against:

- `identity/scim/user/create` / `identity/scim/user/list` /
  `identity/scim/user/show` / `identity/scim/user/update` /
  `identity/scim/user/delete`
- `identity/scim/group/create` / `identity/scim/group/list` /
  `identity/scim/group/show` / `identity/scim/group/update` /
  `identity/scim/group/delete`

**Note for ADR 0021:** its §5.A policy names should be corrected to the same
slash convention in a future revision of that ADR; this ADR does not attempt to
fix 0021 retroactively, only avoids repeating its naming inconsistency.

**Role-existence enforcement (ADR 0020 §7.3):** the `manager`/`admin`/
`scim_provisioner` role strings above are only meaningful if a `Role` with
that exact name actually exists — the naming-drift bug this ADR originally
shipped with (invented `SystemAdmin`/`DomainManager` literals with no
backing `Role`, silently producing an unreachable authorization) is now
caught structurally: mapping rule create/update rejects any `RoleRef`
whose `id` doesn't resolve against the `Role` store with `422
Unprocessable Entity` (`MappingProviderError::RoleNotFound`), rather than
relying on this ADR's prose staying in sync with the rego by hand.

The §3.C ownership-fencing check happens **before** OPA evaluation and is not a
substitute for it — a realm's own credential may still lack a role authorizing a
given operation even against its own resources.

---

## 9. Auditing

Every SCIM write emits a CADF event per ADR 0023's actually-implemented
`CadfEventPayload`, which carries a single `action: String` (no separate
`category` field exists in `crates/audit/src/types.rs` — ADR 0021 §5.C's mention
of a `control` category is unimplemented prose, not a real field, and this ADR
does not repeat it). The `action` is drawn from the existing `Operation` enum
(`crates/core-types/src/events.rs`): `Create`/`Update` for writes, `Disable` for
the deprovisioning paths in §6.

`target.type_uri` is `data/security/account` (User) or `data/security/group`
(Group). `realm_provider_id` and `external_id` are captured in the event
attachment for cross-referencing against the IdP's own provisioning logs.

**`initiator.id` caveat.** Per ADR 0021 §3 Step 4 / §5.D, `initiator.id` is
derived from the authenticating API key's `client_id`, not from `provider_id` —
this is per-_key_, not per-_realm_, identity, chosen precisely so distinct keys
sharing a `provider_id` produce distinct audit identities. Consequently
`initiator.id` on SCIM CADF events **changes** across a zero-downtime key
rotation (ADR 0021 §5.D) even though the realm performing the action has not
changed. Consumers correlating "who acted on behalf of this realm" across a
rotation window MUST group by the `realm_provider_id` attachment field, not by
`initiator.id`.

This is an operational gap, not just a documentation note: a SIEM/SOC pipeline
built against `initiator.id` alone (a reasonable default, since that's the field
ADR 0021 already calls the actor identity) will silently split one realm's
activity into two apparently-unrelated actors across a rotation, which is
precisely the window where a leaked pre-rotation key is most likely to be
abused. This ADR does not itself ship a fix for downstream SIEM configuration,
but requires that operational runbooks for SCIM ingress (a deliverable of the
rollout, not of this ADR) explicitly call out `realm_provider_id` as the
correlation key, and that alerting rules keyed purely on `initiator.id`
stability are flagged as insufficient for SCIM traffic during review.

---

## 10. Error Mapping (RFC 7644 §3.12)

SCIM error responses use the standard envelope:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "scimType": "uniqueness",
  "detail": "userName already exists within this domain"
}
```

| Internal Condition                               | HTTP Status | `scimType`                                  |
| ------------------------------------------------ | ----------- | ------------------------------------------- |
| Realm not registered / disabled (§2.B)           | 403         | _(no body — generic)_                       |
| Resource not owned by caller's realm (§3.C)      | 404         | _(no body)_                                 |
| `userName`/`displayName`/`externalId` collision  | 409         | `uniqueness`                                |
| Disallowed filter attribute/operator/mixed chain | 400         | `invalidFilter`                             |
| Disallowed PATCH `path`                          | 400         | `invalidPath`                               |
| Cross-realm/manual-user membership reference     | 400         | `invalidValue`                              |
| `If-Match` version mismatch                      | 412         | _(no body — standard precondition failure)_ |

---

## 11. Threat Model

- **Realm confusion / IDOR:** mitigated structurally by §3.C — ownership is
  checked before any read/write, independent of role authorization.
- **Cross-realm membership injection:** mitigated by §7.
- **Provisioning DoS:** SCIM resource writes ride the same per-`lookup_hash`
  token-bucket rate limiter as authentication (ADR 0021 §6.A); a second,
  write-specific limiter keyed on `provider_id`
  (`[keystone] scim_realm_write_rate_limit`, default 500/min, mirroring ADR 0020
  §7.2's shadow-registry limiter) bounds bulk provisioning bursts from a single
  compromised or misconfigured realm.
- **Membership-graph bombs:** a single `PATCH`/`PUT` is capped at 1000 `members`
  entries; larger syncs must paginate across multiple requests.
- **Filter/PATCH complexity:** bounded to the tables in §5.B/§5.C — eliminates
  the arbitrary-expression parsing surface that would otherwise require its own
  ReDoS-style hardening.
- **Silent group privilege retention on delete:** addressed by §6.B's immediate
  role-assignment clearing, rather than treating "deleted-looking" as
  sufficient.
- **Name-collision race (TOCTOU):** a naive read-then-write uniqueness check
  (§3.D) is racy under concurrent creates for the same name; closed by requiring
  a DB-level unique constraint or an equivalent serializable check-and-insert
  transaction, not the pre-flight query alone.
- **Audit-trail fragmentation across key rotation:** `initiator.id` changes
  across a zero-downtime SCIM key rotation (§9); mitigated by requiring
  downstream correlation on `realm_provider_id`, and flagged as an operational
  requirement for SIEM/SOC configuration, not something this ADR can enforce
  in-band.

---

## 12. Consequences

- New keyspaces: `scim_realm`, `scim_resource`, plus two lookup indices (§3.B).
  No migration of existing `User`/`Group` schemas for the fallback path in §3.D;
  the preferred path (a `UNIQUE(domain_id, LOWER(name))` constraint) does
  require a schema migration shared with non-SCIM create paths.
- ADR 0021's ingress hydration gains an additive `provider_id` field on the
  ephemeral context (§2.C) — existing non-SCIM consumers are unaffected.
- ADR 0020's Mapping Engine CRUD API gains a new write-time validation rule
  (§2.C): rulesets whose `provider_id` is bound to an active `ScimRealmResource`
  may not contain `Authorization::Project` entries.
- `POST /Users`/`Groups` now performs a domain-wide `userName`/`displayName`
  existence check (§3.D) against core Identity, in addition to the realm-scoped
  `externalId` check — the first piece of cross-realm uniqueness enforcement
  introduced for user/group names, though still not a general schema-level
  constraint outside the SCIM create path.
- New CRUD API family `/v4/scim-realms` and OPA policies (§8, slash-separated
  naming) require CLI support, per the standing convention from ADR 0006 ("New
  APIs must be implemented in the CLI").
- `/Bulk`, full filter grammar, and full PATCH path expressions are deliberately
  deferred; broader RFC 7644 compliance requires a follow-up ADR revision once
  real-world IdP integration experience justifies the added complexity.
- The janitor gains a new purge phase (§6.C) alongside its existing API-key and
  shadow-registry archive phases, plus an operator-triggered `purge-now` path
  for erasure requests (§6.C) that bypasses the configured retention window.
- `ScimResourceIndex.version` writes (§5.E) and the §3.D uniqueness
  check-and-insert both require compare-and-swap / transactional semantics from
  the backing store rather than separate read-then-write calls — a correctness
  requirement on the implementation, not just documentation.
