# 45. Global IAM Across Continents: A Mesh of Identity Authorities

**Date:** 2026-11-14

## Status

Draft (not yet Proposed). Latencies are estimates, not measurements.

This is a target design. Every part of it is opt-in (section 0): a deployment
that does not configure it behaves exactly as today.

Relates to: ADR 0016-v2 (Raft storage), ADR 0026 (OAuth2/OIDC provider), ADR
0034 (per-domain assignment drivers), ADR 0036 (service delegation), ADR 0041
(OAuth2 sessions), ADR 0043 (DPoP), ADR 0044 (single-use registry), ADR 0046
(domain member invitations, draft), [vision](../vision.md) (scope-less tokens,
`OpenStack-Target`, `/v4/authz/check`), [IAM data plane](../iam-data-plane.md),
`doc/plans/iam-control-data-plane-split.md`,
`doc/src/contributor/security-model.md`.

## Context

A cloud spans regions on several continents and needs one IAM view: a single
domain/project namespace, tokens valid everywhere, and users authenticating
without a cross-continent dependency. Constraints:

- **Data protection law is the driver.** Identity data (users, credentials,
  group membership, contact attributes) must stay inside a legal boundary: for
  example, data of EU users must not be stored in the US. An authority is the
  unit of that boundary. User data never crosses the boundary of the authority a
  user is homed in. Users authenticate only there; they may consume resources
  elsewhere. What does cross is limited to opaque identifiers (`iss`, `sub`,
  group IDs, project IDs). No attribute, credential or contact data crosses.
  Such identifiers are pseudonymous, and some laws still treat them as personal
  data; whether the design satisfies a given law is a legal question (open item
  10). Availability is therefore improved inside a boundary (section 2.1), never
  by copying identity data out of it.
- The cloud grows: an operator starts with one deployment and adds replicas and
  further authorities later, without migrating IDs or breaking tokens.
- Raft is a poor transport across continents. By analysis: commit = one quorum
  RTT (150-300 ms if voters span continents); Tier 2/3 reads and writes on a
  non-leader cross the WAN; snapshot install is one in-memory, non-resumable
  stream with no window tuning; no explicit RPC timeouts; every learner needs
  the DEK and decrypts the whole log; no relay tier.
- Per-site roots of trust (SPIRE + OpenBao per site, federated) rule out a
  shared DEK/KEK across sites.
- Much IAM state is not in Raft (identity, assignment, resource, revocation
  drivers are SQL or OpenFGA).
- ADR 0034 dispatches assignments on the target because the target-keyed
  partition is closed under the hierarchy.
- Token validation and authentication need records that are local today:
  - the **domain**: auth validation fetches the user's domain
    (`core/src/auth.rs:123`, `DomainNotFound` otherwise), token scope building
    fetches project and user domains (`core/src/token/service.rs:135,426`),
    trust checks read `get_domain_enabled` (`auth.rs:245`);
  - the **user**: token validation loads the user through `get_user_core` /
    `get_user` and fails with `UserNotFound` when it is missing
    (`core/src/token/service.rs:400-411`); trust checks load the trustor
    (`auth.rs:215-224`).

  A user homed in another authority is never present, so the current validation
  path cannot accept a foreign token.

- The vision moves to scope-less tokens: a JWT says who, the request names the
  target (`OpenStack-Target`), and the service asks Keystone (`/v4/authz/check`)
  against a replica of live state. Delegation facts travel in
  `delegation_context` (ADR 0036 §7). This model needs no scope at issuance,
  which is what a mesh needs.
- Hyperscalers keep the container (account, project, subscription) logically
  global with replicated policy, resources regional, IAM writes concentrated and
  evaluation replicated and statically stable, and they accept minutes of
  propagation delay:
  - AWS: one IAM control plane for all commercial Regions, in us-east-1; it
    propagates changes to an independent, read-only IAM data plane in every
    Region, which authenticates and authorizes that Region's requests and keeps
    working when the control plane is impaired
    ([fault isolation boundaries](https://docs.aws.amazon.com/whitepapers/latest/aws-fault-isolation-boundaries/global-services.html),
    [IAM resilience](https://docs.aws.amazon.com/IAM/latest/UserGuide/disaster-recovery-resiliency.html)).
    Changes "take time to become visible from all possible endpoints", with
    caching on top
    ([IAM troubleshooting](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html)).
    Session tokens from Regional STS endpoints are valid in all Regions, so no
    exchange happens between Regions
    ([STS in a Region](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html)).
  - GCP: IAM is eventually consistent; an allow or deny policy change typically
    takes 2 minutes, potentially 7 or more, and a group membership change
    several minutes, potentially hours; removals propagate more slowly than
    additions
    ([access change propagation](https://docs.cloud.google.com/iam/docs/access-change-propagation)).
  - Azure: role assignment changes can take up to 10 minutes because Azure
    Resource Manager caches; at management-group scope the data plane may lag
    several hours, and so may a managed identity's group or role membership
    ([RBAC troubleshooting](https://learn.microsoft.com/en-us/azure/role-based-access-control/troubleshooting)).

  The mesh targets 30 s for revocation (section 9), stricter than any of these,
  and a group change at home takes effect with the next token (section 5).

- Python Keystone coexistence is out of scope.

## Terminology

- **Authority** (identity authority): one keystone-rs deployment that is the
  issuer of tokens and the home of a set of users. Owns its DEK/KEK and trust
  bundle, and is made of one or more SPIFFE trust domains (section 11). Unit of
  residency, trust and Raft. Not a region, cluster, partition, cell or realm
  (those words are taken in the catalog, Raft/storage, Nova and SCIM
  respectively).
- **Home authority** of a user or domain: where the user or the domain's home
  lives. **Target authority**: the authority that owns a resource/project.
- **Core** (write and authentication plane): 3 Raft voters in 3 AZs of one
  region (or nearby regions, or sites of one jurisdiction, section 2.1).
- **Evaluation plane**: read-only regional identity endpoints that validate
  tokens, answer authorization checks (`/v4/authz/check`), serve catalog and
  read APIs. This is the vision's IAM data plane, placed per authority. While
  the core is unreachable it may also authenticate, only as section 2.1 allows.
- **Region**: unchanged catalog meaning (where endpoints are). An authority
  serves many catalog regions through its evaluation plane.
- **Site**: a physical location with its own Tier 1 root of trust (SPIRE,
  OpenBao). Usually one per catalog region, but the two are distinct concepts.
- **Mesh domain**: a domain registered in the registry (section 4), visible to
  and partable into other authorities. **Authority-local domain**: a domain that
  is not registered; it behaves as today and never leaves its authority.
- The term is introduced as a first-class concept: registry record, read-only
  `authority` attribute on projects and list results, `authority_id` on identity
  catalog endpoints (additive), metrics and audit labels. The registry, not the
  catalog, owns the authority record because it holds trust anchors.

## Decision

### 0. Opt-in and growth stages

Nothing in this ADR is active unless configured. The stages are cumulative and
each is a separate operator decision:

| Stage | Adds                                                      | Active components                                                                                          | Reversible                                         |
| ----- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| 1     | nothing: one authority, as today                          | none of this ADR                                                                                           | n/a                                                |
| 2     | evaluation replicas in more regions of the same authority | M2 learners; per-site DEK wrap (11.2) if voters or learners span sites; optional availability levels (2.1) | yes                                                |
| 3     | a second (and further) authority                          | registry, reservation group, M4 feed, trust bundles, reverse index, proxy                                  | until a mesh domain has parts in another authority |

- A stage 1 deployment runs no registry, feed or mesh code paths; the
  foreign-domain source, the user-less validation path (section 5) and the proxy
  are disabled.
- Existing domains and IDs are kept when growing. Domain IDs stay locally
  generated UUIDs; joining a mesh registers them (section 4), it does not
  rewrite them.
- Stage 3 requires the scope-less token model (section 5) for cross-authority
  access. Clients and services that use only v3 scoped tokens keep working
  inside their own authority.

### 1. Model

- A mesh of independent authorities. No Raft, DEK or log of an authority's core
  is shared between them; the only shared Raft group is the reservation group
  for unique names (section 4), which holds no identity data.
- **Users are homed in exactly one authority and never replicated.**
  Authentication happens only at the home authority: at its core, and at its own
  evaluation replicas only as section 2.1 allows. Authorization federates: a
  user consumes resources in other authorities.
- **Domain and project IDs are globally unique.** Both are locally generated
  UUIDs; the registry rejects a colliding domain ID on registration and locates
  every project of a mesh domain (section 4). Security decisions never rely on a
  project ID alone: wherever a project crosses an authority (the delegation
  boundary, revocation events, trust records, guardrails) it is named as
  `(authority, project-id)`. The bootstrap `default` domain, and any domain an
  operator chooses not to register, is authority-local: never partable, never in
  the registry, and referenced from outside only as `(authority, domain-id)` in
  audit.
- A mesh domain has a home authority and may have **parts** in other authorities
  (projects and their assignments). A **project is owned by exactly one
  authority**; project hierarchies stay inside one authority, so ADR 0034's
  closure invariant holds.
- **Project names stay unique per domain**, as in Keystone. Creating or renaming
  a project in a foreign part claims the name at the domain's home (one WAN
  round trip). The claim carries the project ID, and home rejects an ID it has
  already recorded for the domain, so a peer cannot shadow another authority's
  project. If the home is unreachable, the create fails; reads and checks are
  unaffected. The home records each claim as
  `(domain-id, project-id) -> authority` and publishes it in the domain's
  registry record (section 4); projects in the home's own part are recorded the
  same way.
- Domain-level assignments that cascade and role definitions are domain data and
  are replicated to every authority holding a part of the domain. They contain
  no user attributes, only pseudonymous `(issuer, principal-id)` and group
  references (see Context).

### 2. Two planes per authority

|             | Core (write and authn plane)                                                                                                         | Evaluation plane                                                                          |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| Placement   | one region (3 AZs) or nearby regions                                                                                                 | every catalog region of the authority                                                     |
| Does        | authentication, credential flows, writes, admin, signing-key generation, sessions/refresh tokens, revocation source, the feed source | token validation, authz checks, catalog, read APIs; replica authentication only under 2.1 |
| Consistency | linearizable (Raft)                                                                                                                  | replica with measured lag, `max_staleness`                                                |
| Failure     | writes/logins down                                                                                                                   | keeps serving until `max_staleness` (static stability)                                    |

Tier 2/3 records (hashed credentials, application credentials) are
linearizable-only on the normal path, so authentication stays at the core while
the core is reachable. Section 2.1 defines what replicas may do when it is not.

#### 2.1 Static availability inside the residency boundary

AWS keeps authentication available per Region because each Region's IAM data
plane authenticates locally. A mesh cannot do that across authorities without
copying identity data out of its boundary. It does it inside the boundary, in
four levels; each level is opt-in, and a later level assumes the earlier ones.
Every site involved already holds the authority's DEK and Tier 2/3 data as a
learner (section 11.1), so none of them moves identity data anywhere new.

| Level | Mechanism                        | Survives                | Covers                                   |
| ----- | -------------------------------- | ----------------------- | ---------------------------------------- |
| A1    | core voters spread across sites  | loss of one site        | everything                               |
| A2    | session continuation at replicas | loss of the core quorum | users and workloads with a live session  |
| A3    | no-replay methods at replicas    | loss of the core quorum | application credentials, X.509-SVID mTLS |
| A4    | password and MFA at replicas     | loss of the core quorum | new interactive logins                   |

- **A1. Spread the core inside the boundary** (recommended for every residency
  authority). Three voters in three sites of the same jurisdiction within the M1
  rule (<= ~50 ms; for example three EU regions) keep logins and writes through
  the loss of a site, at a commit cost of one intra-boundary RTT. This needs
  only the per-site KEK wrap (section 11.2).
- **A2. Session continuation.** When a replica cannot reach a core leader, it
  may issue a new access token to the holder of a valid access token of an
  existing session, the model of Entra ID's backup authentication service
  ([backup authentication system](https://learn.microsoft.com/en-us/entra/architecture/backup-authentication-system)),
  which serves existing sessions but not new sign-ins. **Only sender-constrained
  tokens are continued** (DPoP, ADR 0043, or mTLS-bound); a bearer token is
  refused, since continuing it would turn a stolen token into a credential that
  lives for `continuation_max` instead of one TTL (security-model I11). The
  holder proves possession with a DPoP proof whose `jti` the replica checks
  against its per-node cache (ADR 0043); a replayed proof only yields a token
  bound to the same key, which is useless without it. The new token keeps `sub`,
  `amr`, `aud`, `delegation_context` and the binding of the presented one, is
  signed by the site's **continuation key** (below), and carries
  `auth_plane: "replica"` and the issue time of the last core-issued token. It
  is refused once that time is older than `continuation_max` (default 12 h) or
  the session's absolute lifetime. The replica checks the user, revocations and
  the site deny list (below) against its own state as of its last core contact.
  Nothing revoked after that reaches it except through the site deny list
  (below); the two clocks under "Outage clocks" bound how long it keeps issuing.
  Refresh tokens are not rotated at replicas (rotation is a linearizable write);
  the client keeps its refresh token for the core's return.
- **A3. No-replay methods.** Application-credential secrets (checked against the
  replicated hash) and X.509-SVID mTLS (checked against the bundles the replica
  holds) need no write. A replica may authenticate them while the core is
  unreachable, within `continuation_max` of the last core contact, signing with
  the continuation key and marking `auth_plane: "replica"`. An application
  credential deleted at the core shortly before the outage stays usable at the
  replica for the rest of the outage window (at most `continuation_max`), unless
  a site break-glass entry denies it. JWT assertions (JWT-SVID, Kubernetes
  service-account tokens, external IdP assertions) are **not** in A3: ADR 0044
  makes their `jti` single-use, which is a linearizable write, so they stay at
  the core.
- **Outage clocks.** `auth_max_staleness` (default 1 h) bounds replication lag
  while a core leader is reachable: a replica that lags more stops issuing. When
  the replica cannot reach a core leader (missing heartbeats, not lag) its state
  is frozen and the clock is `continuation_max` (default 12 h), measured from
  its last contact with the core. After it, replicas stop issuing under A2 and
  A3. Revocations made in the window reach the replica only through the site
  deny list.
- **A4. Password and MFA** (opt-in per domain, off by default). Writes that
  login depends on become local to the replica: failed-attempt counters (the
  effective lockout threshold becomes threshold times the number of sites
  authenticating: the core plus each replica), the TOTP replay cache (a code can
  be replayed once at each other replica within its 30 s window) and passkey
  sign counters (clone detection is delayed). Federated logins stay at the core:
  their `state`, nonce and assertion replay records are single-use (ADR 0044)
  and need linearizable writes. A domain that enables A4 accepts these
  weakenings in exchange for logins during a core outage.
- **Continuation keys.** One signing key per site, not per domain, generated by
  the core, wrapped to that site's key only (section 11.2) and listed in the
  JWKS of every domain that enables A2 or A3, ahead of use like a Next key
  (appendix A). The JWKS entry and the feed record carry a
  `ks_use: continuation` member, so a verifier can tell it from a core key (G1,
  G15). A per-domain key would not shrink a site compromise: the site already
  holds the DEK and every domain's data. The key count stays the number of
  sites. G1 accepts a continuation `kid` only for issuers whose domain enables
  A2 or A3, and only from a site of the issuer's home authority.
- **Site break-glass deny.** While the core is down nothing can be revoked
  through it. A site operator may write a deny entry (user `(iss, sub)`, domain,
  or `jti`/`root_jti`) to a store local to the site, outside Raft, authenticated
  with the site's own Tier 1 identity. The site's replicas refuse matching
  continuation and authentication at once and apply it to validation like a
  revocation. Entries only add denials, are audited, expire with
  `continuation_max`, and are sent to the core as revocation events when it
  returns. They do not leave the authority; other authorities learn of them
  through the core's priority stream once it is back. An entry is local to the
  site where it was written: the authority's other sites apply it only if an
  operator enters it there too.
- For A2-A4, policies and deny guardrails (section 13) can refuse sensitive
  operations to tokens with `auth_plane: "replica"`. Audit records for replica
  issuance are kept locally and shipped when the core returns. No replica ever
  writes identity data; anything the core missed is recomputed from the audit
  trail, not merged.
- Other authorities accept replica-issued tokens like any token of the issuer
  (G15); an authority guardrail can refuse them.

### 3. Replication mechanisms

| Id  | Mechanism                                 | Used for                                          | Rule                               |
| --- | ----------------------------------------- | ------------------------------------------------- | ---------------------------------- |
| M1  | Raft quorum                               | commits, linearizable reads, elections            | voters <= ~3 ms (AZs) or <= ~50 ms |
| M2  | Raft learners                             | evaluation replicas in the same authority         | <= ~100 ms                         |
| M4  | Cursor-based change feed, inter-authority | registry, revocation, domain-level data, pointers | any distance                       |
| M5  | PostgreSQL replication                    | SQL-backed drivers per authority                  | same distance rule                 |
| M6  | Trust bundle exchange                     | SPIFFE federation bundles, issuer JWKS            | any distance                       |
| M7  | Object-store snapshot bundles             | seeding learners, re-seeding feed consumers       | any distance, resumable            |

(M3, an intra-authority feed for far replicas, is dropped; see Alternatives. The
reservation group of section 4 is an M1 group that is exempt from its distance
rule.)

Raft never crosses an authority, except the identity-free reservation group
(section 4). **Inside an authority, evaluation replicas are only Raft
learners**: they reuse today's state machine and `StorageApi`
(`ReadConsistency::Local`) and add the learner role and `max_staleness`. A
region beyond the M2 limit, or one that is often partitioned, becomes its own
authority instead of a stretched replica. The WAN fixes in the prerequisites may
raise the M2 limit later; until measured, ~100 ms is the rule.

**Inter-authority feed (M4).**

- The outbox is a keyspace written by the state machine on apply, keyed by Raft
  index (the version). Every voter holds the same outbox, so any voter can serve
  the feed and a cursor survives leader change **[proposed]**. Retention is
  bounded separately from the Raft purge policy. Only the event kinds M4 carries
  are written to it, not every keyspace.
- **SQL-backed source drivers** (resource, role, assignment, revoke, and the
  trust-record and invitation stores when they are SQL) do not write through the
  state machine, so they have no Raft outbox. The outbox is therefore a driver
  seam, as in ADR 0035: `raft` (above) and `sql`, an outbox table written in the
  same transaction as the mutation, with ADR 0035's relay. Its cursor is a
  sequence assigned at commit, not at insert: a `BIGSERIAL` allocated before
  commit lets a reader pass a gap that a slower transaction fills later, so the
  relay reads only up to the oldest in-flight transaction's horizon (details in
  the companion plan, open item 3). A source authority may mix drivers; each
  kind has one outbox and the feed merges them per kind.
- A consumer is the receiving authority's core. It opens an mTLS stream with a
  filter, receives events after its cursor, and **applies them through its own
  providers** (resource foreign-domain source, revoke, assignment, role), which
  write to whichever driver is configured (Raft or SQL), together with the
  cursor, idempotently. No new storage mode: the received data reaches local
  learners through local Raft like any other write. The volume is small
  (registry, revocations, domain-level data, pointers).
- The source decrypts with its DEK and sends plaintext over the mTLS stream; the
  consumer stores it under its own DEK. No DEK leaves its authority.
- Filters by event kind and domain are bound to the subscriber's SPIFFE
  identity. **Tier 2/3 keyspaces and single-use keyspaces (ADR 0044) are never
  on the feed**, whatever the filter.
- The head is advertised on every heartbeat so silent partitions are detected. A
  consumer that falls off the outbox loads a resumable bundle (M7) and continues
  from its index.
- Revocations use a separate priority stream.
- Feed protocol, filter language and retention will be specified in a companion
  plan (open item 3).

### 4. Registry

- The registry is global: every authority holds a full replica and stage 3 does
  not work without it. It is replicated to every authority through M4: domain
  id, name, enabled flag, home authority, issuer, trust bundle, parts, the
  domain's **project locator**, `allowed_authorities`, `guardrail_version`,
  authority records, global role names.
- **Project locator.** The domain's home publishes
  `(domain-id, project-id) -> authority` for every project of the domain, from
  the name claims it already serves (section 1), so locating a project costs no
  extra write. Routing (section 6) and the proxy find a project's authority
  here. The home's reply to a claim carries the entry; the authority holding the
  part applies it to its own replica before answering the create
  (read-your-writes) and the feed delivers it everywhere else. The home stays
  the only writer. Entries are keyed by domain, so a peer that homes a domain
  and claims a victim's project UUID adds a second entry and cannot remove or
  shadow the first. A request that names the domain routes by the pair. A bare
  project ID routes only if exactly one domain lists it; otherwise the request
  fails with an error naming the domains, and the duplicate raises an alert.
  Security checks never use a bare project ID (section 1). Authority-local
  domains have no locator; their projects are never addressed from outside.
- **Partitioned by home; no global writer.** Each record has exactly one writer:
  an authority writes its own authority record and the records of the domains it
  is home of; the authority holding a part writes that part's record. Every
  authority serves the whole registry from its replica. Losing an authority
  stops writes to its own records only; there is no failover to design for a
  temporary loss. A permanent loss of a domain's home is not handled here (open
  item 9).
- **Mesh-wide uniqueness without a home-grown protocol.** The cross-writer
  constraints are uniqueness of domain IDs, domain names, issuers and global
  role names. They are met by construction where possible and by standard Raft
  where not:
  - **Issuers by construction.** A domain's issuer is
    `<authority base URL>/v4/oauth2/<domain_id>` (ADR 0026). The base URL is in
    the authority record and pinned by every peer at join (bilateral). It is
    reserved in the reservation group (below) in the same step that adds the
    joiner's voter, so two authorities that never pinned each other still cannot
    share a base URL. Given unique domain IDs, issuers are unique without
    further coordination.
  - **Domain IDs, domain names, global role names and authority base URLs in a
    reservation group** **[proposed]**: a separate openraft group, the same Raft
    implementation as each authority's core, with one voter per authority. Its
    state machine holds only reservations `(kind, value) -> (authority, ref)`,
    where `ref` names the domain, role or authority record, with compare-and-set
    semantics: a claim commits if the value is free, otherwise it fails with the
    holder. After commit the home publishes the domain record as before; records
    stay partitioned by home and are never written through this group.
  - **Reservation lifecycle.** A claim commits as `pending`; the home marks it
    `confirmed` once the registry record is published. The home reconciles its
    own pending claims at start and on a timer: it confirms those whose record
    exists and releases the rest, so a crash between claim and publication does
    not hold a name forever. Only the holder releases its reservations, on
    domain or role deletion. A rename is one compare-and-set that claims the new
    name and releases the old in the same entry.
  - The group holds no identity data (no users, groups or credentials), so it
    does not cross a residency boundary any more than the registry already does.
    It has its own FjallDB instance and its own DEK, wrapped to every member's
    site keys (section 11.2), and never shares a log, DEK or keyspace with an
    authority's core.
  - Cost: one cross-continent commit (150-300 ms) per registration, rename or
    global role creation, which are rare admin operations. Election and
    heartbeat timeouts are set for WAN RTT. A partitioned minority cannot
    register or rename; reads, checks and everything already registered are
    unaffected, since the published records live in the registry, not in the
    group.
  - With two authorities a two-voter group needs both. An operator who wants
    registration during a partition adds a third voter in a third location; it
    holds only reservations, so it may sit in any jurisdiction.
  - Alternative standard implementation: an etcd cluster with one member per
    authority, using transactional compare-and-create on the key. Rejected as
    the default only because it adds a second consensus system to operate; it
    remains a valid driver behind the same reservation interface.
- **Joining the mesh** is bilateral: the operators of the joining authority and
  of each peer pin each other's trust bundle (M6). The joiner then publishes its
  authority record.
- **Registration, not allocation.** A domain keeps its locally generated UUID.
  Registering it reserves the ID and the name mesh-wide; a collision is
  rejected. Joining a mesh registers the authority's existing domains that the
  operator selects; the `default` domain is never registered.
- The resource provider gets a foreign-domain source: local table first, then
  the registry replica behind `get_domain_ref` and `get_domain_enabled`; the
  auth and token callers stay unchanged.
- Attaching a part is a synchronous operation between the domain's home and the
  target that installs the domain record before any project exists; elsewhere
  propagation is eventual and fail-closed (`DomainNotFound` until delivered,
  optional on-miss lookup at the domain's home).
- Disabling a domain is a revocation event. Deleting a mesh domain requires all
  its parts to be detached first (a part detaches only when it holds no
  projects).

### 5. Cross-authority tokens: scope-less, validated without the user

**Cross-authority access uses only the scope-less model of the vision.**

- The home authority issues the vision's access token (ADR 0026, vision §4.3):
  `iss`, `sub`, `aud`, `exp` (about 15 minutes), `jti`, `amr`, `act`,
  `delegation_context`, `restrictions`, group claims, and no scope or roles.
- The caller names the target per request (`OpenStack-Target`) or the target is
  derived from the addressed resource. The target authority's evaluation plane
  answers `/v4/authz/check` against its own assignments, which reference
  `(issuer, principal-id)` or mapped groups. The target never calls home on the
  request path.
- **User-less validation.** For a token whose `iss` is a trusted foreign issuer
  (from the registry), the validation path does not load the user. The principal
  is built from the verified claims (a federated-principal identity, distinct
  from `IdentityInfo::User`); `get_user_core`/`get_user` are not called. User
  and domain liveness come from the priority revocation stream (section 9) and
  the token TTL, not from a local user record. Tokens of the local issuer keep
  today's path.
- **Issuer keys are published before they sign.** ADR 0026 §3 promotes a pending
  key to active in one step, which is safe only when every verifier reads the
  same Raft. Foreign verifiers receive JWKS over M4/M6, so a mesh issuer adds a
  **Next** generation: a new key is published (JWKS and feed) for at least the
  tolerated feed lag before it becomes active **[proposed]** (amends ADR 0026
  for mesh domains; text in appendix A). A verifier that meets an unknown `kid`
  from a trusted issuer fetches that issuer's public JWKS once (rate limited,
  cached) and otherwise fails closed. Emergency rotation skips the wait; the
  revoked `kid` travels on the priority stream and foreign verifiers use the
  on-miss fetch for the new one.
- **Delegation boundary in the token.** When a token's audience reaches beyond
  the home authority, `delegation_context` carries the complete boundary signed
  by home: `grant_id` / application-credential id, the delegated roles,
  `delegated_project_id` together with `delegated_authority` (the project's
  owner, from the locator at minting), and `root_jti` for on-behalf-of chains.
  Role IDs are per authority, so mesh-audience tokens name roles by a
  mesh-stable reference: the global role **name** (global role names are in the
  registry and resolve to local IDs at each authority), or
  `(domain-id, role-id)` for domain-specific roles, which replicate with the
  domain's data and keep their IDs **[proposed]**. Implied roles are expanded at
  the target. The target's check intersects live roles of `sub` on the target
  with these roles and, when set, requires its own authority ID to equal
  `delegated_authority` and the target to equal `delegated_project_id`, as ADR
  0036 §7 does with the grant record. Revoking or changing a grant, or deleting
  an application credential, is a priority revocation event; staleness is
  bounded by the token TTL. The security-model invariants hold: the boundary is
  a chain fact from the verified token, never from scope or from the calling
  service.
- **Group claims are filtered by audience.** A mesh-audience token names its
  target authorities in `aud` (the caller asks for them, or home uses the
  authorities in the user's reverse index, section 8). Home includes only the
  groups that have grants in those authorities: the reverse index records group
  principals as well as users, and home knows its own domains' cascading group
  assignments. A group granted something at a target after minting becomes
  effective with the next token (at most one TTL). If the filtered list still
  exceeds the size limit, home refuses to mint (explicit error) rather than
  truncating **[proposed]**. A group membership change at home is a revocation
  event for the member's outstanding tokens.
- **v3 scoped tokens are authority-local.** A v3 token is scoped only to
  projects and domains of the issuing authority. v3 trusts do not cross
  authorities; deferred cross-authority automation uses ADR 0036 service grants.
- **Compatibility shim.** A legacy consumer that needs a target-local scoped
  token (keystonemiddleware without `/v4/authz/check`, Horizon) gets it through
  an RFC 8693 token exchange at the target **[proposed]**:
  - Input: a home mesh token whose `aud` includes the target authority, and one
    target project (or domain) as the requested scope.
  - The target verifies the home token offline, computes roles from its own
    assignments for `(iss, sub)` and the filtered groups, intersected with the
    delegation boundary and minus the roles denied by guardrails (section 13),
    and mints a v3 token under its own issuer.
  - The minted token records the foreign principal (`iss`, `sub`, groups,
    `delegation_context`) instead of a local user ID, so it is validated through
    the same user-less path. It is scoped to exactly that one target, its expiry
    is not later than the home token's, it cannot be rescoped or used to obtain
    another token, and it carries the home token's `jti` as `root_jti` so
    revoking the home token revokes it.
  - A home token bound by DPoP (`cnf.jkt`) is refused: a v3 token cannot carry
    the binding, so exchanging it would turn a sender-constrained token into a
    bearer token (security-model I11, section 12).
  - The v3 rendering of the foreign principal (`token.user`) uses a derived ID,
    UUIDv5 of `iss` and `sub`, never the bare `sub`: services that store or
    compare `user_id` (owner checks, quotas, audit) must not confuse a foreign
    principal with a local user whose ID happens to equal `sub`. The domain is
    the principal's home domain from the registry.
  - No payload in today's providers can hold a foreign principal (open item 5).
  - Python Keystone's SAML Keystone-to-Keystone federation is not used; see
    Alternatives.

### 6. Routing and API shape

- **Authentication is never proxied or redirected.** Login, credential and
  token-issuing endpoints (including the OAuth2 token endpoint and assertion
  endpoints) are served only by the user's home authority (its core, and its
  replicas under section 2.1). A foreign authority rejects such a request with
  an error that names the home authority's issuer; clients discover the endpoint
  from the registry/catalog. No secret ever transits a foreign authority.
- Clients talk to their regional endpoint for everything else; any node answers.
  **Proxy by default** **[proposed]**: a node forwards a request for a record
  homed elsewhere over mesh mTLS (SPIFFE), with a hop limit, idempotency keys
  for writes and `served-by`/version in responses. The target authorizes against
  the caller's credential, never the proxy's identity. Redirects are opt-in.
- **DPoP (ADR 0043) is verified at the edge.** The node that receives the
  request verifies the proof against its own `htu`/`htm` and its local `jti`
  cache. When it proxies, it forwards the access token plus a
  proof-of-possession attestation (`jkt`, verified-at, its SPIFFE ID) signed
  over the mesh mTLS session. The target trusts the proxy only for proof of
  possession, checks the attested `jkt` against the token's `cnf`, and
  authorizes on the token. A request sent directly to the target is verified
  there as usual.
- **Idempotency keys** for proxied writes are stored at the target core, keyed
  by `(sub, key)`, retained for the client retry window (24 h default)
  **[proposed]**.
- **Targeting at create time.** Primary: call the target authority's own
  identity endpoint (found in the catalog by `authority_id`/region).
  Convenience: a routing header (`OpenStack-Authority`) lets a client with one
  endpoint target another authority; payloads are unchanged in v3. A v4 field
  `authority` may follow. Default when unspecified: the receiving authority if
  it holds or may hold a part of the domain, otherwise the domain's home. After
  creation everything routes by id: a project through the domain's project
  locator (section 4) by `(domain-id, project-id)`, a bare project ID only when
  it is unique, a domain through its registry record.
- **Listings** default to the local view; a global view of a domain is explicit
  (`authority=all`), fans out only to the domain's parts, and marks unreachable
  authorities. Results carry `authority` and endpoint.

### 7. Administration across authorities

- **Attaching a part** (once per domain per authority): registry operation
  permitted by the domain's `allowed_authorities` and by the target's admission
  policy (which domains it accepts, quota). Target-local admins own admission,
  with a mesh-level default **[proposed]**. The attach installs a default
  assignment: the domain's home manager group becomes domain manager of the
  part. Local admins of the target can narrow or revoke it (opt-in with default
  roles) **[proposed]**.
- **Creating a project** in a foreign part: the request reaches the target
  authority (section 6), which claims the name at the domain's home (section 1)
  and authorizes the federated manager under Keystone's domain-manager
  semantics.
- **Granting** a role on a foreign project to home users or groups: stored in
  the target authority (ADR 0034). Grants to principals of the same domain are
  allowed to the domain's managers as today. The target cannot check that the
  principal exists (user data never crosses); it stores the reference and sends
  a pointer event to the principal's home, which confirms or flags it. A flagged
  grant is marked `dangling` in the target's listings and audit, and is never
  deleted automatically (home may only be lagging). It is harmless: IDs are
  UUIDs and are not reused.
- **Cross-domain grants to individuals use invitations** (ADR 0046, draft): a
  manager of the target domain offers roles bounded by their own; the invitee
  accepts at the target authority with a mesh token (non-delegated, verified
  user-less, recently authenticated; G11). The grant is created for `(iss, sub)`
  of the accepting token, so it is never dangling, and the accept sends the
  pointer event to home. Mesh adjustments to that draft: the inviter's liveness
  comes from the target's own assignments and the revocation stream, not a user
  lookup; an email-constrained invitation is matched by asking the invitee's
  home "does `sub` have verified email hash H" (yes or no), never by putting the
  email in the token; invitations live, and are previewed and accepted, at the
  authority that owns the target.
- **Cross-domain grants to groups, and direct grants without an invitation,**
  need a **trust record** **[proposed]**: one-way, created by an admin of the
  granting domain, stored with that domain's data, naming the trusted principal
  domain, the roles that may be granted to its principals and an expiry. Without
  a record, only invitations cross domains. Deleting or expiring the record is a
  revocation event for the grants it allowed.
- System-scope roles stay authority-local (ADR 0034); no mesh-level system role
  initially.
- Role definitions: each authority defines its global roles; the registry
  carries global role names, and delegation boundaries and trust records
  reference global roles by name. Domain-specific roles replicate with the
  domain's data.

### 8. Actor-keyed queries: reverse index at home

Target-keyed storage makes actor-keyed queries (`GET /v3/auth/projects`, role
assignment listings, SCIM group delete) scatter queries. A target authority
sends a pointer event `(issuer, principal-id) -> authority` to the principal's
home on every grant create/revoke; principals are users and groups. The index
also selects the groups carried in mesh tokens (section 5). The home answers
"where can this user act" locally; fan-out to a domain's parts is the fallback
and consistency check.

### 9. Revocation

- Events: user disabled or deleted, domain disabled, group membership change,
  service grant revoked or changed, application credential deleted, trust record
  deleted or expired, signing key revoked (`kid`), token revoked (`jti`, or
  `root_jti` for on-behalf-of chains).
- Fan-out set. User, group-membership and domain events go to every authority
  that trusts the issuer (the whole mesh unless an operator restricts issuer
  trust). The volume is small, and a grant created by invitation is known to its
  target only through the reverse-index pointer, which must not be a condition
  for revocation. Events about a grant, trust record or application credential
  go to the authority holding it, the authorities in the principal's reverse
  index and every authority holding a part of its domain. The reverse index is
  the query path (section 8), not the revocation path.
- Applied at every authority in the fan-out set within 30 s via the priority
  stream. Beyond `max_staleness` sensitive operations fail closed; others
  degrade per caller policy **[proposed]**. The access-token TTL (about 15
  minutes) is the backstop.

### 10. Interaction with other ADRs

- **ADR 0044:** authentication happens only at the home core, so the single-use
  store keeps its `(domain_id, issuer)` scope against that core's Raft. A
  domain's external identity-provider configuration lives only at its home;
  target authorities never serve the assertion endpoint (section 6). Evaluation
  replicas cannot consume and forward authentication to the core. Single-use
  records are not sent on the feed.
- **ADR 0043 (DPoP):** proof verification and the `jti` cache are local to the
  verifying node (the edge, section 6); the `/token` nonce stays with the home
  authority, which is the only issuer of the token.
- **ADR 0036:** service grants and on-behalf-of exchange happen at the grantor's
  home; the delegation boundary travels in `delegation_context` (section 5)
  instead of being fetched from `GET /v4/service-grants/{id}` across
  authorities.
- **ADR 0026:** cross-authority tokens are its access tokens without
  `openstack_context`.
- **ADR 0034:** unchanged; extended by the reverse index for actor-keyed
  queries.
- **ADR 0046 (domain member invitations, draft):** the path for cross-domain
  grants to individuals (section 7).

### 11. Zero trust: per-site roots of trust, trust domains and keys

Each site has its own Tier 1 root of trust: SPIRE server(s), OpenBao and SPIRE
PostgreSQL, federated with the other sites by bundles only. No site holds
another site's CA key or Bao material; there is no flow from a node to another
site's Bao.

**11.1 Trust domains and roles.**

- **An authority is a set of one or more SPIFFE trust domains**, recommended one
  per site: one for each core site and one for each evaluation site, all
  federated with each other and with other authorities. A nested downstream
  server inside a single trust domain would let a compromised site server mint
  any SPIFFE ID in that domain, including a core voter; per-site domains confine
  it. A single trust domain per authority remains valid for small deployments.
- **A role is bound to a full SVID, not to a path or a trust domain.** A path
  segment is chosen by whoever registers the workload in SPIRE, and a trust
  domain holds many workloads, so neither can say which peer is the voter. The
  receiver keeps a table from full SPIFFE ID to roles: one SVID may hold several
  roles (a core node is `node` and `voter`), and two workloads of one trust
  domain may hold different ones. A listed SVID holds exactly its listed roles
  whatever its path says. In a trust domain with no entry, an SVID resolves
  only `node` and the operator role, by the existing path convention or the
  allow-list. A trust domain with any entry is managed by its entries alone, so
  a compromised registrar there cannot mint `node` or the operator by path.
  Every other role (`voter`, `learner`, `eval-replica`, `feed-consumer`,
  `proxy`, `reservation-voter`) is granted by the table only. A role check
  passes when any role of the peer is allowed for the RPC.
- **The authority record drives the table.** It lists the authority's trust
  domains and, for each, the SVIDs and their roles. The trust domain still
  bounds what may be bound: `voter` only in the core trust-domain set; `learner`
  and `eval-replica` in the listed evaluation sites; `feed-consumer` and
  `proxy` for authority-to-authority peers, and `reservation-voter` for their
  reservation-group voters, with the federated trust domain pinned. The node
  checks that every bound SVID is in one of its trusted domains. The role and
  domain matrix is enforced where the table is produced from the record; the
  first step reads the table from the site configuration (`peers` in
  `site.toml`), and reading it from the registry is open item 11.
- **A node chooses the SVID it presents by role.** A workload may match several
  SPIRE entries (its node identity, a reservation-group identity, a feed
  identity), and the Workload API returns them in no meaningful order, so the
  node names them: a list of its own SVIDs with the roles each is used for
  (`identities` in `site.toml`). A connection made for a role (replication as
  `node`, the reservation group as `reservation-voter`, the feed as
  `feed-consumer`) presents the SVID listed for that role. SVIDs are matched on
  the full SPIFFE ID, trust domain included: matching the path alone is
  ambiguous once a workload holds SVIDs from several trust domains. A role is
  served by one SVID only, and the list must serve `node`, whose SVID is also
  the one the Raft listener presents. Without the list a node keeps the single
  path-pinned SVID for every role.
- Not covered yet: the dialing side authorizes the server by trust domain
  only, so it does not check that the server holds the role it is dialed for
  (open item 11).
- SVID lifetime and the 30-day leaf limit are unchanged. Renewal is local to the
  site, so partitions do not stop it.
- **Bundles across partitions.** A peer keeps the last bundle it fetched, so
  trust survives a partition only while the CAs in that bundle still sign the
  other side's SVIDs. With SPIRE's self-signed CA (short `ca_ttl`, rotated
  roughly every half-life) that is hours. Each site therefore runs SPIRE under
  an `UpstreamAuthority` backed by its own Bao PKI with a long-lived root
  (years) **[proposed]**: the federated bundle then carries a stable root, and
  intermediate rotation does not need a bundle refresh. Tolerated partition =
  the shortest remaining root validity minus a margin; root rollover publishes
  the new root in the bundle long before the old one stops signing. To verify
  against the deployed SPIRE version (open item 4).
- Each site's SPIRE confines a compromise to its own trust domain. Toward other
  authorities, feed filters bound to the subscriber identity and the exclusion
  of Tier 2/3 from the feed stop a rogue peer from obtaining credentials. Inside
  an authority, a learner holds the DEK and the whole log, including Tier 2/3
  (hashed credentials): every site hosting a learner is inside the authority's
  credential boundary. An operator who does not accept that for a site makes the
  site its own authority instead.

**11.2 KEK and DEK.**

Scope: this applies inside one authority, only when its Raft members (voters or
M2 learners) span more than one site. The reservation group (section 4) uses the
same wrap over the site keys of every member authority; its DEK is its own and
is never an authority's DEK. Since evaluation replicas are learners, every site
that hosts one is in the wrap set. Other authorities never receive the
authority's DEK (item 6), so a single-site authority keeps today's `transit`
provider.

1. Each site's Bao holds an asymmetric Transit wrapping key (RSA); its public
   key is published in the registry and in Raft. The private key never leaves
   that Bao (assumption: Transit RSA key type and public-key export in the
   deployed OpenBao; fallback: a software-held site key under that Bao's own
   KEK).
2. The leader wraps each DEK version **offline** to every site's public key
   (RSA-OAEP-SHA256) and writes one blob per site
   (`_meta:dek:wrapped:<site>:<version>`). The context
   `cluster_id || dek_version || site` is bound inside the wrapped plaintext and
   checked after unwrap, so the scheme does not depend on Transit supporting an
   OAEP label. No Bao call, no plaintext DEK on the network.
3. A node unwraps its own site's blob with its local Bao (Transit decrypt,
   JWT-SVID auth) at start and on rotation. All nodes need only `decrypt` on
   their site's key.
4. Onboarding a site: register its public key; the leader wraps the current and
   retained DEK epochs to it before the first node joins. Site loss: replace by
   onboarding. Site key rotation: rotate the Bao key, publish the new public
   key, the leader rewraps that site's blobs, the old private key stays until
   all are rewrapped.
5. Single-site authorities keep the `transit` provider (symmetric wrap of one
   blob); the per-site scheme is an additional provider (`transit-per-site`).
6. Other authorities have their own DEK and site KEK, never receive the
   authority's DEK, and receive plaintext over the M4 mTLS stream which they
   store under their own DEK: no `FetchDek`, no cross-authority restart
   dependency.
7. Rotation cost scales with the number of sites (one wrap each), not nodes.
   Per-node cost stays one Transit decrypt per start and per DEK rotation,
   against the node's own site's Bao, so a fleet restart loads only that site's
   Bao.
8. Token signing keys stay with key-repository; their JWKS travel on M4 and are
   published before use (section 5).
9. Crypto inventory: RSA-OAEP wrapping is a new primitive; add its row to
   `doc/src/contributor/crypto-inventory.md` and the `// Crypto inventory: <ID>`
   marker, and route it through the `storage-crypto` backend seam so it can use
   the FIPS module.

**11.3 Resilience.**

| Event                   | Response                                                                                                                                            |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| A site's Bao down       | its nodes keep the in-memory DEK; restart blocked until it returns; other sites unaffected; quorum unaffected while a majority of voters is healthy |
| A site's SPIRE down     | renewal for that site stalls until leaf lifetime and margin run out; federated bundles keep other sites trusted                                     |
| A core site lost        | remaining voters keep quorum (for example 2 of 3); replacement site onboarded (11.2.4) and federated before nodes join                              |
| Partition between sites | each side keeps its own SPIRE and Bao; the quorum side continues; evaluation replicas serve to `max_staleness`                                      |
| A site's CA compromised | remove that trust domain from all peers' bundles (trust reset scoped to one site); drop its public key from the wrap set and rotate the DEK         |
| SPIRE DB                | one PostgreSQL/Patroni/etcd cluster per site inside the site's Tier 1 boundary; no cross-site DB replication                                        |

### 12. Security model for foreign principals

The mesh adds a trust boundary that `doc/src/contributor/security-model.md` does
not cover: a principal whose authentication chain was established by another
authority and arrives only as signed claims. The rules below extend that
document's invariants. They are numbered `G1`-`G16` so they can be added there
as one section when this ADR is accepted. Each names what can go wrong without
it.

- **G1. Issuer binding.** A token is accepted from a foreign issuer only if the
  registry maps its `iss` to a mesh domain, that domain's record names a home
  authority, the `iss` starts with that home's pinned base URL, and the `kid` is
  in that home's published key set for that issuer. Issuers are unique by
  construction (section 4), so two records can never claim one issuer. Keys are
  fetched only from the registry-listed endpoint over mesh mTLS; `jku`, `x5u`
  and embedded keys in the token are ignored. _Without it:_ a compromised
  authority signs tokens for users of a domain homed elsewhere.
- **G2. Audience.** The target requires its own authority ID in `aud`. A token
  without `aud`, or whose `aud` is only its home, is refused outside home.
  _Residual:_ a token naming several authorities is a bearer credential at each
  of them; callers that do not need several should request one, and DPoP
  (section 6) removes the residual.
- **G3. Principal namespace.** A foreign principal is always the pair
  `(iss, sub)`. Assignment lookups, owner comparisons and policy input never
  match on `sub` alone, and `Credentials.user_id` is empty for a foreign
  principal; policy sees `principal_issuer` and `principal_id` instead. The v3
  shim uses the derived ID (section 5). _Without it:_ a foreign `sub` equal to a
  local user ID inherits that user's grants or passes an "own resource" rule.
- **G4. Home-only self-service.** Credentials, application credentials, trusts,
  EC2 credentials, MFA rules, passwords and OAuth2 clients of a principal are
  created only at its home. A target refuses these operations for a foreign
  principal with a "home is X" error (as section 6 does for login). _Without
  it:_ a target stores a delegation for a principal it cannot check, and the
  delegation outlives a disable at home.
- **G5. Delegation facts from the verified token (I1, I2, I4).**
  `delegation_context` is the chain for a foreign principal. A token whose
  `delegation_context` is present but lacks `delegated_project_id` is refused
  outside home, as is one with `delegated_project_id` but no
  `delegated_authority`. The target is compared to the pair
  `(delegated_authority, delegated_project_id)` and never taken from
  `OpenStack-Target` alone; I3's tripwire becomes "own authority and resolved
  target equal that pair" and runs in both Rust and Rego. _Without the
  authority:_ a peer that creates a project with the same UUID passes the check.
  Effective roles are `live roles of (iss, sub) at the target ∩ boundary roles`,
  after implied-role expansion at the target, on every request and in the shim.
- **G6. Role references are names, so names are reserved.** Global role names in
  the registry are reserved like domain names. A delegation boundary or trust
  record may not name roles that an authority marks non-delegable (system
  `admin` and service roles by default). _Residual:_ "reader" at a target means
  whatever that authority's implications say; the registry entry records the
  implied-role closure each authority publishes for a global role, so an
  operator can see a difference before it matters.
- **G7. Groups in the token are cached facts (deviation from I9).** I9 relies on
  re-resolving group membership on every validation; a target cannot, since
  membership stays at home. The membership in the token is trusted for at most
  one TTL, and a membership change at home is a user-bound revocation event
  (section 9). Group IDs in claims are qualified by `iss`; a target never
  matches them against its local groups.
- **G8. Liveness is bounded, not checked.** A disabled user, domain or grant
  keeps access at a target until the event arrives (30 s target) or the token
  expires (about 15 minutes). Beyond `max_staleness` the default is fail closed
  for writes and for every operation of a role marked sensitive; reads degrade
  only where the caller's policy allows **[proposed]**. Each target exports the
  age of the last event from each authority as a metric.
- **G9. Who may revoke what.** A revocation event is accepted only from the
  authority that owns its subject: the home of the user, domain, issuer or
  `kid`, or the authority holding the grant, trust record or invitation. Events
  only add revocations; there is no event that restores access. _Without it:_ a
  rogue peer revokes another authority's keys (denial of service).
- **G10. Trust records pin identities, not names.** A trust record names the
  trusted domain by ID and issuer. A rename does not change it; deleting and
  re-registering a name does not inherit it.
- **G11. Invitation accept.** The accepting token must be non-delegated, carry
  the target in `aud`, have been authenticated recently (`auth_time` within the
  invitation's `max_auth_age`, default 10 minutes) and, if the domain requires
  DPoP, be bound. The grant is for the token's `(iss, sub)`. The email check
  asks home about the token's own `sub` only, sends the accepting token as
  proof, and is answered once per invitation; home answers yes or no and rate
  limits per target. _Without it:_ the yes/no answer becomes an oracle for
  guessing any user's email address.
- **G12. Exchange shim (I4, I5, I11).** The shim refuses bound home tokens, does
  not issue a token usable as a `token` auth method, cannot be rescoped, carries
  the boundary of the home token and `root_jti`, and expires no later than the
  home token. It is not available for delegated home tokens unless the target
  equals `(delegated_authority, delegated_project_id)`. Roles denied by a
  guardrail are removed before minting (G16).
- **G13. Proxy attestation (I11).** The attestation covers `jkt`, `ath`, the
  original `htm`/`htu`, a timestamp and its own `jti`; it is valid for 30 s and
  the target keeps a replay cache of attestation `jti`s. Only SVIDs with the
  `proxy` role may attest. _Residual:_ a compromised proxy can use a bound token
  it has stolen. That is the same exposure as a compromised edge that verifies
  DPoP itself, and it is confined to tokens that pass through that proxy.
- **G14. Audit.** The initiator of an action by a foreign principal is
  `(iss, sub)` from the verified token plus the delegation identifiers, built
  from the chain like any other initiator; a proxy appears as `observer`, never
  as initiator.
- **G15. Replica-issued tokens.** A token signed by a continuation key (section
  2.1) is accepted only if its `kid` is one of the home authority's site keys
  listed for that issuer and marked `continuation`, it carries
  `auth_plane: "replica"`, and its last-core-issue time is within
  `continuation_max`. Policy input exposes `auth_plane`; replicas never mint a
  token without it, and a token whose `auth_plane` disagrees with the key that
  signed it is refused. Other authorities accept such tokens by default; an
  authority guardrail may refuse them. _Without it:_ a site key signs tokens
  that look core-issued and escape the guardrails written for replica tokens.
- **G16. Guardrails (section 13).** Deny is evaluated before allow on every path
  that grants access: `/v4/authz/check`, Keystone's own enforcement, v3 token
  issuance and the exchange shim (role-level rules). Principal selectors match
  only chain facts (G5); an unevaluable condition denies; a target whose rules
  are older than its registry's `guardrail_version` fails closed as section 13
  says. _Residual:_ operation-level rules do not bind a legacy service that
  enforces with local oslo.policy (section 13).

### 13. Deny guardrails

Grants (assignments, invitations, trust records) only add access. A domain that
spans authorities also needs to forbid things everywhere, whatever any part
grants, as AWS service control policies, GCP deny policies and Azure deny
assignments do. Guardrails are available from stage 1; the mesh only adds their
replication.

- **Shape** **[proposed]**: a deny rule follows GCP IAM deny policies
  ([deny policies](https://docs.cloud.google.com/iam/docs/deny-overview)):
  `denied_principals`, `exception_principals`, `denied_operations`,
  `exception_operations` and an optional `condition`. It is data, evaluated by
  one fixed rule set shipped with Keystone (`policy/guardrail/`); tenants never
  write Rego.
- **Attachment points:**
  - `domain:<id>`: applies to the domain and every project of it, in every
    authority that holds a part.
  - `project:<authority>:<id>`: applies to the project and its subtree (inside
    one authority, section 1).
  - `authority:<id>`: applies to everything the authority owns, including parts
    of foreign domains. This is the target operator's own sovereignty control
    (for example "no principal homed outside the EU may read secrets here").
- **Principal selectors**, all from the verified authentication chain (G5),
  never from scope or `context`: `(iss, sub)`; a group `(iss, group-id)`; every
  principal of an issuer; every principal homed in an authority; any delegated
  token; an on-behalf-of actor (matched against `act`); `*`.
- **Operations**: patterns over the vision's operation vocabulary
  (`<service-type>:<resource>:<verb>`, `*` allowed). Until the vocabulary
  exists, a rule may deny a role on the target instead, which removes it from
  the effective role set.
- **Conditions**: CEL, the language of GCP IAM conditions, restricted to a
  closed set of attributes: target authority, principal's home authority, `amr`,
  `auth_plane` (section 2.1), DPoP binding, delegated or not, and resource tags.
  A condition that cannot be evaluated counts as true, so the deny applies (as
  in GCP).
- **Evaluation**: deny is checked before allow, in `/v4/authz/check` and in
  Keystone's own policy enforcement, at the authority that owns the target, on
  its local copy. Any matching rule denies; exceptions only narrow the rule they
  are written in. Rules per attachment point are bounded (default 500) to bound
  evaluation cost.
- **Legacy enforcement points.** A Python service behind keystonemiddleware
  enforces with its local oslo.policy and never calls `/v4/authz/check`, so an
  operation-level rule does not bind it. What binds there is the role level:
  Keystone removes denied roles when it issues a v3 token and in the exchange
  shim (section 5). An operator who needs an operation-level guardrail on such a
  service must move it to `/v4/authz/check`, or express the guardrail as a role
  deny.
- **Who writes**: domain rules by the domain's admins (not managers, who could
  otherwise lift a guardrail meant to bind them), stored with the domain's data
  at its home; project rules by admins of the domain at the owning authority;
  authority rules by that authority's system admins only. A part can never
  remove or override a domain rule.
- **Replication and freshness**: domain rules travel with the domain's data (M4)
  to every part. A new or tightened rule travels on the priority stream (30 s
  target); a relaxed or deleted rule on the normal feed, so a lagging target
  errs towards denying. The domain record carries `guardrail_version`. The
  version bump travels in the same event as the rule change that caused it
  (priority stream for tightening, normal feed for relaxing), so a target never
  learns a version before the rules behind it. A target whose applied rules are
  older than the version in its registry copy (possible only after a lost event
  or a re-seed) refuses the domain's mutating operations until it catches up,
  and refuses all of the domain's operations beyond `max_staleness`.
- **Minted v3 tokens.** A tightened rule does not change a v3 token that is
  already minted, by the exchange shim or for a local user: its denied roles
  stay until it expires (its own TTL) or is revoked. An operator who needs
  immediate effect revokes the affected tokens.
- **Audit**: a decision denied by a guardrail records the rule ID, so an
  operator can tell a guardrail denial from a missing grant.

## Consequences

### Positive

- Optional and incremental: a single deployment is unchanged; replicas and
  further authorities are added without rewriting IDs.
- User attributes and credentials stay in one authority by construction;
  residency enforceable. Only opaque identifiers cross (open item 10). No secret
  transits a foreign authority.
- Local-latency validation and authorization everywhere; a region or authority
  cut off keeps serving; independent failure domains; commit latency stays 1-3
  ms for a core in one region, one intra-boundary RTT (<= ~50 ms) for a core
  spread across sites (A1).
- No shared DEK or KEK across sites; no cross-site restart dependency.
- Logins survive a site loss (A1) and existing sessions survive a core outage
  (A2) without identity data leaving its boundary.
- Domain-wide deny guardrails bind every part of a domain, whatever a part
  grants.
- Same asymmetry as hyperscalers (concentrated writes, replicated evaluation)
  but distributed per authority. Builds on the vision's scope-less model rather
  than a mesh-specific token format.

### Negative

- A new control plane: registry, feed, reverse index, proxy routing.
- Cross-authority access requires the scope-less model (`OpenStack-Target`,
  `/v4/authz/check`) or the exchange shim; v3-only clients are limited to their
  home authority.
- Token validation gains a second path (foreign issuer, no user lookup) whose
  liveness depends on the revocation stream.
- Every verifier holds all trusted issuers' bundles; mesh tokens are bound to
  target authorities in `aud` and carry only the groups relevant there, so a
  group granted something new takes effect with the next token.
- Revocation, grant changes and domain changes are eventually consistent (30 s
  target, token TTL backstop).
- Cross-authority admin writes (project-name claims, domain registration,
  invitation acceptance) and global listings cost WAN round trips; partitions
  fail those operations. With two authorities, registering a domain needs both.
- A region too far for a Raft learner must become its own authority; there is no
  stretched far replica. Learner sites hold the DEK and hashed credentials, so
  they are inside the authority's credential boundary (section 11.1).
- Mesh domains rotate signing keys more slowly (a Next generation published
  ahead), amending ADR 0026.
- One Raft group spans authorities (the reservation group). It holds only names
  and IDs, but it is a cross-continent Raft to operate and tune.
- Replica authentication (section 2.1, A2-A4) trades freshness, and for A4
  lockout and replay strength, for availability; it is opt-in for that reason.
  Bearer tokens get no continuation, and workloads that log in with JWT
  assertions get no replica login.
- During a core outage revocation is local to each site (break-glass deny) until
  the core returns; other authorities do not see it before then.
- The registry is a global replica that every authority must hold, and it grows
  with the number of mesh projects (the locator).
- Operation-level guardrails do not bind legacy services that enforce with local
  oslo.policy; only role-level rules do. A tightened rule does not change v3
  tokens already minted.
- A deny entered at one site during a core outage does not reach the authority's
  other sites.
- Opaque identifiers (`sub`, group and project IDs) cross authorities and may
  count as personal data in some jurisdictions.

## Prerequisites

Stage 2 (inside an authority):

1. Learner-role local reads with applied index and `max_staleness`.
2. WAN-ready snapshot transfer (stream from disk, HTTP/2 windows, resumable),
   RPC timeouts honoring openraft's `RPCOption`, larger linearizable retry
   budget; object-store snapshot bundles (M7) for seeding learners.
3. Per-SVID role binding in `PeerAuthz` and the per-role SVID a node presents
   (section 11.1; done for the site-configured table, registry-driven table is
   open item 11); the `transit-per-site` KEK provider (offline RSA wrap per
   site) when Raft members span sites.
4. Availability inside the boundary (section 2.1): A1 is a deployment choice on
   top of item 3; A2 and A3 need per-site continuation keys, replica issuance,
   and the site break-glass deny store; A2 needs DPoP or mTLS binding (ADR
   0043); A4 needs replica-local counters and caches.
5. Deny guardrails (section 13) in Keystone's own enforcement, and in
   `/v4/authz/check` once it exists (item 6); not tied to a stage.

Stage 3 (mesh):

6. Scope-less access tokens, `OpenStack-Target` and `/v4/authz/check` (vision,
   ADR 0026, ADR 0036 §7) on the evaluation plane.
7. User-less validation path for foreign issuers (federated-principal identity
   in the security context), with security-model review.
8. Delegation boundary claims in `delegation_context` for mesh-audience tokens,
   with mesh-stable role references and `delegated_authority`; audience-bound
   group filtering.
9. Outbox and M4 feed applied through providers; priority revocation stream;
   reverse index for users and groups.
10. Global registry with records partitioned by home, including the project
    locator; the reservation group (an openraft group across authorities, or
    etcd) for domain IDs, domain names, global role names and authority base
    URLs, with pending/confirmed reservations; issuers derived from the pinned
    authority base URL.
11. Foreign-domain source in the resource provider.
12. Next signing-key generation and on-miss JWKS fetch (ADR 0026 amendment).
13. Proxy with edge DPoP verification and PoP attestation.
14. Domain member invitations (ADR 0046) with the mesh adjustments (section 7);
    trust records.
15. `sql` outbox driver for SQL-backed source kinds (section 3), when any of
    them is SQL.

## Open items before Proposed

Resolved in this revision: group claims (audience filtering, section 5),
registry failover (partitioned by home, section 4), cross-domain grants
(invitations plus trust records, section 7), bundle expiry (long-lived per-site
upstream roots, section 11.1), M2 versus M3 (learners only, section 3), security
rules for foreign principals (section 12, first pass), hyperscaler statements
(checked, Context), SQL-backed sources (outbox driver seam, section 3), ADR 0026
amendment text (appendix A), invitations numbering (ADR 0046), uniqueness
without a home-grown protocol (Raft reservation group, section 4), deny
guardrails (section 13), availability inside the residency boundary (section
2.1), project location and authority-qualified project references (sections 1,
4, G5), replica authentication bounds (DPoP-only continuation, no-replay A3,
per-site continuation keys, break-glass deny, G15), orphaned reservations and
base URL uniqueness (section 4), guardrails at legacy enforcement points
(section 13, G16).

1. Measure latencies (WAN test bed with netem), including the M2 limit and
   commits in the reservation group with WAN election timeouts.
2. Security review sign-off of section 12 by a second reviewer, then fold
   `G1`-`G16` into `doc/src/contributor/security-model.md` together with the
   checklist entries. Open within it: the `max_staleness` default for reads
   (G8), and whether multi-authority `aud` should require DPoP (G2).
3. Companion plan for M4: protocol, filter language, outbox retention versus
   Raft purge policy, the `sql` outbox commit horizon, apply-through-provider
   contract, reservation group (membership changes when an authority joins or
   leaves, the reconciliation timer for pending claims), size and delivery of
   the project locator for large domains (whole record or per-project events).
4. Verify against deployed versions: OpenBao Transit RSA key type and public-key
   export; SPIRE `UpstreamAuthority` on Bao PKI and federated bundle behaviour
   during partitions; federation topology (mesh vs hub). Consider a KEM instead
   of RSA before rollout; per-site Bao rotation duties and cross-site
   break-glass.
5. Exchange shim (checked against the code): neither token provider can carry a
   foreign principal today.
   - `token-driver-fernet` has a fixed msgpack layout per payload type (type
     codes 0-6, 8 and 9 from Python Keystone, 11 for restricted tokens). The
     closest, `FederationProjectScopePayload`, holds a user ID, group IDs,
     `idp_id` and `protocol_id`; it has no field for `iss`, `delegation_context`
     or `root_jti`. A new payload type with a Rust-only code outside Python's
     range is needed; such tokens are not readable by Python Keystone, which is
     acceptable because shim tokens are authority-local. Size: the group list
     and boundary make Fernet tokens long; the shim should cap them like the
     home token does (section 5).
   - `token-driver-jws` uses the Python-compatible claim set, with `sub` as the
     user ID; it needs new optional claims and the same Rust-only caveat.
   - Validation (`crates/core/src/token/service.rs`, `validate_to_context_impl`)
     always loads the user with `get_user`/`get_user_core` and resolves roles by
     user ID; the foreign payload needs the user-less branch of section 5.
   - Legacy consumers: keystonemiddleware `auth_token` in every Python service
     (validates through `GET /v3/auth/tokens`, so the response must render the
     derived user ID and home domain), Horizon (rescopes on every project
     switch, so it needs one exchange per project), Swift's `keystoneauth`
     (account from `project_id`), and services that store `user_id` on resources
     (Nova, Cinder, Glance). Heat is excluded: its trusts are v3 trusts and do
     not cross authorities.
6. ADR 0046 open question 6: whether target-domain groups are ever offered to
   foreign principals (would need target-side membership for `(iss, sub)`).
7. Section 2.1: defaults for `continuation_max` and `auth_max_staleness`;
   whether A4 should be offered at all, given its weaker lockout and replay
   protection; how replica audit is reconciled with the core; how the site
   break-glass deny store authenticates its operators (required before Proposed)
   and whether sites push entries to each other; whether a derived replay option
   (ADR 0044) later lets JWT-SVID join A3.
8. Section 13: whether CEL is adopted as is (a Rust CEL implementation becomes a
   dependency) or a smaller closed condition syntax is used first; whether a
   level above the domain (mesh-wide guardrails) is needed.
9. Authority leave and loss of a domain's home: transfer of the home through the
   reservation group (compare-and-set of the owner) and re-publication of the
   domain's records, name claims, locator and guardrails; detaching or re-homing
   parts. Companion plan.
10. Legal review of what crosses a boundary: pseudonymous `sub`, group and
    project IDs, audit records and the reverse index at the target. Decide
    whether a pairwise `sub` per target authority is needed.
11. Section 11.1: read the SVID-to-role table from the authority record in the
    registry instead of the site configuration, and generate it so the role and
    trust-domain matrix holds. Have the dialing side check that the server's
    SVID holds the role it is dialed for (today it checks the trust domain
    only), and let a listener present a different SVID per role if a single
    server SVID proves too coarse.

## Alternatives considered

- **One stretched Raft cluster with voters on every continent:** every write
  100-300 ms, one DEK/KEK across continents; rejected.
- **Cross-authority Raft learners:** requires the source DEK in every authority.
- **Replicating users or principal stubs:** violates residency.
- **Home mints v3 scoped tokens for foreign projects:** home needs foreign
  project records, roles are frozen at issuance against another authority's
  state, and scope becomes a cross-authority attack surface; rejected in favor
  of scope-less tokens.
- **Token exchange as primary path:** extra hop and shadow principals; not what
  hyperscalers do within one cloud; kept as optional shim for legacy consumers.
- **Python Keystone-to-Keystone federation (SAML ECP):** the identity provider
  turns a project-scoped token into a SAML assertion carrying user, roles,
  groups and project as attributes; the service provider maps the attributes
  through its mapping rules to a shadow user and local groups at every login.
  Rejected: a shadow user per principal at each service provider (residency);
  access decided by attribute patterns rather than explicit grants with consent;
  no revocation across the boundary (an assertion-derived token lives to expiry
  and nothing reports a disable at the identity provider); the delegation chain
  is lost; every pair of deployments needs its own metadata, certificate and
  `remote_ids` (N² setup); it needs a scoped token at the identity provider; and
  it requires a SAML stack (Shibboleth or mellon, xmlsec1). The exchange shim
  keeps the one useful property, a local v3 token for legacy consumers, with the
  bounds of section 5.
- **Fetching grant records from home at check time:** a call home on the request
  path; rejected in favor of the boundary in the token.
- **Registry-allocated domain IDs:** blocks growing an existing cloud into a
  mesh; rejected in favor of registration of local UUIDs.
- **Proxying or redirecting authentication:** exposes secrets to, or makes the
  login flow depend on, a foreign authority; rejected.
- **Project names unique per part:** breaks `(domain, name)` lookup and
  name-based scoping; rejected.
- **Intra-authority change feed (M3) for far replicas:** needs a second
  `StorageApi` implementation (read-only FjallDB without Raft, fed by a cursor)
  and a second consistency model for every driver; rejected in favor of learners
  only, with far regions becoming authorities.
- **Single writable registry owner:** needs failover design and makes one
  authority special; rejected in favor of records partitioned by home and a
  reservation group for uniqueness.
- **A cross-authority Raft group for the whole registry:** every registry write
  pays a cross-continent quorum; rejected. Only uniqueness claims, which are
  rare, go through such a group (section 4).
- **A custom majority-reservation protocol (ballots by timestamp):** a
  home-grown consensus; whether an authority that granted a higher ballot may
  also grant a later, lower one decides whether two claims can both commit, and
  proving it needs model checking that standard Raft already has. Rejected in
  favor of the reservation group.
- **Authority-qualified names (`name@authority`):** no coordination at all, but
  breaks the single domain namespace; rejected.
- **Reserving every project ID in the reservation group:** strict uniqueness,
  but every project create pays a cross-continent commit and fails in a
  partition; rejected in favor of the home-published locator plus
  authority-qualified references in every security check.
- **Project locator written by the owning authority:** needs no home, but the
  name claim and the locator become two writes by two writers; rejected, since
  the home already sees every claim.
- **Refusing both entries when a project ID repeats across domains:** a peer
  that homes a domain could deny routing to any project UUID it learns; rejected
  in favor of routing by `(domain-id, project-id)`.
- **Revoking only through the reverse index:** a grant created by invitation
  reaches its target only by a pointer event, so a lost pointer would skip the
  revocation; rejected for user and domain events, which go to the whole mesh.
- **One staleness clock for replica issuance:** it would stop A2 and A3 after
  `auth_max_staleness` of an outage, so the 12 h window could never be used;
  rejected in favor of two clocks (section 2.1).
- **Continuing bearer tokens at replicas (A2):** turns a stolen token into a
  `continuation_max`-long credential; rejected, only sender-constrained tokens
  are continued.
- **Per-domain continuation keys:** domains × sites keys, with no smaller blast
  radius since a site already holds every domain's data; rejected.
- **JWT assertions at replicas with a per-site replay cache:** an assertion
  could be replayed once at every other site; rejected for A3.
- **Replicating a user between two authorities inside one boundary:** would give
  a home failover but makes a user have two homes (two issuers, two revocation
  sources); rejected in favor of spreading one authority's core across sites
  (section 2.1, A1).
- **Truncating or digesting group claims:** truncation silently drops access;
  shipping group membership to targets violates residency; rejected in favor of
  audience filtering.
- **Domain-level trust records as the only cross-domain path:** grants
  individuals without their consent and admits any principal of the trusted
  domain; kept for groups and automation, invitations for individuals.
- **Binding roles to a trust domain, or to a path segment:** a domain holds many
  workloads, and a path is picked by whoever registers the workload, so a
  compromised or careless registration would mint a voter; rejected in favor of
  a per-SVID table, with the trust domain as a bound on that table.
- **One SVID per node for every role:** a node that is a core voter and a
  reservation-group voter would present one identity to both groups, and the
  receiver could not tell which role it speaks for; rejected in favor of an
  SVID per role (section 11.1).
- **Region as the term:** collides with the catalog region concept.
- **Multi-raft inside an authority:** possible for isolating hot regional data;
  not required here; separate ADR if pursued.

## Appendix A: ADR 0026 amendment (Next key generation)

To be added to ADR 0026 §3, "Key Lifecycle Operations", when this ADR is
accepted.

> **Next key (pre-publication).** A domain whose signing keys are verified
> outside its own Raft (a mesh domain, ADR 0045; optionally any domain) adds a
> third generation. Normal rotation commits the new keypair as **Next**
> (`_meta:oauth2:signing_key:<domain_id>:next`). A Next key is published on
> `GET /v4/oauth2/{domain_id}/jwks` and on the inter-authority feed but never
> signs. The key janitor promotes Next to Primary/Active, and demotes the
> Primary to Previous, in one Raft proposal once the Next key has been published
> for `[oauth2] signing_key_prepublish_seconds`.
>
> The minimum is the larger of the JWKS `max-age` (300 s) and the tolerated feed
> lag of the slowest consumer authority; the default is 900 s, and a configured
> value below the minimum is rejected at startup. At most one Next key exists
> per domain; a rotation requested while one is pending reports `pending` and
> does nothing. The audit event for the rotation is written at promotion and
> names the Next, new Primary and retiring keys.
>
> Emergency rotation is unchanged: it promotes a new key directly, publishes the
> revoked `kid` on the priority revocation stream, and relies on verifiers
> fetching the issuer's JWKS once on an unknown `kid`.
>
> Verifiers: an unknown `kid` from a trusted issuer triggers one fetch of that
> issuer's JWKS from the registry-listed endpoint, at most once per issuer per
> 30 s, with the result cached until its `max-age`. A `kid` still unknown after
> the fetch fails closed.

This also removes the validation gap that ADR 0026 accepts today for external
caches (Python middleware, edge proxies) between promotion and their next
300-second JWKS refresh.
