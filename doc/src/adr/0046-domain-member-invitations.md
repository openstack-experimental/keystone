# 46. Domain member invitations

**Date:** 2026-11-17

## Status

Proposed (design exploration; nothing is implemented).

## Reference

Related: ADR 0020 (mapping engine, domain resolution), ADR 0026 (OAuth2/OIDC
provider), ADR 0036 (service delegation, cross-domain grants), ADR 0038 (unified
limits), ADR 0042 (event delivery and delete cascades), ADR 0045 (global IAM
mesh; invitations are its path for cross-domain grants to individuals), vision
§7.7 (domain manager persona). Security invariants:
`doc/src/contributor/security-model.md`.

## Context

A domain manager can manage the domain's projects, groups and role assignments,
but has no way to bring another person into the domain unless that person
already exists and the manager knows their user ID. Creating a user inside the
domain is possible, but it forces the manager to invent a credential and ties
the person to this one domain. Keycloak's Organizations feature solves the same
problem with an invitation: a manager enters an email address, the system sends
a link, and the recipient joins the organization on acceptance.

### How Keycloak does it (from memory, to be re-checked against current docs)

- An organization has members. An organization manager (`manage-members`)
  invites by email.
- If the email belongs to an existing realm user, the link asks that user to
  confirm joining. If not, the link opens the registration form with the email
  pre-filled, and the new user becomes a member once registered. This path
  requires registration to be enabled on the realm.
- The invitation is an action token: signed, single use, expiring (72 hours by
  default).
- Users are realm-level. One person can belong to several organizations, and
  membership is an association, not a copy of the user.

### What keystone looks like today

- A user belongs to exactly one domain (`UserResponse.domain_id`). Access to
  another domain is a role assignment on that domain, so "membership in domain
  D" for a user of another domain is a set of grants. Cross-domain grants are
  already an accepted pattern (ADR 0036 §3.2).
- Groups are domain-local, so group membership cannot express cross-domain
  membership.
- There is no email field on the user (it lives in `extra` at best), no outbound
  mail path, no pending-grant resource, and no user self-registration.
- Federation (ADR 0020) can create `Local` users on first login in the domain
  that the mapping ruleset is bound to (`DomainResolutionMode::Fixed`).
  Mapping-driven roles are applied by the mapping engine at login.
- Domain management is already delegated to domain managers (vision §7.7,
  `policy/` conventions).

### The deployment pattern that drives the design

A common multi-tenant setup is: one federation IdP lets anybody sign up, the
mapping ruleset places **all** those users into one shared domain `S`
("public"), and each user then creates and owns one or more **tenant domains**
`T1`, `T2`, ... in which they hold `manager`. The inviter and the invitee
therefore usually live in the same shared domain `S`, while the inviter acts in
a different domain `T`. An invitation system built on "create a user inside the
inviting domain" would be wrong for this pattern: it would copy identities per
tenant. An invitation system built on "pick any user and add them" would let
every tenant owner enumerate every user in `S`.

## Decision

### 1. An invitation is a pending grant offer, not a user

An invitation offers a set of grants on the inviter's domain to a person who has
not yet proven who they are. Accepting it turns the offer into ordinary role
assignments for the **accepting principal's own user**. The invitation never
creates membership by itself, and never moves or copies a user between domains.

```rust
pub struct Invitation {
    pub id: String,
    pub domain_id: String,            // target domain
    pub invited_by: UserRef,          // inviter (issuer, user_id) only
    pub invitee: InviteeHint,         // see §3
    pub grants: Vec<InvitationGrant>, // domain roles, project roles, target-domain groups
    pub state: InvitationState,       // pending | accepting | accepted | declined | revoked | expired
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,    // default 72h, domain max 30d
    pub max_auth_age: Duration,       // default 10 min, settable at create (§4)
    pub accepted_by: Option<UserRef>, // set when the claim is taken (§4 step 5)
    pub claimed_at: Option<DateTime<Utc>>,
    pub token_hash: [u8; 32],         // SHA-256 of the 256-bit random token
    pub delivery: DeliveryState,      // none | pending | sent | failed (§8)
}
```

`UserRef` identifies a principal by `(issuer, user_id)`. In a single deployment
the issuer is always the local one; in a mesh (§10) the inviter or the accepting
user may be homed in another authority, and the reference never carries more
than the pair. The inviter's authentication chain at creation is not stored on
the record; it goes into the `create` audit event (§9), which is where the audit
trail reads it.

The provider trait is backend-neutral. The first driver follows the Raft driver
pattern (`data:invitation:<id>`, plus indexes by domain and by token hash). A
SQL driver is not part of phase 1, so a deployment without Raft storage cannot
enable invitations: keystone refuses to start with `invitations.enabled` set and
no invitation driver. A SQL driver can be added behind the same trait when such
a deployment needs it; it must offer the same compare-and-set on `state` that §4
relies on. Expired and terminal invitations are swept after a retention period.
In a mesh, the invitation is stored in the authority that owns its targets
(§10).

The invitation record and the grants it produces live in different stores: role
assignments and group memberships stay in their own backends (SQL, OpenFGA,
per-domain drivers, LDAP). §4 therefore does not rely on a single transaction
across both.

### 2. API

- `POST   /v4/domains/{domain_id}/invitations`: create. Response contains the
  accept link and token **once**.
- `GET    /v4/domains/{domain_id}/invitations` and `GET .../{id}`: list and
  show. Never returns the token.
- `DELETE /v4/domains/{domain_id}/invitations/{id}`: revoke.
- `POST   /v4/invitations/accept` (authenticated): body `{token}`. Accept.
- `POST   /v4/invitations/decline` (authenticated): body `{token}`. Only a
  principal who matches the invitee constraint (email or user reference, §4
  step 3) may decline. Link-only invitations cannot be declined, because every
  holder of the link would qualify; they end by expiry or revocation. A caller
  who fails the match gets 403 and the invitation is unchanged.
- `POST   /v4/invitations/preview` (unauthenticated, token is the credential,
  rate limited): body `{token}`. Returns only target domain name, role names and
  expiry, so the recipient can decide whether to log in.

The token never appears in a URL path or query string, so it does not reach
access logs or referrers. The accept link has the form
`<invitations.accept_url>#token=<token>`, where `invitations.accept_url` is a
deployer-configured client page (a dashboard view, for example). Keystone serves
no HTML page for it. The fragment is not sent to any server; the client page
reads it, removes it from the address bar and history (`history.replaceState`),
is served with `Referrer-Policy: no-referrer`, and calls preview and accept with
the token in the POST body. Without a configured `accept_url`, the create
response returns the token alone and the manager delivers it as they see fit.

Policy files:
`policy/identity/invitation/{create,list,show,delete,accept,decline}.rego`. List
re-checks every item with the per-item read policy.

### 3. Resolving the invitee: three modes

The inviter supplies a hint, never a lookup result.

1. **Email hint.** `{ "email": "a@b.c" }`. The email is only a delivery address
   and an optional match constraint, not an identity. Keystone does not reveal
   whether an account with that email exists.
2. **Link-only.** No hint. The manager hands the link to anybody (a Slack
   message, a QR code). Whoever authenticates and redeems it first gets the
   grants. Allowed per-domain setting, off by default.
3. **User reference.** `{ "user_id": "...", "user_domain_id": "..." }` for the
   case where the manager already knows the user (for example another tenant
   owner whose ID they were told). Only the named user may accept. Existence is
   not revealed at creation: the response is the same whether or not the user
   exists. System admins and domain managers of the user's own domain already
   have lookup rights through the existing user APIs.

**Anti-enumeration rule:** creating an invitation must not become a user lookup.
Domain managers get no new right to list or search users of other domains, and
the create response and timing do not depend on whether the invitee exists.

### 4. Accepting

Accepting requires an authenticated, non-delegated principal, so all three cases
below collapse into "log in, then redeem":

- **Existing user:** logs in with whatever they use, presents the token.
- **New user via federation:** logs in through the federation IdP; the mapping
  engine creates the `Local` user in `S` as it does today, then the token is
  redeemed in the same session. If the IdP allows open sign-up, **this already
  gives the "invite a new user" experience without any keystone
  self-registration**.
- **New user via keystone self-registration (phase 2):** the invitation token is
  accepted by the registration endpoint as proof of eligibility (see §6).

**Who may accept.** "Non-delegated" is an allowlist, not a blocklist. The
authentication context of the token presented to accept must be one of the
interactive human login methods: `Password`, `Totp`, `WebauthN`, `Oidc`, or
`Mapping` when the mapping ruleset is marked as an interactive browser login.
Every other context gets 403, including `Token` (token-from-token and rescoped
tokens), application credentials, trusts, service grants and service clients,
EC2 credentials, K8s auth, SPIFFE and `Admin` principals, API keys, dynamic auth
plugins, workload mappings, and any token carrying a token restriction. New
authentication methods are excluded until they are added to the list. The check
reads the authentication context, never the token scope.

The token must also be fresh: its `issued_at` must be within the invitation's
`max_auth_age` (default 10 minutes). Because `Token` contexts are refused,
`issued_at` is the time of the login itself, not of a later rescope. Accept
needs no scope, so the unscoped token from the login is the expected one. A
stolen long-lived token, or one minted by a non-interactive credential, cannot
accept. The same freshness rule applies to a principal from another authority
(§10).

On accept:

1. Authenticate the caller under the rules above.
2. Look the invitation up by token hash; verify the hash (constant time), that
   it is not expired, and that `state == pending`. If `state` is `accepting` or
   `accepted` and `accepted_by` is the caller, continue at step 6: a repeated
   accept by the same principal is a no-op that finishes any outstanding work,
   never a second grant. Any other state, or another caller, is rejected.
3. If the invitation names a user or carries an email constraint, verify the
   accepting principal matches. Email matching uses only the user's
   `verified_email` attribute (§4a), never `extra`. If the attribute is absent,
   matching fails closed. Domains that do not want this strictness use
   link-only mode. For an accepting principal homed in another authority, the
   match is decided by that principal's home (§10). **A failed match changes
   nothing**: the invitation stays `pending` for the real invitee, and the
   attempt is audited and rate limited.
4. Re-check the **inviter's authority** against the current state, not the state
   at creation. The inviter is not authenticated at this moment, so there is no
   authentication chain to read; the check reads the inviter's current role
   assignments from the assignment backend (direct, via groups, inherited, and
   expanded by implication) and the current domain settings, and re-runs every
   rule of §5 for every grant. For a local inviter, the user must also exist and
   be enabled. If any check fails, the invitation moves to `revoked`. For an
   inviter homed in another authority, the user record is not available;
   liveness comes from the revocation stream instead (§10).
5. **Claim**: a compare-and-set on the invitation record from `pending` to
   `accepting`, setting `accepted_by` and `claimed_at`. Exactly one claim wins.
   This is the commit point: from here the grants are owed to this principal.
   The `accepting` record acts as the outbox entry for the grant writes (ADR
   0042 §3: work that must happen across stores does not run in a hook).
6. Write the role assignments and group memberships listed in `grants` for the
   accepting user through their own providers. Each write is create-if-absent;
   an existing equal assignment or membership counts as done.
7. Compare-and-set `accepting` to `accepted`, emit the audit event.

If step 6 or 7 fails, the caller gets an error and may retry (step 2 sends a
retry to step 6). A sweeper also rolls forward invitations that have stayed in
`accepting` longer than a bound, by repeating steps 6 and 7. A half-applied
accept is completed, never undone, because the principal was verified before the
claim. Expiry does not apply to `accepting`. Group grants whose group is in a
read-only identity backend (LDAP) are rejected at creation, so step 6 never
depends on a backend that cannot write.

### 4a. Verified email

`extra` is free-form and can be written by anyone who can update the user, and
tokens do not carry the IdP's `email_verified` claim after mapping. Email
matching therefore needs a new user attribute, `verified_email`, outside
`extra`, which is part of phase 1:

- It is written only by: the mapping engine at login, from the IdP's email claim
  when `email_verified == true`, and only when a system admin has marked that
  IdP as email-trusted (the value is replaced on every login and cleared when
  the claim is missing or not verified); the phase 2 registration flow (§6);
  and system admins.
- The user update API rejects it from every other caller, including managers of
  the user's own domain. A mapping ruleset bound to a domain cannot set it for
  an IdP that is not email-trusted, so a domain admin who writes rulesets cannot
  forge it either.
- It is not part of policy input for other users and is not returned by user
  list or show to callers below system admin.

### 5. What an inviter may grant

The rule is that an invitation never grants more than the inviter could grant
directly. The checks below run at create and again at accept (§4 step 4)
against current assignments and current domain settings.

- **Role grants are bounded by the inviter.** For a grant of role R on target X
  (the domain, or a project in it), R must be in the inviter's effective roles
  for X, expanded by the role implication order. Effective roles for X are
  computed from assignment data: roles held on X directly, through the
  inviter's groups, or inherited from the domain; and, for a project X, the
  roles the inviter holds on the owning domain when those include `manager` or
  `admin`, since a domain manager administers the domain's projects without a
  role on each one. The result is further limited by the domain setting
  `invitable_roles`. `manager` cannot invite `admin`. A manager may invite
  another `manager` only when the domain setting allows it.
- **Group memberships are bounded by the group's roles.** Membership in group G
  may be offered only when (a) the inviter could add members to G directly
  today, (b) every role G holds, on any target and including inherited and
  implied roles, passes the role rule above as if it were offered directly, and
  (c) G's identity backend is writable. Without (b), offering membership in a
  group that holds `admin` would grant `admin` through the group. Roles granted
  to G later reach its members, as they do for any member of G; changing G's
  roles is a separate right and is not widened here.
- The accepting principal must not be the inviter. This only blocks the trivial
  case; the bound above is what stops a second account from gaining more than
  the inviter holds.
- Targets are the domain itself, projects inside it, and groups inside it. No
  grants on other domains, never `system`. In a mesh, one invitation's targets
  must all be owned by one authority, and group memberships are not offered to
  principals of another authority (§10).
- **Only interactive human logins can invite.** Create applies the allowlist of
  §4, except that a `Token` context is accepted when the token's original
  methods are all on the list and it carries no delegation or restriction (an
  inviter normally uses a domain-scoped token obtained by rescope). Accept
  applies §4 unchanged. Invitations extend standing human membership, not a
  delegated task. The check reads the authentication context, not the token
  scope.

### 6. Dependency on self-registration

Self-registration (anonymous creation of a local user) does not exist and is its
own design. This ADR only needs it for one case, and has a defined interface to
it:

- **Phase 1 (this ADR):** invitees must be able to authenticate by some existing
  means: a local account, or a federation IdP that accepts sign-up. No
  registration code is needed.
- **Phase 2 (after a registration ADR):** the registration endpoint accepts an
  optional `invitation_token`. A valid token (a) lets registration proceed even
  when open registration is off, which makes invite-only registration possible,
  (b) pre-fills the email and sets `verified_email` (§4a), but only when the
  invitation was delivered by keystone's own notifier to that address (§8),
  since only then did the link provably reach that mailbox, and (c) redeems
  the invitation in the same request. The user is created in the
  **registration domain** configured for registration (the shared domain `S`),
  never in the inviter's tenant domain, so one person can be invited into many
  tenants with one identity.
- A per-domain option `create_users_in_target` (default `false`) allows the
  exceptional case of an enterprise domain whose users must be local to that
  domain. It requires the domain manager to also hold user-create rights there
  and is a phase 2 option only.

### 7. Federation, the shared domain, and tenant domains

- The mapping engine and invitations must not fight over assignments. Mapping
  rules own assignments they create at login (ADR 0020 `Authorization`). An
  invitation-created assignment must survive a mapping re-sync. **Open
  verification:** whether the engine ever deletes assignments it did not create;
  if it does, invitation grants need a provenance tag
  (`source = invitation:<id>`) on the assignment record, and the engine must
  skip tagged records.
- An invited user from the shared domain `S` scoped to tenant domain `T` works
  with today's token model: the token carries the user's own `domain_id = S` and
  the scope is `T`. No user copy, name collision, or per-tenant credential.
- The tenant-owner flow (create domain, become its manager) is a prerequisite of
  the pattern but not part of this ADR. It needs: a self-service domain create
  operation gated by quota (ADR 0038) and a mapping or API step that grants the
  creator `manager` on the new domain. Without it, tenants are created by
  operators and invitations still work.
- Offboarding: removing a member means deleting their assignments on `T`. The
  invitation record is history, not membership. A "members of domain" view is a
  role-assignment query on `T` with effective-user expansion, and does not need
  a new entity in phase 1.

### 8. Delivery of the invitation

Keystone has no mail path today. Phase 1 does not add SMTP.

1. The create response returns the accept link (or token, §2) once; the manager
   can deliver it.
2. When the invitation has an email hint and a notifier is configured, keystone
   delivers it through an **outbox**, not a hook. ADR 0042 §3 makes hooks
   at-most-once with errors swallowed, so a hook-based delivery would be lost on
   a crash or a failed task. The invitation is created with `delivery = pending`
   and the plaintext token in a separate `delivery_secret` field of the same
   Raft record, which is encrypted at rest (crypto inventory STO-1). A delivery
   worker on the Raft leader calls the configured `InvitationNotifier` (webhook,
   message bus, mail relay sidecar) with the link and email hint, retries with
   backoff, and passes the invitation id as idempotency key, since delivery is
   at-least-once. On success it sets `sent`; after the retry budget, or when the
   invitation reaches a terminal state, it sets `failed` or leaves the state as
   is. In every case it erases `delivery_secret`. The field is never returned by
   list or show, never part of policy input, and never logged. Without an email
   hint or a notifier, `delivery = none` and the plaintext is never stored.
3. The ADR 0042 event `invitation.created` carries the invitation id, target
   domain, inviter and grants, and **never** the token, the link or
   `delivery_secret`. By default that event is also the audit event (ADR 0042
   §1), so the rule is that nothing secret enters it, not a marker that would
   have to filter it out later.
4. A built-in SMTP sender can be added later as a notifier without changing this
   API.

### 9. Abuse and security controls

- Token: 256 bits from the OS RNG, stored as SHA-256, single use (the claim of
  §4 step 5), constant-time compare, never logged. The plaintext exists at rest
  only in `delivery_secret` while an outbox delivery is pending (§8). It travels
  only in the URL fragment of the accept link and in POST bodies, never in a
  path or query string (§2).
- Rate limits (ADR 0022) on create per inviter and per domain, on preview,
  accept and decline per source address and per invitation.
- A domain-level cap on pending invitations, and per-domain disable switch
  `invitations.enabled`. Defaults: disabled globally until an operator turns it
  on.
- Audit (CADF, ADR 0023): `create`, `accept`, `decline`, `revoke`, `expire`,
  with the inviter's authentication chain and the roles granted.
- Cascades: deleting a domain, or disabling or deleting the inviter, removes or
  revokes pending invitations (ADR 0042). A user deleted before accepting leaves
  the invitation valid for other principals only if it was link-only.
- Secrets stripped from policy input: the token, token hash and
  `delivery_secret` are not part of `input.target`.
- Cryptography. Implementing this ADR adds rows to
  `doc/src/contributor/crypto-inventory.md` and the matching
  `// Crypto inventory: <ID>` markers in the same change:
  - token generation: 256 bits through the `storage-crypto` `random_bytes`
    seam, so it runs on the validated module in `fips` builds;
  - token hash: SHA-256 used as a lookup key for a secret, so it is a security
    primitive; it goes through the `storage-crypto` seam (a SHA-256 helper is
    added there if missing), together with the constant-time compare;
  - email hint hash (§10): SHA-256 that keeps the plaintext out of request logs
    only; listed as **Not a security primitive**.
- Invitations are not a way around approval: if a domain requires approvals for
  grants (future), acceptance would enter the same approval path.

### 10. Mesh deployments (ADR 0045)

This section applies only when a deployment is part of an ADR 0045 mesh (stage
3); a single deployment ignores it. In the mesh, invitations are the path for
cross-domain grants to individual users; grants to whole groups or without
consent use a trust record (ADR 0045 §7).

**Placement.**

- An invitation is stored, previewed and accepted at the authority that owns its
  targets: domain-level grants at the domain's home (domain-level assignments
  replicate from there to the domain's parts); project grants at the authority
  that owns the project. An invitation whose targets span authorities is
  rejected; the manager creates one per authority.
- Create requests route to the owning authority as any write does (ADR 0045 §6).
  The accept link points at that authority's endpoint.
- Preview and accept are not authentication endpoints. The invitee logs in at
  their own home authority only; the accept call carries the resulting token.

**Accepting with a token from another authority.**

- The invitee presents a mesh access token whose `aud` includes the owning
  authority. It is verified through the user-less path (ADR 0045 §5); the
  principal is `(iss, sub)`.
- "Non-delegated" (§4, §5) is read from the verified token: no `act`, no grant
  or application-credential ID in `delegation_context`. A token obtained through
  the exchange shim is not accepted.
- The token must have been authenticated recently: `auth_time` within the
  invitation's `max_auth_age` (default 10 minutes, settable at create). If the
  domain requires DPoP (ADR 0043), the token must be bound and the proof is
  verified as for any request (ADR 0045 §12, G11).
- Grants are created for `(iss, sub)` of the accepting token, so they always
  reference a principal that was proven to exist and are never `dangling`. The
  owning authority sends the pointer event to the invitee's home (ADR 0045 §8).
- A user-reference invitation (§3 mode 3) may name a principal of another
  authority as `(issuer, user_id)`. The owning authority cannot check that it
  exists, which matches the anti-enumeration rule.

**Inviter liveness.** The inviter's roles come from the owning authority's own
assignments. When the inviter is homed elsewhere, "disabled or deleted" arrives
as a revocation event on the priority stream (ADR 0045 §9); on receipt, the
owning authority revokes the inviter's pending invitations, as the local cascade
does (§9). Between the event and its delivery (30 s target) an accept may still
succeed; the same bound applies to tokens.

**Email constraint.** The email never travels in a token. The owning authority
asks the invitee's home: "does `sub` have a verified email whose SHA-256 is H",
where H is the hash of the normalized email hint, and gets yes or no. Home uses
its verified attribute or federation claim, under the same rules as §4 step 3.
The hash keeps the plaintext out of request logs; it is not a privacy control,
since the hint is already stored at the owning authority. To keep the yes/no
answer from becoming an oracle, the query is about the accepting token's own
`sub` only, carries that token as proof, is asked at most once per
`(invitation, sub)` pair, and is rate limited per owning authority (ADR 0045
§12, G11). Because each answer concerns only the caller's own `sub`, it tells
the caller nothing about anybody else. A `no` affects only that `sub`: as in §4
step 3, the invitation stays `pending`, so a leaked link cannot be used to lock
the real invitee out. The answer is obtained before the claim of §4 step 5 (a
remote call cannot run inside it), and the claim then re-checks state, expiry
and token hash. If home is unreachable, the accept fails and can be retried.

**Group memberships.** Groups of the target domain are identity data at the
domain's home, and a foreign principal's token carries only groups of its own
home. A membership of a foreign principal in a target-domain group would not be
evaluated, so invitations to principals of another authority offer roles only.
Group-based access for them is a trust-record grant to their home group (ADR
0045 §7).

**Shared domain across authorities.** The §7 pattern still holds when the shared
domain `S` is homed in authority A and tenant domain `T` (or a part of it) in
authority B: the user logs in at A and accepts at B. No user is copied.

**Other rules.** Rate limits and the pending-invitation cap apply per owning
authority. The `invitation.created` event is emitted there. Offboarding deletes
the assignments at the owning authority, which sends the pointer removal to the
user's home.

## Alternatives considered

- **Create the user inside the target domain on invite.** Matches today's admin
  workflow but copies a person per tenant, needs a password or reset flow, and
  breaks the shared-domain pattern above. Kept only as an opt-in for phase 2.
- **Cross-domain group membership as the membership model.** Needs a deep change
  to keystone's group semantics. Role assignments already express the same.
- **Trusts.** Wrong tool: trusts delegate a specific user's authority, and ADR
  0036 is moving away from them.
- **A first-class Organization / member entity (Keycloak model).** Cleaner
  member UX (list, role changes, "managed" members) but a second source of truth
  next to role assignments. Deferred until the member-list view proves too slow
  or limiting.
- **Realm-per-tenant like a separate Keycloak realm.** Defeats the shared
  identity goal.

## Consequences

- Domain managers can onboard people without knowing user IDs and without
  creating credentials.
- Phase 1 is shippable without self-registration whenever there is an IdP that
  accepts sign-up; phase 2 adds invite-only registration.
- The tenant pattern works without duplicating identities, and cross-domain user
  enumeration remains closed.
- Cost: a new Raft resource (deployments without Raft storage cannot enable
  invitations until a SQL driver exists), new policy files, a
  system-controlled `verified_email` user attribute with an operator-level
  email-trusted flag on IdPs, an outbox delivery worker with a notifier
  contract, a sweeper that rolls forward stuck accepts, a client page that
  serves the accept link, and new crypto inventory rows.
- Inviter authority and all grant limits are re-evaluated at accept, so an
  invitation never outlives the inviter's rights or a tightened domain setting.
- In an ADR 0045 mesh, the same flow grants access across authorities without
  copying users. Limits there: one owning authority per invitation, roles only
  for foreign principals, and an accept round trip to the invitee's home when an
  email constraint is set.
- Risk: invitation links are bearer capabilities until redeemed by an
  authenticated principal; the constraints in §3, §4 and §9 are what keep that
  safe.

## Open questions

1. Does the mapping engine delete assignments it did not create (§7)?
2. Local password users get `verified_email` only from a system admin in phase
   1. Should phase 2 add a self-service verify-by-mail flow, and who may mark
   an IdP as email-trusted beyond system admins?
3. Should declined and accepted invitations also be visible to the invitee ("my
   invitations" list), which needs an email-to-user index and conflicts with §3
   anti-enumeration?
4. Should system admins be able to invite into any domain without being manager
   there?
5. Do we need an approval step for tenants that want owner sign-off on
   invitations created by sub-managers?
6. Mesh (§10): should target-domain group memberships ever be offered to
   principals of another authority? That would need the target to evaluate its
   own group memberships for `(iss, sub)` at check time (ADR 0045).
