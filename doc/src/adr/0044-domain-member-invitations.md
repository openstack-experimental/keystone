# 44. Domain member invitations

**Date:** 2026-10-24

## Status

Proposed (design exploration; nothing is implemented).

## Reference

Related: ADR 0020 (mapping engine, domain resolution), ADR 0026 (OAuth2/OIDC
provider), ADR 0036 (service delegation, cross-domain grants), ADR 0038
(unified limits), ADR 0042 (event delivery and delete cascades), vision §7.7
(domain manager persona). Security invariants:
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
    pub invited_by: UserRef,          // inviter, recorded with auth chain id
    pub invitee: InviteeHint,         // see §3
    pub grants: Vec<InvitationGrant>, // domain roles, project roles, target-domain groups
    pub state: InvitationState,       // pending | accepted | declined | revoked | expired
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,    // default 72h, domain max 30d
    pub accepted_by: Option<UserRef>,
    pub token_hash: [u8; 32],         // SHA-256 of the 256-bit random token
}
```

Storage follows the Raft driver pattern (`data:invitation:<id>`, plus indexes by
domain and by token hash). A SQL driver is not planned; state is small and
short-lived. Expired and terminal invitations are swept after a retention
period.

### 2. API

- `POST   /v4/domains/{domain_id}/invitations`: create. Response contains the
  accept link and token **once**.
- `GET    /v4/domains/{domain_id}/invitations` and `GET .../{id}`: list and show.
  Never returns the token.
- `DELETE /v4/domains/{domain_id}/invitations/{id}`: revoke.
- `POST   /v4/invitations/accept` (authenticated): body `{token}`. Accept.
- `POST   /v4/invitations/decline` (authenticated or token only): optional.
- `GET    /v4/invitations/preview?token=...` (unauthenticated, token is the
  credential, rate limited): returns only target domain name, role names and
  expiry, so the recipient can decide whether to log in.

Policy files: `policy/identity/invitation/{create,list,show,delete,accept}.rego`.
List re-checks every item with the per-item read policy.

### 3. Resolving the invitee: three modes

The inviter supplies a hint, never a lookup result.

1. **Email hint.** `{ "email": "a@b.c" }`. The email is only a delivery
   address and an optional match constraint, not an identity. Keystone does not
   reveal whether an account with that email exists.
2. **Link-only.** No hint. The manager hands the link to anybody (a Slack
   message, a QR code). Whoever authenticates and redeems it first gets the
   grants. Allowed per-domain setting, off by default.
3. **User reference.** `{ "user_id": "...", "user_domain_id": "..." }` for the
   case where the manager already knows the user (for example another tenant
   owner whose ID they were told). Only the named user may accept. Existence
   is not revealed at creation: the response is the same whether or not the
   user exists. System admins and domain managers of the user's own domain
   already have lookup rights through the existing user APIs.

**Anti-enumeration rule:** creating an invitation must not become a user lookup.
Domain managers get no new right to list or search users of other domains, and
the create response and timing do not depend on whether the invitee exists.

### 4. Accepting

Accepting requires an authenticated, non-delegated principal, so all three
cases below collapse into "log in, then redeem":

- **Existing user:** logs in with whatever they use, presents the token.
- **New user via federation:** logs in through the federation IdP; the mapping
  engine creates the `Local` user in `S` as it does today, then the token is
  redeemed in the same session. If the IdP allows open sign-up, **this already
  gives the "invite a new user" experience without any keystone
  self-registration**.
- **New user via keystone self-registration (phase 2):** the invitation token is
  accepted by the registration endpoint as proof of eligibility (see §6).

On accept, in one Raft transaction:

1. Verify `state == pending`, not expired, token hash matches (constant time).
2. Verify the **inviter's authority is still live**: the inviter user exists,
   is enabled, and still holds `manager` or `admin` on the target domain. If
   not, the invitation moves to `revoked`. Authority is checked at accept time
   against the authentication-chain-derived roles, never against what was
   written at creation (security model: decisions keyed on the chain, not on
   stale scope).
3. If the invitation names a user or an email constraint, verify the accepting
   principal matches. Email matching uses a verified email claim from the
   federation login (`email_verified == true`) or, for local users, a verified
   `extra.email` set by an admin; otherwise matching fails closed. Domains that
   do not want this strictness use link-only mode.
4. Create the role assignments and group memberships listed in `grants` for the
   accepting user. Grants are idempotent; accepting twice is a no-op, not a
   second grant.
5. Mark the invitation `accepted`, emit the audit event.

### 5. What an inviter may grant

- Roles are **bounded by the inviter**: the inviter can offer only roles they
  hold on that target (or lower in the role implication order), additionally
  limited by a domain setting `invitable_roles`. `manager` cannot invite
  `admin`. A manager may invite another `manager` only when the domain setting
  allows it.
- Targets are the domain itself, projects inside it, and groups inside it. No
  grants on other domains, never `system`.
- **Delegated credentials cannot invite.** An application credential, trust, or
  service grant principal gets 403 on create and on accept, because invitations
  extend standing human membership, not a delegated task. The check reads the
  authentication context, not the token scope.

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
  (b) pre-fills the email and marks it verified, since the link reached that
  mailbox, and (c) redeems the invitation in the same request. The user is
  created in the **registration domain** configured for registration (the
  shared domain `S`), never in the inviter's tenant domain, so one person can be
  invited into many tenants with one identity.
- A per-domain option `create_users_in_target` (default `false`) allows the
  exceptional case of an enterprise domain whose users must be local to that
  domain. It requires the domain manager to also hold user-create rights there
  and is a phase 2 option only.

### 7. Federation, the shared domain, and tenant domains

- The mapping engine and invitations must not fight over assignments. Mapping
  rules own assignments they create at login (ADR 0020 `Authorization`). An
  invitation-created assignment must survive a mapping re-sync. **Open
  verification:** whether the engine ever deletes assignments it did not create;
  if it does, invitation grants need a provenance tag (`source = invitation:<id>`)
  on the assignment record, and the engine must skip tagged records.
- An invited user from the shared domain `S` scoped to tenant domain `T` works
  with today's token model: the token carries the user's own `domain_id = S`
  and the scope is `T`. No user copy, name collision, or per-tenant credential.
- The tenant-owner flow (create domain, become its manager) is a prerequisite
  of the pattern but not part of this ADR. It needs: a self-service domain
  create operation gated by quota (ADR 0038) and a mapping or API step that
  grants the creator `manager` on the new domain. Without it, tenants are
  created by operators and invitations still work.
- Offboarding: removing a member means deleting their assignments on `T`. The
  invitation record is history, not membership. A "members of domain" view is a
  role-assignment query on `T` with effective-user expansion, and does not need
  a new entity in phase 1.

### 8. Delivery of the invitation

Keystone has no mail path today. Phase 1 does not add SMTP.

1. The create response returns the accept link once; the manager delivers it.
2. An `invitation.created` event (ADR 0042 dispatch) carries the link and email
   hint so a deployer-provided notifier (webhook, message bus, a mail relay
   sidecar) can send it. The event payload is marked secret-bearing so it is not
   written to the CADF audit trail or logs.
3. A built-in SMTP sender can be added later as a notifier without changing
   this API.

### 9. Abuse and security controls

- Token: 256 bits from the OS RNG, stored as SHA-256, single use, constant-time
  compare, never logged. Link form `.../accept#token=...` (fragment) so
  referrers and proxy logs do not see it.
- Rate limits (ADR 0022) on create per inviter and per domain, on preview and
  accept per source address.
- A domain-level cap on pending invitations, and per-domain disable switch
  `invitations.enabled`. Defaults: disabled globally until an operator turns it
  on.
- Audit (CADF, ADR 0023): `create`, `accept`, `decline`, `revoke`, `expire`,
  with the inviter's authentication chain and the roles granted.
- Cascades: deleting a domain, or disabling or deleting the inviter, removes or
  revokes pending invitations (ADR 0042). A user deleted before accepting leaves
  the invitation valid for other principals only if it was link-only.
- Secrets stripped from policy input: the token and token hash are not part of
  `input.target`.
- Invitations are not a way around approval: if a domain requires approvals for
  grants (future), acceptance would enter the same approval path.

## Alternatives considered

- **Create the user inside the target domain on invite.** Matches today's admin
  workflow but copies a person per tenant, needs a password or reset flow, and
  breaks the shared-domain pattern above. Kept only as an opt-in for phase 2.
- **Cross-domain group membership as the membership model.** Needs a deep change
  to keystone's group semantics. Role assignments already express the same.
- **Trusts.** Wrong tool: trusts delegate a specific user's authority, and ADR
  0036 is moving away from them.
- **A first-class Organization / member entity (Keycloak model).** Cleaner member
  UX (list, role changes, "managed" members) but a second source of truth next
  to role assignments. Deferred until the member-list view proves too slow or
  limiting.
- **Realm-per-tenant like a separate Keycloak realm.** Defeats the shared
  identity goal.

## Consequences

- Domain managers can onboard people without knowing user IDs and without
  creating credentials.
- Phase 1 is shippable without self-registration whenever there is an IdP that
  accepts sign-up; phase 2 adds invite-only registration.
- The tenant pattern works without duplicating identities, and cross-domain
  user enumeration remains closed.
- Cost: a new Raft resource, new policy files, an event consumer contract for
  delivery, and a requirement that email claims be trustworthy before email
  matching is enabled.
- Risk: invitation links are bearer capabilities until redeemed by an
  authenticated principal; the constraints in §3, §4 and §9 are what keep that
  safe.

## Open questions

1. Does the mapping engine delete assignments it did not create (§7)?
2. Is a verified-email attribute on local users in scope, or are email
   constraints limited to federated logins?
3. Should declined and accepted invitations also be visible to the invitee
   ("my invitations" list), which needs an email-to-user index and conflicts
   with §3 anti-enumeration?
4. Should system admins be able to invite into any domain without being
   manager there?
5. Do we need an approval step for tenants that want owner sign-off on
   invitations created by sub-managers?
