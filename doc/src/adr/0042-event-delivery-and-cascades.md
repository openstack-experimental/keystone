# 42. Provider event delivery and delete cascades

**Date:** 2026-10-12

## Status

Accepted. Amends ADR 0023 (audit) and ADR 0035 (relation sync provider).

## Reference

Tracking issue #1425. Related: ADR 0017 (security context), ADR 0019
(credentials), ADR 0023 (audit), ADR 0035 (relation sync provider), ADR 0038
(unified limits).

## Context

Issue #1425 reported that `ProviderHooks` were not notified for authenticated
API calls and that the dependent objects of a deleted resource were not cleaned
up. Four separate problems sat behind it.

1. **Dispatch gap.** `audited_op!` only calls `emit_critical`, the fail-closed
   `AuditHook` channel of ADR 0023. `ProviderHooks` were notified only on the
   branch without a security context, so every authenticated call, which is
   nearly all real traffic, never reached a hook. Per-site workarounds existed
   for `create_domain`, `delete_domain` and `delete_project` only.
2. **Empty hooks.** Of the `ProviderHooks` implementations, only the ones for
   limits, OAuth2 keys, OAuth2 sessions, dynamic plugin identity and
   back-channel logout did any work. Identity, assignment, application
   credential, trust, role, resource, token, revoke and the rest were empty.
   Deleting a user left its application credentials, trusts and role assignments
   behind; deleting a domain left its projects, users and groups.
3. **Lossy delivery.** `EventDispatcher::emit` spawns every hook as a task and
   discards the result. There is no ordering, no retry, and a crash between the
   operation and the hook loses the event. ADR 0035 already concluded that work
   which must happen cannot live in a hook and uses an outbox with the hook only
   as a wake-up.
4. **No enforcement.** The audit coverage test guaranteed that every mutating
   provider method was audited. Nothing guaranteed that it notified hooks.

## Decision

### 1. One dispatch point; audit stays separate

`audited_op!` is not extended to notify hooks. It is the audit primitive: it
needs a `ValidatedSecurityContext`, it is also used for non-mutations
(authentication, the CADF hook itself), and the audit event is not the hook
event (`update_user` audits one `Update`, while hooks need `Disable`,
`password_change` or `mfa_enabled`). Merging the two would also not fix problems
2 and 3, and internal callers (janitors, SCIM, hooks) have no context and would
still need their own emit.

Instead:

- `audited_if_ctx!` is the single wrapper for state-changing provider
  operations. It runs the audited operation when there is a security context and
  the bare operation when there is not, and on **success** in both cases emits
  to `ProviderHooks`. An optional `hook_events:` argument replaces the default
  (the audit event) when one operation needs several hook events.
- `audited_notify_op!` is `audited_op!` followed by the same emit, for the sites
  that keep an explicit `if/else`.
- The emit happens strictly after the audited operation succeeded, never on
  `Err`.

### 2. Enforcement

`audit_coverage.rs` rejects a bare `audited_op!` in a service method: it must be
`audited_if_ctx!` or `audited_notify_op!`. A method that only calls other
audited operations (a cascade) is allow-listed with a reason.

### 3. Cascades are inline, not hooks

A hook cannot carry a cascade whose absence is a security problem: delivery is
at-most-once and the error is swallowed. So:

- **Cascades that must not be missed run inline in the owning service, in the
  same audited operation, and their errors propagate.** The operation fails and
  can be retried; the audit event is emitted only after the cascade succeeded.
  `delete_credentials_for_user` was the template.
- Each cascade goes through the **owning provider's own audited operation** and
  does not reach into its storage. Assignments are revoked with `revoke_grant`
  and trusts removed with `delete_trust`, so the audit event and the revocation
  of the tokens carrying the role or minted under the trust are not skipped.
  Application credentials and credentials, which have no revocation side effect,
  use a bulk backend method.
- **Best-effort derived state stays on hooks** and must be idempotent: caches,
  OAuth2 sessions, the plugin identity index, limits.
- **Work that needs at-least-once delivery across stores** follows the outbox
  pattern of ADR 0035, with the hook as a wake-up only. No cascade here needs it
  yet.

The cascades:

| Deleted | Removed with it                                                                                         |
| ------- | ------------------------------------------------------------------------------------------------------- |
| user    | credentials, application credentials and access rules, trusts (as trustor or trustee), role assignments |
| project | credentials, application credentials, role assignments on the project                                   |
| domain  | projects (leaf first), users, groups, role assignments on the domain, id mappings                       |

Rules that came out of implementing them:

- A **listing by project is not a listing of the project's own grants**: it also
  returns the inheritable grants of the parent projects. The cascade filters on
  the assignment's own target, otherwise deleting a child would revoke the
  parent's grants. The direct and the inheritable grants on the target are two
  listings (`RoleAssignmentListParameters::inherited`), and the project and
  domain cascades run both.
- **Deleting a group revokes all of its grants**, on any target, including
  the ones on other domains and the system (`delete_assignments_for_group`).
- **Project deletion is ordered**: children before parents, by depth, with the
  depth walk bounded so corrupt parent data cannot hang it.
- **Users and groups of a read-only identity backend (LDAP) are skipped** during
  a domain delete; they are not ours to remove, and failing on them would make
  such a domain undeletable.
- The domain cascade is **idempotent**: a failure leaves the domain row in place
  and a retry resumes with what is left.
- The **per-entity cascades are retry-safe** too. The entity row goes first, so
  a failure in a later cascade step leaves the entity gone and its dependents
  behind. Deleting a user, group or project that no longer exists therefore
  still runs the cascade and only then returns `NotFound`; a retry finishes
  the cleanup and the caller still sees that the entity was already deleted.

### 4. A destructive cascade needs the domain disabled

Before the cascade a domain delete removed one row. With it, one call can wipe a
whole domain. Python Keystone refuses to delete an enabled domain; this
implementation never had the check, and adding it unconditionally would break
every caller that deletes an empty, freshly created domain.

So the check is tied to the cascade: deleting an **enabled** domain that still
owns projects, users or groups fails with `DomainEnabled` (HTTP 403) and touches
nothing. An empty domain deletes as before, and a disabled domain cascades.

### 5. Orphan sweep as the safety net

Some leftovers cannot be reached by a cascade: anything removed by a writer
that emits no event (a co-deployed Python Keystone, a node that stopped half
way through a cascade) and grants written after their target was removed.

A background sweep (`orphan_sweep`) lists all role assignments hourly and
reports those whose user, group, project or domain no longer exists. It is
**report-only** for now: it logs the count and the first IDs and deletes
nothing. A failed existence lookup is counted as an error and never reported as
an orphan. The pass is read-only and idempotent, so it runs on every node.

Deletion by the sweep is deferred until the false-positive rate on real
deployments is known, because a wrong delete is a lost grant.

## Consequences

- Authenticated API calls now notify `ProviderHooks`. Hooks that were written
  against the old behaviour see events they never saw before; the ones that do
  work (limits, OAuth2, plugin identity, back-channel logout) are idempotent.
- A user, project or domain delete does more work and can fail half way, with
  the earlier steps already committed. It is safe to retry; it is not atomic.
  Each step is audited on its own.
- Deleting a user with many assignments or trusts issues one revocation event
  per item.
- A domain delete of a large domain is a long synchronous request.
- Deleting an enabled, non-empty domain now fails where it used to leave the
  contents behind.
- Known gap: the users and groups of a read-only identity backend are skipped
  by a domain delete, so the grants they hold on targets outside the domain
  stay behind. The sweep reports them once the domain is gone.
- Known gap: data keyed by a domain in providers that have no cascade yet
  (federation, mappings, k8s-auth, catalog endpoints).
- The sweep covers role assignments only.
- The sweep interval is a constant, not a `[section]` option.
