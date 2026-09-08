# 35. Relation Sync Provider

**Date:** 2026-09-08

## Status

Proposed.

Adds an optional provider. Nothing changes for a deployment that does not
configure it.

## Context

ADR 0033 shipped the OpenFGA assignment driver with a documented hole in it:

> Nothing syncs Keystone identity group membership into OpenFGA — the
> deployment owns that. [...] **A deployment that switches
> `driver = "openfga"` without first building that membership sync issues
> tokens missing every group-derived role**, silently, from the first
> request onward.

That warning is load-bearing for more than the assignment driver. Where
OpenFGA is the cloud's authorization PDP, the services querying it are not
only OpenStack: platform services outside Keystone's API surface resolve
their own decisions against the store, with Keystone nowhere in the call
path. For those consumers a Keystone group is only useful if
`user:U member group:G` tuples actually exist in the store, and provisioning
from an external IdP — SCIM (ADR 0024) and federated login — is precisely
the moment a tenant expects a new team to become usable everywhere.

So the store needs Keystone's membership edges, and Keystone has to put them
there.

### Why not inside the write transaction

Writing to OpenFGA inline, in the same unit of work as the SQL membership
mutation, makes OpenFGA a hard dependency of `POST /v3/groups/{id}/users/{id}`
and of every SCIM provisioning call. A store outage becomes a Keystone
outage, and a driver that the plugin architecture exists to keep optional
becomes mandatory for an operation that has nothing to do with assignments.
There is no distributed transaction across the two stores in any case: a
commit in SQL followed by a failure against OpenFGA has to be reconciled
afterwards no matter how tightly the call is wrapped.

### Why not the existing event dispatcher on its own

`EventPayload::GroupMembership` events are already emitted at every membership
mutation site in `crates/core/src/identity/service.rs`, so a `ProviderHooks`
subscriber that wrote tuples is the obvious shape. It is not sufficient.
`EventDispatcher::emit` (`crates/core/src/events.rs:260-274`) is documented
fire-and-forget:

```rust
pub async fn emit(&self, event: Event) {
    let _ = self.tx.send(event.clone());          // result discarded
    for hook in hooks {
        tokio::spawn(async move {
            let _ = hook.on_event(&event).await;  // result discarded
        });
    }
}
```

The broadcast channel drops events when its buffer (256 in
`EventDispatcher::production`) is full, hook errors are logged and swallowed,
and a process restart between the SQL commit and the spawned task loses the
notification with no record that it existed. That is at-most-once delivery
with silent loss — not eventual consistency, but permanent divergence at a low
but non-zero rate.

The direction of the loss is not symmetric. A lost membership *addition* is a
user who cannot do something and files a ticket. A lost membership *removal*
is retained privilege that nobody reports and nothing detects, and removal is
exactly what SCIM deprovisioning does.

The project already met this problem in the audit subsystem and answered it
with a second, fail-closed channel (`AuditHook` / `emit_critical`, ADR 0023) —
plus `postaudit_dropped_count` as a gauge acknowledging that post-commit drops
still happen. Membership sync cannot use the fail-closed channel without
re-creating the hard dependency of the previous section.

### A second writer exists

Two writers mutate `user_group_membership` in deployments this project
targets, and neither emits an event this process can observe:

- a co-deployed **python keystone** sharing the database, which the schema
  compatibility constraint exists to support;
- an **LDAP-backed domain** (ADR 0027), where membership changes happen in the
  corporate directory and Keystone is a reader — `identity-driver-ldap`
  returns `readonly` for every membership write.

Any design in which the event stream is the source of truth is therefore
structurally incomplete in the deployments that matter. A periodic diff is not
a safety net behind the event stream; it is the correctness mechanism, and
events only make convergence fast.

### Not every membership change is a write

Three membership transitions produce no `INSERT` or `DELETE` that an outbox
row could be attached to. All three are *removals*, the direction the
previous section identified as the dangerous one.

**Federated memberships expire by the clock.** The
`expiring_user_group_membership` table (`user_id`, `group_id`, `idp_id`,
`last_verified`) is filtered at read time against
`FederationProvider::get_expiring_user_group_membership_cutof_datetime()`
(`crates/config/src/federation.rs:46`), which returns
`now - [federation] default_authorization_ttl`. There is no cleanup job: the
row stays and simply stops matching the predicate
(`user_group/list.rs:60,111,147`). A membership sourced from an external IdP
therefore stops being effective with no write, no event, and nothing to
enqueue — and this is the dominant path for exactly the IdP-driven
provisioning this ADR exists to serve.

**Deleting a user or a group is a database cascade.** `user/delete.rs` and
`group/delete.rs` hold one `delete` function each and never reference
`user_group_membership`; within `crates/identity-driver-sql/src/` that table
is touched only under `user_group/`. The membership rows disappear underneath
the application, so a design that enqueues only at membership mutation sites
sees neither deletion.

**A deleted group is invisible to a per-group diff.** A reconciler that walks
Keystone's groups cannot visit a group Keystone no longer has. Tuples for a
deleted group are then revisited by nothing, in either mechanism, forever.

### The relevant shape of the existing code

- Membership writes in `crates/identity-driver-sql/src/user_group/add.rs`,
  `remove.rs` and `set.rs` take a `&DatabaseConnection` and issue a bare
  insert/delete with no transaction. `user/create.rs:133` and
  `user/update.rs:46` already use `db.begin()`, so the pattern is established
  in the crate.
- `user_group/set.rs` exposes `set_user_groups` and
  `set_user_groups_expiring`: both replace one user's membership set, so the
  edges they affect are only knowable by reading the prior set.
- `crates/identity-driver-sql` has **no** `src/migration/` directory: it maps
  onto a schema python owns. Crates that own their own tables ship one
  (`token-restriction-driver-sql`, `k8s-auth-driver-sql`, `webauthn`,
  `federation-driver-sql`).
- When keystone-rs needed a richer model than a python-owned table allowed, it
  added a parallel rust-only table rather than altering the python one:
  `federated_identity_provider` alongside `identity_provider`
  (`crates/federation-driver-sql/src/migration/m20250414_000001_idp.rs`).
- `BackendRegistration<B>` + `declare_backend_registry!`
  (`crates/core/src/plugin_manager.rs:89-138`) is how a provider gets pluggable
  drivers; `register_backends` builds every registration whose `selected`
  predicate accepts the config. ADR 0018 covers crate naming and the linker
  anchor.
- `crates/core/src/scim_resource/janitor.rs` and `api_key/janitor.rs` give the
  leader-gated background sweep pattern: spawn on every node, act only when
  `storage.current_leader().await == storage.node_id().await`.
- The OpenFGA driver already owns tuple I/O (`openfga_write` with a `delete`
  flag, `openfga_read`, retry/backoff and concurrency knobs) and the
  Keystone-id-to-object mapping (`user_actor_types`, `group_actor_types`,
  `id_transform` in `crates/config/src/assignment.rs`).
- OpenFGA's `read` cannot enumerate tuples by user alone (ADR 0033
  "Impedance mismatch"), but it does filter by object, including by object
  *type* alone. A per-**group** diff and a whole-type sweep are both
  expressible; a per-user one is not. §2 and §7 both turn on this asymmetry.
- ADR 0024 caps a SCIM group at `MAX_GROUP_MEMBERS` = 1000, which bounds the
  tuple set a per-group diff has to compare.

## Decision

### 1. A new optional provider, `relation_sync`

Add `crates/core/src/relation_sync/` holding a provider with **two**
independently pluggable driver kinds, both registered through the existing
`BackendRegistration` machinery and added to `declare_backend_registry!`:

| Trait object            | Selected by                    | Ships as             |
| ----------------------- | ------------------------------ | -------------------- |
| `dyn RelationSyncOutbox`| `[relation_sync] outbox_driver`| `sql`                |
| `dyn RelationSyncTarget`| `[relation_sync] targets`      | `openfga`, `log`     |

Crate names follow ADR 0018:
`openstack-keystone-relation-sync-outbox-driver-sql` and
`openstack-keystone-relation-sync-target-driver-openfga`. Both carry `driver`
in the name, so `crates/keystone/build.rs` anchors them automatically.

**v1 ships only a `sql` outbox driver.** A raft-backed deployment — this
workspace already has a full raft driver family (`scim-driver-raft`,
`mapping-driver-raft`, and others) but no `identity-driver-raft` — has no
outbox to write to and therefore no `relation_sync` provider at all in that
mode: `outbox_driver` cannot select `sql` without a SQL identity backend
underneath it, and no raft outbox exists to select instead. Such a deployment
gets §7 reconciliation-only convergence: no per-write trigger, no §4 scheduled
expiry publishing, worst-case lag bounded only by `reconcile_interval`. This is
stated here as a known limitation of v1, not a design goal — an
`identity-driver-raft` would need a matching `relation-sync-outbox-driver-raft`
before this provider serves that deployment shape, and neither is in scope
here.

`targets` is a list. Each target keeps its own progress and its own failure
state, so a slow or broken target never blocks another, and one relation
stream can be published to several policy information points — a second ReBAC
store, an entitlement service, a message bus — without Keystone learning
anything about them beyond the trait.

This generality is not speculative: it is what makes a data-bundle-style push
target — for example, pushing group membership into RadosGW's own access
metadata — a `RelationSyncTarget` implementation rather than a second event
pipeline built beside this one. Such a target reuses the outbox, the relay,
both reconciliation directions, and every metric in §10 unchanged; only the
`RelationSyncTarget` impl and its `[relation_sync.target.*]` block are new.
Two roadmap items collapse onto one mechanism, one lag metric, and one
reconciler — worth keeping in mind when that target's own ADR specs its
write/read/delete semantics against the trait defined here.

**The provider is absent unless configured.** With no `[relation_sync]`
section, `Provider` holds `None`, the hook is not subscribed, no outbox row is
ever written, and no background task is spawned. This is what keeps OpenFGA
optional: the pluggable architecture is preserved because the entire subsystem
is, not because the OpenFGA driver is written defensively.

### 2. What is synced

v1 syncs **group membership edges only**, from *both* membership tables —
`user_group_membership` and `expiring_user_group_membership`. An edge is
synced if and only if Keystone would resolve it as effective, which for the
expiring table means `last_verified` is still inside
`default_authorization_ttl` (§4).

Role assignments are the assignment driver's business (ADR 0033, ADR 0034) and
are written to OpenFGA directly by that driver when a deployment selects it;
duplicating them here would give two writers for one relation.

The trait is nonetheless phrased over a generic `RelationChange` so a later ADR
can add relation kinds (project hierarchy, for instance) without reshaping the
outbox.

```rust
/// A relation edge whose projection into a target store may be stale.
/// Deliberately a *key*, never a payload — see §5.
pub enum RelationKey {
    /// One membership edge, from either membership table.
    Membership { user_id: String, group_id: String },
    /// Every membership edge of one group. Enqueued when a group's member
    /// set is replaced wholesale, and when the group itself is deleted.
    Group { group_id: String },
}
```

There is deliberately **no `User` variant**, and the reason is the enumeration
asymmetry from the Context. Resolving `Group { group_id }` after the group is
gone still works: Keystone reports no members, the target is asked for every
tuple on `group:<id>` — an object-filtered `read`, which OpenFGA supports —
and all of them are deleted. The same trick is impossible for a user, because
`read` cannot enumerate by user, so a `User` key would name a set the relay
could not compute once the rows had cascaded away. User deletion is therefore
expanded into per-group `Membership` rows *before* the cascade, inside the
deleting transaction (§3). A `User` variant may become worthwhile later for
targets that can enumerate by subject; OpenFGA is not one.

### 3. The outbox is written in the mutating transaction

Membership writes, and the two deletion paths, change from bare inserts and
deletes to a `db.begin()` transaction that performs the mutation and inserts
the outbox rows, then commits. Either both land or neither does.

| Mutation site | Enqueued |
| --- | --- |
| `user_group/add.rs` (plain and expiring) | `Membership` per edge; expiring edges additionally get a due-dated row (§4) |
| `user_group/remove.rs` (plain and expiring) | `Membership` per edge |
| `user_group/set.rs` `set_user_groups[_expiring]` | `Membership` for the union of the user's prior and new group ids, the prior set read inside the transaction |
| `user/delete.rs` | `Membership` for every group the user is currently in, read inside the transaction **before** the cascade removes the rows |
| `group/delete.rs` | `Group` |

The outbox table is **new and rust-only** — python keystone neither reads nor
writes it — which is the `federated_identity_provider` precedent from the
Context and keeps the compatibility constraint intact: no python-owned table is
altered, and a co-deployed python keystone is unaffected.

```
relation_sync_outbox
  seq          bigint  pk, autoincrement   -- drain order
  kind         string(16)                  -- "membership" | "group"
  user_id      string(64) null
  group_id     string(64)
  due_at       timestamp                   -- not claimable before this; §4
  enqueued_at  timestamp
  attempts     int  default 0
  dead         bool default false
  leased_until timestamp null
```

`due_at` equals `enqueued_at` for every row except the scheduled expiry rows of
§4. It is indexed together with `dead` and `leased_until`, since the relay's
claim query filters on all three.

The enqueue helper lives in `crates/core` (already a dependency of
`identity-driver-sql`) so the identity driver does not gain a dependency on the
sync subsystem, and is a no-op returning immediately when the provider is not
configured — an unconfigured deployment pays one `Option` check per membership
write, and the extra reads in the `set_*` and `user/delete.rs` paths are
skipped entirely.

`identity-driver-ldap` enqueues nothing: its membership writes already fail
with `readonly`, and LDAP-sourced edges reach targets through §7
reconciliation, which is the only mechanism that can see them at all.

### 4. Expiry is a scheduled outbox row

A federated membership stops being effective at a time that is fully
determined when it is written: `last_verified + default_authorization_ttl`.
The transition is invisible to any write-triggered mechanism (Context), but it
is perfectly predictable, so the outbox schedules it.

Writing or refreshing a row in `expiring_user_group_membership` enqueues, in
the same transaction, a `Membership` row with
`due_at = last_verified + default_authorization_ttl`. The relay ignores rows
until `due_at <= now`. When one becomes claimable it is resolved by the
ordinary §5 rule — ask Keystone whether the edge is effective *now*:

- **Not refreshed.** Keystone no longer resolves the edge, the relay deletes
  the tuple. Expiry has been published at the moment it took effect, not at
  the next reconciliation.
- **Refreshed since** (another login or SCIM sync bumped `last_verified`).
  Keystone still resolves the edge, the tuple stays, and the refresh has
  already enqueued its own later-dated row.

Re-verification therefore leaves superseded future rows in the table. They are
harmless — each resolves to a no-op — and the relay coalesces rows for one edge
within a batch. A deployment that re-verifies very frequently can bound the
churn by deduplicating on `(kind, user_id, group_id, due_at)` at enqueue.

Two operational consequences follow, and both matter:

- Not-yet-due rows are **excluded** from `outbox_depth` and `lag_seconds`
  (§10). A table holding a week of scheduled expiries must not read as a week
  of backlog.
- `default_authorization_ttl` becomes a sync input. Changing it does not
  re-date rows already enqueued; the reconciler (§7) repairs the difference,
  and a large reduction should be followed by a forced reconciliation pass.

### 5. The outbox row is a trigger, not a payload

A row names an edge. It does not say whether the edge was added or removed,
and the relay does not trust anything about the row except the key and
`due_at`.

To drain a `Membership` row the relay asks the identity provider whether the
edge is effective *now* and writes or deletes the tuple accordingly. Three
properties follow, and they are the reason for the design:

- **Idempotent.** Replaying a row is a no-op.
- **Order-insensitive.** `Event` carries no sequence number and
  `tokio::spawn`-per-hook does not preserve ordering, so an add and a remove of
  the same edge can be observed out of order. Recomputing from the
  authoritative row makes that harmless; trusting an event payload would
  converge to the wrong value.
- **Coalescing.** Duplicate rows for one edge collapse into one target write.
  This is what makes §4's superseded expiry rows free.

The relay treats OpenFGA's "tuple already exists" and "tuple not found"
responses as success for exactly this reason.

### 6. The relay

A leader-gated background loop, following the janitor pattern
(`scim_resource/janitor.rs`), one pass per target:

1. Claim a bounded batch of rows with `dead = false`, `due_at <= now` and no
   live lease, oldest `seq` first, taking a lease (`leased_until`).
2. Resolve each key against the identity provider and apply the resulting
   tuple writes/deletes through the target driver, honouring that driver's
   own retry and concurrency configuration.
3. Delete drained rows; on failure release the lease and increment
   `attempts`.
4. After `max_attempts`, mark the row `dead`, emit a `WARN` and a counter, and
   move on. **A poison row never blocks the queue** — §7 repairs whatever it
   leaves behind.

Dead rows are not deleted at step 4. They are retained, unretried, for
`janitor_deadletter_retention_days` (§9) so an operator can inspect what
failed before it is gone, then purged by the same leader-gated sweep pattern
as `scim_resource/janitor.rs` and `api_key/janitor.rs` — the two comparable
subsystems in this codebase that dead-letter or tombstone rows both ship a
retention janitor rather than an unbounded table. Purging a dead row does not
lose the edge: §7's Keystone-driven pass still repairs it on the next
reconciliation from the live data, since the outbox row was only ever a
trigger (§5), never the source of truth.

`RelationSyncHook` subscribes to `EventPayload::GroupMembership` and
`EventPayload::Group` on the ordinary fire-and-forget dispatcher and does one
thing: notify the relay to wake early. It performs no I/O against the target
and no outbox write, so the dispatcher's at-most-once semantics cost nothing —
a dropped notification delays a drain to the next poll tick and cannot lose
data. The event system is used for latency, never for correctness.

### 7. Reconciliation is bidirectional, and is the correctness mechanism

A second leader-gated loop periodically diffs Keystone against each target.
It has **two** directions, and the second is not optional.

**Keystone-driven.** For each Keystone group: `list_users_of_group` against an
OpenFGA `read` filtered on `group:<id>`, writing the missing tuples and
deleting the extra ones. Cost is bounded by `MAX_GROUP_MEMBERS` (ADR 0024) per
group.

**Target-driven (orphan reap).** A sweep of the target's own membership tuples
filtered on the `group:` object *type*, collecting the distinct group ids the
store believes in. Any group id Keystone does not have is deleted wholesale.

This filters on the tuple's **object**, and a role-assignment tuple's object
is always `project:`/`domain:`/`system` — `assignment-driver-openfga` maps
every role grant onto one of those three target types via its `ObjectMapper`
and never onto `group:` — regardless of whether the authorization model
expresses group-derived roles
by rewriting through the group's `member` relation (a userset naming
`group:G` as the *user* field of the role tuple) or some other mechanism. An
object-type filter on `group:` cannot match a tuple whose object is a
project, domain, or the system, so it cannot see or delete a role grant no
matter how that grant reaches the group. The sweep's blast radius is exactly
the membership tuples this design writes, never the role tuples the
assignment driver writes — asserted here explicitly because a wholesale
delete on the wrong object type would be a production access incident, not a
sync bug.

Without the second direction the design has no garbage collection at all. A
group deleted in Keystone leaves the Keystone-driven pass nothing to iterate,
so its tuples survive every future reconciliation — permanently, and
unconditionally when the deletion came from a co-deployed python keystone,
which enqueues nothing. In a store that other platform services trust, those
orphans are retained group-derived privilege that no Keystone-side observation
can find.

Together the two directions are the only mechanism covering:

- memberships written by a co-deployed python keystone, which emit no event
  into this process;
- LDAP-domain memberships, which change entirely outside Keystone;
- expiries whose scheduled row (§4) was lost or dead-lettered;
- deletions whose outbox row was lost or dead-lettered;
- a store mutated out-of-band, or restored from a backup.

The sweep is paced and the interval is configurable: it sets the worst-case
convergence time for every writer that is not this process, which makes it a
security parameter and not a housekeeping one (§8). The orphan direction may
run on a longer interval than the Keystone-driven one, since it is a
whole-type scan.

### 8. The two staleness directions are not equivalent

Convergence lag is routinely discussed as one number. It is two, and they
warrant different responses:

- **Stale addition** — Keystone has the edge, the target does not. The user
  cannot do something they should be able to. Self-reporting, visible, and
  not a security event.
- **Stale removal** — the target has the edge, Keystone does not. Privilege
  survives its revocation across every service reading the store. Nothing
  reports it.

The policy this ADR adopts:

1. `lag_seconds` (§10) is alerted on, because it bounds stale removal for
   writers this process observes.
2. Time since the last *completed* reconciliation pass is alerted on
   separately, because it — not `lag_seconds` — bounds stale removal for
   python, LDAP and any expiry whose scheduled row was lost.
3. An operator-triggered forced reconciliation pass is a supported operation,
   for use after a store restore, a `default_authorization_ttl` reduction, or
   a dead-letter alarm.

Keystone deliberately does **not** fail its own requests closed when lag is
high. Refusing to issue tokens would not close the hole: the other services
reading the store answer from the same stale tuples regardless, and Keystone
is only one of its consumers. It would trade a partial exposure for a total
outage. Lag is an alarm, not a gate.

For the same reason Keystone resolves group-derived roles through the store
like every other consumer rather than short-circuiting to its local tables.
Doing otherwise would make Keystone the one service that keeps working
correctly while the sync is broken — hiding the failure in the component the
operator watches most closely.

### 9. Configuration

```ini
[relation_sync]
# Absent section = provider not built. This is the default.
outbox_driver = sql
targets = openfga
relay_interval = 5              # seconds between drain passes
relay_batch_size = 500
max_attempts = 8
janitor_deadletter_retention_days = 30
reconcile_interval = 3600       # seconds between Keystone-driven passes
reconcile_orphans_interval = 86400  # seconds between target-driven sweeps
reconcile_enabled = true

[relation_sync.target.openfga]
driver = openfga
api_url = https://fga.example.com/
store_id = 01J...
model_id = 01J...
membership_relation = member    # relation written for a membership edge
```

Target credentials live in server configuration only, never in the domain
configuration API, for the reason ADR 0034 §6 gives for assignment driver
configuration: an API-writable endpoint or bearer token for a store that
governs authorization decisions is a privilege-escalation anchor.

`membership_relation` is validated at startup against the assignment driver's
`role_to_relation` values when both are configured against the same store; an
overlap is a fatal misconfiguration, since it would let the relay write
relations that grant roles.

`reconcile_orphans_interval` must be finite. Disabling the orphan sweep
disables the only garbage collection the design has (§7).

### 10. Metrics

Per ADR 0031's `keystone_<subsystem>_<noun>[_<unit>]` shape, all labelled by
`target`:

| Metric                                            | Type      | Notes                                     |
| ------------------------------------------------- | --------- | ----------------------------------------- |
| `keystone_relation_sync_outbox_depth`             | gauge     | Claimable rows only — excludes `due_at` in the future |
| `keystone_relation_sync_scheduled_depth`          | gauge     | Rows waiting on a future `due_at` (§4)    |
| `keystone_relation_sync_lag_seconds`              | gauge     | Age of the oldest *claimable* row         |
| `keystone_relation_sync_applied_total`            | counter   | `op` = write/delete                       |
| `keystone_relation_sync_failures_total`           | counter   | `reason`                                  |
| `keystone_relation_sync_deadletter_total`         | counter   | Rows abandoned after `max_attempts`       |
| `keystone_relation_sync_deadletter_purged_total`  | counter   | Dead rows erased past retention           |
| `keystone_relation_sync_reconcile_repairs_total`  | counter   | `direction` = added/removed               |
| `keystone_relation_sync_reconcile_orphans_total`  | counter   | Tuples reaped for objects Keystone lacks  |
| `keystone_relation_sync_reconcile_age_seconds`    | gauge     | Since the last *completed* pass, per direction |
| `keystone_relation_sync_reconcile_duration_seconds`| histogram | Sweep cost                               |

`lag_seconds` and `reconcile_age_seconds` are the security-relevant numbers,
for the two different populations §8 separates. Alert on both, on any non-zero
`deadletter_total`, and on a `reconcile_repairs_total{direction="removed"}`
that stops being near-zero in steady state — a rising removed-repair rate
means the write path is missing revocations that the sweep is cleaning up
after.

### 11. Rollout

1. Configure `[relation_sync]` with the OpenFGA target while the assignment
   driver is still `sql`.
2. Let the first full reconciliation pass complete — it is the bootstrap
   backfill; there is no separate import path. Let the first orphan sweep
   complete too, since a store that has been populated by hand will have
   objects Keystone does not know.
3. Confirm `lag_seconds`, `reconcile_age_seconds` and
   `reconcile_repairs_total` are steady.
4. Only then switch `[assignment] driver = "openfga"`, globally or per domain
   (ADR 0034).

Reversing step 4 is immediate; the tuples the relay wrote remain valid for
non-Keystone consumers of the store.

## Alternatives considered

**Write to the target inside the membership transaction.** Rejected: makes
OpenFGA mandatory for identity operations and couples Keystone's availability
to it, without actually achieving atomicity across two stores.

**A `ProviderHooks` subscriber that writes tuples directly.** Rejected: the
dispatcher is at-most-once with silent loss (Context), so divergence would be
permanent and undetectable. This ADR keeps the hook, but only as a wake-up.

**Contextual tuples at check time.** OpenFGA's `Check`, `BatchCheck` and
`ListObjects` accept per-request tuples, so the assignment driver could supply
membership from the identity provider instead of relying on stored tuples —
always fresh, nothing to sync, and structurally the same query-time expansion
`assignment-driver-sql` already performs via `list_groups_of_user`. Rejected
as a substitute for two reasons. It cannot serve consumers that query the
store without Keystone in the call path, which is the requirement driving this
ADR. And per §8 it would make Keystone the one service immune to sync
breakage, removing the operator's earliest signal that it has broken. It
remains worth adding behind a flag as a diagnostic and emergency mode — a way
to answer correctly while a sync fault is being repaired — but not as the
default resolution path. Note also that OpenFGA bounds contextual tuples per
request, which a user in very many LDAP groups can exceed.

**A periodic full push instead of an outbox.** Rejected: it makes
`reconcile_interval` the revocation SLO for *every* writer rather than only
the unobservable ones, and the scheduled-expiry mechanism of §4 already shows
that predictable removals can be published when they happen.

**Splitting membership out of the identity provider into its own provider.**
Rejected. It dissolves the SQL foreign keys and the single-transaction SCIM
path, adds a cross-provider dependency on ID mapping, and forces a Python
configuration parity story (ADR 0027) that makes it opt-in only — for a
benefit this ADR obtains without moving anything.

**Attributed membership edges** (`granted_by`, `expires_at`, provenance on the
edge). Out of scope: it requires altering a python-owned table, which the
co-deployment constraint forbids, and its governance value is unsound while a
second writer shares that table.

## Consequences

### Positive

- ADR 0033's documented hole is closed by a component an operator can choose,
  and the OpenFGA assignment driver becomes safe to adopt.
- Keystone becomes a publisher of identity relations to a platform PDP, which
  is the deployment shape driving this work; targets beyond OpenFGA are a new
  crate, not a change here — including non-ReBAC pushes such as the RadosGW
  data-bundle case in §1.
- Availability is not coupled: a target outage delays convergence and raises
  `lag_seconds`, it does not fail a Keystone request.
- Correctness does not depend on event delivery, so the existing
  fire-and-forget dispatcher can stay exactly as it is.
- Federated expiry — the transition with no write behind it, and the dominant
  one for IdP-sourced groups — is published when it happens rather than at the
  next sweep.
- The design has explicit garbage collection, so deleted users and groups do
  not leave privilege behind in a store other services trust.
- No python-owned table changes; a co-deployed python keystone keeps working
  and its writes still converge, via §7.

### Negative

- **The projection is eventually consistent, and the window is a security
  parameter.** Between a membership removal and the corresponding tuple
  delete, the target store answers with stale authority. Bounded by relay
  latency for writers this process observes, and by the reconciliation
  intervals for python, LDAP and lost scheduled rows — §8 is the whole reason
  those are two separate alarms.
- Membership writes take a transaction where they previously took a bare
  insert, and `user/delete.rs` and `set_user_groups*` gain a read of the prior
  membership set. Small, but on a hot path, and paid to make deletion
  observable at all.
- One more table, a relay and two reconciliation sweeps, and a leader
  dependency for all of them — a deployment with no leader runs them on every
  node, which is safe (the work is idempotent) but wasteful.
- The orphan sweep is a whole-type scan of the target store; on a large cloud
  it is the most expensive thing this subsystem does, and its interval trades
  directly against how long an orphaned tuple can survive.
- The outbox table holds scheduled rows proportional to the number of live
  federated memberships, not to write throughput.
- `delete_group` and `set_user_groups` enqueue work proportional to the group
  or the user's group count.
- **Raft deployments are unserved by v1.** No outbox driver exists for them
  (§1); such a deployment falls back to reconciliation-only convergence, with
  `reconcile_interval` as the only lag bound.

## Open questions

- Whether the Keystone-driven reconciler should walk groups on a rolling shard
  per pass rather than the full set, once cloud sizes justify it.
- Whether the orphan sweep can be made incremental — a stored high-water mark
  over the target's tuple ids — rather than a full type scan.
- Whether a target should be able to declare "membership is authoritative
  here", letting the reconciler repair *Keystone* from the store rather than
  only the other way round — relevant if an operator manages groups in OpenFGA
  directly.
- Whether the scheduled-expiry mechanism should be generalised to any
  time-bounded relation, which is the shape a later JIT/PIM elevation feature
  would need.
- Whether the `log` target belongs in the shipped set or only in test builds.
- Whether a raft outbox driver is worth building, and what it would need from
  `identity-driver-raft` (which does not exist yet) to enqueue at the same
  mutation sites §3 uses today.

## See Also

- ADR 0033 — OpenFGA assignment driver, and the membership-sync gap this ADR
  closes
- ADR 0034 — per-domain assignment drivers; the same store may be reached by
  only some domains
- ADR 0024 — SCIM v2 provisioning, the main producer of membership changes
- ADR 0027 — LDAP identity driver, a membership source Keystone cannot write
- ADR 0023 — audit dispatch, and why fire-and-forget was insufficient there too
- ADR 0018 — driver crate naming and linker anchors
- `crates/core/src/events.rs` — the dispatcher's fire-and-forget semantics
- `crates/core/src/scim_resource/janitor.rs` — the leader-gated sweep pattern
- `crates/config/src/federation.rs` — `default_authorization_ttl`, which sets
  when a federated membership expires
