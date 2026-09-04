# 33. OpenFGA Assignment Driver

**Date:** 2026-09-04

## Status

Accepted. Implemented in `crates/assignment-driver-openfga`
(`openstack-keystone-assignment-driver-openfga`), selectable via
`[assignment] driver = "openfga"` plus an `[openfga]` config section
(`crates/config/src/assignment.rs`, `OpenFGAAssignmentDriver`). Linked into the
`keystone` binary only when the `openfga` cargo feature is enabled.

## Context

Keystone's role assignments (who has which role on which project / domain /
system) are a natural relationship graph. [OpenFGA](https://openfga.dev) is a
Zanzibar-style relationship-based authorization store that models exactly this
kind of graph and answers "does user U have relation R on object O?" with group
expansion and userset rewrites built in.

Operators already running OpenFGA as their central authorization service want
Keystone role assignments to live there too, so that a single authorization
model governs both OpenStack and non-OpenStack resources, and so that group
membership and role implication are resolved once, by the model, rather than
separately in each consumer.

The existing SQL driver (`crates/assignment-driver-sql`) stores assignments in
local tables and expands inheritance / group membership itself. The OpenFGA
driver is an alternative `AssignmentBackend` that delegates that expansion to
the relationship store.

### Impedance mismatch

The `AssignmentBackend` trait (`check_grant`, `create_grant`,
`list_assignments`, `revoke_grant`) is shaped by the SQL model. OpenFGA differs
in ways this ADR has to reconcile:

- OpenFGA has no notion of a Keystone entity id. A mapping from
  `(kind, keystone_id)` to an OpenFGA object string (`type:id`) is needed, and
  it must be reversible for listing.
- OpenFGA's `read` (raw tuple listing) matches on a tuple filter; it **cannot**
  enumerate tuples by user alone. Only the model-resolving APIs (`check`,
  `batch-check`, `list-objects`) answer "everything U can do".
- OpenFGA stores one flat relationship tuple per grant. There is no column for
  Keystone's `inherited` flag.
- Group membership and implied roles are the model's job, not the driver's.

## Decision

### 1. Crate structure

Follows the ADR-0018 naming convention:
`openstack-keystone-assignment-driver-openfga`, with the usual
`#[allow(dead_code)] pub fn anchor() {}` linker anchor and an
`inventory::submit! { BackendRegistration::<dyn AssignmentBackend> { name: "openfga", .. } }`
registration.

```
crates/assignment-driver-openfga/
  Cargo.toml
  src/
    lib.rs      # OpenFGADriver, AssignmentBackend impl, HTTP + retry + fan-out
    types.rs    # ObjectMapper, Kind, request/response structs, error enum
    tests.rs    # httpmock-based unit tests
```

### 2. Entity ↔ object mapping is pure config

`ObjectMapper` (in `types.rs`) is stateless and built entirely from the
`[openfga]` section — **no** per-entity lookup table and **no** reverse-mapping
store (Keystone's `id_mapping` table is a public↔local routing table for a
different purpose and is deliberately not reused).

Each Keystone kind (`user`, `group`, `project`, `domain`, `system`) has a list
of OpenFGA type names. The first is _canonical_ (used for writes); every entry
is consulted on reads / checks / deletes, so a store that already holds tuples
under an alternate type name (`account:` instead of `user:`, say) still
resolves. An optional `id_transform` (`uuid-dashes`) inserts/strips canonical
UUID dashes, since Keystone stores dashless UUIDs and OpenFGA stores dashed.

The Keystone role id ↔ OpenFGA relation name mapping is an explicit
`role_to_relation` table in config. An unmapped role id fails fast with
`RoleRelationNotConfigured`.

### 3. `effective` selects the API family

`list_assignments` branches on `RoleAssignmentListParameters::effective`:

| Query shape               | `effective == Some(true)`              | otherwise                                                  |
| ------------------------- | -------------------------------------- | ---------------------------------------------------------- |
| actor + target + role     | `check` (model-resolved)               | `read` of the exact tuple                                  |
| actor + target, no role   | `batch-check` over every role relation | `read {user,object}`, map relations back to roles          |
| actor, no target          | `streamed-list-objects` fan-out        | **501** — `ListingActorWithoutScopeRequiresEffective`      |
| no actor, target (± role) | `read` (see below)                     | `read`                                                     |
| no actor, role only, no target | **501** — `ListingAssignmentsByRoleNotSupported`  | **501** — `ListingAssignmentsByRoleNotSupported`           |
| no actor, no target, no role | **501** — `ListingAllAssignmentsNotSupported`     | **501** — `ListingAllAssignmentsNotSupported`               |

`resolve_implied_roles` has no independent effect; implication is a model
rewrite and therefore only visible in effective mode. A `debug!` records this
when the flag is set outside effective mode. Every assignment this driver
returns — direct or effective — is reported with `inherited: false` and
`implied_via: None`: the driver has no way to tell a directly-stored tuple
from one the model resolved via inheritance or implication. See the Negative
consequences.

A **target-scoped** listing always uses `read` even in effective mode: this
driver does not call `list-users`, so group-derived grants _on the target_ are
not resolved. A `debug!` records the limitation when effective mode is asked for
there. This `read` also never walks the Keystone project tree, in either mode:
a project-scoped listing (`domain_id`/`system_id` have no tree to walk) only
ever sees tuples stored directly on that project. Unlike the SQL driver — which
adds each ancestor project as an `inherited = true` target via
`get_project_parents` regardless of `effective` — a grant made on a parent
project is invisible here even in non-effective mode. Project-tree inheritance
on this driver only exists to the extent the OpenFGA model encodes it as a
rewrite (see §4 and the Negative consequences below).

`check_grant` always calls OpenFGA's model-resolving `check` API — it has no
`effective` parameter, so it cannot restrict itself to a direct tuple the way
`assignment-driver-sql`'s `check` does. See the Negative consequences.

### 4. `inherited: true` is rejected on create

Because a grant is one tuple with no `inherited` marker, an inherited grant
would be indistinguishable from a direct one on read. `create_grant` returns
`InheritedGrantsNotSupported`, which maps to
`AssignmentProviderError::Validation` → HTTP 400, rather than silently storing
it as a direct grant. Project-tree inheritance must be expressed as a relation
rewrite in the OpenFGA authorization model.

### 5. Revoke mirrors the SQL driver's idempotence

`revoke_grant` probes each representation with a direct `read` and issues a
delete only for the ones that actually hold the tuple. Revoking a grant that is
not present is a no-op returning `Ok(())`, matching `assignment-driver-sql`.
This also avoids OpenFGA's "tuple not found" delete error. A real error from
either the `read` or the `delete` propagates.

### 6. Listing has no server-side cursor; pagination is post-fetch

A single `list_assignments` call is a fan-out union across representations,
target kinds and role relations, so no opaque cursor can be pushed into OpenFGA.
Results are fully materialised, de-duplicated, sorted by the assignment
pagination marker, then sliced (`marker` / `limit` / `page_reverse`), mirroring
the SQL driver's post-fetch pagination.

To keep individual OpenFGA calls from truncating silently:

- `read` follows `continuation_token` to completion (bounded by
  `MAX_READ_PAGES = 1000`, with a `warn!` if hit).
- object enumeration uses **`streamed-list-objects`**, not `list-objects`.
  `list-objects` caps its result at `OPENFGA_LIST_OBJECTS_MAX_RESULTS`
  (default 1000) with no continuation token, so a full page silently drops
  assignments. The streaming form is bounded only by
  `OPENFGA_LIST_OBJECTS_DEADLINE`; the driver parses its newline-delimited
  `{"result":{"object":...}}` frames.

### 7. Resiliency: configurable retry

`send()` wraps every OpenFGA call. Transient failures — connection errors,
timeouts, HTTP 429, HTTP 5xx — are retried up to `max_retries` times (default
`0`, i.e. off) with exponential backoff from `retry_backoff_ms` (default 100). A
4xx other than 429 is returned immediately.

### 8. Concurrency: bounded fan-out

Every fan-out (over actor/target representations, target kinds, role relations)
issues its OpenFGA requests concurrently via `buffer_unordered`, capped at
`max_concurrency` (default 10). `read` continuation and `batch-check` chunking
stay sequential. `max_concurrency = 1` forces fully serial calls without
changing results.

### 9. No caching

`check_grant` / `list_assignments` results are not cached in the driver. OpenFGA
is the source of truth and has its own consistency controls; a Keystone-side
cache would add a staleness window on authorization decisions for no clear
benefit at current call volumes. Revisit if profiling shows OpenFGA round-trips
dominating auth latency.

### 10. Error mapping

`OpenFGADriverError` (in `types.rs`) converts to `AssignmentProviderError`:
`InheritedGrantsNotSupported` → `Validation` (400); the three unsupported-listing
variants (`ListingActorWithoutScopeRequiresEffective`,
`ListingAssignmentsByRoleNotSupported`, `ListingAllAssignmentsNotSupported`) →
`AssignmentProviderError::NotImplemented` → HTTP 501; everything else → `Driver`
(500). The unsupported-listing shapes are a permanent property of the query
(no target scope, only a role filter, or no filter at all), not a transient
backend fault, so they are kept out of the 500 path: a 501 tells the caller
"this driver can't answer this", where a 500 would read as a bug and page an
operator. `GET /v3/role_assignments` reaches all three from public,
policy-gated query parameters (`role.id` alone, or no parameters at all, or
`user.id`/`group.id` without `effective=true` and without a target scope).

## Consequences

### Positive

- A single authorization model spans OpenStack and non-OpenStack resources;
  group expansion and role implication are resolved once, by OpenFGA.
- No new persistence: the driver is stateless, the mapping is config, and there
  is no schema to migrate.
- Alternate type names and UUID-format differences are absorbed by config, so
  the driver can point at a pre-existing OpenFGA store.
- Retry and concurrency are tunable per deployment; both default to conservative
  behaviour (retry off, modest parallelism).

### Negative

- **Authorization-model coupling.** The driver is only correct if the OpenFGA
  model encodes group membership (e.g. a `member` relation) and implied roles as
  rewrites. Nothing syncs Keystone identity group membership into OpenFGA — the
  deployment owns that. This is not limited to `GET /v3/role_assignments`:
  every scoped-token issue path
  (`resolve_project_default_roles`/`resolve_domain_roles`/`resolve_system_roles`
  in `crates/core/src/auth.rs`) calls `list_assignments` with
  `effective = true`, which on this driver is a `batch-check` against the
  model with no Keystone-side group expansion (the SQL driver expands
  `list_groups_of_user` itself before querying). **A deployment that switches
  `driver = "openfga"` without first building that membership sync issues
  tokens missing every group-derived role**, silently, from the first request
  onward.
- **Asymmetric listing.** Actor-only listing needs `effective = true`;
  target-scoped listing never resolves group-derived grants; a non-effective
  project-scoped listing does not walk the project tree either (see the
  `read`-only target-scoped path in §3) — parent-project `inherited = true`
  grants that the SQL driver surfaces via `get_project_parents` are simply
  absent. Callers relying on the SQL driver's fully-symmetric listing may see
  different results.
- **`check_grant` is always model-resolved.** Unlike the SQL driver's `check`
  (an exact match on actor/target/role **and** the `inherited` flag), this
  driver's `check_grant` calls OpenFGA's `check` API, so it also returns `true`
  for a grant reached via group membership, implication or inheritance, with
  no way to ask for "direct only" (the method takes no `effective` flag).
  Harmless today — `check_grant` has no production caller (the `HEAD
  /v3/projects/{id}/users/{id}/roles/{id}` handler goes through
  `list_role_assignments` instead) — but a future caller wiring `check_grant`
  directly will get a different answer per driver.
- **`implied_via` provenance is lost.** Effective-mode results always report
  `implied_via: None`, even for a role the model only granted through
  implication. `GET /v3/role_assignments?include_names` therefore cannot show
  which grant implied which role on this driver, unlike the SQL driver.
- **No cursor.** Large assignment sets are materialised in memory before
  pagination. Acceptable for realistic per-actor / per-target scopes; not for a
  hypothetical "all assignments" query (which is unsupported anyway).
- **Actor-only effective listing fans out per role.** `(actor, no target)` in
  effective mode issues one `streamed-list-objects` graph walk per
  `(representation, target kind, role relation)` combination — roughly
  `users × 3 × role count` calls, each a full graph traversal, bounded only by
  `max_concurrency` in flight, not in total. `GET /v3/auth/projects` (an
  unscoped→scoped token flow step, e.g. Horizon's project picker) takes this
  path. The SQL driver answers the equivalent query with two table scans.
  Acceptable at a handful of configured roles; worth profiling before pointing
  this driver at a large `role_to_relation` table.
- **`inherited` grants are unavailable** through this driver. Deployments that
  depend on Keystone project-tree inheritance must model it in OpenFGA or stay
  on the SQL driver.
- **New dependency surface:** `reqwest` to talk to OpenFGA, plus `futures` for
  the bounded fan-out.

### Testing

`crates/assignment-driver-openfga/src/tests.rs` exercises every path against an
`httpmock` OpenFGA: actor/target mapping and representation fan-out, the
`effective` branch matrix, streamed object enumeration (multi-frame, no
truncation), retry (retries a 503, does not retry a 400), idempotent revoke,
`inherited` rejection, and post-fetch pagination. Config parsing is covered by
`openstack-keystone-config`. A live-OpenFGA functional suite is reasonable
follow-up work and is not part of this change. Also follow-up, not part of
this change: profiling the actor-only effective fan-out call count
(`users × target kinds × role relations`, see Negative consequences) against a
realistic `role_to_relation` table size, and — if group-membership sync into
OpenFGA gets built — an integration test asserting a scoped token actually
carries a group-derived role end to end.
