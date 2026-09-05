# 34. Per-Domain Assignment Drivers

**Date:** 2026-09-05

## Status

Proposed. Nothing in this ADR is implemented yet; it records the design so it
can be reviewed before code lands.

Extends the domain configuration work of issue #960 (per-domain identity
backend selection, `crates/core/src/identity/service.rs`) to the assignment
provider, and builds on ADR 0033, which added the OpenFGA assignment driver as
a cloud-wide alternative to SQL.

## Context

A domain configuration already selects a domain's **identity** backend.
`IdentityService` holds every registered `IdentityBackend` by name plus a
`DomainConfigResolver`, and `driver_for` resolves the domain's stored
`identity/driver`, dispatching to the named backend and falling back to the
global `[identity] driver` when per-domain drivers are off, the domain is
unknown, no driver is stored, or resolution fails.

The assignment provider has nothing equivalent. `AssignmentService`
(`crates/core/src/assignment/service.rs`) holds exactly one
`backend_driver: Arc<dyn AssignmentBackend>`, resolved once in
`AssignmentService::new` from `[assignment] driver`. Since ADR 0033, a
deployment must therefore choose `sql` **or** `openfga` for the entire cloud.
There is no way to:

- migrate one domain at a time onto OpenFGA and keep the rest on SQL;
- let a single tenant whose authorization already lives in a central OpenFGA
  store keep it there while the rest of the cloud stays on local tables;
- evaluate the OpenFGA driver against production traffic in one domain without
  betting every domain's token issuance on it — a live risk, given ADR 0033's
  warning that a deployment without a group-membership sync silently issues
  tokens missing every group-derived role.

### Why the identity pattern does not transfer unchanged

An identity entity belongs to exactly one domain, so `driver_for_user` has one
question to answer. A role assignment has **two** entities — an actor (user or
group) and a target (project, domain or system) — and they need not share a
domain: a user in domain A can hold a role on a project in domain B.

Dispatch must therefore pick one of them as the key, and the choice is not
symmetric. That is the central decision of this ADR.

### The relevant shape of the existing code

- `AssignmentApi` (`crates/core/src/assignment/provider_api.rs`) has three
  methods: `create_grant`, `list_role_assignments`, `revoke_grant`.
  `AssignmentBackend` (`crates/core/src/assignment/backend.rs`) adds
  `check_grant`, which has no production caller.
- `AssignmentCreate` and `Assignment` both carry `target_id` and an
  `AssignmentType` (`UserProject`, `GroupDomain`, `UserSystem`, …) that names
  the target kind. Both write paths thus always know their target.
- `RoleAssignmentListParameters` carries `user_id` / `group_id` (actors) and
  `domain_id` / `project_id` / `system_id` (targets), all optional. A fully
  empty value is legal.
- The `DomainConfigResolver` (`crates/core/src/domain_config/resolver.rs`)
  already exists on `Provider`, exposed as `get_domain_config_resolver`, and
  overlays the database source onto the file source (the database wins,
  option by option) into a raw `DomainConfig`.
- Domain-configurable option names are whitelisted explicitly in
  `crates/core-types/src/domain_config/option.rs` — today only the `identity`
  and `ldap` groups.

## Decision

### 1. Dispatch keys on the target, never on the actor

The driver serving an assignment is chosen from the **target**:

| Target kind | Domain used for dispatch                             |
| ----------- | ---------------------------------------------------- |
| domain      | the target domain itself                             |
| project     | the project's `domain_id`, via `get_project`         |
| system      | **none** — always the default driver                 |

The decisive reason is not convenience but an invariant: **the target-keyed
partition is closed under Keystone's assignment hierarchy.** Every expansion a
driver performs stays inside the target's domain:

- A project's ancestors are always in the same domain as the project, so the
  SQL driver's `get_project_parents` walk never leaves the domain.
- A domain-level `inherited: true` grant applies only to that domain's
  projects.
- Implied-role expansion rewrites the role, not the target.

Actor-keyed dispatch would violate this. A cross-domain grant (actor in A,
project in B) would be stored in A's driver, but B's project-tree walk and B's
target-scoped listings query B's driver and would not find it. The assignment
would be simultaneously present and absent depending on which side asked.
Target-keyed dispatch has no such split: whoever asks about a target asks the
one driver that owns it.

A second consequence follows for free: because the two write paths always
carry `target_id` and `AssignmentType`, `create_grant` and `revoke_grant`
dispatch unambiguously with no extra lookup beyond the project→domain
resolution.

System-scoped assignments have no owning domain and stay on the default
driver. This is deliberate rather than a fallback: system roles are the most
privileged scope in the deployment, and keeping them out of any
domain-selected backend bounds the blast radius of §6.

### 2. Gated by a new `[assignment] domain_specific_drivers_enabled`

A new switch in `crates/config/src/assignment.rs`, defaulting to `false`,
independent of `[identity] domain_specific_drivers_enabled`. An operator
running per-domain LDAP identity must not silently acquire per-domain
assignment routing — the two are unrelated concerns with very different
security profiles, and an existing deployment that already sets the identity
switch must not change behaviour on upgrade.

When the switch is off, `AssignmentService` keeps a `None` resolver and every
operation goes to the global driver, exactly as today.

The *sources* the resolver consults remain gated by the existing `[identity]`
keys (`domain_specific_drivers_enabled` for the file source,
`domain_configurations_from_database` for the database source), because
`DomainConfigResolver::new` reads them. This is an accepted wart:
`[assignment] domain_specific_drivers_enabled` turns dispatch on, but a
domain's stored configuration is only visible if at least one `[identity]`
source is enabled. Promoting the resolver's source gating to its own
`[domain_config]` keys is follow-up work, deliberately out of scope here so
that this ADR does not also redesign the identity path.

### 3. Two new domain-config groups: `assignment` and `openfga`

Mirroring `identity` + `ldap` — the group that names the driver, and the group
that configures it. In `crates/core-types/src/domain_config/option.rs`:

- `DomainConfigGroupName::{Assignment, Openfga}`, extending `ALL`, `as_str`
  and `FromStr`.
- `ASSIGNMENT_WHITELISTED_OPTIONS = &["driver", "list_limit"]`,
  `ASSIGNMENT_SENSITIVE_OPTIONS = &[]`.
- `OPENFGA_WHITELISTED_OPTIONS`: `api_url`, `model_id`, `store_id`, `timeout`,
  `max_retries`, `retry_backoff_ms`, `max_concurrency`, `role_to_relation`,
  `user_actor_types`, `group_actor_types`, `project_target_types`,
  `domain_target_types`, `system_target_types`, `id_transform`.
- `OPENFGA_SENSITIVE_OPTIONS = &["api_key"]`, so a domain's bearer token is
  write-only and is redacted by the existing `Serialize` and `Debug` impls on
  `DomainConfig` / `DomainConfigOption`.

As with `[ldap]`, the list is transcribed explicitly rather than derived from
`OpenFGAAssignmentDriver`, so that a newly added `[openfga]` option never
becomes domain-writable by accident.

`DomainConfig` gains `resolve_assignment(&Config) -> AssignmentProvider` and
`resolve_openfga(&Config) -> Result<OpenFGAAssignmentDriver, _>` beside the
existing `resolve_identity` / `resolve_ldap`. Note that `Config.openfga` is
`Option<OpenFGAAssignmentDriver>`: `resolve_openfga` must succeed when a
domain supplies the whole section and the global config has none, and must
fail with a clear error when neither does.

### 4. Driver instances become per-domain

This is the structural cost of §3 and must not be understated.

The OpenFGA driver today is a single shared instance that reads
`state.config_manager.config.read().await.openfga` on each call, so one
instance serves the whole cloud. Once a domain can override `store_id`,
`api_url` or `role_to_relation`, that no longer holds: two domains on
`driver = "openfga"` may point at different stores.

`AssignmentService` therefore keeps, in addition to the name→backend registry
that `plugin_manager` provides:

- a map of `domain_id` → resolved `Arc<dyn AssignmentBackend>`, built lazily
  from the domain's resolved configuration on first use;
- the global driver, used for `system` targets, for unconfigured domains, and
  as the fallback whenever resolution fails.

A domain whose `assignment` group names a driver but sets no group-specific
options resolves to a configuration equal to the global one; the
implementation should collapse those onto the shared instance rather than
minting a duplicate.

`plugin_manager` needs an `assignment_backends()` accessor returning the whole
registry, matching the existing `identity_backends()`; only
`get_assignment_backend(name)` exists today.

### 5. Untargeted requests fan out across every active driver and union

Four production paths reach the provider without a target:

- `crates/keystone/src/api/v3/auth/project/list.rs` — `GET /v3/auth/projects`
  passes `user_id` and `effective: true` and discovers the projects; by
  definition it has no target.
- `crates/keystone/src/api/v4/auth_plugin/identity_link/mod.rs`
  (`target_holds_system_role`) — `user_id` and `effective: true`, filtering
  the result for system assignments. This one is avoidable: it could set
  `system_id` and take the default driver directly, since `system` is a
  singleton target, and the implementation should do so.
- `crates/keystone/src/scim/group/delete.rs` — lists a group's assignments by
  `group_id` alone and revokes each one.
- `crates/keystone/src/api/v3/role_assignment/list.rs` —
  `GET /v3/role_assignments` with entirely caller-supplied filters, which may
  carry neither actor nor target.

These query **every active driver instance** (the global driver plus each
per-domain instance) and union the results.

Serving them from the default driver alone — the obvious cheap answer — is
rejected on two grounds. `GET /v3/auth/projects` would omit a user's projects
in any OpenFGA-backed domain, breaking the unscoped→scoped token flow that
Horizon's project picker depends on. Worse, SCIM group deletion would revoke
only the grants held in the default driver and silently leave the rest
standing: a group that looks deleted but still grants roles is exactly the
escalation path that code path exists to close.

Three sub-decisions follow.

**The fan-out set.** Because instances are per-domain (§4), the set is derived
by enumerating the domains that have an `assignment` group stored. The `fs`
source already holds every domain configuration in memory from startup; the
`sql` source needs a "list domains setting this option" query on
`DomainConfigBackend`. The set is warmed at startup and refreshed when a
domain configuration is written through the config API.

**Merging.** Results are concatenated, de-duplicated, then re-sorted and
sliced by `Assignment::pagination_marker`, so `marker` / `limit` /
`page_reverse` apply to the union rather than per driver. This is the same
post-fetch pagination both existing drivers already perform (ADR 0029, ADR
0033 §6), lifted one level up.

**Partial failure fails the request.** Any error from any driver in the
fan-out — including the `NotImplemented` / HTTP 501 shapes OpenFGA returns for
unsupported listing shapes (ADR 0033 §10) — fails the whole call. The
alternative, skipping the failing driver with a warning, silently shrinks a
listing that a caller may be using to revoke grants. A short, honest 501 is
better than a long answer that is quietly missing rows. The cost is stated in
the Negative consequences.

### 6. The `assignment` and `openfga` groups are cloud-admin only

Per `doc/src/contributor/security-model.md`, this is the load-bearing
requirement of the whole design.

Token issuance resolves a scope's roles through the target's driver:
`resolve_domain_roles`, `resolve_project_default_roles`,
`resolve_project_roles` and `resolve_trust_roles` in
`crates/core/src/auth.rs` all call `list_role_assignments` with a target and
`effective: true`. A principal who can write a domain's `assignment/driver`
and `openfga/*` options can therefore point that domain at a relationship
store they control and mint arbitrary roles on that domain's projects — for
themselves or anyone else.

The domain configuration API policy must consequently restrict these two
groups to cloud administrators, not to domain administrators, even where a
domain administrator may write that domain's `identity` and `ldap` groups. The
policy rules must key on the authentication chain, as every other
authorization decision does, and must not be satisfiable by a
domain-scoped token.

The `system` carve-out of §1 bounds the residual exposure: even a
misconfiguration or a policy mistake here cannot manufacture system-scoped
roles, so it cannot reach the rest of the cloud.

### 7. No single-domain registration lock for `assignment/sql`

Identity needs one — `DomainConfigService::claim_sql_registration` lets a
single domain claim `identity/driver = sql`, because the SQL identity tables
cannot represent more than one domain's users.

Assignment rows carry globally unique actor and target ids and are already
partitioned by target, so any number of domains can share the SQL assignment
driver without collision. The omission of a lock is therefore deliberate, and
is recorded here so that it is not later read as an oversight in the identity
parity.

### 8. Caching and invalidation

The resolved `domain_id` → driver name mapping is cached in an
`RwLock<HashMap<..>>`, mirroring `IdentityService::resolved_driver_cache`, and
inherits the same known limitation: no invalidation, so a change made through
the config API is picked up on restart.

That limitation bites harder here than it does for identity, because the
fan-out set of §5 must also be refreshed when a domain gains or loses an
`assignment` group. The implementation should invalidate both on a config
write in the same process; cross-process invalidation stays a restart, as it
is for identity today.

## Consequences

### Positive

- A domain can be migrated onto OpenFGA on its own, so ADR 0033's driver can
  be exercised against real traffic without wagering every domain's token
  issuance on the deployment having built a group-membership sync.
- Target-keyed dispatch is closed under project-tree inheritance and
  domain-level inherited grants, so no driver ever has to answer a question
  about a target it does not own.
- Both write paths dispatch from data they already carry; no new field on
  `AssignmentCreate` or `Assignment` is needed.
- System-scoped assignments are structurally excluded from domain-selected
  backends, so the most privileged scope keeps a single, operator-controlled
  source of truth.
- The resolution layer, the config API, the whitelist mechanism and the
  sensitive-option redaction are all reused unchanged; the new surface is two
  group variants, two `resolve_*` methods and the dispatch itself.
- No persistence change and no migration: an existing deployment with the
  switch off behaves exactly as it does today.

### Negative

- **An untargeted listing is as weak as the weakest driver.** With one
  OpenFGA-backed domain, an unfiltered `GET /v3/role_assignments`, a
  role-only listing, and any actor-only non-effective listing return 501 for
  the whole cloud, because the fan-out propagates the driver's
  unsupported-shape error (§5). Notably the SCIM group-delete path
  (`crates/keystone/src/scim/group/delete.rs`) lists by `group_id` with
  `effective` unset, which is precisely that shape — SCIM group deletion
  breaks against an OpenFGA-backed domain until that call site sets
  `effective`, and this should be fixed as part of the implementation rather
  than left to be discovered in production.
- **Untargeted calls cost O(active drivers).** `GET /v3/auth/projects` is on
  this path and is already the most expensive query on the OpenFGA driver
  (ADR 0033 lists it as a `users × target kinds × role relations` graph-walk
  fan-out). Fanning it out across domains multiplies that. Worth profiling
  before enabling per-domain drivers on a cloud with many OpenFGA domains.
- **Driver instances stop being singletons.** Per-domain `[openfga]`
  configuration means an instance map keyed by domain, lazily built, with its
  own lifecycle — a departure from the one-instance-per-name registry every
  other backend uses, and a new place for connection pools to accumulate.
- **A new privilege boundary to get right.** §6 is a policy requirement, not
  something the type system enforces. A policy file that lets a domain admin
  write the `assignment` group is a role-minting escalation within that
  domain. This must be covered by an explicit policy test, not left to review.
- **Two switches that interact.** Until the resolver's source gating is
  promoted out of `[identity]`, enabling `[assignment]
  domain_specific_drivers_enabled` alone does nothing visible, which is a
  confusing operator experience.
- **Stale resolution is now more visible.** With identity, a stale cached
  driver affects one domain's users. Here, a stale fan-out set can omit an
  entire domain from an untargeted listing until restart.
- **Cross-driver consistency is not transactional.** A grant written to one
  domain's driver and a revocation event written centrally are two operations;
  a driver failing mid-way leaves them disagreeing, as it does today, but with
  more drivers there are more ways for it to happen.
- **`check_grant` diverges further.** It already behaves differently between
  SQL and OpenFGA (ADR 0033). Per-domain drivers mean a single deployment can
  now exhibit both behaviours. Harmless while it has no production caller;
  a future caller must not assume uniformity.

### Testing

The implementation should carry, at minimum:

- A `per_domain_dispatch` unit suite for `AssignmentService`, modelled on
  `crates/core/src/identity/service/tests/per_domain_dispatch.rs`: resolution
  from a stored `assignment/driver`, the empty-config and resolution-error
  fallbacks to the global driver, per-domain caching (the config source
  consulted exactly once for two calls), project→domain resolution for a
  project target, a domain target, and the system carve-out.
- A cross-domain grant test proving the invariant of §1 directly: a grant by
  an actor in domain A on a project in domain B is written to and read from
  B's driver, and is visible in B's target-scoped listing.
- Fan-out tests for §5: the union and de-duplication, marker pagination
  applied across the union rather than per driver, and a driver returning
  `NotImplemented` failing the whole call rather than being skipped.
- A policy test asserting the `assignment` and `openfga` groups are refused to
  a domain-scoped administrator (§6), since nothing else enforces it.
- An integration suite modelled on `tests/integration/src/domain_config.rs`,
  driving two domains on two drivers through the provider stack, including a
  scoped-token issue against each.
- Config-parsing coverage for the new switch and the two new groups in
  `openstack-keystone-config` and `openstack-keystone-core-types`.

Note that `crates/core-types/src/domain_config/option.rs` currently uses
`"assignment"` as its example of an *unknown* group in
`unknown_group_is_rejected`; that test needs a different example when this
lands.
