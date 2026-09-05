# 34. Per-Domain Assignment Drivers

**Date:** 2026-09-07

## Status

Proposed.

Extends the domain configuration for the identity driver.

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

### Two things a domain needs to move onto OpenFGA

Moving a domain off the global driver takes two distinct pieces of information:

- a **driver name** — which registered backend serves the domain. Small, holds
  no secret, safe to change at runtime.
- a **driver configuration** — for OpenFGA the store id, model id, API URL and
  bearer token; for SQL nothing beyond the global `[database]`. The endpoint and
  the bearer token are trust anchors for every authorization decision the domain
  makes.

This ADR routes the first through the domain configuration API and keeps the
second in server configuration. §3 and §4 give the reasoning; the short version
is that an API-writable driver configuration is a role-minting escalation (§6).

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
  overlays the database source onto the file source (the database wins, option
  by option) into a raw `DomainConfig`. `IdentityService` builds its own
  instance, gated on `[identity] domain_specific_drivers_enabled`;
  `DomainConfigResolver::new` decides which of the two sources it holds by
  reading the `[identity]` switches directly. Per-domain assignment consults a
  resolver for a single value, `assignment/driver`.
- Domain-configurable option names are whitelisted explicitly in
  `crates/core-types/src/domain_config/option.rs` — today only the `identity`
  and `ldap` groups.

## Decision

### 1. Dispatch keys on the target, never on the actor

The driver serving an assignment is chosen from the **target**:

| Target kind | Domain used for dispatch                     |
| ----------- | -------------------------------------------- |
| domain      | the target domain itself                     |
| project     | the project's `domain_id`, via `get_project` |
| system      | **none** — always the default driver         |

The decisive reason is not convenience but an invariant: **the target-keyed
partition is closed under Keystone's assignment hierarchy.** Every expansion a
driver performs stays inside the target's domain:

- A project's ancestors are always in the same domain as the project, so the SQL
  driver's `get_project_parents` walk never leaves the domain.
- A domain-level `inherited: true` grant applies only to that domain's projects.
- Implied-role expansion rewrites the role, not the target.

Actor-keyed dispatch would violate this. A cross-domain grant (actor in A,
project in B) would be stored in A's driver, but B's project-tree walk and B's
target-scoped listings query B's driver and would not find it. The assignment
would be simultaneously present and absent depending on which side asked.
Target-keyed dispatch has no such split: whoever asks about a target asks the
one driver that owns it.

A second consequence follows for free: because the two write paths always carry
`target_id` and `AssignmentType`, `create_grant` and `revoke_grant` dispatch
unambiguously with no extra lookup beyond the project→domain resolution.

System-scoped assignments have no owning domain and stay on the default driver.
This is deliberate rather than a fallback: system roles are the most privileged
scope in the deployment, and keeping them out of any domain-selected backend
bounds the blast radius of §6.

### 2. Per-provider dispatch; resolver sources gated in `[domain_config]`

Two orthogonal decisions, deliberately kept apart.

**Per-provider dispatch.** A new switch in `crates/config/src/assignment.rs`,
`domain_specific_drivers_enabled`, defaulting to `false`, independent of
`[identity] domain_specific_drivers_enabled`. An operator running per-domain
LDAP identity must not silently acquire per-domain assignment routing — the two
are unrelated concerns with very different security profiles, and an existing
deployment that already sets the identity switch must not change behaviour on
upgrade. When the switch is off, `AssignmentService` keeps a `None` resolver and
every operation goes to the global driver, exactly as today.

**Resolver sources.** Which of the two sources a `DomainConfigResolver` holds —
the `fs` source (per-domain files under `[identity] domain_config_dir`) and the
`sql` source (the `domain_config` table) — is shared infrastructure, not a
per-provider concern: both sources carry every group, and each consumer filters
to its own (`resolve_identity`, `resolve_assignment_driver_name`). Today
`DomainConfigResolver::new` reads the `[identity]` switches directly, which is
why `[assignment] domain_specific_drivers_enabled` on its own would resolve
every domain to the empty configuration unless an `[identity]` source were also
enabled. This ADR moves that gate to its own section rather than leave the
dependency implicit:

```toml
[domain_config]
from_files    = false  # hold the fs source
from_database = true   # hold the sql source
```

Config blocks in this ADR are rendered as TOML for readability. The primary
`keystone.conf` is INI; there these are plain INI sections (the `config` crate
splits dotted section headers, as `[auth_plugin.<name>]` already relies on), and
a `KEYSTONE_SITE_VARS_FILE` overlay may equally be TOML. The same holds for
every block below.

- Both fields are `Option<bool>` internally. `DomainConfigResolver::new` reads
  the effective value
  `from_files.unwrap_or([identity] domain_specific_drivers_enabled)` and
  `from_database.unwrap_or([identity] domain_configurations_from_database)`. A
  deployment that sets only the old `[identity]` keys is unchanged, defaults
  included.
- When a `[domain_config]` key is set explicitly it wins; if a deprecated
  `[identity]` key is also set to a different value, construction logs one
  `WARN` naming the deprecated key and the winner.
- `[identity] domain_configurations_from_database` becomes a deprecated alias
  for `[domain_config] from_database`.
  `[identity] domain_specific_drivers_enabled` is only _partially_ superseded —
  it keeps its second job, turning on identity per-domain dispatch — so it is
  not deprecated, only its source-gating side effect moves.
  `[identity] domain_config_dir` (the fs driver's path) stays in `[identity]`.
  Both are residual warts, smaller than the one they replace and now explicit.

**Per-provider resolver instances.** `IdentityService` keeps its own
`Option<Arc<DomainConfigResolver>>`, built at startup and restart-only, gated on
`[identity] domain_specific_drivers_enabled`. `AssignmentService` holds its own,
inside the `ArcSwap` bundle of §9, gated on
`[assignment] domain_specific_drivers_enabled`. Both instances read the same
`[domain_config]` gate and wrap the same shared `fs` / `sql` backend `Arc`s —
the split exists only so a §9 reload can swap assignment's resolver without
disturbing identity's restart-only path. `Provider::get_domain_config_resolver`
is retained, built from the same effective gate; removing it is not this ADR's
job.

The honest residual: source gating (`[domain_config]`) and dispatch
(`[assignment] domain_specific_drivers_enabled`) are two knobs and both are
required. That is strictly better than today's silent dependence on an
`[identity]` key, because the dependency now has its own name and its own
documentation.

### 3. The domain configuration API carries a driver name, not a configuration

One new domain-config group, `assignment`, with exactly one option. In
`crates/core-types/src/domain_config/option.rs`:

- `DomainConfigGroupName::Assignment`, extending `ALL`, `as_str` and `FromStr`.
- `ASSIGNMENT_WHITELISTED_OPTIONS = &["driver"]`,
  `ASSIGNMENT_SENSITIVE_OPTIONS = &[]`.

There is **no** `openfga` domain-config group. A domain's stored configuration
names the driver it wants — nothing else. `list_limit` is deliberately excluded:
it is a per-provider tuning knob (`[assignment] list_limit`), not a per-domain
concern, and a domain that raises it would shift load onto shared driver
instances.

`driver` is validated at write time against the set of names the operator has
made bindable (§4): `sql`, the driver of the global `[assignment]` section, and
every driver named by an `[assignment.backends.*]` block. A write naming any
other value — including `openfga` when the deployment configures no OpenFGA
backend anywhere — is rejected by the config API, not stored and later ignored.

`DomainConfig` gains `resolve_assignment_driver_name(&Config) -> Option<String>`
beside the existing `resolve_identity` / `resolve_ldap`. There is deliberately
no `resolve_openfga`: the API layer never constructs a driver configuration.

**Why the configuration stays out of the API.** Per
`doc/src/contributor/security-model.md`, a domain's assignment driver
configuration is a trust anchor for every token issued in that domain (§6). An
API-writable configuration would:

- carry the OpenFGA bearer token and any mTLS material through the config API
  and into the shared `domain_config` table, the `Serialize` / `Debug` redaction
  the only thing between it and a log line;
- let whoever holds the config-API policy repoint a domain at an OpenFGA store
  **they** control and mint arbitrary roles there — the endpoint itself, not
  merely the choice among vetted endpoints, would be attacker-supplied;
- add a per-option whitelist (fourteen `[openfga]` keys) that has to track the
  driver struct as it grows, each new key one review slip from being
  domain-writable.

Keeping the configuration in server config removes all three. The API caller
chooses **among** backends the operator has provisioned; it cannot define one.

### 4. Per-domain driver parameters live in server configuration

`crates/config/src/assignment.rs` gains two maps: named **backend** blocks that
each hold one driver configuration, and a **domain → backend** table.

```toml
[assignment]
driver = "sql"                       # global default; system + fallback
domain_specific_drivers_enabled = true

# A named driver configuration. Any number of domains may point at it.
[assignment.backends.central_fga]
driver   = "openfga"
api_url  = "https://openfga.internal:8080"
store_id = "01JQ..."
model_id = "01JQ..."
api_key  = "..."                     # secret; never leaves the host
# ... the full [openfga] option set, typed, no whitelist

# Map a domain to a backend block. No per-domain parameters.
[assignment.domains]
"1111...1111" = "central_fga"
"2222...2222" = "central_fga"
```

Rendered as TOML; in `keystone.conf` these are plain INI sections
(`[assignment.backends.central_fga]`, `[assignment.domains]`), as noted in §2.

- Both maps are typed in `crates/config` like the rest of the file. There is no
  whitelist and no redaction plumbing because they never cross a process
  boundary.
- **Multiple domains share one backend by naming it.** Two domains mapped to
  `central_fga` resolve to the _same_ `AssignmentBackend` instance — one OpenFGA
  client, one connection pool — with no configuration repeated. Instances are
  keyed by backend name, not by domain.
- A backend block's `driver` must equal the mapped domains' API-stored
  `assignment/driver` binding (§3). A `sql` backend block is allowed but rarely
  needed: an SQL-backed domain with no `[assignment.domains]` entry already
  shares the global `[database]` instance (§7).
- The global `[assignment] driver` — and, for `openfga`, the global `[openfga]`
  section — still serves `system` targets, unconfigured domains, and every
  resolution fallback. A domain that wants the _global_ OpenFGA store binds
  `openfga` with no `[assignment.domains]` entry and shares the default
  instance; nothing is repeated for that case either.

`AssignmentService` therefore keeps, in addition to the name→backend registry
that `plugin_manager` provides:

- a map of **backend name** → resolved `Arc<dyn AssignmentBackend>`, built from
  the `[assignment.backends.<name>]` block the first time a bound domain
  resolves to it and reused by every other domain that names it;
- the global driver, used for `system` targets, for domains with no binding or
  no mapping, and as the fallback whenever resolution fails.

**Joining the binding to the parameters.** Resolution for a domain is:

1. Resolve `assignment/driver` through the `DomainConfigResolver` (§3). Absent →
   global driver.
2. Name present → look up the domain in `[assignment.domains]`.
   - Mapped to a backend whose block exists and whose `driver` equals the bound
     name → build or reuse that backend instance, shared with every other domain
     mapped to the same name.
   - Not mapped, and the bound name equals the global `[assignment] driver` →
     the global instance.
3. Mapped to a missing or `driver`-mismatched backend, or bound to a non-global
   name with no mapping → **fall back to the global driver and log a `WARN`.**
   This is the stale-binding case: an operator removed or renamed a backend
   block while a domain's API-stored binding still names `openfga`. The
   write-time check of §3 stops the common case at the source; the resolve-time
   fallback keeps a bad edit from failing token issuance.

### 5. Untargeted requests fan out across every active driver and union

Four production paths reach the provider without a target:

- `crates/keystone/src/api/v3/auth/project/list.rs` — `GET /v3/auth/projects`
  passes `user_id` and `effective: true` and discovers the projects; by
  definition it has no target.
- `crates/keystone/src/api/v4/auth_plugin/identity_link/mod.rs`
  (`target_holds_system_role`) — `user_id` and `effective: true`, filtering the
  result for system assignments. This one is avoidable: it could set `system_id`
  and take the default driver directly, since `system` is a singleton target,
  and the implementation should do so.
- `crates/keystone/src/scim/group/delete.rs` — lists a group's assignments by
  `group_id` alone and revokes each one.
- `crates/keystone/src/api/v3/role_assignment/list.rs` —
  `GET /v3/role_assignments` with entirely caller-supplied filters, which may
  carry neither actor nor target.

These query **every active driver instance** (the global driver plus each
distinct per-domain backend instance) and union the results.

Serving them from the default driver alone — the obvious cheap answer — is
rejected on two grounds. `GET /v3/auth/projects` would omit a user's projects in
any OpenFGA-backed domain, breaking the unscoped→scoped token flow that
Horizon's project picker depends on. Worse, SCIM group deletion would revoke
only the grants held in the default driver and silently leave the rest standing:
a group that looks deleted but still grants roles is exactly the escalation path
that code path exists to close.

Three sub-decisions follow.

**The fan-out set.** The active set is the global driver plus one instance per
distinct `[assignment.backends.*]` block that a bound domain maps to (§4). The
bindings come from the domain-config sources — the `fs` source holds them all in
memory from startup, the `sql` source needs a "list domains that set
`assignment/driver`" query on `DomainConfigBackend` — while the backend blocks
and the `[assignment.domains]` table are already in memory. Several domains
mapped to one backend contribute a single instance and a single fan-out query.
The set is warmed at startup, refreshed when a binding is written through the
config API, and rebuilt on a configuration reload (§9).

**Merging.** Results are concatenated, de-duplicated, then re-sorted and sliced
by `Assignment::pagination_marker`, so `marker` / `limit` / `page_reverse` apply
to the union rather than per driver. This is the same post-fetch pagination both
existing drivers already perform (ADR 0029, ADR 0033 §6), lifted one level up.

**Partial failure fails the request.** Any error from any driver in the fan-out

- including the `NotImplemented` / HTTP 501 shapes OpenFGA returns for
  unsupported listing shapes (ADR 0033 §10) - fails the whole call. The
  alternative, skipping the failing driver with a warning, silently shrinks a
  listing that a caller may be using to revoke grants. A short, honest 501 is
  better than a long answer that is quietly missing rows. The cost is stated in
  the Negative consequences.

### 6. The `assignment` group is cloud-admin only

Per `doc/src/contributor/security-model.md`, this is the load-bearing policy
requirement of the design.

Token issuance resolves a scope's roles through the target's driver:
`resolve_domain_roles`, `resolve_project_default_roles`, `resolve_project_roles`
and `resolve_trust_roles` in `crates/core/src/auth.rs` all call
`list_role_assignments` with a target and `effective: true`. A principal who can
write a domain's `assignment/driver` moves that domain's role resolution to a
different backend.

§3 and §4 already bound what that backend can be: `sql`, the global `[openfga]`
store, or a named `[assignment.backends.*]` block the operator mapped to the
domain — never an endpoint the principal supplies. The residual privilege is
still real: flipping the binding activates whatever backend the operator has
staged for that domain, or the global OpenFGA store, and changes which backend
resolves the domain's roles. The domain configuration API policy must therefore
restrict the `assignment` group to cloud administrators, even where a domain
administrator may write that domain's `identity` and `ldap` groups. The policy
rules must key on the authentication chain, as every other authorization
decision does, and must not be satisfiable by a domain-scoped token.

The `system` carve-out of §1 bounds the residual exposure: even a
misconfiguration here cannot manufacture system-scoped roles, so it cannot reach
the rest of the cloud.

### 7. No single-domain registration lock for `assignment/sql`

Identity needs one — `DomainConfigService::claim_sql_registration` lets a single
domain claim `identity/driver = sql`, because the SQL identity tables cannot
represent more than one domain's users.

Assignment rows carry globally unique actor and target ids and are already
partitioned by target, so any number of domains can share the SQL assignment
driver without collision. The omission of a lock is therefore deliberate, and is
recorded here so that it is not later read as an oversight in the identity
parity. It also means an SQL-backed domain needs no `[assignment.domains]` entry
at all (§4).

### 8. Caching and invalidation

The resolved `domain_id` → driver-name binding is cached in an
`RwLock<HashMap<..>>`, mirroring `IdentityService::resolved_driver_cache`. The
backend **parameters** are not cached at this layer — they are read from
`ConfigManager`'s live configuration and refreshed on its reload path (§9) - and
backend instances are keyed by backend name, so N domains mapped to one backend
hold one entry. Whether the resolver has a source at all is likewise read from
live configuration: the `[domain_config]` gate of §2 (with its `[identity]`
fallback) is re-evaluated on the same reload path.

Unlike identity, the binding cache is not invalidation-free: the config API
writer clears it in its own process, and a configuration reload rebuilds it
(§9). What is not covered is a database-sourced binding write on another node,
which that node observes only after its own reload signal or a restart. Because
only the binding — a driver name — is database-sourced, that gap can move a
domain between already-configured backends; it can never carry an endpoint or a
secret across nodes.

The fan-out set of §5 must be refreshed on the same events, since it changes
whenever a domain gains or loses an `assignment/driver` binding or the
`[assignment.domains]` / `[assignment.backends.*]` configuration changes. The
config API writer invalidates the binding cache and the fan-out set in its own
process on every write; a configuration reload invalidates them too and
additionally rebuilds the resolver and the per-backend driver instances (§9).

### 9. Configuration reload rebuilds the resolver, drivers and caches

Keystone reloads its configuration in place, and provider subsystems react
through `ConfigManager::notify_tx`: the dummy-hash cache, the rate limiters and
the database connection each have a reactor in
`crates/keystone/src/server/startup/background.rs`. The per-domain assignment
state must react the same way, because every input it derives from can change
across a reload:

- `[assignment] domain_specific_drivers_enabled` — dispatch may switch on or off
  — and the `[domain_config]` source keys of §2 (with their `[identity]`
  fallbacks) — the resolver may gain or lose a source.
- the `[assignment.backends.*]` blocks and the `[assignment.domains]` table — a
  backend's parameters, a whole backend, or a domain's mapping may be added,
  edited or removed.
- the `fs` domain-config directory — a domain's stored `assignment/driver`
  binding file may be added, edited or removed on disk.
- the global `[assignment]` section — the driver every unconfigured domain and
  every `system` target inherits.

A new `reload_assignment_drivers_on_config_change` reactor, registered beside
the others in `background.rs`, subscribes to `notify_tx` and on each
notification (or a lagged receiver) performs, against the current configuration:

1. **Resolver.** Rebuild `AssignmentService`'s `DomainConfigResolver` from the
   current effective `[domain_config]` gate — `None` when the dispatch switch is
   now off, sourceless when both `[domain_config]` keys resolve off — so the
   file source re-reads the config directory. Identity's own resolver instance
   is not touched (§2).
2. **Binding cache.** Drop the resolved `domain_id` → driver-name map of §8 in
   full.
3. **Per-backend instances.** Resolve the set of
   `(bound name, mapped backend block)` pairs the current configuration produces
   and diff it by backend identity against the live instance map: build and swap
   in an instance for a backend that is new or whose parameters changed, drop an
   instance no bound domain maps to any more, and leave an unchanged backend's
   instance — and its connection pool — untouched. Editing one
   `[assignment.backends.*]` block rebuilds exactly that instance; every domain
   mapped to it picks up the new instance on its next resolve.
4. **Fan-out set.** Recompute the §5 set from the rebuilt inputs.

This requires the resolver, the binding cache, the instance map and the fan-out
set to sit behind interior mutability on `AssignmentService` — one `ArcSwap`
over an immutable bundle is enough and keeps readers lock-free — where today
`backend_driver` is a plain `Arc`.

Failure is last-known-good, matching the rate-limiter reactor: a reload whose
new configuration does not resolve is logged and the previous bundle is
retained, rather than tearing running drivers down on a bad edit.

This closes the in-process half of the §8 invalidation gap for file-sourced
bindings and for every driver parameter, and goes one step beyond the identity
path, which still needs a restart to pick up a changed `identity/driver`.
Bringing the identity service onto the same reactor is reasonable follow-up work
but is out of scope here.

## Consequences

### Positive

- A domain can be migrated onto OpenFGA on its own, so ADR 0033's driver can be
  exercised against real traffic without wagering every domain's token issuance
  on the deployment having built a group-membership sync.
- Driver endpoints and the OpenFGA bearer token never cross the API boundary or
  land in the shared `domain_config` table: the API caller selects among
  backends the operator has provisioned on the host, it cannot define one (§3).
- Any number of domains share one OpenFGA backend — one client, one connection
  pool, one fan-out query — by mapping to a named `[assignment.backends.*]`
  block, with no driver configuration repeated per domain (§4).
- The new domain-config surface is a single option, `assignment/driver`. There
  is no per-`[openfga]`-option whitelist to keep in sync with the driver struct.
- Target-keyed dispatch is closed under project-tree inheritance and
  domain-level inherited grants, so no driver ever has to answer a question
  about a target it does not own.
- Both write paths dispatch from data they already carry; no new field on
  `AssignmentCreate` or `Assignment` is needed.
- System-scoped assignments are structurally excluded from domain-selected
  backends, so the most privileged scope keeps a single, operator-controlled
  source of truth.
- The resolution layer, the config API, the whitelist mechanism and the
  sensitive-option redaction are reused unchanged; the new surface is one group
  variant, one `resolve_*` method, the two config maps and the dispatch.
- No persistence change and no migration: an existing deployment with the switch
  off behaves exactly as it does today.
- The resolver's source gating is a named `[domain_config]` concern rather than
  a side effect of an `[identity]` switch (§2). Enabling per-domain assignment
  drivers takes `[assignment] domain_specific_drivers_enabled` plus a
  `[domain_config]` source; no `[identity]` key is involved, and existing
  deployments keep working through the `[identity]` fallback.
- A configuration reload picks up a changed switch, a changed global
  `[assignment]` section, and an added, edited or removed backend block, domain
  mapping or domain binding file, without a restart (§9) — a capability the
  identity path does not yet have.

### Negative

- **Onboarding a domain onto a named OpenFGA backend is a two-role operation.**
  The operator adds or reuses an `[assignment.backends.*]` block, adds an
  `[assignment.domains]` mapping and reloads; a cloud administrator then writes
  the `assignment/driver` binding through the API. A binding with no matching
  mapping is inert — it falls back to the global driver with a `WARN` (§4) — so
  the two steps must agree. This is the deliberate cost of keeping the
  configuration off the API. (Binding a domain to the _global_ OpenFGA store
  needs no config edit — just the API write.)
- **Divergence from the identity per-domain model.** Issue #1202 puts a domain's
  identity driver configuration through the config API; this ADR keeps the
  assignment driver configuration in server config. Until identity follows, an
  operator meets two different mental models for two adjacent features. The
  security asymmetry — an assignment backend mints roles cloud-wide through
  token issuance — is the justification, recorded in §3.
- **An untargeted listing is as weak as the weakest driver.** With one
  OpenFGA-backed domain, an unfiltered `GET /v3/role_assignments`, a role-only
  listing, and any actor-only non-effective listing return 501 for the whole
  cloud, because the fan-out propagates the driver's unsupported-shape error
  (§5). Notably the SCIM group-delete path
  (`crates/keystone/src/scim/group/delete.rs`) lists by `group_id` with
  `effective` unset, which is precisely that shape — SCIM group deletion breaks
  against an OpenFGA-backed domain until that call site sets `effective`, and
  this should be fixed as part of the implementation rather than left to be
  discovered in production.
- **Untargeted calls cost O(distinct active backends).** `GET /v3/auth/projects`
  is on this path and is already the most expensive query on the OpenFGA driver
  (ADR 0033 lists it as a `users × target kinds × role relations` graph-walk
  fan-out). Fanning it out multiplies that — once per distinct backend, not once
  per domain, since domains sharing a backend share its query. Worth profiling
  before enabling per-domain drivers on a cloud with many distinct OpenFGA
  backends.
- **Driver instances stop being singletons.** Named `[assignment.backends.*]`
  blocks mean an instance map keyed by backend name, lazily built, with its own
  lifecycle — a shared store is still one instance, but this is a departure from
  the one-instance-per-driver-name registry every other backend uses, and a new
  place for connection pools to accumulate.
- **A new privilege boundary to get right.** §6 is a policy requirement, not
  something the type system enforces. A policy file that lets a domain admin
  write the `assignment` group binds that domain's role resolution to another
  backend. This must be covered by an explicit policy test, not left to review.
- **Source gating and dispatch are separate knobs.** `[domain_config]` decides
  whether the resolver has a source;
  `[assignment] domain_specific_drivers_enabled` decides whether assignment
  dispatches per domain. Both are required, and setting only the second still
  resolves every domain to the global driver (§2). This is deliberate — the
  sources are shared with identity — but it is one more thing an operator must
  get right.
- **Two config keys only partially migrate.**
  `[identity] domain_configurations_from_database` becomes a deprecated alias;
  `[identity] domain_specific_drivers_enabled` keeps its identity-dispatch job
  and is not deprecated, only its source-gating side effect moves;
  `[identity] domain_config_dir` stays put. The `[identity]` section keeps a
  foot in domain-config gating until the identity path is reworked too (§2).
- **Stale resolution is now more visible.** With identity, a stale cached driver
  affects one domain's users. Here, a stale fan-out set can omit an entire
  domain from an untargeted listing until restart.
- **Cross-driver consistency is not transactional.** A grant written to one
  domain's driver and a revocation event written centrally are two operations; a
  driver failing mid-way leaves them disagreeing, as it does today, but with
  more drivers there are more ways for it to happen.
- **`check_grant` diverges further.** It already behaves differently between SQL
  and OpenFGA (ADR 0033). Per-domain drivers mean a single deployment can now
  exhibit both behaviours. Harmless while it has no production caller; a future
  caller must not assume uniformity.
- **A configuration reload now churns assignment state.** Where a reload today
  touches a cache and a connection pool, it now re-resolves every configured
  backend and may build or drop `AssignmentBackend` instances, each with its own
  OpenFGA client and pool. A reload that flips the
  `domain_specific_drivers_enabled` switch off tears down every per-backend
  instance at once. The reactor must diff rather than rebuild wholesale (§9) so
  that an unrelated reload does not drop healthy driver connections.

### Testing

The implementation should carry, at minimum:

- A `per_domain_dispatch` unit suite for `AssignmentService`, modelled on
  `crates/core/src/identity/service/tests/per_domain_dispatch.rs`: resolution
  from a stored `assignment/driver`, the empty-config and resolution-error
  fallbacks to the global driver, per-domain caching (the config source
  consulted exactly once for two calls), project→domain resolution for a project
  target, a domain target, and the system carve-out.
- A cross-domain grant test proving the invariant of §1 directly: a grant by an
  actor in domain A on a project in domain B is written to and read from B's
  driver, and is visible in B's target-scoped listing.
- Fan-out tests for §5: the union and de-duplication, marker pagination applied
  across the union rather than per driver, and a driver returning
  `NotImplemented` failing the whole call rather than being skipped.
- A policy test asserting the `assignment` group is refused to a domain-scoped
  administrator (§6), since nothing else enforces it.
- A binding-validation test: a config-API write of `assignment/driver` naming a
  driver that no `[assignment.backends.*]` block or the global `[assignment]`
  section defines (and not `sql`) is rejected, and a resolve against a binding
  whose mapped backend was later removed falls back to the global driver with a
  `WARN` (§4).
- A shared-backend test: two domains mapped to one `[assignment.backends.*]`
  block resolve to the _same_ instance (pointer equality), editing that block
  rebuilds it once and both domains observe the new instance, and the fan-out
  set counts it once.
- A reload-reactor test (§9): a reload that adds, changes and removes
  `[assignment.backends.*]` blocks and `[assignment.domains]` mappings swaps the
  corresponding instances and leaves an unchanged backend's instance identical
  (pointer equality); the binding cache and fan-out set are rebuilt; flipping
  the switch off drops every per-backend instance; a reload with an unresolvable
  new configuration retains the previous bundle.
- An integration suite modelled on `tests/integration/src/domain_config.rs`,
  driving two domains on two drivers through the provider stack, including a
  scoped-token issue against each.
- Config-parsing coverage for the new switch, the `assignment` domain-config
  group and the `[assignment.backends.*]` / `[assignment.domains]` maps in
  `openstack-keystone-config` and `openstack-keystone-core-types`.
- `[domain_config]` gating coverage (§2): a `DomainConfigResolver::new` test
  that an explicit `[domain_config]` key overrides a conflicting `[identity]`
  one (and logs the `WARN`), that an unset key falls back to the `[identity]`
  value including its default, and that with every gate off the resolver holds
  no source and every domain resolves to the global driver; plus a config-parse
  test for `Option<bool>` round-tripping (unset vs explicit `false`).

Note that `crates/core-types/src/domain_config/option.rs` currently uses
`"assignment"` as its example of an _unknown_ group in
`unknown_group_is_rejected`; that test needs a different example once this
lands.
