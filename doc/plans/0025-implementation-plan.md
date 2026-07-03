# ADR 0025 Implementation Plan: Dynamic Auth Plugins via WebAssembly

This document breaks ADR 0025 (`0025-dynamic-auth-plugins.md`) into an
incremental, independently-mergeable sequence of PRs. It is a working plan, not
a design document — all design decisions live in the ADR itself; this file only
sequences the work and pins the implementation choices the ADR deliberately left
to an implementer (crate layout, test strategy, rollout order).

## Ground rules for every phase

- Each PR must build, pass `cargo test`/`cargo clippy` for the whole workspace,
  and leave `main` in a releasable state — no phase depends on a later phase's
  code existing, only on its own preceding PRs.
- No phase changes the public behavior of an existing, already-shipped auth
  method. Everything is additive behind `[dynamic_plugins]` /
  `[dynamic_plugin.*]` config sections that default to empty (no plugins
  configured → zero behavioral change, zero new dependencies pulled into a
  running node's request path).
- Every PR that adds a host-callable capability must land its CADF audit
  wrapping (§6.E) in the _same_ PR — audit is infrastructure, not a follow-up,
  per the ADR. No PR grants a capability before its audit event exists.

## Decisions pinned for this plan

(Selected in the interview that produced this document — recorded here so future
readers don't have to re-derive them.)

| Decision                                    | Choice                                                                                                                                         |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Phasing strategy                            | Incremental, mode-by-mode: runtime + `full_auth` → `mapping` → `route` → admin APIs                                                            |
| Crate layout                                | New dedicated crate `crates/dynamic-plugin-runtime` (Extism/wasmtime isolated from `core`)                                                     |
| Test plugin                                 | A minimal Rust reference plugin, built via the Extism Rust PDK, checked into the repo and compiled to `.wasm` in CI, used by integration tests |
| Admin APIs (`identity_links`, `revoke_all`) | Deferred to Phase 4, after `full_auth` self-provisioning is proven                                                                             |
| This document's scope                       | Plan only — no scaffolding code included in this change                                                                                        |

---

## Phase 0 — Runtime Foundation (no auth-method wiring yet)

Goal: get Extism/wasmtime into the workspace, loading and validating plugin
config, with resource limits enforced, but not yet reachable from any auth
request. This isolates the highest-uncertainty new dependency (a WASM runtime
that has never existed in this codebase) from the auth-method logic that depends
on it.

**New crate:** `crates/dynamic-plugin-runtime`
(`openstack-keystone-dynamic-plugin-runtime`)

- Depends on `extism` (host SDK) and transitively `wasmtime`; depends on
  `openstack-keystone-config` for its config types and
  `openstack-keystone-core-types` for shared types (`ResolvedIdentityHandle`,
  wire structs). Does **not** depend on `openstack-keystone-core` — keeps the
  dependency direction one-way (core will depend on this crate, not vice versa),
  matching the `*-driver-*` crate pattern already used for backends.

### PR 0.1 — Crate skeleton + `[dynamic_plugins]` config parsing

- `crates/dynamic-plugin-runtime/Cargo.toml`, empty `lib.rs`.
- `crates/config/src/dynamic_plugins.rs`: `DynamicPluginsConfig` (plugin name
  list) + `DynamicPluginConfig` (per-plugin: `path`, `sha256`, `mode`,
  `capabilities`, `exposed_headers`, `allowed_hosts`,
  `http_fetch_auth_header`/`_secret_env`, `provision_domain_id` /
  `allowed_provision_domains`, `assign_role_allowed`, `inspect_methods`,
  `route_targets`, `timeout_ms`, `fuel_limit`, `memory_limit_mb`,
  `invocation_rate_limit_per_source_per_minute`,
  `invocation_rate_limit_per_minute`, `max_concurrent_invocations`), following
  the `K8sAuthProvider` pattern (`serde::Deserialize` + `Default`
  - `validator::Validate`).
- Validation errors implemented as **config-load-time** failures per the ADR's
  fail-loud posture: reserved-name collisions (§4 "Reserved Auth-Method Names"),
  `mode`-vs-`capabilities` mismatches (§4 capability-restriction rules for
  `mapping`/`route`), a hard-denylisted header in `exposed_headers`,
  `route_targets` containing `admin`/`trust`, a plugin granted neither
  `provision_user` nor `find_user` in `full_auth` mode.
- Unit tests: one per validation rule (reject case) + one happy-path parse.
- **Acceptance:** `cargo test -p openstack-keystone-config` covers every
  fail-loud rule in ADR §4/§5 with a dedicated test; no other crate touched.

### PR 0.2 — Plugin loading, checksum verification, `WasmPluginRegistry`

- `WasmPluginRegistry`: loads each configured plugin at startup, computes
  SHA-256 of the file on disk, compares to the pinned `sha256`. On mismatch: log
  `CRITICAL`, increment `keystone_dynamic_plugin_load_failure{plugin_name}`,
  **do not** register that plugin, continue loading the rest (§5). On match:
  compile once via `wasmtime`/`extism::Plugin` and cache the compiled module.
- No host functions registered yet in this PR — registry only proves load +
  checksum + compile succeeds/fails correctly.
- Integration test: three fixture files (valid small `.wasm` — see PR 0.3
  reference plugin once it exists, or a placeholder empty-module `.wasm` for
  this PR — missing file, tampered checksum) → assert registry state (loaded /
  not loaded) and that the metric fires only in the mismatch case.
- **Acceptance:** a config with an intentionally wrong `sha256` starts the
  process successfully with every _other_ method available, per ADR §5
  "Cross-node divergence is the trade-off... accepted explicitly."

### PR 0.3 — Reference test plugin (Rust, Extism PDK)

- New crate under e.g.
  `crates/dynamic-plugin-runtime/tests/fixtures/reference-plugin` (or a
  top-level `test-fixtures/` dir — keep it out of the release workspace member
  list so it doesn't affect the shipped binary's dependency graph), implementing
  `authenticate`, `mapping`, and `route` entry points behind compile-time
  feature flags or three separate crates, whichever the Extism Rust PDK's
  `#[plugin_fn]` macro makes cleaner as a single small crate exporting multiple
  functions.
- Add a `build.rs`/CI step (Makefile or `xtask`) that compiles it to
  `wasm32-unknown-unknown` (Extism's target) and computes its SHA-256 for test
  fixtures, so tests never hand-maintain a stale hash.
- Document in the crate's README how a third-party plugin author would repeat
  this (mirrors the ADR's stated goal of multi-language PDK support, though only
  the Rust PDK is exercised by our own tests).
- **Acceptance:** `cargo xtask build-test-plugin` (or equivalent) produces a
  `.wasm` artifact consumed by Phase 1+ integration tests; CI caches/ rebuilds
  it as part of the normal test job.

### PR 0.4 — Resource limits (fuel / wall-clock / memory) + isolation

- Wire `fuel_limit`, `timeout_ms`, `memory_limit_mb` into the `Store`
  construction per invocation (fresh `Store` per call, per ADR §7 "Isolation
  between requests").
- Tests: a fixture plugin function that spins (fuel exhaustion), one that sleeps
  past `timeout_ms`, one that allocates past `memory_limit_mb` — each asserted
  to fail closed with the right error variant, not panic/hang the test process.
- **Acceptance:** all three bounds independently provable to trigger via a
  dedicated fixture export in the reference plugin (PR 0.3).

---

## Phase 1 — `full_auth` Mode End-to-End

Goal: a plugin can be configured as a real `[auth] methods` entry and
authenticate a request it provisions itself. This is the ADR's primary mechanism
and the only mode needed to satisfy requirements 1–3 from ADR §1.

### PR 1.1 — Host functions A–D (capability-gated) + mandatory audit (§6.E)

- Implement `http_fetch` (§6.A, including connect-time IP re-validation against
  the resolved `IpAddr`, no-redirect-by-default, host-injected secrets),
  `provision_user`/`find_user` (§6.B/C, namespace-scoped, atomic upsert on
  `(plugin_name, external_id)`), `assign_role` (§6.D, three-axis scope
  restriction).
- Each is only registered into a given plugin's `extism::Plugin` instance if
  listed in that plugin's `capabilities` — implemented as conditional
  registration, not a runtime permission check (ADR §6 opening paragraph).
- CADF audit wrapping (§6.E) as an inline, fail-closed `AuditHook` extension:
  new `EventPayload` variant recording `plugin_name`, host function, outcome.
- New storage: `(plugin_name, external_id) -> user_id` mapping table +
  per-`Store` handle map for `ResolvedIdentityHandle`. Confirm backend (likely
  SQL, alongside other identity-adjacent tables — needs a migration in whichever
  driver crate backs `IdentityBackend`).
- **Acceptance:** each host function has a unit test proving the
  namespace-scoping/domain-restriction/role-scope invariant it's supposed to
  enforce actually holds (e.g. `find_user` cannot resolve a handle for a
  `user_id` provisioned by a different `plugin_name`), plus one test per
  function proving the audit event fires on both success and failure.

### PR 1.2 — `AuthenticationContext::WasmPlugin` + auth-method dispatch

- Extend `AuthenticationContext` (`crates/core-types/src/auth.rs`) with the
  `WasmPlugin { plugin_name, plugin_sha256, claims, token }` variant.
- Wire method-name resolution in `crates/core/src/api/auth.rs`: unmatched method
  name → `WasmPluginRegistry` lookup → build `AuthPluginRequest` (payload,
  `exposed_headers`-filtered headers with the hard denylist enforced at
  config-load _and_ re-checked here defensively, trusted `remote_addr` only) →
  invoke `authenticate` → map `Allow`/`Deny` to `ValidatedSecurityContext` via
  the existing `new_for_scope()` pipeline.
- Enforce identity-binding validation (§4 "Identity Binding" steps 3–4):
  reject + audit a `resolved_identity` handle that doesn't match this
  invocation's issued handles.
- Response payload bounds (§7 "Response Payload Bounds"): size cap, claims
  count/key/value caps, `plugin_claims.<plugin_name>.*` namespacing, rejection
  of the reserved envelope key / `__keystone`-prefixed keys.
- **Acceptance:** an end-to-end integration test using the reference plugin (PR
  0.3) that: provisions a new user on first login, returns the same user on
  second login (idempotency), denies on a bad handle, and confirms claims land
  under `plugin_claims.<plugin_name>.*` only.

### PR 1.3 — Rate limiting & concurrency (§7)

- Per-source token bucket → per-plugin token bucket → concurrency semaphore,
  using `governor` (already a workspace dependency), mirroring ADR 0020 §7.2's
  two-tier pattern with the added source-scoped front tier.
- `remote_addr = None` fallback behavior (bounds 2/3 only) implemented and
  tested explicitly, matching the ADR's documented residual gap.
- **Acceptance:** load-test-style unit tests proving each of the three bounds
  independently rejects with `429`/audit `RateLimited` once exceeded, and that
  one plugin's exhausted budget doesn't affect another plugin's.

### PR 1.4 — Plugin Version Binding + token verification

- Token minted via `WasmPlugin` embeds `plugin_sha256`; verification path
  compares against the currently-loaded hash for that `plugin_name` and rejects
  with `PluginVersionMismatch` on drift.
- **Acceptance:** integration test — mint a token, "patch" the plugin (swap the
  loaded module + hash in a test harness), confirm the old token now fails
  verification while a fresh login against the new plugin succeeds.

**Phase 1 exit criteria:** a `mode = full_auth` plugin is usable end-to-end in a
real `[auth] methods` deployment: load, checksum-verify, rate-limit,
resource-bound, provision/find/assign, audit, mint a version-bound token, verify
it. This is independently shippable and useful without Phases 2–4.

---

## Phase 2 — `mapping` Mode

Goal: let a plugin feed the existing, already-reviewed Mapping Engine (ADR 0020)
instead of terminating authentication itself — the direct path to authenticating
SCIM-provisioned and other pre-existing users without new identity-binding
machinery.

### PR 2.1 — `IdentitySource::WasmPlugin` + `mapping` entry point

- `crates/core-types/src/mapping/resolution.rs`: add
  `WasmPlugin { plugin_name }`.
- New guest entry point `mapping(request) -> MappingResponse` (`Claims`/`Deny`,
  no `Allow`), gated so `mode = mapping` plugins never get A–D registered
  (config-load-time error if they're granted, per PR 0.1's validation).
- Route `mapping`-mode plugin output into the existing evaluator under
  `provider_id = "wasm:<plugin_name>"`, unmodified.
- **Acceptance:** integration test — author a `MappingRuleSet` under
  `wasm:<plugin_name>` with an `IdentityMode::Local` rule, drive a login through
  the reference plugin's `mapping` export, confirm it resolves to the
  pre-existing local user and that a plugin with no ruleset authored gets
  `MappingNotFound` (fail-closed by construction, §4 step 4).

### PR 2.2 — `MappingContext.wasm_plugin_sha256` + verification

- Add the optional field (ADR §4 "Plugin-version binding for `mapping` mode"),
  populate on issuance, check alongside `ruleset_version` at verification.
- **Acceptance:** same drift test pattern as PR 1.4, applied to the mapping
  path.

**Phase 2 exit criteria:** `mapping` mode fully covers the SCIM/pre-existing-
user login case without touching `full_auth`'s identity-binding code at all.

---

## Phase 3 — `route` Mode

Goal: pre-dispatch request routing for clients that can't send a custom method
name (Terraform `application_credential` case).

### PR 3.1 — `route` entry point + host-side dispatch rewrite

- `route(request: RouteRequest) -> RouteResponse` guest contract.
- Host-side: `inspect_methods` trigger scoping (invoke only when
  `identity.methods` intersects it), `route_targets` allowlist enforcement
  (malformed-response rejection on off-allowlist target, not correction),
  scope-immutability (no `scope` field on `RouteResponse` at the type level),
  single-shot flag on the rewritten request (internal, non-guest- settable).
- Independent rate-limit/concurrency budget from the target method (reuse PR
  1.3's bucket implementation, instantiated per-router).
- Audit: originally-requested method list + decision + resulting `target_method`
  recorded distinctly from the eventually-dispatched method's own audit trail
  (§4 "Audit").
- **Acceptance:** integration test — reference plugin's `route` export
  configured with `inspect_methods = application_credential`, prove: (a)
  `password` requests never invoke it, (b) a `Route` response correctly
  redispatches to an allowlisted target and that target still independently
  verifies the payload, (c) a `Route` naming a non-allowlisted target is
  rejected as malformed, (d) a request already routed once cannot be routed
  again, (e) `Deny`/timeout/trap fails closed without falling through to the
  original method.

**Phase 3 exit criteria:** all three modes from ADR §4 are implemented and
independently tested.

---

## Phase 4 — Admin APIs & Bulk Revocation

Goal: admin-authorized external identity linking (the `full_auth` path to
pre-existing users the ADR frames as required for the SCIM full-authority case)
and incident-response tooling.

### PR 4.1 — `POST/DELETE /v4/dynamic_plugins/{plugin_name}/identity_links`

- RBAC-tiered per ADR §4 (system-admin if target holds system-scope;
  domain-admin scoped to target's own domain otherwise), enforces the plugin's
  `provision_domain_id`/`allowed_provision_domains` against the target user's
  domain, `409` on re-link without prior `DELETE`.
- `{scim_provider_id, scim_external_id}` convenience form resolving via the
  existing ADR 0024 §3.B index.
- `find_user` (PR 1.1) updated to re-validate live `domain_id` on every
  resolution for admin-linked entries (§4 "Domain restriction is re-checked at
  resolve time").
- `DELETE` triggers existing token-revocation pipeline for the unlinked user.
- **Acceptance:** integration tests for the domain-move-revokes-reach case, the
  `409` conflict case, and the SCIM-convenience resolution path.

### PR 4.2 — `POST /v4/dynamic_plugins/{plugin_name}/revoke_all`

- System-admin only; disables provisioned users, revokes plugin-granted role
  assignments individually, deletes `identity_links` entries, triggers token
  revocation for every affected user; returns per-category counts; idempotent
  no-op on a plugin with no remaining state.
- **Acceptance:** integration test proving a provisioned user with an unrelated
  (non-plugin) role assignment keeps that assignment after `revoke_all`, and
  that re-running the endpoint twice is safe.

**Phase 4 exit criteria:** full ADR 0025 scope implemented, including
incident-response tooling.

---

## Cross-cutting, tracked but not blocking any phase

- **Documentation:** operator-facing docs for `[dynamic_plugins]` config, a
  "writing your first plugin" guide referencing the reference plugin (PR 0.3)
  and the Extism PDK, added once Phase 1 ships (real, usable guidance) rather
  than speculatively earlier.
- **Metrics/alerting wiring:** `keystone_dynamic_plugin_load_failure` (PR 0.2)
  and rate-limit counters (PR 1.3) should get dashboard/alert examples in ops
  docs once Phase 1 ships — not a blocking code change, tracked as a follow-up.
- **Fuzzing:** `AuthPluginResponse`/`RouteResponse` deserialization (attacker-
  shaped guest output, §7 "Response Payload Bounds") is a good `cargo-fuzz`
  target once Phase 1/3 land; not required to ship either phase.

## Explicitly out of scope for this plan (per ADR §8)

Per-domain plugin scoping, hot reload/upload API, signing beyond SHA-256, secret
rotation without restart, and the "reinstate only one non-vulnerable version's
state" gap in `revoke_all` are all ADR-documented future work, not part of this
implementation plan.
