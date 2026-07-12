# ADR 0025 Implementation Plan: Dynamic Auth Plugins via WebAssembly

**Status (post-review update): Phases 0–4 all implemented and tested,
including Phase 3 (`route` mode) and PR 2.2, which were previously unmarked
here despite being merged.** The ADR itself remains `Status: Proposed` -
implementation completeness and ADR acceptance are being tracked separately.
See each phase below for its actual (not just planned) status.

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
  method. Everything is additive behind `[auth_plugins]` /
  `[auth_plugin.*]` config sections that default to empty (no plugins
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
| Crate layout                                | New dedicated crate `crates/auth-plugin-runtime` (Extism/wasmtime isolated from `core`)                                                     |
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

**New crate:** `crates/auth-plugin-runtime`
(`openstack-keystone-auth-plugin-runtime`)

- Depends on `extism` (host SDK) and transitively `wasmtime`; depends on
  `openstack-keystone-config` for its config types and
  `openstack-keystone-core-types` for shared types (`ResolvedIdentityHandle`,
  wire structs). Does **not** depend on `openstack-keystone-core` — keeps the
  dependency direction one-way (core will depend on this crate, not vice versa),
  matching the `*-driver-*` crate pattern already used for backends.

### PR 0.1 — Crate skeleton + `[auth_plugins]` config parsing — DONE

- `crates/auth-plugin-runtime/Cargo.toml`, empty `lib.rs`.
- `crates/config/src/auth_plugins.rs`: `DynamicPluginsConfig` (plugin name
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

### PR 0.2 — Plugin loading, checksum verification, `WasmPluginRegistry` — DONE

- `WasmPluginRegistry`: loads each configured plugin at startup, computes
  SHA-256 of the file on disk, compares to the pinned `sha256`. On mismatch: log
  `CRITICAL`, increment `keystone_auth_plugin_load_failure{plugin_name}`,
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

### PR 0.3 — Reference test plugin (Rust, Extism PDK) — DONE

- New crate under e.g.
  `crates/auth-plugin-runtime/tests/fixtures/reference-plugin` (or a
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

### PR 0.4 — Resource limits (fuel / wall-clock / memory) + isolation — DONE

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

### PR 1.1 — Host functions A–D (capability-gated) + mandatory audit (§6.E) — DONE

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

### PR 1.2 — `AuthenticationContext::WasmPlugin` + auth-method dispatch — DONE

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

### PR 1.3 — Rate limiting & concurrency (§7) — DONE

- Per-source token bucket → per-plugin token bucket → concurrency semaphore,
  using `governor` (already a workspace dependency), mirroring ADR 0020 §7.2's
  two-tier pattern with the added source-scoped front tier.
- `remote_addr = None` fallback behavior (bounds 2/3 only) implemented and
  tested explicitly, matching the ADR's documented residual gap.
- **Acceptance:** load-test-style unit tests proving each of the three bounds
  independently rejects with `429`/audit `RateLimited` once exceeded, and that
  one plugin's exhausted budget doesn't affect another plugin's.

### PR 1.4 — Plugin Version Binding + token verification — DONE

- Version binding is a per-plugin `valid_since` timestamp in config, not a
  token-embedded hash — the `FernetToken` payload is a fixed variant set with no
  plugin-bearing case, so there is nowhere to embed and re-compare a
  `plugin_sha256`. A `WasmPlugin`-authenticated token mints as an ordinary scoped
  token carrying its own `issued_at`; verification looks up the token's
  `plugin_name`, and if `issued_at` predates that plugin's configured
  `valid_since`, rejects with `PluginVersionMismatch`. Fresh mints have no token
  yet, so a past `valid_since` never blocks new logins.
- **Post-merge review finding, fixed:** the original landing only added this
  check inside `ValidatedSecurityContext::new_for_scope`'s `WasmPlugin`/
  `Mapping` match arms, gated on `ctx.token().is_some()`. Real token
  re-verification (`TokenService::validate_to_context_impl`,
  `crates/core/src/token/service.rs`) reconstructs a plain
  `AuthenticationContext::Token` for a plugin-authenticated token (only
  `ApplicationCredential`/`Trust` get their original context restored), so
  those arms were never actually reachable on the real verification path -
  the check was dead code; a stale token stayed valid indefinitely regardless
  of `valid_since`. Fixed by adding the authoritative check directly in
  `validate_to_context_impl`, keyed on the token's own `methods` list (which
  carries the plugin name for a `full_auth` login). The original arms are
  kept as harmless defense-in-depth, documented as unreachable via this path.
- **Acceptance:** unit tests on the real verification path -
  `crates/core/src/token/service.rs::tests::test_validate_wasm_plugin_stale_token_is_rejected`
  and `test_validate_wasm_plugin_fresh_token_after_cutoff_is_accepted` - plus
  the original defense-in-depth-arm tests
  (`crates/core/src/auth.rs::tests::test_wasm_plugin_stale_token_is_rejected`
  and siblings), now documented as exercising a path real token verification
  doesn't take.

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

### PR 2.1 — `IdentitySource::WasmPlugin` + `mapping` entry point — DONE

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

### PR 2.2 — `mapping`-mode version binding via `valid_since` — LANDED, NOT FUNCTIONAL (documented gap)

- Original plan: recover the plugin name from the matched ruleset's
  `IdentitySource::WasmPlugin` at verification (loaded via the token's
  `mapping_id`) and apply the same `valid_since`-vs-`issued_at` cutoff as
  `full_auth`.
- **Post-merge review finding:** this is not achievable with the current
  token format and was never actually wired into the real verification path.
  A `mapping`-mode login mints an ordinary scoped token whose payload carries
  only `methods = ["mapped"]` - there is no `mapping_id` (or any other
  plugin-recoverable field) anywhere in a `FernetToken` payload for
  `TokenService::validate_to_context_impl` to key off. The code that exists
  (`ValidatedSecurityContext::new_for_scope`'s `Mapping` arm,
  `crates/core/src/auth.rs`) only runs against a hand-built test
  `SecurityContext` that sets both a `Mapping` context and a token
  simultaneously - a combination production token re-verification never
  produces. **Decision (recorded in ADR §4/§8): document as a known gap
  rather than force a fix.** Closing it properly requires widening a token
  payload to carry a plugin-recoverable identifier, which is out of scope for
  this plan; tracked as ADR §8 future work. Operator remediation for a
  compromised `mapping`-mode plugin today is revocation events or a short
  token TTL, not `valid_since`.
- **Acceptance:** the arm's own unit test
  (`crates/core/src/auth.rs::tests::test_mapping_wasm_plugin_stale_token_is_rejected`)
  passes but exercises only the unreachable-in-production code path; there is
  no test proving mapping-mode version binding end-to-end because the
  property doesn't hold end-to-end.

**Phase 2 exit criteria:** `mapping` mode fully covers the SCIM/pre-existing-
user login case without touching `full_auth`'s identity-binding code at all.

---

## Phase 3 — `route` Mode

Goal: pre-dispatch request routing for clients that can't send a custom method
name (Terraform `application_credential` case).

### PR 3.1 — `route` entry point + host-side dispatch rewrite — DONE

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

### PR 4.1 — `POST/DELETE /v4/auth_plugins/{plugin_name}/identity_links` — DONE

- RBAC-tiered per ADR §4 (system-admin if target holds system-scope;
  domain-admin scoped to target's own domain otherwise), enforces the plugin's
  `provision_domain_id`/`allowed_provision_domains` against the target user's
  domain, `409` on re-link without prior `DELETE`. Done: handlers in
  `crates/keystone/src/api/v4/auth_plugin/identity_link/{create,delete}.rs`,
  Rego in `policy/auth_plugin/identity_link/{create,delete}.rego`, types in
  `crates/api-types/src/v4/auth_plugin.rs`.
- **Post-merge review finding, fixed:** the original Rego (`allow if { "admin"
  in input.credentials.roles }`, no scope check) let a project-scoped `admin`
  - not just a system-scope one - link any user, including one holding a
  system-scope role. Tightened to require `input.credentials.system ==
  "all"` alongside `admin` for the system tier, matching `revoke_all.rego`'s
  existing posture and the ADR text's actual intent. Verified with `opa eval`
  against four scenarios (system-admin/system-target,
  project-admin/system-target, domain-manager/own-domain,
  domain-admin/other-domain).
- `find_user` (PR 1.1) updated to re-validate live `domain_id` on every
  resolution for admin-linked entries (§4 "Domain restriction is re-checked at
  resolve time").
- `DELETE` triggers existing token-revocation pipeline for the unlinked user.
- **Acceptance:** 11 handler unit tests (`cargo test -p openstack-keystone
  --lib auth_plugin::identity_link`) cover the `409` conflict, the
  domain-outside-plugin `400`, policy `403`, unauth `401`, unknown-plugin /
  non-full_auth / unknown-user `404`/`400`, and the delete-revokes-tokens path
  (`create_revocation_event` asserted). Enforcer is mocked, so the Rego is
  exercised at the real-server layer, not here.
- **Deferred:** the `{scim_provider_id, scim_external_id}` convenience form
  (needs realm→domain resolution over the ADR 0024 §3.B index) is not yet
  wired; only the direct `{external_id, user_id}` body is accepted.

### PR 4.2 — `POST /v4/auth_plugins/{plugin_name}/revoke_all` — DONE

- System-admin only (cross-domain by construction); disables every user the
  plugin provisioned or that an admin linked to it, deletes those
  `identity_links` entries, and triggers token revocation for each affected
  user; returns per-category counts (`users_disabled`, `links_deleted`);
  idempotent no-op on a plugin with no remaining state. Done: handler in
  `crates/keystone/src/api/v4/auth_plugin/revoke_all.rs`, Rego in
  `policy/auth_plugin/revoke_all.rego` (system-scope `admin` only), types in
  `crates/api-types/src/v4/auth_plugin.rs`.
- Enumeration is a new `DynamicPluginIdentityApi::list_by_plugin` (prefix scan
  on the existing `auth_plugin_identity:v1:<plugin_name>:` key layout, no new
  index/migration — plugin names are colon-free). Both provisioned and
  admin-linked users share that table, so one scan covers every affected user.
- **ADR deviation (recorded in the ADR):** the endpoint does **not** revoke the
  plugin's role assignments. Attributing a stored grant to the plugin would
  require per-record origin bookkeeping the ADR rejects for version scoping.
  Disabling the account already denies all access; it is the operator's
  responsibility to review a re-enabled user's assignments against the CADF
  audit trail (`plugin_name` on every `assign_role`) and revoke any they deem
  compromised via the existing per-grant API.
- **Acceptance:** 7 handler unit tests (`cargo test -p openstack-keystone --lib
  auth_plugin`) — happy path, user de-dup, empty no-op, policy `403`,
  unauth `401`, unknown-plugin `404`, non-full_auth `400` — plus 2 raft-driver
  tests for `list_by_plugin` (plugin isolation + `external_id` containing `:`).
  The enforcer is mocked in those, so the system-scope Rego gate is verified at
  the real-server layer: `test_revoke_all_requires_system_scope`
  (`tests/api/.../token/auth_plugin.rs`) asserts a project-scoped admin gets
  `403`. Only the deny path runs there — `revoke_all` is plugin-scoped and the
  shared real server has a single `full_auth` plugin, so an actually-revoking
  test would disturb other tests provisioning through it.

**Phase 4 exit criteria:** full ADR 0025 scope implemented, including
incident-response tooling.

---

## Cross-cutting, tracked but not blocking any phase

- **Documentation:** operator-facing docs for `[auth_plugins]` config, a
  "writing your first plugin" guide referencing the reference plugin (PR 0.3)
  and the Extism PDK, added once Phase 1 ships (real, usable guidance) rather
  than speculatively earlier.
- **Metrics/alerting wiring:** `keystone_auth_plugin_load_failure` (PR 0.2)
  and rate-limit counters (PR 1.3) should get dashboard/alert examples in ops
  docs once Phase 1 ships — not a blocking code change, tracked as a follow-up.
  **DONE (post-review):** `keystone_auth_plugin_load_failure{plugin_name}` was
  originally only a `tracing::error!` log line, not a real metric despite the
  ADR/admin docs describing it as one - fixed by adding
  `Service::auth_plugin_load_failures` and serving it as a real Prometheus
  counter from the existing `/metrics` handler
  (`crates/core/src/auth_plugin_startup.rs::format_load_failure_metrics`).
- **Fuzzing:** `AuthPluginResponse`/`RouteResponse` deserialization (attacker-
  shaped guest output, §7 "Response Payload Bounds") is a good `cargo-fuzz`
  target once Phase 1/3 land; not required to ship either phase.
- **Post-review hardening (fixed):**
  - `LoadedPlugin::invoke` (synchronous, up to `timeout_ms` of wall-clock
    work) now runs under `tokio::task::block_in_place` at all three dispatch
    call sites (`crates/core/src/auth_plugin_auth.rs`) - previously ran
    directly on the async executor's reactor thread, risking stalling
    unrelated work under a slow/spinning plugin.
  - `provision_user`'s idempotent repeat-call path (an entry already exists
    for this `external_id`, whether self-provisioned or admin-linked) now
    re-checks the resolved user's live `domain_id`, matching `find_user`'s
    existing behavior - previously only `find_user` enforced this, so a
    `provision_user` call could keep resolving a handle for a user moved
    outside the plugin's domain(s) after linking.
  - `http_fetch`'s redirect chain now shares one `timeout_ms` budget across
    all hops instead of a fresh budget per hop (previously up to
    `MAX_REDIRECTS + 1`× the configured budget).
  - A guest-supplied header colliding with the host-injected
    `http_fetch_auth_header` name is now dropped before the secret is added,
    rather than sent alongside it as a second header value (`reqwest`'s
    `RequestBuilder::header` appends, it does not replace).
  - `totp` added to `RESERVED_AUTH_METHOD_NAMES` - it's a live builtin
    dispatched ahead of the plugin lookup but was missing from the reserved
    list, so a plugin named `totp` would have passed config validation while
    being silently unreachable.
  - Per-source keyed rate-limit state (`PluginInvocationLimiter::per_source`)
    is now periodically shrunk (`shrink_idle_sources`, called from the
    existing minute-scale cleanup tick in
    `crates/keystone/src/bin/keystone.rs`) - previously grew one entry per
    distinct source address forever.
  - The shared reference-plugin fixture's route target and `[auth_plugin.*]`
    example name were renamed `hacked_appcred_handler` →
    `hacked_appcred_handler` across the fixture, `tools/start-api.sh`, the
    real-server test file, and this doc's examples - the old name was both
    an unprofessional label and, in one in-process unit test
    (`auth_plugin_auth::route_acceptance_tests::test_route_to_allowlisted_target_succeeds`),
    an actual pre-existing test bug (the test configured `route_targets =
    "hacked_appcred_handler"` while the shared fixture's `route()` hardcoded
    `"hacked_appcred_handler"` as its output, so the test failed
    deterministically before this rename).

## Explicitly out of scope for this plan (per ADR §8)

Per-domain plugin scoping, hot reload/upload API, signing beyond SHA-256, secret
rotation without restart, and the "reinstate only one non-vulnerable version's
state" gap in `revoke_all` are all ADR-documented future work, not part of this
implementation plan.
