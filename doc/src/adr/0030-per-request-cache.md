# 30. Per-Request Cache via `tokio::task_local!`

**Date:** 2026-07-28

## Status

Proposed

## Context

Several sessions of query-log analysis found the same shape of bug repeatedly: a
single incoming request re-fetches the same row more than once because two
independent code paths, invoked within the same request, each do their own
lookup with no way to know the other already ran. Two concrete instances fixed
ad hoc so far:

- Token validation fetched the token's domain twice — once to validate scope,
  once to build the response — because the two call sites had no shared state
  between them.
- `identity-driver-sql` fetched a user's **entire password history** on every
  display/auth path (`GET /users/:id`, `GET /users`, password auth), even though
  every consumer only ever reads the newest row (`merge_passwords_data` always
  calls `.next()` on the iterator it's given). That one was fixed by pushing
  `ORDER BY ... DESC LIMIT 1` / `DISTINCT ON` down into SQL rather than by
  caching, because the DB can answer "give me only the newest row" directly — no
  caching involved, just asking for less data. This ADR does not change that
  fix.

Both were fixed individually because there was no general mechanism. This ADR is
about the _next_ one: a request-scoped cache so redundant lookups within a
single request (e.g., two provider calls in the same handler both resolving the
same `domain_id`, or a nested provider call re-fetching a `project` its caller
already loaded) stop needing a bespoke fix each time.

### Why not extend the existing process-lifetime cache pattern

`crates/core/src/identity/service.rs` already has a cache:
`user_id_domain_id_cache: RwLock<HashMap<String, String>>`, config-gated by
`identity.caching`, manually invalidated on user delete and domain reassignment.
That pattern works because the cached fact (`user_id` → `domain_id`) is close to
immutable for the life of the process. Most candidate lookups for a per-request
cache (a `project` row, a `domain` row, resolved role assignments) are _not_
immutable — they can be mutated by a concurrent request a moment later. A
process-lifetime cache for those would need real invalidation plumbing
(bus/event-driven cache busting) to avoid serving stale data to a _different_
request after a write. A cache whose scope is exactly one request sidesteps that
entirely: it is populated from reads made within the request, discarded when the
request ends, and never observed by any other request, so there is no
invalidation problem to solve at all — correctness is automatic, not maintained
by hand.

### Why not thread an explicit cache parameter through every call

`ExecutionContext<'a>` (`crates/core/src/auth.rs:548`) is the object passed by
reference into every provider trait method
(`crates/core/src/identity/provider_api.rs` and the equivalent `provider_api.rs`
in every other domain crate). It looks like the natural place to hang a cache
field. It isn't, in practice: handlers routinely construct a **fresh**
`ExecutionContext::from_auth(&state, &user_auth)` inline at each call site
rather than building one and reusing it — e.g.
`crates/keystone/src/federation/api/identity_provider/update.rs` constructs two
separate `ExecutionContext`s in the same handler function. Adding a cache field
to the struct would only dedupe lookups made through the _same_
`ExecutionContext` instance, missing exactly the multi-call-site case this ADR
exists to fix, unless every handler in the codebase were first refactored to
build one `ExecutionContext` per request and thread `&ctx` through every call —
a much larger, invasive change than the caching mechanism itself warrants.

### Why `tokio::task_local!` is the right shape here

A per-request cache needs to be reachable from deep inside provider/backend code
(`crates/core/src/identity/service.rs`, `crates/identity-driver-sql/src/lib.rs`,
...) without adding a parameter to every trait method across every domain.
`tokio::task_local!` gives exactly that: state that travels implicitly with the
currently-executing async task, readable from any function running on that task
without being passed explicitly, and automatically gone once the task's scope
ends. This is not a new idea in this codebase —
`crates/core/src/events.rs:117-125` already uses `tokio::task_local!` for
`EMIT_CRITICAL_RECURSION`, a reentrancy guard for
`EventDispatcher::emit_critical`, with exactly the defensive access pattern
(`try_with(...).unwrap_or(default)`) this ADR reuses: code running outside any
established scope (tests, CLI tooling, background jobs) just sees "no cache,"
not a panic or an error.

Axum's per-request execution unit **is** a single tokio task (the handler's
future, spawned once per accepted connection/request), so "task-scoped" and
"request-scoped" coincide exactly here — there is no separate request
abstraction to scope against.

### No new dependency

`tokio` is already a workspace dependency (`Cargo.toml:185`,
`tokio = { version = "1.52", default-features = false }`) and
`task_local!`/`LocalKey::scope`/`LocalKey::try_with` are part of `tokio`'s core
API surface with no additional feature flag required — proven by the existing
`crates/core/src/events.rs` usage compiling and running today under the same
`default-features = false` configuration. `moka`, `lru`, and `once_cell` are not
present in the workspace and are not needed. `dashmap` and `arc-swap` are
already workspace dependencies but are unnecessary here: the cache is exclusive
to a single task by construction (never accessed concurrently), so a plain
`RefCell` needs no interior synchronization — using `dashmap` would only be
paying for concurrency control this design never needs.

## Decision

### New module: `crates/core/src/request_cache.rs`

```rust
tokio::task_local! {
    /// Per-request cache. Established once per incoming request by Axum
    /// middleware; absent outside a request scope (tests, CLI tooling,
    /// background jobs), in which case reads/writes are silent no-ops.
    static REQUEST_CACHE: RequestCache;
}

#[derive(Default)]
pub struct RequestCache {
    entries: RefCell<HashMap<(&'static str, String), Box<dyn Any + Send>>>,
}
```

- Keyed by `(namespace, id)` — `namespace` is a `&'static str` literal owned by
  the calling module (e.g. `"resource.domain"`, `"resource.project"`), `id` is
  the lookup key (e.g. a `domain_id`). Namespacing avoids collisions between
  domains caching under the same raw id string.
- Values are `Box<dyn Any + Send>`, downcast by the typed accessor below. `Send`
  (not `Send + Sync`) is required and sufficient: nothing needs `Sync` because
  access is never concurrent — the cache belongs to exactly one task — but the
  _task itself_ must remain `Send` for Axum's multi-thread runtime to move it
  between worker threads at `.await` points, which requires every value the task
  owns, including task-local storage, to be `Send`.
- `RefCell`, not `RwLock`/`Mutex`: no async code holds a borrow across an
  `.await` point (get and insert are both synchronous, bracketing any async
  fetch — see below), and there is never concurrent access to fight over, so an
  async-aware lock would be pure overhead.

### Accessor API

```rust
impl RequestCache {
    pub fn get<T: Clone + 'static>(&self, namespace: &'static str, id: &str) -> Option<T> { ... }
    pub fn set<T: Send + 'static>(&self, namespace: &'static str, id: &str, value: T) { ... }
}

/// Reads from the current request's cache, if any. Outside a request scope
/// (no `task_local` established), always returns `None`.
pub fn cache_get<T: Clone + 'static>(namespace: &'static str, id: &str) -> Option<T> {
    REQUEST_CACHE.try_with(|c| c.get(namespace, id)).ok().flatten()
}

/// Writes into the current request's cache, if any. Outside a request scope,
/// silently does nothing.
pub fn cache_set<T: Send + 'static>(namespace: &'static str, id: &str, value: T) {
    let _ = REQUEST_CACHE.try_with(|c| c.set(namespace, id, value));
}
```

Call-site pattern (e.g. resolving a `domain` inside a provider method):

```rust
if let Some(domain) = cache_get::<DomainResponse>("resource.domain", domain_id) {
    return Ok(Some(domain));
}
let domain = self.backend_driver.get_domain(ctx.state(), domain_id).await?;
if let Some(d) = &domain {
    cache_set("resource.domain", domain_id, d.clone());
}
Ok(domain)
```

The cache check and the cache write are both synchronous and bracket the
`.await` — no borrow is ever held across an await point, satisfying `RefCell`'s
requirements without needing an async lock.

**Known, accepted race**: two concurrent lookups for the same key that both miss
will both hit the backend and both write — the second write just overwrites the
first with an equal value. This is intentionally not guarded with an
in-flight-request de-dup (e.g. a `HashMap<Key, oneshot::Receiver>` pattern) —
that adds real complexity for a benefit that only matters if the _same_ request
independently kicks off two concurrent fetches of the _same_ key, which existing
call sites don't do (the duplicate-fetch bugs this ADR targets are sequential,
not concurrent, within a request).

### Middleware: establish the scope once per request

New `axum::middleware::from_fn` layer, added next to the existing
`proxy_headers` layer (`crates/keystone/src/server/proxy_headers.rs:116-120`) in
the `ServiceBuilder` chain built by `build_router`
(`crates/keystone/src/bin/keystone.rs:781`):

```rust
async fn with_request_cache(req: Request, next: Next) -> Response {
    REQUEST_CACHE.scope(RequestCache::default(), next.run(req)).await
}
```

Added to both entry points that build an Axum `Router` independently: the main
router in `build_router` and the SCIM router (`crates/keystone/src/scim.rs:70`,
nested at `/SCIM/v2`), since the SCIM router is constructed separately and would
otherwise never establish the scope.

### Provider-layer usage

`cache_get`/`cache_set` are called from the domain provider layer
(`crates/core/src/identity/service.rs` and equivalent `service.rs` files in
`resource`, `assignment`, etc.) — the same layer that already hosts the
process-lifetime `user_id_domain_id_cache` — not from the `*-driver-sql` backend
crates, which stay backend-agnostic and untouched. This is opt-in per call site:
only lookups that are (a) read multiple times within a plausible single request
and (b) not already the cheapest possible query (recall the password fix:
sometimes the right answer is "ask the DB for less," not "cache more") get wired
up. There is no blanket "cache every provider read" policy — that would risk
masking future N+1 patterns instead of surfacing them.

## Consequences

- Redundant same-request lookups (repeated `domain`/`project`/similar reads
  across independent call sites within one request) can be eliminated by adding
  a `cache_get`/`cache_set` pair at the provider layer, with no changes to trait
  signatures, no threading a new parameter through `ExecutionContext` or any
  `provider_api.rs`, and no per-crate dependency changes.
- No invalidation logic is needed anywhere: the cache is torn down automatically
  when the request's task completes (`REQUEST_CACHE.scope` ends), so a write
  made by request A can never be observed by request B. This is strictly simpler
  than the existing `user_id_domain_id_cache`, which requires manual
  invalidation on every mutating call that touches its cached facts.
- Code outside a request scope (unit tests calling provider methods directly,
  CLI tooling, background jobs, `ExecutionContext::internal` paths not reached
  via Axum) sees `cache_get` always return `None` and `cache_set` as a no-op —
  correct by construction, not by an explicit feature flag, so no test setup
  changes are required for the bulk of the existing test suite. Tests that
  specifically want to exercise cache behavior must wrap the call under test in
  `REQUEST_CACHE.scope(...)`.
- The mechanism only helps deduplicate reads _within_ one request; it does
  nothing for the "fetch too much data" class of problem (the password-list
  fix). Both remain valid, complementary tools — engineers should default to
  "can the query ask for less" first, and reach for the per-request cache only
  when the same data is genuinely re-derived from scratch more than once inside
  one request.
- Adds one new module (`crates/core/src/request_cache.rs`) and one new
  middleware layer registered in two places (`build_router`,
  `crates/keystone/src/scim.rs`). No new workspace dependency.
