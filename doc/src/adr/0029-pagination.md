# 29. Generalized Marker Pagination for v3/v4 List Endpoints

**Date:** 2026-07-24

## Status

Accepted

## Context

Issue #308 asked for consistent, python-keystone-compatible pagination across
all list endpoints. Two domains (federation `identity_provider`, ADR 0007)
already had a first-cut implementation before this ADR, but it had real gaps:

- **False-positive `next` link.** The original `build_pagination_links()`
  inferred "more pages exist" purely from `data.len() >= limit`. If the table
  had exactly `limit` rows left, it wrongly emitted a `next` link to an empty
  page.
- **No config-driven limit resolution.** Nothing mirrored python-keystone's
  `Hints.get_limit_with_default` precedence chain (user limit → per-resource
  default → global `list_limit` → absolute `max_db_limit`).
- **Duplicated fields per domain.** The existing code hand-rolled
  `limit`/`marker` fields directly on each domain's list-parameters struct
  instead of a single shared, reusable pagination type.

Real python-keystone (`keystone/common/driver_hints.py`, the `@truncated`
decorator, `keystone/server/flask/common.py` `wrap_collection`) avoids the
false-positive by always fetching `limit + 1` rows and trimming the extra one
off before returning — that is the mechanism this design replicates. It's
also worth noting real upstream `wrap_collection` hardcodes
`links: {next, self, previous: null}` — `previous` is never computed, and
there's no working `page_reverse` anywhere in current upstream. So
byte-for-byte v3 compatibility (OSC, keystoneclient) only requires
forward-marker paging with `previous` always absent/null. v4 is our own API,
not constrained by OSC compatibility, so it gets real bidirectional paging.

`serde_urlencoded` (what axum's `Query<T>` extractor uses) does not support
`#[serde(flatten)]` on typed numeric fields — `limit: Option<u64>` flattened
into an outer struct fails to deserialize `"limit=10"` with a type-coercion
error, because flatten forces buffering through `serde::private::de::Content`,
which loses string-to-number coercion. A single shared pagination struct is
still achievable without flatten: axum allows a handler to take **two
independent `Query<T>` extractors** against the same request — each runs its
own `serde_urlencoded::from_str` over the full query string and silently
ignores fields it doesn't declare. This is the mechanism used throughout.

## Decision

### Shared types

- **`PaginationQuery`** (`crates/api-types/src/lib.rs`): `{ limit: Option<u64>,
  marker: Option<String>, page_reverse: bool }`. Taken as a **second,
  independent** `Query<PaginationQuery>` extractor in every v3 and v4 list
  handler, alongside each domain's existing (unchanged) filter-only params
  struct. v3 handlers accept `page_reverse` in the query string (harmless,
  ignored) but never read or forward it — only v4 handlers wire it through.
- **`ListPagination`** (`crates/core-types/src/lib.rs`): `{ limit: Option<u64>,
  marker: Option<String>, page_reverse: bool }`. Embedded as a single named
  field, `pub pagination: ListPagination`, on every domain's
  `*ListParameters` struct — replacing what would otherwise be three
  duplicated fields per domain.
- **`ResourceIdentifier`** trait (`crates/keystone/src/api/common.rs`):
  `fn get_id(&self) -> String`. Implemented once per domain, normally on the
  API-facing response type (the type actually returned to the handler after
  provider conversion). See "RoleAssignment" below for the one domain that
  deviates from this.

### Over-fetch-and-trim helpers (`crates/keystone/src/api/common.rs`)

Two functions, both generic over `T: ResourceIdentifier`:

- **`paginate_forward`** (v3): assumes the backend already returned up to
  `limit + 1` rows in ascending order. If it got the extra row, trims it and
  emits a `next` link built from the last remaining item's id; `previous` is
  never emitted (matches upstream `wrap_collection`).
- **`paginate_bidirectional`** (v4): same over-fetch/trim logic, but also
  emits a real `previous` link whenever the request carried a `marker` at
  all (i.e., this isn't the first page). Handles `page_reverse` by trimming
  from the appropriate end.

Both return `(trimmed_items, Option<Vec<Link>>)`; call sites replace the
naive `Json(List { data, links: None })` construction with the trimmed vec
plus the returned links.

### Config: per-provider limits (`crates/config/src/pagination.rs`)

```rust
#[derive(Deserialize, Debug, Clone, Default)]
pub struct ListLimitConfig {
    pub list_limit: Option<u64>,
    pub max_list_limit: Option<u64>,
}
```

Embedded as `pub list_limit: ListLimitConfig` on each per-domain provider
config struct (e.g. `CatalogProvider`, `AssignmentProvider`,
`ScimRealmProvider`, `MappingProvider`). Resolution is
`Config::resolve_list_limit(&self, provider_limit: &ListLimitConfig, requested:
Option<u64>) -> Option<u64>`, called by the handler before invoking the
provider: user-supplied `limit` → provider's `list_limit` → clamped to
`max_list_limit` if set.

### Backend responsibility: over-fetch by one

Each backend is responsible for actually fetching `limit + 1` rows in
marker/direction order — the API layer's `paginate_forward`/
`paginate_bidirectional` only trims what it's given, it never re-queries.
Two shapes of backend exist in this codebase:

- **SQL-backed, single-cursor domains** (User, Project, Domain, Group, Role,
  Service, Region, Endpoint, Credential, K8sAuthInstance,
  TokenRestriction, federation `identity_provider`): the marker/limit filter
  applies directly to the driving SQL query (`Column::Id.gt(marker)`,
  `.order_by_asc(...)`, `.limit(effective_limit + 1)`; reversed comparison
  and ordering when `page_reverse`).
- **Raft-backed, in-memory domains** (ScimRealmResource, OAuth2ClientResource,
  ApiClientResource, MappingRuleSet): there is no SQL cursor at all. The
  backend fetches the full filtered candidate set, sorts it by a chosen
  unique key, `retain()`s items strictly greater/less than the decoded
  marker depending on `page_reverse`, then truncates (or `split_off`s, for
  the reverse direction) to `limit + 1`.

### RoleAssignment: the one deliberate deviation

RoleAssignment's result set is a union of two SQL queries plus in-memory
role-implication expansion (`resolve_implied_roles`); it cannot be paginated
via a SQL cursor at all. It reuses the in-memory sort/retain/truncate pattern
from the Raft-backed domains, but inside the **SQL** driver's outer
`list_assignments` function, applied after the union and expansion are fully
materialized.

Assignment rows have no single `id` column, so pagination uses a synthetic
composite marker:

```
format!("{type}:{actor_id}:{target_id}:{role_id}:{inherited}:{implied_via_or_empty}")
```

This deliberately matches the exact tuple `resolve_implied_roles()`'s
`HashSet<Assignment>` already uses for full-struct-equality deduplication —
chosen specifically because two different prior roles can each imply the
same `role_id` for the same actor/target, producing rows that would
otherwise collide without `implied_via` in the key.

Because the API-facing `Assignment` response type lacks `inherited` and
`implied_via`, `ResourceIdentifier` is implemented on the **core-types**
`Assignment` instead (legal per Rust's orphan rule, since `ResourceIdentifier`
is a local trait), and `paginate_forward` is called on the raw provider
result **before** API conversion, rather than after as in every other
domain.

## Consequences

- All 16 domains identified in the original rollout now share one
  pagination mechanism: User, Project, Domain, Group, Role, federation
  `identity_provider`, Service, Region, Endpoint, Credential,
  K8sAuthInstance, ScimRealmResource, OAuth2ClientResource,
  ApiClientResource, TokenRestriction, RoleAssignment, and mapping
  `MappingRuleSet`.
- `ServiceAccount` and `RevocationEvent` are out of scope: neither has a
  list capability exposed over REST (ServiceAccount) or a public REST
  endpoint at all (RevocationEvent, internal-only).
- v3 responses never gain a `previous` link, matching upstream
  python-keystone byte-for-byte; only v4 endpoints support
  `page_reverse`/`previous`.
- Every domain's list handler follows the same mechanical recipe, making it
  straightforward for new domains to adopt: add `pagination: ListPagination`
  to the core-types list-params struct, apply over-fetch-by-one in the
  driver, implement `ResourceIdentifier`, add the second `PaginationQuery`
  extractor plus `paginate_forward`/`paginate_bidirectional` in the handler,
  add `list_limit: ListLimitConfig` to the provider's config struct.
