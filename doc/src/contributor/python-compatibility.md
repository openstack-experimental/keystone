# Python API compatibility

Tracks where this implementation's HTTP surface differs from python Keystone's.
Started as the documentation deliverable requested by
[#938](https://github.com/openstack-experimental/keystone/issues/938); it is
seeded from that issue's body table and grows as rows are closed. #938's table
is itself stale in places, so rows here are checked against the code and the
[Identity API v3 reference](https://docs.openstack.org/api-ref/identity/v3/)
rather than copied verbatim.

Verify with the tempest identity suite:

```console
tools/run-tempest-local.sh                 # full suite
TEMPEST_REGEX='tempest\.api\.identity\.admin\.v3\.test_policies' \
  tools/run-tempest-local.sh               # one module
```

Claims in this document are backed by a measured before/after pair on the same
revision and host, not by a remembered score. The most recent run, against
`8fc78201`:

| | Baseline | With the policy API |
| --- | --- | --- |
| Ran | 133 | 133 |
| Passed | 61 | **63** |
| Failed | 68 | **66** |
| Skipped | 4 | 4 |

Diffing the two failing-test lists shows exactly two fixed —
`test_create_update_delete_policy` and `test_list_policies` — and **zero**
regressions.

## Endpoint coverage

| Feature | Endpoints | Status |
| --- | --- | --- |
| Service catalog | `/v3/services` (CRUD) | Done |
| Endpoints | `/v3/endpoints` (CRUD) | Done — legacy `region` attribute auto-vivifies a Region and is mirrored back |
| Regions | `/v3/regions` (CRUD, plus `PUT /v3/regions/{id}`) | Done (#1078) |
| Policies (legacy blob store) | `/v3/policies` (CRUD) | Done (#1035) — tempest verified, see below |
| Limits | `/v3/limits`, `/v3/limits-model` | Missing |
| Project tags | `/v3/projects/{project_id}/tags` | Missing |
| Application credentials (v3.10) | `/v3/users/{user_id}/application_credentials` | Missing |
| Access rules (v3.13) | `/v3/users/{user_id}/access_rules` | Missing |
| System role assignments | `/v3/system/users/{user_id}/roles`, `.../roles/{role_id}` | Partial — user grants (`GET`/`HEAD`/`PUT`/`DELETE`) implemented; the `/v3/system/groups/{group_id}/roles*` variants are missing |
| Project hierarchy | `/v3/projects/{project_id}/parents`, `.../subtree` | Missing |
| OS-INHERIT role inference list | `/v3/role_inferences` | Done |
| OS-TRUST | `/v3/OS-TRUST/trusts` | Partial — create/get/list/delete; no `PATCH` (python has none either). Missing `/{id}/roles` sub-resource and response `links.self` (#1082) |
| OAuth2 | `/v3/OS-OAUTH2/*` | Missing |
| OS-ENDPOINT-POLICY | `/v3/policies/{id}/OS-ENDPOINT-POLICY/*`, `/v3/endpoints/{id}/OS-ENDPOINT-POLICY/policy` | Missing — needs the `policy_association` table; deliberately out of scope for #1035, follow-up issue to be filed |

## Cross-cutting behaviours

- **Malformed JSON bodies** answer `400` with an `{"error": ...}` document.
  Axum's `Json<T>` extractor natively answers a type-mismatch body with `422
  text/plain`; `crates/keystone/src/api/json_rejection.rs` normalizes it.
- **Collection pagination** follows [ADR 0029](../adr/0029-pagination.md):
  `?limit=`/`?marker=` with `links`. Python Keystone instead truncates to
  `[DEFAULT] list_limit` and sets a `truncated` flag on the collection. This is
  a deliberate, uniform deviation across every collection endpoint here, not a
  per-resource gap.
- **Per-member `links.self`** is not emitted on any resource yet (#1082).

## Policies (`/v3/policies`)

Storage for opaque policy documents that *remote* services fetch and interpret.
Deprecated upstream ("Keystone is not a policy management service") and
unrelated to this service's own OPA-based authorization — see
`openstack_keystone_core::policy_store`.

Implemented verbs, matching python Keystone's `PolicyResource` exactly:

| Verb | Path | Success |
| --- | --- | --- |
| `POST` | `/v3/policies` | 201 |
| `GET` | `/v3/policies` (`?type=` exact match) | 200 |
| `GET` | `/v3/policies/{policy_id}` | 200 |
| `PATCH` | `/v3/policies/{policy_id}` | 200 |
| `DELETE` | `/v3/policies/{policy_id}` | 204 |

There is deliberately **no `PUT /v3/policies/{policy_id}`** — python Keystone
does not define one, so it answers `405`. (Contrast `/v3/regions/{id}`, which
*does* have an upstream `PUT`.)

Request/response details carried over from upstream:

- `blob` is accepted as a **string only** on `POST`/`PATCH`, per
  `keystone/policy/schema.py`. An object-valued `blob` is a `400`. Responses
  carry whatever JSON value is stored, so rows written by older python releases
  (object blobs) still read back correctly.
- The stored column is JSON-encoded exactly as python's `JsonBlob` type
  decorator does. Round-tripping is **JSON-semantic**, not byte-identical:
  whitespace, string escaping, and object-key ordering may differ between
  `json.dumps` and `serde_json`.
- `id` is always server-assigned on create; a caller-supplied `id` is
  discarded (`_assign_unique_id`). On `PATCH` an `id` is accepted only when it
  equals the path segment, else `400` ("Cannot change policy ID"), and is never
  persisted.
- An empty `{"policy": {}}` patch document is a `400` (`minProperties: 1`).
- Unknown properties round-trip through the `extra` column. On **create** their
  names are normalized (`:` and `-` become `_`), matching upstream's
  `_normalize_dict`; `PATCH` does not normalize, also matching upstream.
- `PATCH` **merges** `extra` into the stored properties (supplied keys win,
  omitted stored keys survive), matching upstream's `update_policy`. Note this
  differs from e.g. `RegionUpdate.extra`, which this codebase overwrites
  wholesale.

Authorization mirrors `keystone/common/policies/policy.py`:
`list`/`show` are admin-or-system-reader, `create`/`update`/`delete` are
admin-only.

## Follow-ups

Known gaps deliberately left out of #1035. **These issues still need to be
filed** — no issue numbers exist yet, so nothing here links to one:

- **`OS-ENDPOINT-POLICY`** — `/v3/policies/{id}/OS-ENDPOINT-POLICY/*` and
  `/v3/endpoints/{id}/OS-ENDPOINT-POLICY/policy`, backed by the
  `policy_association` table. Tempest's `test_policies` does not exercise it.
- **`input.credentials.system_scope` audit** — several policies compare
  against a key `Credentials` never emits. The affected rules are not uniform
  and `region`'s python default is *broader* than the rego, so this needs an
  endpoint-by-endpoint audit rather than a rename. See
  [security model](security-model.md) §9 for the per-rule breakdown.
