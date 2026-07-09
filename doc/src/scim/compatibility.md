# SCIM v2 Protocol Reference & RFC 7644 Compatibility

This page is a protocol-level reference for whoever configures the SCIM side of
an Identity Provider connector (Okta, Entra ID, Workday, ...) against Keystone,
and a compatibility matrix against
[RFC 7644](https://datatracker.ietf.org/doc/html/rfc7644) for anyone evaluating
whether Keystone's SCIM implementation fits their IdP's requirements. For how to
register a realm and grant it access, see the [Administrator Guide](admin.md).
For full design rationale, see [ADR 0024](../adr/0024-scim-v2-provisioning.md).

Keystone implements a **deliberately restricted subset** of RFC 7644, not full
compliance — the restrictions exist to bound worst-case query/PATCH complexity
per request (the same posture applied elsewhere in this codebase to claim
mapping and rate limiting). Most enterprise IdPs, including Okta and Entra ID,
tolerate a narrower filter grammar and `bulk.supported: false` without issue;
check the matrix below against your specific connector before assuming a feature
works.

## Base URL & Authentication

```
https://<host>/SCIM/v2/{domain_id}/...
Authorization: Bearer kscim_...
```

Every request is scoped to one domain and authenticates with a bearer API key
(see [API-Key Authentication](../api_key.md)) — never a Fernet token. The key
must belong to an active, registered realm for that `(domain_id, provider_id)`
coordinate, or every request gets `403` regardless of role (see
[Realm Activation Gate](admin.md#realm-activation-gate)).

## Content Negotiation

Request bodies (`POST`/`PUT`/`PATCH` carrying a payload) must declare
`Content-Type: application/scim+json` or, for connectors that only speak plain
JSON, `application/json` — either is accepted. Anything else, or a missing
header on a request that does carry a body, is rejected with
`415 Unsupported Media Type`. Every response carries
`Content-Type: application/scim+json`, including error responses.

## Discovery

```
GET /SCIM/v2/{domain_id}/ServiceProviderConfig
GET /SCIM/v2/{domain_id}/Schemas
GET /SCIM/v2/{domain_id}/ResourceTypes
```

Unauthenticated within the SCIM sub-router (bearer auth is still accepted, just
not required) — most connectors probe these before presenting credentials.
`ServiceProviderConfig` honestly advertises what's _not_ supported rather than
claiming full compliance:

```json
{
  "patch": { "supported": true },
  "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
  "filter": { "supported": true, "maxResults": 200 },
  "changePassword": { "supported": false },
  "sort": { "supported": false },
  "etag": { "supported": true },
  "authenticationSchemes": [{ "type": "oauthbearertoken", "primary": true }]
}
```

## Resource Endpoints

```
POST   /SCIM/v2/{domain_id}/Users            GET   .../Users        GET .../Users/{id}
PUT    /SCIM/v2/{domain_id}/Users/{id}        PATCH .../Users/{id}   DELETE .../Users/{id}

POST   /SCIM/v2/{domain_id}/Groups            GET   .../Groups       GET .../Groups/{id}
PUT    /SCIM/v2/{domain_id}/Groups/{id}       PATCH .../Groups/{id}  DELETE .../Groups/{id}
```

An HTTP method not mapped for a given path (e.g. `POST .../Users/{id}`, or any
method on `/ServiceProviderConfig` other than `GET`) returns
`405 Method Not Allowed`.

### Ownership fencing

A resource is only visible to the realm that created it. `GET`/`PUT`/`PATCH`/
`DELETE` against an `id` owned by a different realm — or a same-ID resource that
doesn't exist at all — both return an identical `404`, by design: this prevents
realm-boundary probing via response-shape differences.

### `POST` — required fields, `schemas` validation

The request body's `schemas` array must contain the resource's core schema URI
(`urn:ietf:params:scim:schemas:core:2.0:User` / `...:Group`) — a missing or
mismatched `schemas` array is rejected with `400 invalidValue`. For Users,
`externalId` is additionally **mandatory** (`400` if empty/absent) and drives
deterministic `id` derivation so a later federated JIT login for the same IdP
`sub` claim converges onto the same account rather than creating a duplicate.

### Response `meta`

Every response carries `meta.location` (an absolute URL), and `201 Created`
responses on `POST` additionally carry an HTTP `Location` header matching it.
RFC 7644 doesn't mandate the header outside `201`; the body field is present on
every response regardless.

### Attribute Mapping (User)

| SCIM attribute                       | Keystone field                             |
| ------------------------------------ | ------------------------------------------ |
| `id`                                 | deterministic (`domain_id` + `externalId`) |
| `externalId`                         | realm-scoped ownership index               |
| `userName`                           | `name`                                     |
| `active`                             | `enabled`                                  |
| `name.givenName` / `name.familyName` | extension attributes                       |
| `emails[primary eq true].value`      | extension attribute                        |
| `displayName`                        | extension attribute                        |

### Attribute Mapping (Group)

| SCIM attribute | Keystone field                                                                                |
| -------------- | --------------------------------------------------------------------------------------------- |
| `id`           | server-assigned                                                                               |
| `externalId`   | realm-scoped ownership index                                                                  |
| `displayName`  | `name`                                                                                        |
| `members`      | resolved membership, capped at 1000 entries, must reference Users owned by the **same realm** |

A `members` entry referencing a user owned by a different realm, or a
manually-created user with no SCIM ownership record at all, is rejected with
`400 invalidValue` on both `PUT` and `PATCH add`.

### `DELETE` semantics

Neither Users nor Groups are hard-deleted by `DELETE`. A User is disabled and
its sessions revoked; a Group has its role assignments immediately stripped
(closing live authorization) while its membership snapshot is retained for a
forensic window. Both become invisible to subsequent `GET`/`PUT`/`PATCH`/`List`
(`404`) immediately. See
[Deprovisioning & retention](admin.md#deprovisioning--retention) for the
retention window and operator purge-now path — this deviates from a strict
reading of RFC 7644 §3.6, which doesn't distinguish soft- from hard-delete.

## Filtering

```
filter := term (LOGICAL_OP term)*      # "and"/"or" MUST NOT be mixed in one filter string
term    := ATTR OP value
OP      := eq | ne | co | sw | pr
```

No nested/parenthesized expressions, no complex-attribute filters
(`emails[type eq "work"]`). A filter string over 512 bytes or 8 terms is
rejected. Violations return `400 invalidFilter`.

| User attribute | Allowed operators    |
| -------------- | -------------------- |
| `userName`     | `eq, ne, co, sw, pr` |
| `externalId`   | `eq, ne, pr`         |
| `id`           | `eq, pr`             |
| `active`       | `eq, pr`             |

| Group attribute | Allowed operators    |
| --------------- | -------------------- |
| `displayName`   | `eq, ne, co, sw, pr` |
| `externalId`    | `eq, ne, pr`         |
| `id`            | `eq, pr`             |

## Pagination

`startIndex` (1-based, default `1`), `count` (default and max `200`). No
cursor/continuation token — a bounded scan over the realm's own resource set,
excluding deprovisioned entries.

## PATCH

`Operations: [{op, path, value}]`, `add`/`replace`/`remove` only, restricted to
these top-level scalar paths:

| Resource | Patchable paths                                                                        |
| -------- | -------------------------------------------------------------------------------------- |
| User     | `active`, `userName`, `displayName`, `externalId`, `name.givenName`, `name.familyName` |
| Group    | `displayName`, `externalId`, `members` (`add`/`remove` only — no `replace`)            |

`id` and `meta` are real SCIM attributes but always immutable — a `PATCH` naming
either returns `400 mutability` (distinct from a path that isn't a recognized
attribute at all, which returns `400 invalidPath`). Any other unrecognized path,
an array-index path, or a complex filter expression
(`emails[type eq "work"].value`) also returns `400 invalidPath`. `PUT` performs
a full declarative replace, including a full membership resync for Groups.

## ETags & Concurrency

`GET`/`PUT`/`PATCH`/`POST` responses carry a weak ETag: `W/"<version>"`. Send
`If-Match: W/"<version>"` on `PUT`/`PATCH` to get an atomic compare-and-swap; a
stale version returns `412 Precondition Failed` (no response body). This closes
the lost-update race for concurrent push-group syncs from a single IdP without
needing a distributed lock.

## `/Bulk` and `/Me`

Both return `501 Not Implemented` with a SCIM-shaped error body rather than a
generic `404` — RFC 7644 clients commonly probe these before falling back.
Neither is planned for this subset (see
[Explicitly out of scope](#explicitly-out-of-scope) below).

## Errors

Standard envelope:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "scimType": "uniqueness",
  "detail": "userName already exists within this domain"
}
```

| Condition                                                                              | HTTP status | `scimType`      |
| -------------------------------------------------------------------------------------- | ----------- | --------------- |
| Realm not registered / disabled                                                        | 403         | _(no body)_     |
| Resource not owned by caller's realm                                                   | 404         | _(no body)_     |
| `userName`/`displayName`/`externalId` collision                                        | 409         | `uniqueness`    |
| Missing/wrong request `schemas`, cross-realm membership reference, invalid PATCH value | 400         | `invalidValue`  |
| Disallowed filter attribute/operator/mixed chain/oversized                             | 400         | `invalidFilter` |
| Disallowed or unrecognized PATCH `path`                                                | 400         | `invalidPath`   |
| PATCH targeting a real but immutable path (`id`, `meta`)                               | 400         | `mutability`    |
| Malformed JSON request body                                                            | 400         | `invalidSyntax` |
| Unsupported/missing `Content-Type` on a bodied request                                 | 415         | _(no body)_     |
| Unmapped HTTP method on a mapped path                                                  | 405         | _(no body)_     |
| `If-Match` version mismatch                                                            | 412         | _(no body)_     |
| `/Bulk`, `/Me`                                                                         | 501         | _(no body)_     |

`noTarget`, `tooMany`, `invalidVers`, and `sensitive` are defined by RFC 7644
§3.12 but never emitted — see the compatibility matrix below for why.

## Explicitly out of scope

`/Bulk`, `sortBy`/`sortOrder`, arbitrary filter/PATCH path expressions
(`emails[type eq "work"]`), and multi-valued complex-attribute addressing.
Extending any of these requires a ratifying ADR 0024 revision given their
DoS/complexity surface.

---

## RFC 7644 Compatibility Matrix

| RFC 7644 §         | Feature                                                       | Status                          | Notes                                                                                                          |
| ------------------ | ------------------------------------------------------------- | ------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| §3.1               | HTTP methods, `Content-Type`, `Location` header               | Supported                       | Accepts `application/json` in addition to `application/scim+json`                                              |
| §3.2               | Discovery (`ServiceProviderConfig`/`Schemas`/`ResourceTypes`) | Supported                       | Honestly advertises unsupported features rather than over-claiming                                             |
| §3.3               | `POST` (create)                                               | Supported                       | `schemas` and (User) `externalId` are mandatory                                                                |
| §3.4.2             | Filtering                                                     | Partial                         | Restricted attribute/operator allowlist, homogeneous `and`/`or` only, no nesting — see [Filtering](#filtering) |
| §3.4.2.2           | Alternative search (`POST .search`)                           | Not supported                   | —                                                                                                              |
| §3.4.3             | Pagination                                                    | Supported                       | Offset/count only, no continuation token                                                                       |
| §3.4.4             | Sorting                                                       | Not supported                   | `sort.supported: false` in discovery                                                                           |
| §3.4.5             | `attributes`/`excludedAttributes` query params                | Not supported                   | Always returns the full mapped resource                                                                        |
| §3.5.1             | `PUT` (replace)                                               | Supported                       | Full declarative replace, incl. Group membership resync                                                        |
| §3.5.2             | `PATCH` (modify)                                              | Partial                         | Scalar top-level path allowlist only — see [PATCH](#patch)                                                     |
| §3.6               | `DELETE`                                                      | Partial                         | Soft-delete/tombstone semantics, not hard delete — see [DELETE semantics](#delete-semantics)                   |
| §3.7               | Bulk operations                                               | Not supported                   | Explicit `501`, not a bare `404`                                                                               |
| §3.11              | `/Me`                                                         | Not supported                   | Explicit `501` — no "current resource" concept for an API-key-authenticated client                             |
| §3.12              | Error response format                                         | Partial                         | Envelope always present; only 6 of 10 defined `scimType`s are emitted — see [Errors](#errors)                  |
| §3.14              | ETag / conditional requests                                   | Supported                       | Weak ETags, atomic compare-and-swap on `If-Match`                                                              |
| §4 (core schema)   | `User` resource attributes                                    | Partial                         | Core identity + name/email/displayName only — see [Attribute Mapping](#attribute-mapping-user)                 |
| §4 (core schema)   | `Group` resource attributes                                   | Partial                         | `displayName` + `members` only — see [Attribute Mapping](#attribute-mapping-group)                             |
| §4 (core schema)   | Extension schemas (Enterprise User, etc.)                     | Not supported                   | —                                                                                                              |
| §7 (multi-tenancy) | Tenant isolation                                              | Supported (different mechanism) | Domain + realm scoping instead of a `tenant` attribute — see [Ownership fencing](#ownership-fencing)           |
| §8 (security)      | Bearer token auth                                             | Supported                       | Domain-scoped API keys (ADR 0021), not OAuth2                                                                  |
