# SCIM v2 Support: Administrator Guide

This page is for Keystone operators and domain managers who need to enable an
enterprise Identity Provider (Okta, Entra ID, Workday, ...) to push user/group
lifecycle events into a Keystone domain via SCIM. For the protocol-level
reference (endpoints, filter grammar, RFC 7644 compatibility matrix) aimed at
whoever configures the IdP side, see [SCIM v2 Support](../../../user/features/scim/index.md).
For the full design rationale, see
[ADR 0024](../../../adr/0024-scim-v2-provisioning.md).

## Concept

SCIM provisioning is a distinct concern from authentication. It manages the
_existence and attributes_ of real, persistent `User`/`Group` rows in a domain;
how those same accounts later log in (password, OIDC, passkey) is unrelated. A
domain can register any number of independent **realms**, each identified by a
`(domain_id, provider_id)` pair, so more than one authoritative source (e.g. an
Okta tenant for full-time employees and a Workday feed for contractors) can
provision into the same domain without either one able to see, rename, or delete
the other's records or a human administrator's manually created accounts.

Every realm is linked to a federation `IdentityProvider`. If a person is
provisioned ahead of time via SCIM and later authenticates for the first time
through that same IdP, the account converges onto the same `User` row a
federated JIT login would have created — no duplicate accounts.

## Prerequisites

A SCIM realm requires an existing federation `IdentityProvider` in the target
domain. If you haven't set one up yet, see [Federation](../federation/index.md)
first. The `IdentityProvider` doesn't need to be usable for interactive login
yet — SCIM just needs its `id` to exist so realm registration can resolve
`idp_id`.

## Setup walkthrough

Four steps: register the realm, grant it a role via a mapping rule, mint an API
key, then hand the base URL and key to the IdP's SCIM connector.

### 1. Register the SCIM realm

Requires the `manager` role scoped to the target domain, or `admin`.

```
POST /v4/scim_realms/
```

```json
{
  "scim_realm": {
    "domain_id": "d1",
    "provider_id": "entra-scim",
    "idp_id": "entra-idp-1",
    "display_name": "Entra ID SCIM provisioning"
  }
}
```

`provider_id` is an arbitrary operator-chosen coordinate — it doesn't need to
match the `IdentityProvider.id`, though reusing a recognizable name (as above)
keeps audit logs readable. `idp_id` must resolve to an existing
`IdentityProvider` in `domain_id`, checked at both create and update time (`404`
otherwise). Response is `201` with the created `ScimRealmResource` including
`enabled: true`.

Realms have no `DELETE` — see
[Deprovisioning & retention](#deprovisioning--retention) for how to turn one
off.

### 2. Grant the realm a provisioning role

A realm authorizes SCIM traffic (the Realm Activation Gate, below), but
authorizing _specific_ Users/Groups operations against it is separate, and
happens the same way all API-key ingress traffic is authorized: via a
[mapping ruleset](../identity-mapping.md) matched on `IdentitySource::ApiClient`.
`ApiClientResource` carries no `Role`/`RoleAssignment` at all — every role a
SCIM request is evaluated against comes entirely from
`Authorization::Domain{roles}` produced by this ruleset at request time.

```json
{
  "mapping_ruleset": {
    "mapping_id": "entra-scim-mapping",
    "domain_id": "d1",
    "source": { "type": "api_client", "provider_id": "entra-scim" },
    "domain_resolution_mode": "fixed",
    "enabled": true,
    "rules": [
      {
        "name": "entra-scim-rule",
        "match": { "all_of": [] },
        "identity": {
          "user_name": "${claims.api_client.client_id}"
        },
        "authorizations": [
          {
            "type": "domain",
            "domain_id": "d1",
            "roles": [{ "name": "scim_provisioner" }]
          }
        ]
      }
    ]
  }
}
```

The role string must be one of `admin`, `manager`, or `scim_provisioner` (see
[Authorization](#authorization) below) and must resolve against an actual `Role`
— mapping rule create/update rejects an unresolvable `RoleRef` with `422`.
`scim_provisioner` is the narrowest of the three and the recommended choice for
a machine-provisioning integration; create it once per domain if it doesn't
already exist (`POST /v4/roles`).

The write-time ruleset constraint from ADR 0021/0024 applies here: since this
ruleset shares its `provider_id` coordinate with the realm, an
`Authorization::Project` rule can never be added to it — the Mapping Engine CRUD
API rejects that with `422 Unprocessable Entity`. A SCIM realm's ruleset may
only ever resolve `Authorization::Domain`.

### 3. Mint an API key

See [API-Key Authentication](api-keys.md) for the full lifecycle (rotation,
revocation, IP allow-listing). In short:

```
POST /v4/api-keys/
```

```json
{
  "api_key": {
    "domain_id": "d1",
    "provider_id": "entra-scim",
    "description": "Entra ID SCIM provisioning"
  }
}
```

The response's `token` field (`kscim_...`) is shown **once** — this is the
bearer credential the IdP's SCIM connector will use.

### 4. Configure the IdP's SCIM connector

Point the connector at:

```
Base URL:    https://<your-keystone-host>/SCIM/v2/d1
Auth type:   Bearer Token
Token:       kscim_9pQ...xz_1a2b3c4d
```

The connector should discover its capabilities from
`GET {base}/ServiceProviderConfig` — see
[SCIM v2 Support](../../../user/features/scim/index.md) for what it will find (and what it
won't: `bulk`, `sort`, and `changePassword` are all honestly advertised as
unsupported).

## Realm Activation Gate

Every `/SCIM/v2/{domain_id}/Users|Groups` request first resolves the
authenticating API key's `provider_id` and looks up the matching realm. If no
realm is registered for that coordinate, or it's `enabled: false`, the request
is rejected with `403 Forbidden` before touching any User/Group storage —
independent of whatever role the mapping ruleset would otherwise grant.
Realm-level activation and per-operation role authorization are two separate
gates; both must pass.

`ScimRealmAuth` additionally requires the resolved scope to be domain-scoped and
match the URL's `{domain_id}` exactly. A key whose mapping resolves to a project
scope, or a `{domain_id}` mismatch, gets `403` on every `/Users`/`/Groups` route
(the `whoami` diagnostic route is exempt).

## Realm management

```
GET   /v4/scim_realms/?domain_id=d1
GET   /v4/scim_realms/{domain_id}/{provider_id}
PATCH /v4/scim_realms/{domain_id}/{provider_id}
```

`PATCH` can update `idp_id`, `display_name`, and `enabled` — set
`enabled: false` to immediately stop a realm's traffic (see below) without
deleting anything. There is no realm `DELETE`; disabling is the supported way to
turn one off, keeping its provisioned resources and audit trail intact.

## Authorization

Realm CRUD (`POST`/`GET`/`PATCH /v4/scim_realms`) is invoked by a normal
Fernet-authenticated human operator and requires `manager` (domain-scoped) or
`admin`:

- `identity/scim_realm/create`, `identity/scim_realm/list`,
  `identity/scim_realm/show`, `identity/scim_realm/disable`,
  `identity/scim_realm/purge`

SCIM resource CRUD (Users/Groups) is invoked exclusively via API-key ingress and
evaluated against the roles the realm's own mapping ruleset produces (step 2
above — never a real `RoleAssignment`):

- `identity/scim/user/{create,list,show,update,delete}`
- `identity/scim/group/{create,list,show,update,delete}`

Each of these accepts `admin`, `manager` (domain-scoped), or `scim_provisioner`
(domain-scoped).

## Deprovisioning & retention

- `DELETE /Users/{id}` never hard-deletes: it disables the user
  (`enabled: false`), stamps the SCIM index as deprovisioned, and revokes all
  live sessions immediately. Subsequent `GET`/`PUT`/`PATCH` against that `id`
  from the owning realm return `404`.

- `DELETE /Groups/{id}` immediately strips the group's role assignments (closing
  the live authorization surface) and tombstones it the same way, but **retains
  its membership snapshot** for forensic purposes until purge.

- A background janitor permanently deletes tombstoned rows (and, for Groups,
  their retained membership) once
  `[scim_resource] janitor_deprovisioned_retention_days` has elapsed since
  deprovisioning (see [Configuration](#configuration)).

- For a verified erasure request that can't wait for the retention window, an
  operator (`manager`/`admin`) can force an immediate purge of one resource:

  ```
  DELETE /v4/scim_realms/{domain_id}/{provider_id}/purge/{resource_type}/{keystone_id}
  ```

  This refuses to purge a resource that isn't already deprovisioned —
  soft-delete it via SCIM first.

## Configuration

`[scim_realm]` in `keystone.conf`:

| Option   | Default | Purpose                          |
| -------- | ------- | -------------------------------- |
| `driver` | `raft`  | Storage driver for realm records |

`[scim_resource]` in `keystone.conf`:

| Option                                 | Default | Purpose                                                               |
| -------------------------------------- | ------- | --------------------------------------------------------------------- |
| `driver`                               | `raft`  | Storage driver for the resource ownership index                       |
| `janitor_deprovisioned_retention_days` | `365`   | Days a tombstoned User/Group is retained before the janitor purges it |

Set `janitor_deprovisioned_retention_days` well below the default for
deployments under GDPR or a comparable regime that can't justify a full year of
PII retention purely for a forensic snapshot — including near-zero, if your
compliance posture requires it. Use the operator-triggered purge-now path above
for a specific already-received erasure request rather than lowering the global
default.

## Auditing

Every SCIM write emits a CADF event (`Create`/`Update`/`Disable`), with
`target.type_uri` of `data/security/account` (User) or `data/security/group`
(Group), and `realm_provider_id`/`external_id` captured on the event for
cross-referencing against the IdP's own provisioning logs.

**Correlation caveat:** `initiator.id` is derived from the authenticating API
key's `client_id`, not the realm's `provider_id`. Across a zero-downtime key
rotation (rotating to a new key under the same `provider_id`, see
[API-Key Authentication](api-keys.md)), `initiator.id` **changes** even though
the realm performing the action hasn't. Build SIEM/alerting correlation on the
`realm_provider_id` attachment field, not `initiator.id`, for SCIM traffic.

## Troubleshooting

| Symptom                                                       | Likely cause                                                                                                                                                                     |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `403` on every `/Users`/`/Groups` request                     | Realm not registered for this `(domain_id, provider_id)`, or `enabled: false` — check step 1                                                                                     |
| `403` with a valid, enabled realm                             | API key's mapping resolved to project scope, or `{domain_id}` in the URL doesn't match the key's scope                                                                           |
| `401` from the SCIM connector before any SCIM request         | API-key-level auth failure — see [API-Key Authentication](api-keys.md) troubleshooting                                                                                         |
| Individual operations (e.g. create) return `403`/policy error | Mapping ruleset doesn't emit a role in `{admin, manager, scim_provisioner}` — check step 2                                                                                       |
| `422` when writing the mapping rule                           | Role name doesn't resolve to an existing `Role`, or the rule tries to add an `Authorization::Project` entry to a realm-linked ruleset                                            |
| `409 uniqueness` on user/group create                         | `userName`/`displayName`/`externalId` already exists domain-wide, or under this realm — expected, not a bug                                                                      |
| Newly-created resource immediately `404`s                     | Deprovisioned already (unlikely on create), or the request is coming through a _different_ realm than the one that created it — see [Compatibility: Ownership](../../../user/features/scim/index.md) |
