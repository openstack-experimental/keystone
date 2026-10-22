# Service grants

Service grants ([ADR 0036](../../adr/0036-service-delegation.md), phases 1 and 2) let a
user delegate a bounded set of their roles on one project to a registered
OpenStack service, so the service can keep acting on the user's behalf after
the user's own token has expired. Typical users are Heat (stack updates and
autoscaling), Magnum (cluster operations) and Glance (long-running imports).
They replace the parts of `/v3/OS-TRUST` those services rely on.

A grant is a stored record. The service redeems it at the OAuth2 token
endpoint, authenticating with its own SPIFFE identity, and receives a
short-lived JWT access token scoped to the grant's project. Every redemption
re-validates the grant, the grantor and the grantor's current roles, so
revoking a grant or removing a role takes effect at the next redemption.

A delegatable service can also continue an operation the user started, with no
stored record, by exchanging the user's own token ([on-behalf-of
exchange](#on-behalf-of-exchange), phase 2).

Nothing changes for a deployment until an administrator registers a
delegatable service.

## Concepts

| Term        | Meaning                                                                                  |
| ----------- | ---------------------------------------------------------------------------------------- |
| Grantor     | The user who creates the grant. Delegated roles never exceed the grantor's live roles.   |
| Grantee     | A registered OAuth2 client with a `delegation` policy accepting service grants.          |
| Target      | The single project the grant applies to. It may be in another domain than the grantor.   |
| Role subset | The roles the grant carries, chosen at creation and fixed afterwards.                    |
| Redemption  | `POST /v4/oauth2/{domain_id}/token` with the service grant grant type, over SPIFFE mTLS. |

## Prerequisites

- The `[interface_internal]` listener is configured with SPIFFE mTLS (see
  [Configuration](../configuration.md)). Redemption is only accepted on that
  interface, and a client can only list SPIFFE IDs in the listener's
  `trust_domains`.
- Raft storage is enabled. Grants are stored only there; with Raft disabled the
  endpoints answer `501`.
- The target project's domain has an OAuth2 signing key. Keys are provisioned when a
  domain is created through the API, so the bootstrap `default` domain has none
  (see [OAuth2 / OIDC Provider](oauth2.md#provisioning-a-domains-signing-key)).

## Registering a delegatable service

A service becomes a grantee by registering an OAuth2 client that authenticates
with `tls_client_auth`, lists the SPIFFE IDs its workloads present, and carries
a `delegation` policy. Setting or changing `spiffe_ids` or `delegation`
requires an administrator.

```json
{
  "oauth2_client": {
    "provider_id": "heat",
    "name": "Orchestration (Heat)",
    "confidential": false,
    "token_endpoint_auth_method": "tls_client_auth",
    "grant_types": [],
    "allowed_scopes": ["openstack:api"],
    "spiffe_ids": ["spiffe://cloud.example/service/heat-engine/host/*"],
    "delegation": {
      "service_grants": true,
      "cross_domain": true,
      "max_role_ids": ["<member-role-id>", "<reader-role-id>"],
      "max_grant_lifetime": 31536000,
      "max_grants_per_project": 100
    }
  }
}
```

- `spiffe_ids` patterns match segment by segment. `*` matches exactly one
  non-empty segment and is only allowed as the whole last segment. The trust
  domain must match exactly.
- `cross_domain: true` lets users of any domain delegate to the client, on
  projects of any domain. Without it both the grantor and the project must be
  in the client's own domain; otherwise creation is rejected and redemption
  answers as if the grant did not exist.
- `max_role_ids` is a ceiling on the roles a grant to this client may carry. An
  empty list means the grant is bounded only by the grantor's own roles. Every
  id added to the ceiling must be an existing role; ids already stored are not
  re-checked, so a role deleted later simply never matches and does not block
  edits.
- `max_grant_lifetime` (seconds) caps `expires_at`. Without it a grant may be
  created without an expiry.
- `max_grants_per_project` caps live grants per (project, client). The
  `[delegation] max_grants_per_project` backstop applies on top. Exceeding
  either answers `429`.
- `on_behalf_of` lets the service exchange user tokens (see below) and requires
  `max_operation_lifetime` (seconds), the longest an operation may run from the
  moment the user authenticated. `max_role_ids` and `cross_domain` apply to
  grants; for an exchange only `cross_domain` is consulted.

Removing the policy (`"remove_delegation": true` on update), disabling the
client, or deleting it disables every grant naming it with reason
`grantee_removed`.

Users discover delegatable services with `GET /v4/delegatable-services`, which
returns the client id, name, domain and ceilings, never the SPIFFE IDs.

## Configuration (`[delegation]`)

| Option                          | Default            | Meaning                                                                    |
| ------------------------------- | ------------------ | -------------------------------------------------------------------------- |
| `max_grants_per_project`        | `10000`            | Deployment-wide backstop on live grants per project.                       |
| `last_redeemed_update_interval` | `3600`             | Seconds between two `last_redeemed_at` writes of one grant.                |
| `expired_grant_retention`       | `2592000` (30 d)   | Seconds an expired grant is kept before the janitor deletes it.            |
| `janitor_interval`              | `3600`             | Seconds between two janitor runs. Re-read every tick.                      |
| `list_limit`                    | as other list APIs | Pagination limits of `GET /v4/service-grants`.                             |

## Managing grants

```
GET    /v4/delegatable-services
POST   /v4/service-grants
GET    /v4/service-grants
GET    /v4/service-grants/{grant_id}
DELETE /v4/service-grants/{grant_id}
```

A user creates a grant with a regular Keystone token:

```json
{
  "service_grant": {
    "grantee_client_id": "<heat client_id>",
    "project_id": "<project id>",
    "role_ids": ["<member-role-id>"],
    "expires_at": "2027-10-01T00:00:00Z",
    "description": "stack web-frontend"
  }
}
```

- `role_ids` must be a non-empty subset of both the grantor's effective roles on
  the project (group and implied roles included) and the client's
  `max_role_ids`. Omitting it delegates every effective role within the
  ceiling.
- Grants cannot be created from a delegated authentication (trust, restricted
  application credential, service grant) or a restricted token. An unrestricted
  application credential may create grants only on its own project, bounded by
  its own roles.
- Grants are immutable. To change roles or expiry, create a new grant and
  delete the old one.

Who may see and delete a grant (`policy/service_grant/`): the grantor, an
administrator, a manager of the target project or of its domain, and the
grantee service itself. A grantee service calls `GET` or `DELETE
/v4/service-grants/{grant_id}` on the internal interface with its SVID and no
token, which is how Heat cleans up grants when a stack is deleted.

`GET /v4/service-grants` accepts `user_id`, `project_id`, `domain_id` (the
project's domain), `grantee_client_id` and `enabled` filters. A non-admin must
filter on their own `user_id`, or on a project or domain they manage. Every
returned grant is re-checked against the show policy.

## Redeeming a grant

The grantee service calls the token endpoint of the grant's `domain_id`, which
is the project's domain, over the internal interface, presenting its
X.509-SVID:

```
POST /v4/oauth2/{domain_id}/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:openstack:params:oauth:grant-type:service-grant
&grant_id=<grant id>
&client_id=<client id>      (optional; must match when sent)
&roles=<role id> <role id>  (optional; narrows the grant's roles)
&scope=openstack:api        (optional; within the client's allowed_scopes)
&audience=<service type>    (optional; narrows `aud`, as for token exchange)
```

On every redemption Keystone checks that the grant exists and is enabled and
unexpired, that the SVID matches one of the grantee client's `spiffe_ids`, that
the client is enabled and still accepts grants (its current `max_role_ids` and
`max_grant_lifetime`, counted from the grant's creation, apply to existing
grants too), that the grantor, the project
and its domain are enabled, and that the grantor still holds at least one of
the requested roles. The token carries `grant.role_ids ∩ grantor's live roles`
(further narrowed by `roles`). No refresh token is issued.

Errors follow RFC 6749: `invalid_grant` (`400`) for an unknown or foreign grant
or an authentication failure, `invalid_client` (`401`) when the SVID does not
match the grantee, `invalid_request` (`400`) for a `roles` value outside the
grant, and `invalid_grant` with status `403` when the grant is disabled or the
grantor lost every delegated role. Redemption is rate limited per SVID
(`service_grant:<svid>`) with the token endpoint's `[oauth2]` quota, so it never
shares a budget with the client-keyed grants.

### Token content

```json
{
  "sub": "<grantor user id>",
  "amr": ["service_grant"],
  "act": {
    "client_id": "<grantee client id>",
    "sub_type": "spiffe",
    "sub": "spiffe://cloud.example/service/heat-engine/host/h1"
  },
  "delegation_context": {
    "auth_method": "service_grant",
    "delegated_project_id": "<project id>",
    "grant_id": "<grant id>"
  },
  "scope_type": "project",
  "project_id": "<project id>",
  "project_domain_id": "<project domain id>",
  "scope_roles": [{ "id": "<member-role-id>", "name": "member" }]
}
```

The token is issued and signed by the project's domain (`iss` is
`/v4/oauth2/<project domain>`), so each domain's key only vouches for its own
projects. The remaining OpenStack claims (`user_id`, `user_domain_id` naming
the grantor's own domain, roles) are those of any project-scoped access token. Downstream services treat it like any delegated
token: the scope-drift tripwire (`project_id` equals `delegated_project_id`) is enforced by
`verify_openstack_access_token` and must be kept by policy. `act` identifies
the acting service in audit records and is also returned by introspection.

Keystone accepts such a token on its own internal interface only together with
the SVID of the acting service: send `Authorization: Bearer <token>` over the
mutual TLS connection. The SVID must match the client named in `act`;
otherwise, or without an SVID, the request is a `401`. The grant is checked
again on every request, so a revoked grant stops working at once. The request
is a delegated call limited to read operations: a service grant or
on-behalf-of token cannot be used to create, update or delete anything at
Keystone (grants, application credentials, EC2 credentials, trusts, users,
projects, role assignments). Any `Authorization` header sent with an SVID that
is not a valid bound bearer is a `401`. Only tokens issued under
`[DEFAULT] public_endpoint` are accepted.

## On-behalf-of exchange

A service holding a user's token trades it for a token of its own, without any
grant. The user's token handed to the service is the consent, so nothing is
stored and the user's ordinary controls end the exchange: revoking the token,
removing the role, disabling the user.

The service must be registered with `delegation.on_behalf_of` and a
`max_operation_lifetime`, and authenticates exactly as for redemption (its
X.509-SVID on the internal interface). Because an SVID alone does not name the
client, the request carries `client_id`:

```
POST /v4/oauth2/{domain_id}/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&client_id=<client id>
&subject_token=<the user's token>
&subject_token_type=urn:openstack:params:oauth:token-type:keystone
&audience=<service type>    (optional; narrows `aud`)
```

`subject_token_type` is
`urn:openstack:params:oauth:token-type:keystone` for a Fernet or JWS token the
user presented, and `urn:ietf:params:oauth:token-type:access_token` for the
token a previous exchange returned. The caller sends no secret; a request that
carries one is the older secret-authenticated exchange of an application
credential token and is unchanged.

The subject must be a plain login or an application credential. A trust, a
service grant, a restricted token, or a token another service obtained by
exchange is refused with `invalid_grant`: there is no re-delegation. The token's
scope must belong to the domain of the endpoint, and a client or user of
another domain needs `cross_domain`.

### Keeping an operation going

Access tokens are short lived. The service renews by sending the token it
received as the next `subject_token` (type `access_token`). Each renewal checks
again that the root token is not revoked, that the user and domains are enabled
and that the user still holds the roles, and succeeds only while
`now < auth_time + max_operation_lifetime`, counted from when the user
authenticated and never reset. A token never outlives that bound. An
application credential subject stays within its project and roles on every
renewal.

### Token content

```json
{
  "sub": "<user id>",
  "amr": ["on_behalf_of", "password", "token"],
  "act": {
    "client_id": "<client id>",
    "sub_type": "spiffe",
    "sub": "spiffe://cloud.example/service/glance/host/h1"
  },
  "delegation_context": {
    "auth_method": "on_behalf_of",
    "actor_client_id": "<client id>",
    "auth_time": 1757500000,
    "root_jti": "<audit id of the user's token>"
  }
}
```

`delegated_project_id` and `delegated_role_ids` appear only when the subject was
an application credential. A plain subject has no boundary of its own; its
authority is whatever the user's live assignments say at that moment. The token
has the scope of the subject (project, or domain for a plain subject) and no
refresh token is issued. Like service grant tokens it is accepted at Keystone
itself only together with the acting client's SVID, and counts as a delegated
caller even for a plain subject.

Errors are those of redemption: `invalid_client` (`401`) when the SVID does not
authenticate the client or it lacks the capability, `invalid_grant` (`400`) for
a subject that is invalid, revoked, not exchangeable or past the operation
lifetime, and `invalid_request` for a missing `subject_token` or
`subject_token_type`. Exchanges are rate limited per SVID
(`on_behalf_of:<svid>`).

## Lifecycle

| Change                                                              | Effect on grants                        |
| ------------------------------------------------------------------- | --------------------------------------- |
| Grantor disabled                                                    | Disabled, reason `grantor_disabled`     |
| Grantor deleted                                                     | Deleted                                 |
| Target project disabled                                             | Disabled, reason `target_disabled`      |
| Target project deleted                                              | Deleted                                 |
| Role assignment or group membership removed, no delegated role left | Disabled, reason `role_lost`            |
| Grantee client deleted, disabled as delegatable, or policy removed  | Disabled, reason `grantee_removed`      |
| `expires_at` passed                                                 | Disabled by the janitor, reason `expired`, deleted after `expired_grant_retention` |
| User deletes the grant                                              | Deleted                                 |

A grantor who lost only some of the delegated roles keeps the grant; tokens
carry the remaining intersection. Disabled grants are never re-enabled
automatically. Re-enabling a user or project, or restoring a role, requires a
new grant.

These hooks are housekeeping. Redemption re-runs every check, so a change the
hooks miss (for example an inherited assignment or an external assignment
driver) still stops the grant from producing tokens.

## Audit

Each exchange emits an `oauth2` `authenticate` event with the user as initiator
and the client as target, and a signed `on_behalf_of` attachment with
`root_jti`, `user_id`, `actor_client_id`, `actor_spiffe_id` and, for an
application credential subject, `delegated_project_id`.

Grant creation and deletion emit `service_grant` CADF events. Each redemption
emits an `oauth2` `authenticate` event with the grantor as initiator and the
grantee client as target. The event carries a signed `service_grant`
attachment with `grant_id`, `grantor_user_id`, `actor_client_id`,
`actor_spiffe_id` and `delegated_project_id`. Lifecycle disables are written
with the internal context and appear in the grant's `disabled_reason`.

## Known gaps

- Only `tls_client_auth` over the internal interface is supported. JWT-SVID
  `private_key_jwt` on the public interface is phase 3.
- EC2 credentials under a grant (phase 4) are not implemented. Trusts remain
  available.
- An exchange accepts a Keystone token or the token of an earlier exchange. A
  JWT access token issued by the OAuth2 provider cannot start a chain yet.
- Renewal does not re-read an application credential: deleting one ends the
  chain only if the deletion revokes its tokens.
- A revoked hop token is refused by Keystone at the next exchange, but a
  service validating it offline accepts it until it expires.
- A `429` for a grant quota carries no `Retry-After` header: unlike a rate
  limit, waiting does not free quota, only revoking or expiring grants does.
