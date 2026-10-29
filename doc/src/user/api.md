# API Guide

Keystone exposes version discovery at `/`, `/v3`, and `/v4`.

- v3 contains the implemented OpenStack Identity resources, including tokens,
  domains, projects, users, groups, roles, assignments, catalog resources,
  credentials, and EC2 token validation.
- v4 contains Keystone-NG features such as passkeys, federation, Kubernetes
  authentication, mapping rulesets, OAuth2/OIDC, SCIM, and token restrictions.

The deployment's reverse proxy determines whether Python Keystone or
Keystone-NG handles a request. See [Compatibility](../getting-started/compatibility.md).

## OpenAPI and Swagger UI

- [Swagger UI](../swagger-ui.html) provides the rendered API reference.
- [OpenAPI YAML](../openapi.yaml) is the generated specification.
- A running server exposes JSON at `/api-docs/openapi.json`, and Swagger UI at
  `/swagger-ui/` when built with the `swagger-ui` cargo feature (off by default).

The generated specification is authoritative for request fields, response
fields, and status codes.

## Common Resource Requests

The examples use an administrator token stored in `TOKEN`.

### Projects

```console
curl -X POST "${KEYSTONE_URL}/v3/projects" \
  -H "X-Auth-Token: ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{
    "project": {
      "name": "service",
      "domain_id": "default",
      "enabled": true,
      "is_domain": false
    }
  }'
```

A successful create returns `201 Created`. The remaining lifecycle operations
use `GET /v3/projects`, `GET`, `PATCH`, and `DELETE` on
`/v3/projects/{project_id}`.

#### Project hierarchy

`GET /v3/projects/{project_id}` accepts the python keystone compatible
`parents_as_list`, `parents_as_ids`, `subtree_as_list` and `subtree_as_ids`
query parameters. A parameter is enabled when present (with an empty value or
any value other than `false` or `0`). The `*_as_list` and `*_as_ids` variants
of the same relation are mutually exclusive (`400 Bad Request`).

```console
curl "${KEYSTONE_URL}/v3/projects/${PROJECT_ID}?parents_as_list&subtree_as_ids" \
  -H "X-Auth-Token: ${TOKEN}"
```

- `parents_as_list` / `subtree_as_list` add a `parents` / `subtree` list of
  `{"project": {...}}` entries. Parents are ordered from the closest to the
  root, descendants breadth first.
- `parents_as_ids` / `subtree_as_ids` add a nested object keyed by project IDs
  (`{"<id>": {"<id>": null}}`), with `null` for leaves.

Every related project is checked individually with the project `show` policy
and projects the caller is not allowed to see are omitted. In `subtree_as_ids`
the visible descendants of an omitted project are attached to its closest
visible ancestor.

### Users

```console
curl -X POST "${KEYSTONE_URL}/v3/users" \
  -H "X-Auth-Token: ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{
    "user": {
      "name": "service-user",
      "domain_id": "default",
      "enabled": true,
      "password": "<initial-password>"
    }
  }'
```

The response never returns the supplied password. Use `GET /v3/users` and the
`GET`, `PATCH`, and `DELETE` operations on `/v3/users/{user_id}` for the rest of
the lifecycle.

### Credentials

Credential `blob` is a JSON-encoded string, not a nested JSON object:

```console
curl -X POST "${KEYSTONE_URL}/v3/credentials" \
  -H "X-Auth-Token: ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{
    "credential": {
      "type": "totp",
      "blob": "{\"seed\":\"<base32-seed>\"}"
    }
  }'
```

Credential responses can contain decrypted secret material. Treat the complete
response as sensitive.
