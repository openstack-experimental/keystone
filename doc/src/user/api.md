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
- A running server exposes Swagger UI at `/swagger-ui/` and JSON at
  `/api-docs/openapi.json`.

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
