# Federation

Federation exchanges an identity established by an external provider for a
Keystone token. Mapping rules resolve external claims into a Keystone principal,
scope, roles, and groups.

- [Authorization Code flow](oidc.md) covers browser-assisted OIDC login.
- [JWT authentication](jwt.md) covers exchanging an existing provider JWT.

Provider registration, allowed redirect URIs, mapping rules, and vendor setup
belong to the [federation administrator guide](../../../admin/features/federation/index.md).
