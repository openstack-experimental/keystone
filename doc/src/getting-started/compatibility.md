# Compatibility

Keystone-NG augments Python Keystone rather than requiring an immediate full
replacement. Deployments can route selected requests to either service while
both implementations use compatible identity data and token formats.

## API Compatibility

- The v3 API implements an expanding subset of the OpenStack Identity API.
- The v4 API contains Keystone-NG capabilities that are not provided by Python
  Keystone.
- The generated [OpenAPI document](../openapi.yaml) is the source of truth for
  routes and schemas implemented by the current build.

Do not assume that an API described by Python Keystone exists in Keystone-NG.
Check the generated specification or the [user API guide](../user/api.md).

## Parallel Deployment

Python and Rust Keystone can use the same deployment while a reverse proxy
routes requests according to path ownership. Each implementation manages its
own schema additions; database changes must not interfere with the other
service. See [Installation](../install/index.md#parallel-installation-with-the-python-keystone)
for the deployment model.

Fernet interoperability requires every node to use the same key repository.
See the [administrator Fernet guide](../admin/tokens/fernet.md).
