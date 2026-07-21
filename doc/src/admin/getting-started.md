# Getting Started as an Administrator

Install Keystone-NG and configure its database, OPA service, and interfaces
before bootstrapping identity resources. See [Installation](../install/index.md)
and [Configuration](configuration.md).

## Bootstrap

Bootstrap requires `[interface_admin]` and creates or updates the default
domain, admin project, admin user, standard roles, implied-role hierarchy, and
system/project admin assignments. Catalog endpoints are added when their URL
options are supplied.

```console
OS_BOOTSTRAP_PASSWORD='<password>' \
  keystone-manage --config /etc/keystone/keystone.conf bootstrap
```

The username and project default to `admin`. Use
`keystone-manage bootstrap --help` for the current username, project, region,
and endpoint options.

After bootstrap, authenticate through `POST /v3/auth/tokens` as described in
the [user authentication guide](../user/authentication/index.md) and check
`/health` and `/ready` on the metrics listener.
