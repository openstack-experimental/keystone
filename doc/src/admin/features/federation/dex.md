# Using Dex as the Identity Provider

Dex is an identity service that uses OpenID Connect to drive authentication for
other apps. Dex acts as a portal to other identity providers through
“connectors.” This lets Dex defer authentication to LDAP servers, SAML
providers, or established identity providers like GitHub, Google, and Active
Directory. At the same time Dex is not an Identity Provider in the classical
sense since it does not itself stores user identity data. Instead it serves more
like an OpenIDConnect proxy.

Since Dex is not responsible for the ideneity data it also not the right place
for the advanced claims that would be necessary to address all possible
scenarios of the Keystone integration. It should be considered therefore as
mostly suitable for the private IdP mode only or being the only existing IdP.

## Configuration

Dex is designed to be deployed in front of a real IdP (Keycloak, GitHub, Google,
etc). For the sake of example a static user base and a static client is going to
be used.

1. Prepare the Dex configuration

```yaml
{{#include ../../../../../tools/dex.config.yaml}}
```

With this configuration Dex server can be started

```console

  dex server
```

2. Registering the IdP on Keystone.

An `osc` is going to be used to register the IdP.

```console

  osc identity4 federation identity-provider create --oidc-client-id <CLIENT_ID> --oidc-client-secret <CLIENT_SECRET> --oidc-discovery-url <DEX_DISCOVERY_URL> --default-mapping-name dex --domain-id <DOMAIN_ID> --name dex
```

The `--default-mapping-name` parameter must reference a mapping ruleset name
that is created in the next step.

3. Registering the mapping ruleset.

A mapping ruleset must be created via `/v4/mappings/rulesets` that defines how
Dex OIDC claims are mapped to Keystone identities. The `mapping_id` or
`--default-mapping-name` from the IDP is used by the engine to resolve the
correct ruleset and rule at callback time.

```json
{
  "mapping": {
    "mapping_id": "dex",
    "domain_id": "<DOMAIN_ID>",
    "source": { "type": "federation", "idp_id": "<IDP_ID>" },
    "domain_resolution_mode": "fixed",
    "enabled": true,
    "rules": [
      {
        "name": "dex",
        "match": { "all_of": [] },
        "identity": {
          "identity_mode": "local",
          "user_name": "${claims.email}",
          "user_id": "${claims.sub}"
        },
        "authorizations": [],
        "groups": []
      }
    ]
  }
}
```

- `source` identifies the identity provider.
- `match` defines the conditions for rule evaluation (empty array matches all).
- `identity_mode: "local"` performs user CRUD and group sync on every login.
- `user_name` and `user_id` are templates that interpolate OIDC claims.

4. API Login process

The `osc` supports natively the federated authentication.

```yaml
clouds:
  devstack-oidc-kc-shared:
    auth_type: v4federation
    auth:
      auth_url: https://<KEYSTONE_API_URL>
      identity_provider: <IDENTITY_PROVIDER_ID>
      attribute_mapping_name: <OPTIONAL_MAPPING_NAME>
      project_name: <OPTIONAL_TARGET_PROJECT_NAME>
      project_domain_name: <OPTIONAL_TARGET_PROJECT_DOMAIN_NAME>
```

With the `clouds.yaml` configuration entry as above `osc` will prompt user to
open a browser with the specially prepared url. It then starts the callback
handler webserver to receive the OIDC authorization code from the direct IdP
interaction. In the next step it exchanges the code for the Keystone session
token.
