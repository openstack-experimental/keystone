# Using Dex as the Identity provider

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
etc). For the sake of example a static user base and a static client is going to be
used.

1. Prepare the Dex configuration

```yaml
{{#include ../../../tools/dex.config.yaml}}
```

With this configuration Dex server can be started

```console

  dex server
```

2. Registering the IdP on Keystone.

An `osc` is going to be used to register the IdP.

```console

  osc identity4 federation identity-provider create --bound-issuer <DEX_ISSUER> --oidc-client-id <CLIENT_ID> --oidc-client-secret <CLIENT_SECRET> --oidc-discovery-url <DEX_DISCOVERY_URL> --default-mapping-name dex --domain-id <DOMAIN_ID> --name dex
```

The `default-mapping-name` parameter allows the specified mapping to be applied
automatically during the login unless user explicitly specifies the mapping.
Mapping names are unique within the identity provider they are created under.
Then mapping does not exist yet and is going to be created in the next step.
This is an optional parameter and it can be set or unset later.

3. Registering the mapping.

Now it is necessary to create the attribute mapping that converts OIDC protocol
claims into the corresponding user attributes and perform additional
verification (i.e. requiring certain `bound_claims` to be present).

```console

  osc identity4 federation mapping create --user-id-claim sub --idp-id <IDP_ID> --user-name-claim username --name dex --oidc-scopes openid,profile --domain-id <DOMAIN_ID>
```

- `idp-id` is the identity provider is created in the previous step.

- `user-id-claim` represents the claim name which should be used for the remote
  idp user identifier. This is not the resulting `user_id` in Keystone, but a
  `unique_id` property.

- `user-name-claim` represents the claim name with the user name.

- Many more additional attributes can be passed to further tighten the mapping
  process.

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
