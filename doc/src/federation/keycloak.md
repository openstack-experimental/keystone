# Federating Keystone with Keycloak

Kestone enables federating users from the Keycloak to OpenStack. This
integration is considered a primary citizen and is enforced using the
integration tests.

## Connection methods

It is possible to user Keycloak as the shared/global Identity Provider or to
bind it for the single Keystone domain to be used as the private IdP.

### Using Keycloak as a global IdP

When connecting the Keycloak as the Idp that can be used by all Keystone domains
an IdP is registered without specifying the `domain_id`. It is important to
remember also that in this case a single Keycloak realm can be registered at a
time and Keystone is not itself supporting multirealms configuration. It is,
however, possible to register every single Keycloak realm as a technically
independent IdP, what they in reality are.

Further it is necessary to establish rules into which Keystone domains Keycloak
users are going to be placed. It can be accomplished with two different ways:

- domain bound mappings.
- using the `domain_id` in the OIDC claim.

When using the domain bound mapping such mapping specifies the `domain_id`
property and every user is explicitly selecting the desired mapping. Logically
this introduce possibility for users to easily roam between different domains
without control. They only get the permissions explicitly granted them on the
concrete scope, so they will not get elevated privileges. But users are still
going to be created in the different domains. This may be acceptable for the
private cloud use case or when anyway only a single domain is existing. It
should not, however, be used for the public cloud use case.

A far more flexible alternative is to rely on the `domain_id` claim populated
into the user ID token issued by the IdP. This way the IdP controls the user
domain relations and can apply whichever logic is internally desired. The only
requirement for this method is that the `domain_id` claim must be present in the
token. It can be achieved, for example, by creating a client scope that
re-exposes the `domain_id` user attribute as the token claim. On the Keycloak
side users can be structured into groups where each group stands for the
Keystone domain and the `domain_id` attribute is being set on the group level.
Every user automatically inherits all group attributes in Keycloak.

### Keycloak as a private IdP

In a very similar way to connecting Keycloak as a shared IdP making it bound to
the concrete Keystone domain can be chosen (i.e. in a public cloud a certain
customer has already Keycloak instance on premises and is willing to use it to
consume cloud resources). The only difference to the previous scenario is that
both IdP and mapping in Keystone explicitly specify the `domain_id` property of
the domain they should be bound to.

## Configuration

A first step to connect Keycloak as an IdP in Keystone is in the preparation of
the OIDC client. Since the Kecloak volatile and changes the UI concepts quite
often no screenshots are going to be present in this guide. Instead just a
description is given. Functional tests in the project are performing all this
steps using the API and can be used as a reference for uncertainty.

1. A OIDC type client should be created.

- `redirect_uris` specifies list of clients (i.e. user cli/tui, dashboards, etc)
  that would require to provide a callback listener to interact with the IDP as
  a relying party capturing the authorization code. To allow users to use rust
  cli (`osc`) an url `http://localhost:8050/*`) must be added.

- client authorization should be enabled for the client for the better security.
  The `client_secret` is only going to be known by the Keystone itself and is
  not required to be known by the end users of the cloud.

- When using Keycloak in the shared mode it is most likely necessary to add
  `domain_id` claim into the token. For this a protocol mapper should be added
  (or the existing one extended) adding a claim into the access token, id token
  and userinfo token. The claim name is not relevant and is going to be used on
  the Keystone side. It is described in the previous chapter how the
  corresponding attribute can be assigned to the user (directly or through the
  group membership).

2. Registering the IdP on Keystone.

An `osc` is going to be used to register the IdP.

```console

  osc identity4 federation identity-provider create --bound-issuer <KEYCLOAK_ISSUER> --oidc-client-id <CLIENT_ID> --oidc-client-secret <CLIENT_SECRET> --oidc-discovery-url <KEYCLOAK_DISCOVERY_URL> --default-mapping-name keycloak --domain-id <DOMAIN_ID> --name keycloak
```

The `default-mapping-name` references a mapping ruleset managed at
`/v4/mappings/rulesets`. The ruleset must match the IDP source
(`IdentitySource::Federation`) and be named accordingly.

3. Creating the mapping ruleset.

Now it is necessary to create a mapping ruleset that converts OIDC protocol
claims into the corresponding Keystone user attributes via the
`/v4/mappings/rulesets` API:

```json
{
  "mapping": {
    "mapping_id": "keycloak",
    "domain_id": "<DOMAIN_ID>",
    "source": { "type": "federation", "idp_id": "<IDP_ID>" },
    "domain_resolution_mode": "fixed",
    "enabled": true,
    "rules": [{
      "name": "keycloak",
      "match": { "all_of": [] },
      "identity": {
        "identity_mode": "local",
        "user_name": "${claims.preferred_username}"
      }
    }]
  }
}
```

- `source.type` = `federation` binds this ruleset to the identity provider.
- `user_name` template interpolates the OIDC claim into the Keystone user name.
- `identity_mode: local` creates/finds the user and syncs groups on every login.

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

The same in the API would map to the following steps:

- POST call to https://KEYSTONE_API_URL/v4/federation/auth to get the IdP URL.

- waiting for the IdP callback at the given redirect_uri with the authorization
  code.

- POST to https://KEYSTONE_API_URL/v4/federation/oidc/callback to finish the
  authentication exchanging the authorization code for the Keystone API token.
