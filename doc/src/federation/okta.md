# Using Okta as the Identity provider

While it is possible to use Okta as the shared Identity Provider in OpenStack it
only makes sense for private cloud installations. For the public cloud this is
unlikely to be suitable, therefore it is described how to use Okta as the
private (domain bound) identity provider. It is possible to have as many
connections to Okta for different domains as necessary.

## Configuration

Okta/Auth0 as an managed Identity provider can be easily integrated as a source
of the users and groups for the customer dedicated domain.
[A dedicated application](https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/#set-up-your-app)
need to be established on Okta (i.e. OpenStack) for the authentication
delegation. There are many configuration options that can be used on the Okta
side and will influence the interaction. It is not possible to describe every
single one precisely, therefore only the basic setting are described here:

- grant type: authorization code
- sign in redirect uris (enable the cli login):
  [`http://localhost:8050/oidc/callback`].

Group memberships are not exposed by default and require
[additional changes](https://developer.okta.com/docs/guides/customize-tokens-groups-claim/main/#add-a-groups-claim-for-a-custom-authorization-server)

On the Keystone side the following must be implemented:

- register an identity provider with the data obtained from Okta app
  configuration:

```console
  osc identity4 federation identity-provider create --bound-issuer <OKTA_ISSUER> --oidc-client-id <CLIENT_ID> --oidc-client-secret <CLIENT_SECRET> --oidc-discovery-url <OKTA_DISCOVERY_URL> --default-mapping-name okta --domain-id <DOMAIN_ID> --name okta
```

The `--default-mapping-name` references a mapping ruleset managed at
`/v4/mappings/rulesets`. The ruleset must match the IDP source
(`IdentitySource::Federation`) and be named accordingly.

- create mapping ruleset

A mapping ruleset must be created via `/v4/mappings/rulesets` that defines how
Okta OIDC claims are mapped to Keystone identities:

```json
{
  "mapping": {
    "mapping_id": "okta",
    "domain_id": "<DOMAIN_ID>",
    "source": { "type": "federation", "idp_id": "<IDP_ID>" },
    "domain_resolution_mode": "fixed",
    "enabled": true,
    "rules": [{
      "name": "okta",
      "match": { "all_of": [] },
      "identity": {
        "identity_mode": "local",
        "user_name": "${claims.preferred_username}"
      }
    }]
  }
}
```

Afterwards `osc` can be used by users to authenticate.

clouds.yaml

```yaml
clouds:
  devstack-oidc-okta:
    auth_type: v4federation
    auth:
      auth_url: <KEYSTONE_URL>
      identity_provider: <IDP_ID>
```

```console
$ osc --os-cloud devstack-oidc-okta auth show
A default browser is going to be opened at `https://<CENSORED>.okta.com/oauth2/default/v1/authorize?response_type=code&client_id=<CENSORED>&state=<CENSORED>&code_challenge=<CENSORED>&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A8050%2Foidc%2Fcallback&scope=openid+profile+openid&nonce=<CENSORED>`. Do you want to continue? [y/n]
```
