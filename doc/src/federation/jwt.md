# Authenticating with the JWT

It is possible to authenticate with the JWT token issued by the federated IdP.
More precisely it is possible to exchange a valid JWT for the Keystone token.
There are few different use scenarios that are covered.

Since the JWT was issued without any knowledge of the Keystone scopes it becomes
hard to control scope. In the case of real human login the Keystone may issue
unscoped token allowing user to further rescope it. In the case of the workflow
federation that introduces a potential security vulnerability. As such in this
scenario the attribute mapping is responsible to fix the scope.

Login request looks following:

```console

  curl https://keystone/v4/federation/identity_providers/${IDP}/jwt -X POST -H "Authorization: bearer ${JWT}" -H "openstack-mapping: ${MAPPING_NAME}"
```

## Regular user obtains JWT (ID token) at the IdP and presents it to Keystone

In this scenario a real user (human) is obtaining the valid JWT from the IDP
using any available method without any communication with Keystone. This may use
authorization code grant, password grant, device grant or any other enabled
method. This JWT is then presented to the Keystone and an explicitly requested
attribute mapping converts the JWT claims to the Keystone internal
representation after verifying the JWT signature, expiration and further
restricted bound claims.

## Workload federation

Automated workflows (Zuul job, GitHub workflows, GitLab CI, etc) are typical
workloads not being bound to any specific user and are more regularly considered
being triggered by certain services. Such workflows are usually in possession of
a JWT token issued by the service owned IdP. Keystone allows exchange of such
tokens to the regular Keystone token after validating token issuer signature,
expiration and applying the configured attribute mapping. Since in such case
there is no real human the mapping also need to be configured slightly
different.

- It is strongly advised the attribute mapping must fill `token_user_id`,
  `token_project_id` (and soon `token_role_ids`). This allows strong control of
  which technical account (soon a concept of service accounts will be introduced
  in Keystone) is being used and which project such request can access.

- Attribute mapping should use `bound_audiences`, `bound_claims`,
  `bound_subject`, etc to control the tokens issued by which workflows are
  allowed to access OpenStack resources.

### GitHub workflow federation

In order for the GitHub workflow to be able to access OpenStack resources it is
necessary to register GitHub as a federated IdP and establish a corresponding
attribute mapping of the `jwt` type.

IdP:

```json
"identity_provider": {
    "name": "github",
    "bound_issuer": "https://token.actions.githubusercontent.com",
    "jwks_url": "https://token.actions.githubusercontent.com/.well-known/jwks"
}
```

Mapping:

```json
"mapping": {
   "type": "jwt",
   "name": "gtema_keystone_main",
   "idp_id": <IDP_ID>,
   "domain_id": <DOMAIN_ID>,
   "bound_audiences": ["https://github.com"],
   "bound_subject": "repo:gtema/keystone:pull_request",
   "bound_claims": {
       "base_ref": "main"
   },
   "user_id_claim": "actor_id",
   "user_name_claim": "actor",
   "token_user_id": <UID>
}
```

TODO: add more claims according to
[docs](https://docs.github.com/en/actions/reference/security/oidc#oidc-token-claims)

A way for the workflow to obtain the JWT
[is described here](https://docs.github.com/en/actions/reference/security/oidc#methods-for-requesting-the-oidc-token).

Keystone ships a reusable composite action, [`login_jwt`](https://github.com/openstack-experimental/keystone/tree/main/.github/actions/login_jwt),
that performs the whole exchange: it requests the GitHub OIDC token and swaps it
for a Keystone token via the JWT login endpoint, masking the secrets and exposing
the result as the `token` output. The calling job only needs to grant the
`id-token: write` permission.

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  example:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - name: Login to Keystone with JWT
        id: keystone_login
        uses: openstack-experimental/keystone/.github/actions/login_jwt@main
        with:
          keystone_url: https://keystone.example.com
          idp_id: <IDP_ID>
          mapping: gtema_keystone_main
          # audience defaults to https://github.com and must match the
          # mapping `bound_audiences` configured in Keystone.

      - name: Use the Keystone token
        env:
          OS_TOKEN: ${{ steps.keystone_login.outputs.token }}
        run: |
          curl -H "X-Auth-Token: ${OS_TOKEN}" \
            https://keystone.example.com/v3/auth/tokens
```

If you already hold a JWT (for example one issued by a non-GitHub IdP), pass it
via the `jwt` input and the OIDC request step is skipped:

```yaml
      - name: Login to Keystone with JWT
        uses: openstack-experimental/keystone/.github/actions/login_jwt@main
        with:
          keystone_url: https://keystone.example.com
          idp_id: <IDP_ID>
          mapping: gtema_keystone_main
          jwt: ${{ steps.some_previous_step.outputs.jwt }}
```
