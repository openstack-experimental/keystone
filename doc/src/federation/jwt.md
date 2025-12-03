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

```yaml
...
permissions:
  token: write
  contents: read

job:
  ...
  - name: Get GitHub JWT token
    id: get_token
    run: |
      TOKEN_JSON=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://github.com")

      TOKEN=$(echo $TOKEN_JSON | jq -r .value)
      echo "token=$TOKEN" >> $GITHUB_OUTPUT
  ...
  # TODO: build a proper command for capturing the actual token and/or write a dedicated action for that.
  - name: Exchange GitHub JWT for Keystone token
    run: |
      KEYSTONE_TOKEN=$(curl -H "Authorization: bearer ${{ steps.get_token.outputs.token }}" -H "openstack-mapping: gtmema_keystone_main" https://keystone_url/v4/federation/identity_providers/IDP/jwt)

```
