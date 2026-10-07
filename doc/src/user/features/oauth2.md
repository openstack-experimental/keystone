# OAuth2 / OIDC Provider — User & Application Guide

Keystone can act as a standards-compliant **OAuth2 Authorization Server / OpenID
Connect Provider (OP)**. This means:

- Human users can log in through a browser (Authorization Code + PKCE, or the
  Device Authorization Grant for CLIs/headless machines) and get a short-lived,
  self-contained JWT instead of a Fernet token.
- Automated workloads (CI/CD pipelines, Kubernetes controllers, service
  accounts) can authenticate with `client_credentials` and call OpenStack APIs
  directly with the resulting JWT — no Fernet exchange needed.
- Third-party applications (Grafana, Harbor, internal portals) can use Keystone
  as a normal OIDC identity provider ("Login with OpenStack").

See [ADR 0026](../../adr/0026-oauth2-oidc-provider.md) for the full design. This
page covers the flows you actually call. If you're operating/deploying the
provider rather than consuming it, see the
[administrator guide](../../admin/features/oauth2.md).

All endpoints below are under `/v4/oauth2/{domain_id}/...` — the OP is
per-domain, so `domain_id` is always part of the path, and each domain has its
own issuer and signing keys.

## Discovery

```
GET /v4/oauth2/{domain_id}/.well-known/openid-configuration
GET /v4/oauth2/{domain_id}/jwks
```

Both are unauthenticated. Point any standard OIDC library at the discovery
document and it will find `authorization_endpoint`, `token_endpoint`,
`jwks_uri`, `revocation_endpoint`, `introspection_endpoint`,
`userinfo_endpoint`, supported grant types, and scopes.

## Scopes

- `openid`, `profile`, `email` — standard OIDC identity scopes.
- `openstack:api` — a distinct, explicit scope. Only when this is requested
  **and** granted does the returned `access_token` carry OpenStack authorization
  data (`openstack_context`: scope + effective roles) and an `aud` that
  OpenStack services will accept (`openstack-apis:{domain_id}`). Without it, you
  get a minimal identity token good only for calling Keystone's own
  [`/userinfo`](#userinfo-endpoint) — not usable against Nova/Neutron/etc.
- Omitting `scope` entirely defaults to the client's full `allowed_scopes` —
  **except** `openstack:api` is never implied by omission; you must request it
  explicitly every time.

## Machine-to-machine: `client_credentials`

For CI/CD, Kubernetes operators, Terraform controllers, and any workload holding
a registered client secret.

```
POST /v4/oauth2/{domain_id}/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=<id>&client_secret=<secret>&scope=openstack:api
```

Response:

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "openstack:api"
}
```

Use `access_token` directly as `Authorization: Bearer <token>` against any
OpenStack service running the native JWT middleware. No `id_token` is issued for
this grant.

## Human login: Authorization Code + PKCE

For browser-based apps and CLIs that can open a browser.

1. Redirect the user to:

   ```
   GET /v4/oauth2/{domain_id}/authorize
     ?response_type=code
     &client_id=<id>
     &redirect_uri=<your callback>
     &scope=openid profile openstack:api
     &state=<random>
     &code_challenge=<S256 PKCE challenge>
     &code_challenge_method=S256
   ```

   PKCE (`S256` only) is mandatory for public clients. Keystone serves its own
   login and consent pages.

2. On success, your `redirect_uri` receives `?code=...&state=...`. Exchange the
   code:

   ```
   POST /v4/oauth2/{domain_id}/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&code=<code>&redirect_uri=<same as above>
   &code_verifier=<PKCE verifier>&client_id=<id>[&client_secret=<secret>]
   ```

   Response includes `access_token`, `id_token`, `expires_in`, and (if the
   client is registered for `refresh_token`) a `refresh_token`.

3. Refresh when the access token expires:

   ```
   grant_type=refresh_token&refresh_token=<token>&client_id=<id>
   ```

   Refresh tokens rotate on every use (a new one is returned each time; the old
   one becomes invalid). **Do not reuse an old refresh token** — presenting an
   already-used one is treated as a possible theft and revokes the entire token
   family, forcing a fresh login.

   A refresh token family also has an **absolute lifetime** (default 90 days
   from the original login, `[oauth2] refresh_token_absolute_lifetime_days`).
   Rotating never extends it: once reached, the refresh fails with
   `invalid_grant` and the user must log in again. On every refresh the server
   re-checks that the user still exists, is enabled and that the domain is
   enabled; otherwise the whole family is revoked and `invalid_grant` is
   returned. The `expires_in` of the response is the plain access-token
   lifetime. Once roles are embedded in access tokens, a refreshed token carries
   the roles resolved at rotation time.

## CLI / headless login: Device Authorization Grant (RFC 8628)

For `openstack`/`osc` CLI and other headless clients, the same flow every major
cloud CLI (`aws sso`, `gcloud`, `az`) uses.

1. Start the flow:

   ```
   POST /v4/oauth2/{domain_id}/device_authorization
   Content-Type: application/x-www-form-urlencoded

   client_id=<id>&scope=openid profile openstack:api
   ```

   Response:

   ```json
   {
     "device_code": "...",
     "user_code": "WDJB-MJHT",
     "verification_uri": "https://keystone.example.com/v4/oauth2/<domain_id>/device",
     "verification_uri_complete": "https://keystone.example.com/v4/oauth2/<domain_id>/device?user_code=WDJB-MJHT",
     "expires_in": 600,
     "interval": 5
   }
   ```

2. Show the user `verification_uri_complete` (or `verification_uri` +
   `user_code`) and have them approve it in a browser.

3. Poll for the token:

   ```
   grant_type=urn:ietf:params:oauth:grant-type:device_code
   &device_code=<device_code>&client_id=<id>
   ```

   Poll no faster than `interval` seconds — polling too fast returns `slow_down`
   per RFC 8628 §3.5, which means "back off further," not a hard failure.
   `user_code` uses an unambiguous character set (`[A-Z0-9]` minus `O/0/I/l/1`)
   so it's easy to type by hand.

## Token types you'll see

- **`id_token`** — identity only, `aud` is your `client_id`. Never carries roles
  or OpenStack scope; only your client's configured `claims_template` output is
  added.
- **`access_token` (`openstack:api` granted, or any `client_credentials`
  grant)** — carries `openstack_context` (scope + effective roles at issuance
  time) and `aud: "openstack-apis:{domain_id}"`. This is what OpenStack services
  accept.
- **`access_token` (`openstack:api` not granted)** — minimal, `aud` is your own
  `client_id`, not usable against any OpenStack service. Good only for
  `/userinfo` (and for revocation).

Access and ID tokens are short-lived (15 minutes by default) and **stateless
bearer tokens**. You can end a session early with the revocation endpoint below
(refresh tokens always; access tokens individually); otherwise wait out `exp`
(or an operator triggers emergency signing-key rotation, which is out of your
hands as a client). Treat them like any other bearer credential: don't log them,
don't put them in URLs.

## UserInfo endpoint

`GET` or `POST /v4/oauth2/{domain_id}/userinfo` (OIDC Core §5.3), advertised as
`userinfo_endpoint` in the discovery document. Authenticate with the OIDC
`access_token` as an RFC 6750 bearer credential:

```console
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://keystone.example.com/v4/oauth2/$DOMAIN_ID/userinfo
```

The token must carry the `openid` scope, be unexpired and not revoked, and its
user and client must still exist and be enabled. The response is plain JSON
(`userinfo_signing_alg_values_supported` is `["none"]`) with
`Cache-Control: no-store`:

- `sub` — always.
- `name`, `preferred_username`, `updated_at` — with the `profile` scope.
- `email`, `email_verified` — with the `email` scope, and only when the user has
  an email address. Keystone does not verify addresses, so `email_verified` is
  `false` unless the user record explicitly says otherwise.
- Your client's `claims_template` output, identical to the `id_token`.

Failures follow RFC 6750 §3: `401` with `WWW-Authenticate: Bearer` (no token) or
`Bearer error="invalid_token"` (bad, expired, revoked or foreign token, disabled
user or client), and `403` with `error="insufficient_scope"` when the token
lacks `openid`. Access tokens issued with `openstack:api` (or by
`client_credentials`) are not accepted here. The endpoint is rate limited per
source IP.

## Revoking tokens (RFC 7009)

```
POST /v4/oauth2/{domain_id}/revoke
Content-Type: application/x-www-form-urlencoded

token=<refresh or access token>&token_type_hint=refresh_token
```

Authenticate the client exactly as for `/token` (HTTP Basic, or `client_id` /
`client_secret` in the body). `token_type_hint` (`refresh_token` or
`access_token`) is optional and only affects lookup order.

- **Refresh token** — the whole refresh family (the token and everything rotated
  from it) is revoked; any later `refresh_token` grant fails with
  `invalid_grant`.
- **Access token** — its `jti` is added to the domain's JTI revocation list
  (`/jwks/revocation`) until the token's own `exp`. Services that enforce the
  list (see the admin guide) reject it from then on, within the list's cache TTL
  (60s). If the token carries a `sid` claim (the id of the refresh family that
  minted it), that refresh family is revoked too, ending the session. ID tokens
  carry no `jti` and are ignored.

The endpoint always answers `200` with an empty body for an authenticated,
well-formed request — including unknown, expired, already-revoked tokens and
tokens that belong to another client — so it never reveals whether a token
exists. A token is only revoked if it belongs to the authenticated client. Bad
client credentials return `401 invalid_client`, a missing `token` returns
`400 invalid_request`, and the endpoint is rate limited like `/token`.

Limitation: revocation is one-directional. Revoking an access token also ends
its refresh family (via `sid`), but revoking a refresh token does **not** revoke
access tokens already issued from it; they expire on their own (or revoke them
individually). Access tokens from `client_credentials` / token-exchange have no
refresh family and no `sid`.

## Token introspection (RFC 7662)

```
POST /v4/oauth2/{domain_id}/introspect
Content-Type: application/x-www-form-urlencoded

token=<refresh or access token>&token_type_hint=access_token
```

Advertised as `introspection_endpoint` in the discovery document. Use it when a
service cannot accept the stateless revocation window of access tokens: unlike
offline verification it sees the domain's JTI revocation list and the
refresh-token store as they are _now_.

Only an authenticated **confidential** client of the same domain may call it.
Authenticate exactly as for `/token` (HTTP Basic, or `client_id` /
`client_secret` in the body); public clients get `401 invalid_client`.
`token_type_hint` (`refresh_token` or `access_token`) is optional and only
affects lookup order.

The answer is always `200` with a JSON body and `Cache-Control: no-store`. A
token that is unknown, malformed, expired, revoked, already used (refresh) or
issued for another domain yields exactly `{"active": false}`; the response never
says why. For an active token `active` is `true` and the body carries:

- `scope`, `client_id`, `sub`, `exp`, `iat`, `token_use`. For a refresh token
  `exp` is bounded by the refresh family's lifetime cap.
- Access tokens additionally: `token_type` (`Bearer`), `nbf`, `aud`, `iss`,
  `jti`. OpenStack access tokens (`openstack:api`, `client_credentials`) also
  include `openstack_context` and `delegation_context`, the scope and effective
  roles the token will act with.

A missing `token` returns `400 invalid_request`, bad client credentials return
`401 invalid_client`, and the endpoint is rate limited per source IP and per
client.

## Errors

Token endpoint errors follow RFC 6749 §5.2:

```json
{ "error": "invalid_grant", "error_description": "..." }
```

Common ones: `invalid_client` (bad `client_id`/secret), `invalid_grant`
(expired/used code, revoked refresh token, wrong PKCE verifier), `invalid_scope`
(requested a scope outside `allowed_scopes` — the server never silently narrows
a request), `slow_down` / `authorization_pending` (device flow polling).
