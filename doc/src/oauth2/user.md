# OAuth2 / OIDC Provider — User & Application Guide

Keystone can act as a standards-compliant **OAuth2 Authorization Server /
OpenID Connect Provider (OP)**. This means:

- Human users can log in through a browser (Authorization Code + PKCE, or
  the Device Authorization Grant for CLIs/headless machines) and get a
  short-lived, self-contained JWT instead of a Fernet token.
- Automated workloads (CI/CD pipelines, Kubernetes controllers, service
  accounts) can authenticate with `client_credentials` and call OpenStack
  APIs directly with the resulting JWT — no Fernet exchange needed.
- Third-party applications (Grafana, Harbor, internal portals) can use
  Keystone as a normal OIDC identity provider ("Login with OpenStack").

See [ADR 0026](../adr/0026-oauth2-oidc-provider.md) for the full design.
This page covers the flows you actually call. If you're
operating/deploying the provider rather than consuming it, see the
[administrator guide](admin.md).

All endpoints below are under `/v4/oauth2/{domain_id}/...` — the OP is
per-domain, so `domain_id` is always part of the path, and each domain has
its own issuer and signing keys.

## Discovery

```
GET /v4/oauth2/{domain_id}/.well-known/openid-configuration
GET /v4/oauth2/{domain_id}/jwks
```

Both are unauthenticated. Point any standard OIDC library at the discovery
document and it will find `authorization_endpoint`, `token_endpoint`,
`jwks_uri`, supported grant types, and scopes.

## Scopes

- `openid`, `profile`, `email` — standard OIDC identity scopes.
- `openstack:api` — a distinct, explicit scope. Only when this is
  requested **and** granted does the returned `access_token` carry
  OpenStack authorization data (`openstack_context`: scope + effective
  roles) and an `aud` that OpenStack services will accept
  (`openstack-apis:{domain_id}`). Without it, you get a minimal identity
  token good only for calling Keystone's own `/userinfo` — not usable
  against Nova/Neutron/etc.
- Omitting `scope` entirely defaults to the client's full
  `allowed_scopes` — **except** `openstack:api` is never implied by
  omission; you must request it explicitly every time.

## Machine-to-machine: `client_credentials`

For CI/CD, Kubernetes operators, Terraform controllers, and any workload
holding a registered client secret.

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
OpenStack service running the native JWT middleware. No `id_token` is
issued for this grant.

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

   PKCE (`S256` only) is mandatory for public clients. Keystone serves its
   own login and consent pages.

2. On success, your `redirect_uri` receives `?code=...&state=...`. Exchange
   the code:

   ```
   POST /v4/oauth2/{domain_id}/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&code=<code>&redirect_uri=<same as above>
   &code_verifier=<PKCE verifier>&client_id=<id>[&client_secret=<secret>]
   ```

   Response includes `access_token`, `id_token`, `expires_in`, and
   (if the client is registered for `refresh_token`) a `refresh_token`.

3. Refresh when the access token expires:

   ```
   grant_type=refresh_token&refresh_token=<token>&client_id=<id>
   ```

   Refresh tokens rotate on every use (a new one is returned each time;
   the old one becomes invalid). **Do not reuse an old refresh token** —
   presenting an already-used one is treated as a possible theft and
   revokes the entire token family, forcing a fresh login.

## CLI / headless login: Device Authorization Grant (RFC 8628)

For `openstack`/`osc` CLI and other headless clients, the same flow every
major cloud CLI (`aws sso`, `gcloud`, `az`) uses.

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

   Poll no faster than `interval` seconds — polling too fast returns
   `slow_down` per RFC 8628 §3.5, which means "back off further," not a
   hard failure. `user_code` uses an unambiguous character set
   (`[A-Z0-9]` minus `O/0/I/l/1`) so it's easy to type by hand.

## Token types you'll see

- **`id_token`** — identity only, `aud` is your `client_id`. Never carries
  roles or OpenStack scope; only your client's configured
  `claims_template` output is added.
- **`access_token` (`openstack:api` granted, or any `client_credentials`
  grant)** — carries `openstack_context` (scope + effective roles at
  issuance time) and `aud: "openstack-apis:{domain_id}"`. This is what
  OpenStack services accept.
- **`access_token` (`openstack:api` not granted)** — minimal, `aud` is
  your own `client_id`, not usable against any OpenStack service. Good
  only for `/userinfo`.

Access and ID tokens are short-lived (15 minutes by default) and
**stateless bearer tokens** — there's no server-side revocation for them
short of waiting out `exp` (or an operator triggering emergency signing-key
rotation, which is out of your hands as a client). Treat them like any
other bearer credential: don't log them, don't put them in URLs.

## Errors

Token endpoint errors follow RFC 6749 §5.2:

```json
{ "error": "invalid_grant", "error_description": "..." }
```

Common ones: `invalid_client` (bad `client_id`/secret), `invalid_grant`
(expired/used code, revoked refresh token, wrong PKCE verifier),
`invalid_scope` (requested a scope outside `allowed_scopes` — the server
never silently narrows a request), `slow_down` /
`authorization_pending` (device flow polling).
