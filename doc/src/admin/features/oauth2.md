# OAuth2 / OIDC Provider — Administrator Guide

This page covers day-to-day operation of the native OAuth2 Authorization Server
/ OpenID Connect Provider (OP): configuration, client registration, key rotation
(including emergency rotation), and the downstream middleware that lets
Nova/Neutron/etc. accept OP-issued JWTs directly. See
[ADR 0026](../../adr/0026-oauth2-oidc-provider.md) for the full design rationale
and threat model; this page is the operational surface on top of it.

For end-user/application-developer facing flows (login, token requests, device
code), see the [OAuth2 / OIDC user guide](../../user/features/oauth2.md).

## Enabling the provider

The provider **requires Raft storage**: the client, session and signing-key
stores only exist in `[distributed_storage]`. Configure that first.

- `[oauth2] enabled` unset (default): the provider is on exactly when
  `[distributed_storage]` is configured and off otherwise.
- `enabled = false`: `/v4/oauth2` is not mounted (404, absent from the OpenAPI
  document), the OAuth2 janitors do not run and no signing key is provisioned
  for new domains.
- `enabled = true` without `[distributed_storage]` is a startup error.
- `enabled_domains = ["<domain_id>", ...]` restricts the provider to the listed
  domains; any other domain answers 404. An empty list serves no domain. Use it
  to pilot the provider on one domain of a multi-tenant deployment.
- Both settings are read at startup to decide which routes and janitors exist:
  changing `enabled` requires a restart.

If the Raft store cannot be reached while the provider is enabled, `/token`
answers `503 temporarily_unavailable` (RFC 6749 §5.2) with a `Retry-After`
header instead of a 500.

## Concepts

- Every domain owns its own **independent signing keypair** — there is no
  cluster-wide key. Issuer, JWKS, and discovery are all per-domain:
  `GET /v4/oauth2/{domain_id}/jwks`,
  `GET /v4/oauth2/{domain_id}/.well-known/openid-configuration`.
- A domain created through `POST /v3/domains` gets its signing key automatically
  (provisioned by `Oauth2KeyHook` on the domain-create event). A domain
  provisioned any other way — most notably the `default` domain, which is seeded
  directly into the database at bootstrap and never fires that hook — has **no**
  signing key and `/jwks`/`/token`/discovery will fail for it until you
  provision one (see `ensure-signing-key` below).
- Tokens are stateless JWTs (`id_token`, `access_token`) signed ES256 by default
  (`RS256` configurable). Refresh tokens are the one stateful piece — rotating,
  family-tracked, stored in Raft + FjallDB.
- `OAuth2Client` registrations (relying parties / machine identities) are a
  fourth ADR 0020 provider resource, domain-owned, managed via the
  `/v4/oauth2/{domain_id}/clients` CRUD API below.

## Configuration (`[oauth2]` in `keystone.conf`)

| Option                                  | Default | Purpose                                                                                                                                          |
| --------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `enabled`                               | unset   | Serve the provider. Unset: on when `[distributed_storage]` is configured. `true` without it is a startup error.                                 |
| `enabled_domains`                       | unset   | Allowlist of domain ids served by the provider; other domains answer 404. Unset serves every domain.                                              |
| `signing_algorithm`                     | `ES256` | `ES256` or `RS256`. Governs both outbound signing and inbound verification — must match across a deployment.                                     |
| `signing_key_rotation_days`             | 90      | Automatic rotation cadence. Manual rotation via `keystone-manage oauth2 rotate-signing-key` is always available regardless of this value.        |
| `argon2_memory_kib`                     | 65536   | Argon2id memory cost for confidential-client secret hashing.                                                                                     |
| `argon2_time_cost`                      | 3       | Argon2id iterations.                                                                                                                             |
| `argon2_parallelism`                    | 4       | Argon2id lanes.                                                                                                                                  |
| `access_token_lifetime_minutes`         | 15      | `access_token` TTL.                                                                                                                              |
| `id_token_lifetime_minutes`             | 15      | `id_token` TTL.                                                                                                                                  |
| `authorization_code_lifetime_seconds`   | 60      | Single-use authorization code TTL.                                                                                                               |
| `refresh_token_lifetime_days`           | 30      | Idle lifetime of a refresh token family; reset on each rotation (never beyond the absolute lifetime).                                            |
| `refresh_token_absolute_lifetime_days`  | 90      | Absolute lifetime of a refresh token family from root issuance; rotation never extends it.                                                       |
| `refresh_token_reuse_grace_minutes`     | 10      | Grace window before a reused refresh token is treated as a breach (family revoked). `0` = tightest detection, most multi-device false positives. |
| `pre_auth_session_lifetime_minutes`     | 10      | Pre-authentication browser session TTL for the login/consent sequence.                                                                           |
| `device_code_lifetime_minutes`          | 10      | RFC 8628 `device_code`/`user_code` TTL.                                                                                                          |
| `device_code_poll_interval_seconds`     | 5       | Minimum interval between `/token` polls for a `device_code`.                                                                                     |
| `device_code_invalid_quiet_period_seconds` | 300     | Quiet period after an invalid or expired `device_code`: further polls with it get `429` + `Retry-After` before any lookup.                       |
| `device_user_code_free_failures`        | 3       | Failed `/device` lookups of one `(user_code, client IP)` pair before exponential backoff (`429` + `Retry-After`, 1s doubling to 300s) engages.   |
| `device_ip_free_failures`               | 10      | Failed `/device` lookups from one client IP, across all codes, before backoff engages. `0` disables it; do so if many users share one resolved IP (NAT, or a proxy missing from `[rate_limit_trusted_proxies]`). |
| `revoked_family_retention_days`         | 30      | Days a revoked-family refresh token tombstone is kept after its own expiry (forensics only) before the session janitor purges it.            |
| `session_janitor_interval_seconds`      | 300     | Interval of the leader-only janitor that purges expired pre-auth sessions, authorization codes, device grants and refresh tokens from Raft.      |
| `token_rate_limit_burst_size`           | 10      | `/token` rate-limit burst, keyed on unverified `client_id`.                                                                                      |
| `token_rate_limit_replenish_per_minute` | 60      | `/token` sustained rate after burst is exhausted.                                                                                                |
| `dpop`                                  | `disabled` | Global DPoP enforcement (ADR 0043): `disabled`, `optional` or `required`. A floor that domains and clients can only raise. Anything but `disabled` needs `[mapping] cluster_salt`. |
| `dpop_proof_lifetime_seconds`           | 60      | Accepted distance of a DPoP proof's `iat` from the server time, in both directions (1 to 600).                                                   |
| `dpop_nonce_lifetime_seconds`           | 300     | Length of one DPoP nonce slot. A nonce is valid for the rest of its slot and the next one.                                                       |
| `dpop_replay_cache_max_entries`         | 100000  | Live entries of the DPoP replay cache. When full, new proofs are rejected instead of evicting entries.                                           |
| `dpop_replay_cache_max_entries_per_key` | 256     | Live replay cache entries one proof key may hold.                                                                                                |
| `allow_host_header_issuer`              | `false` | **Development only.** Lets the issuer and cookie `Secure` flag follow the request `Host`/`X-Forwarded-Proto` headers when `[DEFAULT] public_endpoint` is unset. |
| `templates_dir`                         | unset   | Directory with operator-supplied page templates (see [Customising the login pages](#customising-the-login-pages)). Read once at startup. |
| `static_dir`                            | unset   | Directory with operator static assets (stylesheets, logos) served at `/v4/oauth2/static/`.                                                       |
| `ui_product_name`                       | `OpenStack` | Product name in page titles, logo `alt` text and the footer.                                                                               |
| `ui_logo_url`                           | unset   | Logo at the top of every page: an absolute path such as `/v4/oauth2/static/logo.svg` (external URLs are blocked by the page CSP).                                  |
| `ui_support_url`, `ui_privacy_url`, `ui_terms_url` | unset | Footer links (`https://` URL or absolute path).                                                                                       |
| `ui_show_client_logos`                  | `false` | Render the `logo_uri` registered for a client on its login and consent pages. Lets the CSP load `https:` images, which leaks sign-in activity to the client's host. |
| `ui_default_locale`                     | `en`    | Locale used when `Accept-Language` matches no available locale.                                                                                  |
| `sso_max_sessions_per_user`             | 10      | Most SSO sessions one user may hold; a new sign-in beyond it ends the oldest. |
| `logout_revokes_refresh_tokens`         | false   | RP-initiated logout naming a client also revokes the user's refresh tokens of that client. |
| `upstream_logout`                       | false   | Logout of a session that came from a federated IdP also ends the IdP session (see [Upstream provider logout](#upstream-provider-logout)). |
| `mfa_max_attempts`                      | 5       | Second-factor codes accepted for checking per login attempt before the pre-auth session is discarded and the user must start over. Best-effort and per session; the per-user rate limit (`[rate_limit_user_auth]`) is the primary brute-force control. |
| `sso_session_lifetime_minutes`        | 480     | Lifetime of the browser SSO session started by a successful sign-in. Later authorization requests in the same browser skip the login form while it lives. `0` is not allowed. |

Exceeding a rate limit returns `429 Too Many Requests`.

## Second factor (TOTP and passkeys)

After the password step a user holding a second factor must pass it on both
the browser flow and the device-code flow; the consent page is unreachable
until then. Two factors are offered:

- **TOTP**: the user has an enabled `totp` credential. A verification-code
  form is shown.
- **Passkey / security key**: the WebAuthn extension is enabled
  (`[webauthn] enabled = true`) and the user has a registered passkey. The
  page shows a "Use a passkey or security key" button that runs the browser
  WebAuthn ceremony against the same `[webauthn]` relying party the
  `/v4/auth/passkey` API uses. Without the extension no passkey is ever
  offered or required.

A user holding both factors may pass either one. The issued `id_token` and
refresh tokens carry `amr` of `["pwd", "otp", "mfa"]` for TOTP and
`["pwd", "hwk", "mfa"]` for a passkey instead of `["pwd"]`. Users with
`multi_factor_auth_enabled = false` skip the step. If a factor lookup or
challenge cannot be produced the login is refused (fail closed).

Each ceremony challenge is single use and bound to the user that passed the
password step; a wrong assertion re-renders the page with a fresh challenge.
The challenge is stored in a slot of its own, derived from the pre-auth
session (or device code) of the login, so calls to the public
`/v4/auth/passkey/start` endpoint and other simultaneous sign-ins of the same
user can neither replace nor consume it.
Attempts count against the same per-session budget (`mfa_max_attempts`) and
the same per-user rate limit (`[rate_limit_user_auth]`) as TOTP codes.

The passkey page is the only OP page with JavaScript: an inline script
allowed through a per-response CSP `script-src 'nonce-...'`. Every other page
(and the TOTP-only page) keeps `script-src 'none'`. A customised `mfa.html`
template must keep the `passkey-form` markup and its script block to keep the
passkey flow working.

## Signing in through an upstream identity provider

If the domain has federation identity providers
(`/v4/federation/identity_providers`) the login page shows one "Sign in with
`<name>`" button per provider next to the password form. A provider is offered
only when it is enabled, belongs to the domain (global providers are not
offered), has an OIDC discovery URL and a default mapping, and `openid` is in
`[auth] methods`. `GET /authorize?...&idp_hint=<idp id>` skips the chooser and
sends the browser straight to that provider; an `idp_hint` that is not one of
those providers is ignored.

The browser returns to
`<public_endpoint>/v4/oauth2/<domain_id>/authorize/federated/callback`. Add
that URL to the provider's `allowed_redirect_uris` when the provider restricts
them. The upstream ID token is verified exactly as for
`/v4/federation/oidc/callback`, the user is resolved (or shadowed) through the
mapping engine, and the login continues to consent. Federated users skip the
local TOTP step, even when a TOTP credential is enrolled: the upstream provider
is the only authenticator and is responsible for strong authentication. The
`amr` of the issued tokens is the upstream `amr` claim when it is a short list,
otherwise `["federated"]`; those values are attested by the provider, not by
Keystone. Set `public_endpoint` in production: without it the callback URL is
derived from the `Host` header. The provider id and the upstream
`sid` claim are stored with the session, the authorization code and the refresh
token family, so logout can later chain to the upstream session.

The device-code verification page offers the same providers. Its browser
returns to `<public_endpoint>/v4/oauth2/<domain_id>/device/federated/callback`,
which also has to be allowed by a provider that restricts redirect URIs; the
upstream `state` is bound to the device grant exactly as it is bound to the
pre-auth session in the browser flow, and the upstream `amr`, provider id and
`sid` are copied to the grant and the refresh token family.

Not covered yet: re-checking expiring group membership
([ADR 0013](../../adr/0013-federation-oidc-expiring-group-membership.md)) at
refresh-token rotation (the OP issues no group or role claims today).

## Single sign-on and logout

A successful sign-in (password, TOTP or upstream provider) starts an SSO
session stored in Raft and tied to the browser by the `keystone_oauth2_sso`
cookie (`HttpOnly`, `SameSite=Lax`, and `Secure` when the public endpoint is
`https`, like the pre-auth and device cookies; with a plain `http` endpoint the
session can be replayed from the network path and Keystone logs a warning at
startup). While it lives, `/authorize` skips the login form and resumes the
original sign-in time and `amr`, so `auth_time` in the ID token is the real
login time. The session is ignored when its user is disabled or belongs to
another domain, and is deleted when the user or domain is disabled or deleted,
or when the user's password changes.

Session hardening:

- Enrolling a TOTP credential, or turning `multi_factor_auth_enabled` on for a
  user, ends that user's SSO sessions (refresh tokens are kept), so a session
  that started with a password alone cannot outlive the stronger requirement.
- `sso_max_sessions_per_user` (default 10) caps the SSO sessions of one user;
  a sign-in beyond the cap ends the user's oldest session.
- With `logout_revokes_refresh_tokens = true`, RP-initiated logout that names a
  client (verified `id_token_hint` or `client_id`) also revokes the user's
  refresh tokens issued to that client. It needs the browser's own SSO
  session, applies to that client only, and does not depend on `sid`. Access
  tokens already issued stay valid until they expire.

The authorization endpoint honours the OIDC request parameters:

- `prompt=none` never shows a page: it answers with `login_required` or
  `consent_required` redirects, or issues a code when the user is signed in and
  the client is pre-authorized. It never sets cookies.
- `prompt=login` and `prompt=select_account` force a fresh login.
- `max_age` forces a fresh login when the SSO session is older than the value
  (`0` always does).
- `login_hint` pre-fills the user name; `ui_locales` selects the page language.

`GET`/`POST /v4/oauth2/{domain_id}/logout` implements OpenID Connect
RP-Initiated Logout 1.0 and is advertised as `end_session_endpoint`. An
`id_token_hint` is verified against the domain keys (expired tokens are
accepted) and must belong to the signed-in user. A
`post_logout_redirect_uri` is only followed when it is registered in the
client's `post_logout_redirect_uris`. Without an `id_token_hint` the user is
asked to confirm first, because any page could otherwise log them out. On
success the SSO session is deleted and the cookie cleared. Logout only ends
the browser SSO session: access tokens and refresh-token families already
issued stay valid until they expire or are revoked (RFC 7009 revocation, user
or domain disable/delete, password change).

### Session ids (`sid`)

Every id token issued under a browser SSO session carries a `sid` claim: an
opaque, per-client value derived from the session (a one-way hash of the SSO
session and the client id), stable across code redemption and refresh. Two
clients never see the same `sid`, and the `sid` cannot be turned back into the
SSO cookie. Grants without a browser session (device code) have no `sid`.

### Back-channel logout

A client may register a `backchannel_logout_uri` (`https://`, no credentials;
set to an empty string on update to clear it) and
`backchannel_logout_session_required`. OIDC Back-Channel Logout 1.0 is
advertised as `backchannel_logout_supported` and
`backchannel_logout_session_supported`. When a user's sign-in ends, every
enabled client that was issued an authorization code under it and has such
a URI receives `POST logout_token=<JWT>` (form encoded, `Cache-Control:
no-store`). The token is signed with the domain's active key, carries
a JOSE type header of `logout+jwt`, `iss`, `aud` (the client), `sub` (the user), `iat`, a
two-minute `exp`, a `jti`, the `sid` of the ended session and the
`http://schemas.openid.net/event/backchannel-logout` event, and has no
`nonce`.

The notification is sent when an SSO session ends:

- on RP-initiated logout;
- when the session expires (janitor), is evicted by `sso_max_sessions_per_user`
  or is removed because its domain is disabled or deleted;
- for every session of the user, when the user is disabled, deleted or changes
  their password.

A session end only reaches clients through that session: the relying parties
are recorded per SSO session when a code is issued and removed when notified.
A client that does not set `backchannel_logout_session_required` may treat the
token as "end all sessions of the user", so it is only notified about a single
session when the user has no other SSO session left. A client that requires the
`sid` is always notified with it, and skipped for grants that carry none.
Replacing a session by signing in again in the same browser sends nothing: the
relying parties stay recorded for the next logout.

Delivery never blocks the request that caused it. A relying party that does
not answer `200` or `204` (or cannot be reached within 5 seconds) is retried
twice, after 2 s and 10 s, then given up on with a warning in the log.
There is no persistent queue: a notification pending when the node stops is
lost.

The endpoint is untrusted input. Its host is resolved by the server on every
attempt and refused when any address is private, loopback, link-local,
cloud-metadata or otherwise internal; the connection is pinned to the checked
address and redirects are never followed. Only `https://` is delivered.

### Front-channel logout

A client may register a `frontchannel_logout_uri` (`https://`) and
`frontchannel_logout_session_required`. OIDC Front-Channel Logout 1.0 is
advertised as `frontchannel_logout_supported` and
`frontchannel_logout_session_supported`. On RP-initiated logout the page that
reports the sign-out loads each such URI of the ended session in a hidden
frame; with `frontchannel_logout_session_required` the URI gets `iss` and `sid`
query parameters. The page's `Content-Security-Policy` allows framing only the
origins of those URIs. If a `post_logout_redirect_uri` was requested, the
browser follows it two seconds later (the page runs no scripts, so this is a
`<meta http-equiv="refresh">`). The relying party must allow being framed by the
provider (`frame-ancestors`, `SameSite` cookies still apply). Front-channel
logout happens only in the browser that logs out; sessions that end without a
browser (expiry, disabled user) use back-channel logout.

### Upstream provider logout

With `[oauth2] upstream_logout = true`, logging out a session that was started
through a federated identity provider also ends the session at that provider.
After the local logout the browser is redirected to the provider's
`end_session_endpoint` (read from its discovery document on every logout; it
must be `https://`) with `client_id` and a `post_logout_redirect_uri` of
`{public_endpoint}/v4/oauth2/{domain_id}/logout/complete`, which has to be
registered at the provider. `logout/complete` then sends the browser on to the
relying party's `post_logout_redirect_uri` (remembered in a short-lived cookie,
checked against the client's registered URIs again) or shows the signed-out
page. A provider without an `end_session_endpoint`, a discovery failure or a
non-`https` endpoint leave the logout local-only, with a warning in the log.
The setting is off by default because the provider session may be shared with
applications that must stay signed in. No `id_token_hint` is sent upstream.

## Remembered consent

On the consent page (browser and device flows) the user can tick "Remember my
decision for this application". The approved scopes are then stored per
(domain, user, client) in Raft, and later requests asking for no more than
those scopes skip the page. The box is ticked by default only for `openid`,
`profile` and `email`; it is not offered for `pre_authorized` clients, which
skip consent anyway. `prompt=consent` always shows the page.

A consent is removed together with its user, domain or client, and by the user
(see the user guide, "Managing connected applications"). Administrators can
list and withdraw any user's consents with the same endpoints; the policies are
`policy/oauth2/consent/list.rego` and `delete.rego`. Withdrawing a consent
revokes the user's refresh tokens of that client and emits a `consent_revoked`
audit event with the real user as initiator (storing one emits
`consent_granted`). Access tokens already issued stay valid until they expire.

## Customising the login pages

The browser pages of the authorization-code and device flows are rendered
from Jinja-style templates (`minijinja`, HTML autoescaping on). The built-in
templates are in `crates/keystone/templates/oauth2/`; copy the ones you want
to change into `[oauth2] templates_dir`. A page whose file is missing there
falls back to the built-in one, so a single page can be rebranded on its own.

Every template additionally receives `branding` (`product_name`, `logo_url`,
`support_url`, `privacy_url`, `terms_url`), `locale` and the translation
function `t("key", name=value)`. The page frame (viewport meta tag, `lang`
attribute, stylesheet link, logo, footer) lives in `base.html`, which the
other templates extend; override it to change all pages at once.

| File                | Context variables                                                              |
| ------------------- | ------------------------------------------------------------------------------ |
| `login.html`        | `client.*`, `csrf_token`, `error` (optional), `action`                         |
| `consent.html`      | `client.*`, `scopes` (list), `csrf_token`, `action`                             |
| `device_entry.html` | `error` (optional), `prefill`, `action`                                         |
| `device_result.html`| `granted` (bool), `client.*`                                                    |
| `error.html`        | `message`                                                                       |

`client` carries `id`, `name`, `description`, `logo_uri` (only with
`ui_show_client_logos`), `policy_uri` and `tos_uri`; the optional ones are
unset when the client has none.

Keep the form field names (`csrf_token`, `username`, `password`, `decision`,
`user_code`) and the `action` URL: the handlers depend on them.

Templates are parsed at startup: an unreadable directory or a template with a
syntax error stops Keystone from starting. Changes need a restart.

### Styling and languages

The default pages ship with a small responsive stylesheet (system fonts,
centred card, dark-mode aware, visible focus rings) served at
`/v4/oauth2/static/style.css`. Put a `style.css` into `static_dir` to replace
it, or link additional files from your templates.

Page texts come from per-locale TOML bundles, selected by the request's
`Accept-Language` header (exact tag, then primary language, then
`ui_default_locale`). Only `en` is built in
(`crates/keystone/templates/oauth2/locales/en.toml`). To add a language copy
that file to `<templates_dir>/locales/<lang>.toml` (for example `de.toml`)
and translate the values; keys missing from a bundle fall back to English.
The quoted keys at the end of the file translate the messages produced by the
server (for example `"invalid username or password"`).

Reference stylesheets and logos with `/v4/oauth2/static/<file>` (served from
`[oauth2] static_dir`; the route answers `404` when it is not configured and
refuses paths that leave the directory, symlinks included). Responses carry
`Cache-Control: public, max-age=3600`. The pages are sent with
`Content-Security-Policy: default-src 'self'; style-src 'self'; img-src 'self'
data:; script-src 'none'; frame-ancestors 'none'`, so stylesheets and images
must be served from the same origin and inline styles or scripts do not run.

## Revoking sessions

During an incident, revoke refresh token families from the command line (the
access tokens already issued stay valid until they expire):

```
keystone-manage oauth2 revoke --domain <domain_id> --user <user_id>
keystone-manage oauth2 revoke --domain <domain_id> --client <client_id>
keystone-manage oauth2 revoke --domain <domain_id> --all --reason "incident 42"
```

This calls `POST /v4/oauth2/{domain_id}/revocations`; a domain `manager` may
revoke in their own domain, `admin` in any. Clients are managed with
`keystone-manage oauth2 client ...`.

## Monitoring

The provider exports `keystone_oauth2_*` Prometheus series (token requests and
latency, refresh reuse, device polls, key rotations and age, janitor activity,
operator revocations); see the OAuth2 table in
[ADR 0031](../../adr/0031-prometheus-metrics.md). The shipped alert rules
(`deploy/prometheus/alert_rules.yaml`, group `keystone_oauth2`) page on refresh
token reuse and warn about stale signing keys and janitors.

## Production checklist

- **Set `[DEFAULT] public_endpoint`** to the externally visible URL of
  Keystone (for example `https://keystone.example.com`). It pins the issuer
  (`iss` claim, discovery `issuer`, `token_endpoint`, `jwks_uri`, the device
  flow `verification_uri`) so no request header can influence them, and its
  scheme decides whether the pre-auth and device cookies carry `Secure`
  (`https` → `Secure`, independent of `X-Forwarded-Proto`), and so does the SSO
  session cookie. Use `https`: with an `http` endpoint all of them travel
  unprotected and Keystone logs a warning at startup.
- When `public_endpoint` is unset, Keystone logs an error at startup and
  `/authorize`, `/device_authorization`, `/token` and discovery answer `503`
  (`server_error`). `[oauth2] allow_host_header_issuer = true` restores the
  Host-header behaviour and must only be used for local development.

## Provisioning a domain's signing key

```
keystone-manage oauth2 ensure-signing-key --domain <domain_id>
```

Idempotent — a no-op if the domain already has a key. Run this once for any
domain that did not go through `POST /v3/domains` (notably `default` after a
non-API bootstrap). Normal domain creation via the API does this automatically;
you only need the CLI for out-of-band-provisioned domains.

## Client registration (relying parties & machine identities)

All admin endpoints below require `SystemAdmin`/domain-manager Tier 1/Tier 2
gating per ADR 0020 §9.A and are authenticated with a normal Keystone token, not
an OAuth2 access token.

```
POST   /v4/oauth2/{domain_id}/clients
GET    /v4/oauth2/{domain_id}/clients
GET    /v4/oauth2/{domain_id}/clients/{provider_id}
PUT    /v4/oauth2/{domain_id}/clients/{provider_id}
POST   /v4/oauth2/{domain_id}/clients/{provider_id}/rotate-secret
DELETE /v4/oauth2/{domain_id}/clients/{provider_id}
```

- Confidential clients get a one-time plaintext `client_secret` in the
  `create`/`rotate-secret` response body — it is never stored or returned again,
  only its Argon2id hash.
- `provider_id` is unique within a domain; `client_id` is server-generated and
  globally unique (it's the sole key presented at `/token`, before `domain_id`
  is known).
- `client_id`, `provider_id`, `domain_id` are immutable after creation.
- `name` (required on create, 1-128 characters) is what users see on the login
  and consent pages instead of the raw `client_id`; users are otherwise asked to
  approve an opaque UUID, which is what consent phishing relies on. Clients
  registered before names existed show their `provider_id`.
  Optional display metadata follows the RFC 7591 names: `description` (up to
  1024 characters), `logo_uri`, `policy_uri` and `tos_uri` (absolute `https://`
  URLs without credentials) and `contacts` (up to 10 entries). On update, an
  empty string clears `description`, `logo_uri`, `policy_uri` and `tos_uri`.
  `GET .../clients?name=<text>` filters by case-insensitive name substring.
- The consent page links `policy_uri` and `tos_uri`. `logo_uri` is only
  rendered when `[oauth2] ui_show_client_logos = true`, because the browser then
  loads the image from the client's host (the CSP `img-src` gains `https:`),
  which tells that host who is signing in.

```json
{
  "oauth2_client": {
    "provider_id": "grafana",
    "name": "Grafana",
    "description": "Operations dashboards",
    "logo_uri": "https://grafana.example.com/logo.png",
    "policy_uri": "https://grafana.example.com/privacy",
    "tos_uri": "https://grafana.example.com/terms",
    "contacts": ["ops@example.com"],
    "confidential": true,
    "token_endpoint_auth_method": "client_secret_basic",
    "grant_types": ["authorization_code", "refresh_token"],
    "redirect_uris": ["https://grafana.example.com/login/generic_oauth"],
    "allowed_scopes": ["openid", "profile", "email"]
  }
}
```
- Setting `pre_authorized: true` (skips user consent for trusted first-party
  device-code clients) requires `SystemAdmin` regardless of the Tier 2
  self-service path otherwise available on this endpoint, and is rejected
  together with `openstack:api` in `allowed_scopes` (a pre-authorized client
  cannot silently gain OpenStack authorization).
- `DELETE` soft-deletes the client and tombstones every refresh token family
  issued to it (revocation reason `client_revoked`) before returning. Setting
  `enabled: false` through `PATCH` does the same, since a disabled client must
  not keep live refresh families. Both emit an `oauth2/client_revoked` CADF
  event carrying the number of revoked families. Pending device grants and
  pre-auth sessions of the client are not purged eagerly: they are rejected at
  redemption because the client is disabled and are removed by the expired
  record janitor. Outstanding bearer access/id tokens remain valid until
  natural `exp` — for immediate access-token invalidation on a compromised
  client, use emergency signing-key rotation instead.
- Every create/update/delete/rotate-secret call emits a CADF audit event.

## Signing key rotation

### Normal rotation

```
keystone-manage oauth2 rotate-signing-key --domain <domain_id>
```

Generates a fresh keypair, commits it via Raft, promotes it to `Primary/Active`,
and demotes the prior `Primary` to `Previous`. The `Previous` key stays
published on JWKS for one full token max-lifetime after demotion so in-flight
tokens keep verifying, then a background janitor removes it. The janitor also
rotates the key automatically once it is older than `signing_key_rotation_days`.

### Emergency rotation (suspected/confirmed key compromise)

Emergency rotation requires **dual control**: the initiating operator stages the
rotation, and a _different_ operator must confirm it within 15 minutes or it
auto-aborts (recorded in the audit log either way).

```
# Operator A, over admin UDS + SPIFFE mTLS:
keystone-manage oauth2 rotate-signing-key --domain <domain_id> --emergency
```

This prints a `rotation_id` and `expires_at`. A second operator then runs:

```
keystone-manage oauth2 confirm-rotate-signing-key \
  --domain <domain_id> --rotation-id <rotation_id> \
  --revoke-jti <jti-1> --revoke-jti <jti-2> ...
```

What happens:

1. A fresh keypair is generated and committed via Raft, promoted directly to
   `Primary/Active` — no grace-window overlap with the compromised key.
2. The compromised key is marked `revoked`, not removed from JWKS outright
   (removing it would invalidate every outstanding token signed by it — a
   domain-wide denial of service). Instead its `jti`s are published on a
   dedicated revocation list: `GET /v4/oauth2/{domain_id}/jwks/revocation`.
3. `--revoke-jti` is how you seed that list: pass every `jti` you already know
   was minted during the compromise window. **This is currently manual** — the
   operator must supply known-suspect JTIs by hand; there is no automatic
   audit-log-derived backfill yet (see the companion ADR amendment tracking this
   gap).
4. The downstream middleware (below) checks this list on every token
   verification and fails closed if the endpoint is unreachable.
5. A distinct CADF event (`oauth2/emergency_key_rotation`) is recorded with
   `domain_id`, revoked `kid`, new `kid`, operator identity, and the full
   `revoked_jtis` list.

Normal rotation cadence resumes afterward; the `signing_key_rotation_days` timer
resets.

**Note:** the stage and confirm steps above go through the normal Raft-backed
HTTP path (admin UDS + SPIFFE mTLS to
`/v4/oauth2/{domain_id}/rotate-signing-key`), which requires Raft quorum to
commit. If the cluster has lost quorum at the same moment a key is compromised,
use the quorum-bypass path below instead.

### Emergency signing key rotation during quorum loss

See [ADR 0028](../../adr/0028-oauth2-quorum-bypass-emergency-rotation.md) for the
full node-local mechanism (guardrail, gossip, scope limits) shared with DEK
rotation. This section covers the OAuth2-specific commands.

Requires `[local_emergency] enabled = true` on the responding node, and the Raft
leader must have been unknown for at least `leaderless_grace_period_seconds`
(guardrail refuses otherwise).

**1. Stage** — during quorum loss, on a guardrail-enabled node:

```bash
keystone-manage oauth2 rotate-signing-key \
  --domain <domain_id> --local-quorum-bypass \
  --justification "suspected key compromise, quorum lost"
```

Writes a rotation candidate to that node's local Fjall keyspace only — never
touches Raft. A background sweep gossips it (best-effort) to reachable peers
every `gossip_interval_seconds`, marking it `conflicted: true` on any node where
a different active candidate already exists for the same domain.

**2. List candidates** — once quorum returns, on every node that may have been
reached during the outage:

```bash
curl -X GET https://keystone:5000/v4/oauth2/<domain_id>/local-emergency-candidates \
  -H "X-Auth-Token: $ADMIN_TOKEN"
```

CLI equivalent:
`keystone-manage oauth2 list-local-emergency-candidates --domain <domain_id>`.
Check `conflicted` before choosing a `rotation_id` — `true` means gossip saw a
different candidate elsewhere and you must decide deliberately which one wins.

**3. Reconcile** — a _different_ operator than the one who staged it, against
the specific node holding the chosen candidate (reconciliation does not fan out
cluster-wide):

```bash
keystone-manage oauth2 reconcile-local-emergency-key \
  --domain <domain_id> --rotation-id <rotation_id>
```

Promotes the candidate's key to `Primary` via the same Raft transaction path
normal rotation uses (requires quorum), demotes the prior `Primary` to
`Previous`, clears the candidate on this node, and revokes any other active
candidate for the domain on this node. Rejects if the confirming operator
matches the initiator (dual-control) or if the candidate was already revoked.
Emits `oauth2/local_emergency_key_reconciled` (CADF) with a
`_local:emergency:audit:<rotation_id>` pointer recorded in the local emergency
store back to the event — staging itself is **not** audited (consistent with the
ordinary emergency path's stage/confirm asymmetry); only reconciliation is.

## Production checklist

- Raft storage is configured and `[oauth2] enabled` resolves to on (see
  [Enabling the provider](#enabling-the-provider)).
- `[DEFAULT] public_endpoint` is set to the external **https** URL. Without it
  the issuer cannot be pinned and the endpoints answer `503 server_error`.
- TLS is terminated in front of Keystone and `[oslo_middleware]
  enable_proxy_headers_parsing` is on, so the client IP and scheme are correct.
- `[rate_limit_global_ip]` and `token_rate_limit_burst_size` /
  `token_rate_limit_replenish_per_minute` are sized for the expected traffic.
- A signing-key rotation cadence is chosen (`signing_key_rotation_days`) and
  the manual rotation runbook has been rehearsed.
- The emergency (dual-control) rotation has been drilled at least once.
- The JWKS and revocation endpoints are monitored and kept highly available:
  downstream verifiers depend on them.
- Raft quorum is monitored. While it is lost `/token` answers `503
  temporarily_unavailable`.
- The metrics endpoint is scraped and the alert rules in
  `deploy/prometheus/alert_rules.yaml` (group `keystone_oauth2`) are loaded,
  see [ADR 0031](../../adr/0031-prometheus-metrics.md).

## Downstream control-plane enforcement (Nova/Neutron/etc.)

> **Design only.** The Python middleware described here is **not** part of this
> repository and is not yet published (repository link: _to be added_). What
> ships here is the Rust reference verifier
> (`openstack_keystone_core::oauth2_client::verify_openstack_access_token`) and
> an integration test that mints a token through `POST /token` and verifies it
> fully offline. The configuration below is the intended interface.

A thin Python WSGI middleware (`KeystoneNativeJwtMiddleware`) drops into
existing Paste Deploy pipelines (e.g. `/etc/nova/api-paste.ini`) **in front of**
`keystonemiddleware.auth_token`. Requests without an OP-issued Bearer JWT fall
through unchanged to the existing Fernet filter chain, so rollout is incremental
per service/region with instant rollback (just remove the filter).

Required config per service:

```ini
# Trust this Keystone: any issuer https://keystone.example.com/v4/oauth2/<domain_id>
# is accepted, with its JWKS and revocation list derived from the issuer URL
# (<issuer>/jwks, <issuer>/jwks/revocation) and fetched lazily. No per-domain
# configuration is needed when domains are created or deleted.
keystone_issuer_base_url = https://keystone.example.com
# Optional: trust only these domains (domain ids). Empty/unset = all domains.
# keystone_allowed_domains = <domain_id>,<domain_id>
# Optional: this service's OpenStack service type (e.g. compute). Lets it also
# accept tokens narrowed to `openstack-apis:<service type>`.
keystone_service_type = compute
signing_algorithm = ES256
```

Operational notes:

- **Fail-closed.** Both the JWKS fetch and the JTI-revocation fetch reject the
  request on failure rather than serving stale data — a Keystone or network
  outage now also blocks OpenStack API calls, not just token issuance. This is
  deliberate: fail-open would let an attacker who can interfere with the
  middleware's connectivity keep an already-revoked compromised key validating
  for the outage's duration. Both endpoints must be treated as load-bearing for
  the whole control plane.
  - JWKS cache TTL: 300s (matches `Cache-Control: max-age=300` on `/jwks`).
  - Revocation list cache TTL: 60s.
- `aud` is the control-plane value `openstack-apis` (or a narrowing to
  `openstack-apis:<service type>`), so one token works across all services and
  across every domain a service trusts. Domain isolation does not rely on `aud`:
  - a token is verified only against the JWKS of the issuer it names, and the
    service fetches that JWKS only from under `keystone_issuer_base_url` (never
    from a host named by the token);
  - the token's scope must lie inside the domain its `iss` names
    (`project_domain_id` / `domain_id` equal to the issuer's domain). A
    compromised domain key can therefore only forge tokens acting inside that
    domain, never in another one. System-scoped tokens are refused by this
    check, and an issuer that does not name a domain is rejected.
- A service accepts every token from every domain it trusts. To trust only some
  domains, set `keystone_allowed_domains`; leave it unset on a public cloud
  where domains come and go.
- A deleted domain serves no JWKS, so its tokens stop validating without any
  change on the services. Unknown issuers are cached negatively (60 s) so a
  forged `iss` cannot trigger a fetch per request.
- Without `keystone_service_type` a service accepts only un-narrowed tokens, so
  enabling `audience` narrowing for clients never breaks services that have not
  been upgraded.
- The revocation list is currently fetched per issuer (60 s cache), which is one
  poll per active domain. A cluster-wide revocation feed is the planned
  follow-up for very large deployments (ADR 0026 §5, "Revocation at scale").

## Relying-party token revocation (RFC 7009)

`POST /v4/oauth2/{domain_id}/revoke` lets a client revoke its own refresh or
access tokens (see the user guide). Operationally:

- Refresh-token revocation tombstones the family with reason `rp_revoke` and
  emits `oauth2/refresh_family_revoked`; every request also emits a `revoke`
  session audit event whose initiator is the authenticated client. A client
  presenting another client's refresh token gets `200` (no oracle) but a
  `failure` audit event is recorded.
- Access-token revocation writes the `jti` to the same per-domain revocation
  list that emergency rotation uses (`/jwks/revocation`), so it is only
  enforced by services that fetch that list (see "Downstream control-plane
  enforcement"), after the list's 60s cache TTL. Entries are dropped once the
  token's `exp` passes.
- The endpoint is rate limited per client (`token_rate_limit_*`) and per source
  IP (global IP limiter) before any token lookup.
- OIDC access tokens carry a private `fid` claim (the refresh family id; tokens issued before it was renamed carry it as `sid`, which revocation still accepts). The `sid` claim of id and logout tokens is the SSO session.
  Revoking such an access token also revokes that family. The reverse does not
  hold: revoking a refresh token does not revoke access tokens already minted
  from its family (the list is keyed by `jti`; the server does not track
  access tokens per family).
- Writes to the per-domain JTI list use optimistic concurrency with bounded
  retries, so concurrent revocations (or a revocation racing an emergency
  rotation) do not lose entries; under sustained contention the call fails with
  a 500 rather than silently dropping a revocation.

## Introspection for high-criticality services (RFC 7662)

Offline JWT verification cannot see a revocation until the service next
refreshes `/jwks/revocation` (and an un-listed token stays valid until `exp`).
A service that cannot accept that window for its most sensitive operations
(deleting volumes, changing quotas, ...) should validate the presented token
with the back-channel endpoint instead:

```
POST /v4/oauth2/{domain_id}/introspect
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

token=<access or refresh token>&token_type_hint=access_token
```

- **Who may call it:** an enabled *confidential* client of the same domain,
  authenticated exactly as on `/token` (`client_secret_basic` or
  `client_secret_post`). Public clients get `401 invalid_client`. No dedicated
  capability flag is needed: register the resource server as an ordinary
  confidential client of the domain. The token does not have to belong to the
  calling client, since a resource server introspects tokens minted for other
  clients; it must belong to the same domain.
- **Active token:** `200` with `active: true`, `scope`, `client_id`, `sub`,
  `exp`, `iat`, `nbf`, `aud`, `iss`, `jti`, `token_type: "Bearer"` and
  `token_use`. For OpenStack access tokens (`openstack:api`) the response also
  carries `openstack_context` (user, scope and roles) and `delegation_context`,
  the authorization data the caller will act on. Refresh tokens return
  `client_id`, `sub`, `scope`, `exp` and `iat`.
- **Anything else** (unknown, malformed, expired, revoked, spent, bad
  signature, token of another domain) is `200 {"active": false}`; the response
  never says why.
- Access tokens are checked against the live JTI revocation list (no cache),
  so a token revoked through RFC 7009 or emergency rotation is inactive
  immediately. Refresh tokens are active only while the record exists, is not
  spent or revoked, and neither the token nor its family has expired.
- If the revocation list or the refresh-token store is unavailable the
  endpoint answers `500` rather than risk reporting a revoked token as active;
  treat that as "deny".
- The endpoint is rate limited per client (`token_rate_limit_*`) and per source
  IP before any lookup, responses are `Cache-Control: no-store`, and every call
  emits a CADF `read` audit event initiated by the calling client. Discovery
  advertises it as `introspection_endpoint`.

Recommended pattern: verify offline for ordinary calls and introspect only for
the operations whose revocation latency you cannot tolerate.

## Migration from Fernet

Everything here is additive — Fernet issuance/validation continues unchanged.
See ADR 0026 §13 for the staged migration path (Fernet interchangeability → JWS
format parity → OP goes live → machine identity migration → human flow migration
→ Fernet sunset). Key operational gate: a service may only prefer JWTs over
falling through to Fernet once its operator has explicitly accepted the
15-minute stateless revocation window (or wired back-channel introspection for
high-criticality operations, see "Introspection for high-criticality services") — record that acceptance in your deployment's
migration runbook.

## Upgrading to the absolute refresh-token lifetime

- **Existing refresh families** (issued before `refresh_token_absolute_lifetime_days`
  existed) carry no cap. On their first rotation after the upgrade they are
  backfilled with `now + refresh_token_absolute_lifetime_days`, so they are
  capped from then on rather than staying uncapped forever.
- **Rolling upgrades of a Raft cluster:** `create_refresh_token` commands now
  carry a `family_expires_at` field. Nodes still running the old version cannot
  apply them, so upgrade all nodes before serving refresh-token traffic from the
  new version (stored records stay readable in both directions).
- Revoking a family because its user or domain is no longer valid emits an
  `oauth2/refresh_family_revoked` audit event (family id and reason:
  `user_deleted`, `user_disabled`, `user_domain_changed`, `password_changed`,
  `domain_disabled`, `domain_deleted`).
- Disabling or deleting a user, changing a user's password, or disabling or
  deleting a domain revokes the affected refresh families right away (one
  audit event per family) and drops pending authorization and device flows
  for that user or domain, matching the v3 token revocation on the same
  events. Disabling a user or domain is now audited as `disable` and a
  password change as `password_change` instead of `update`.

## Known gaps

- **Audit-log-derived JTI backfill** — `--revoke-jti` is manual only.
  Auto-populating the revocation list from a time window against the audit trail
  needs a queryable audit-log store that does not exist yet.
- Quorum-bypass local-emergency rotation
  ([ADR 0028](../../adr/0028-oauth2-quorum-bypass-emergency-rotation.md), gap noted
  in ADR 0026 §3) is implemented — see "Emergency signing key rotation during
  quorum loss" above. Deliberate scope limits: no cross-node broadcast to clear
  a superseded candidate, no unattended reconciliation sweep, per-node (not
  cluster-wide) reconciliation.

## Troubleshooting

| Symptom                                                                       | Likely cause                                                                                                                     |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `/jwks` or `/.well-known/openid-configuration` returns 404                    | Domain has no signing key — run `keystone-manage oauth2 ensure-signing-key --domain <id>`                                        |
| `503 server_error` on `/authorize`, `/device_authorization`, `/token` or discovery ("issuer mismatch" / issuer differs between environments) | `[DEFAULT] public_endpoint` is not set — set it to the external URL; the issuer is otherwise not pinned and the endpoints refuse to serve |
| `429` on `/token`                                                             | Rate limit hit — see `token_rate_limit_*` config                                                                                 |
| `429` on `/authorize`, `/device`, `/device/login`, or `/device_authorization` | Global per-IP limiter hit — see `[rate_limit_global_ip]`                                                                         |
| `confirm-rotate-signing-key` fails with "rotation not found/expired"          | The 15-minute confirmation window elapsed and the rotation auto-aborted; re-run `rotate-signing-key --emergency`                 |
| Downstream service rejects all OP tokens after Keystone/network blip          | Expected fail-closed behavior — check JWKS/revocation endpoint reachability from the service                                     |
| `rotate-signing-key --local-quorum-bypass` refused                            | `[local_emergency] enabled = false` on that node, or leader has not been unknown long enough (`leaderless_grace_period_seconds`) |
| `reconcile-local-emergency-key` fails with dual-control error                 | Confirming operator matches the one who staged the candidate — use a different operator                                          |
