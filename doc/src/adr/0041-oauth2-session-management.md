# 41. OAuth2 provider session management

**Date:** 2026-10-12

## Status

Accepted.

## Reference

Tracking issue #1482. Related: ADR 0026 (OAuth2/OIDC provider), #1475
(RP-initiated logout), #1493 and #1496 (back-channel logout).

## Context

RP-initiated logout and a first back-channel logout existed: a logout token
was sent to the clients of a user, without a `sid`, only on logout or user
lifecycle events. Missing were session-scoped notification, notification when
a session ends without a browser, front-channel logout and ending the session
at an upstream identity provider.

## Decision

- **`sid`.** The id token carries `sid = base64url(SHA-256("keystone-oauth2-sid\0" ||
  sso_ref || 0x00 || client_id))`, where `sso_ref = hex(SHA-256(sso_id))`. The SSO id is the
  bearer cookie value, so it never appears in storage keys, audit events or
  tokens; only its hash does. A client sees a different `sid` than any other
  client.
- **Relying-party index per SSO session.** The Raft index key is
  `oauth2:rp_idx:v1:{user}:{sso_ref}:{client}`; keys of the previous layout
  (`{client}` only) are still read as sessions without a `sid`.
- **One path for ending a session.** `end_sso_session` serves explicit logout,
  expiry, eviction, janitor purge and domain removal and emits an
  `Oauth2SsoSession` event; the back-channel hook turns it into logout tokens.
  A replaced session emits an audit-only event and keeps its relying-party
  records so a later user-wide logout still reaches them.
- **Session-scoped notification rule.** A client that does not require `sid`
  may read the token as "log out everywhere", so for a single ended session it
  is only notified when the user has no other SSO session. Clients requiring
  `sid` are always notified with it. Failure to list the other sessions counts
  as "has other sessions" (never log the user out of unrelated sessions).
- **Retries are in memory.** 2 s and 10 s, then dropped with a warning. A
  persistent queue would need a replicated outbox; deferred.
- **Front-channel.** Rendered by the logout page as hidden frames, with a
  per-response CSP `frame-src` limited to the clients' origins and a meta
  refresh (the pages run no scripts) to the `post_logout_redirect_uri`.
- **Upstream logout.** Opt-in (`[oauth2] upstream_logout`). Discovery is
  repeated at logout instead of persisting `end_session_endpoint` with the IdP
  (no federation schema change). The way back is a fixed
  `logout/complete` URI; the relying party's redirect waits in a short-lived
  `HttpOnly` cookie that is not trusted and is validated against the client
  again.

## Consequences

- Several browser sessions of a user no longer log each other out at relying
  parties that support `sid`.
- Clients and sessions are stored in Raft only, so there is no SQL migration;
  new client fields are trailing and defaulted.
- Back-channel notifications can be lost when a node stops during the retry
  window.
- Upstream logout needs the `logout/complete` URI registered at the IdP, and
  sends no `id_token_hint` because the upstream id token is not stored.
