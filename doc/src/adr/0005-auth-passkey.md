# 5. Passkey Auth

Date: 2025-11-03

## Status

Accepted

## Context

Nowadays password-less authentication becomes standard. In OpenStack it is at
the moment not implemented whether on the API level (for the CLI) nor on the UI.

[Webauthn](https://webauthn.io/) is a well accepted standard for implementing
password-less authentication with the help of hardware or software
authenticators. Keystone should implement support for new authentication methods
relying on the webauthn.

## Decision

Introduce webauthn support in Keystone. This requires adding new database tables
and introduction of the additional flows to allow user registering
authenticators.

- `webauthn_credential` table describes the authenticators of the user (user_id
  as the primary key).

- `webauthn_state` table stores authentication and registration states according
  to the standard.

- User should be able to request the desired scope in the authentication
  initialization request. In this case a scoped token is returned when user has
  the required access.

- To prevent attacks authentication requests for not existing users or users
  without registered authenticators MUST return fake (but valid) authentication
  state.

## Consequences

New authentication method allows users to get valid token without requiring user
to pass any secrets on the wire. Overall security of the system is increased.
