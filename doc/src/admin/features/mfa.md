# Multi-factor authentication rules

A user can require that a login uses a specific combination of authentication
methods. Keystone checks the rules when it issues a token on
`POST /v3/auth/tokens`. This page tells an operator how to set them and which
token-issuing paths they do not cover.

## The rules

The user option `multi_factor_auth_rules` is a list of rules. A rule is a list
of method names. A login passes when the methods it used cover **all** methods
of **at least one** rule:

```json
{
  "user": {
    "options": {
      "multi_factor_auth_rules": [["password", "totp"]]
    }
  }
}
```

With this rule the user may log in only with a password and a TOTP passcode in
the same request, not with a password alone. The request lists both methods:

```json
{
  "auth": {
    "identity": {
      "methods": ["password", "totp"],
      "password": { "user": { "id": "...", "password": "..." } },
      "totp": { "user": { "id": "...", "passcode": "123456" } }
    }
  }
}
```

A login that does not satisfy the rules is refused with `401 Unauthorized` and
an audit record with `reason.reasonCode` `MfaRulesNotSatisfied`. That record
means the first factor was valid, which is a useful signal.

A token obtained with the `token` method carries the methods of the original
token, so a user who passed a rule once can rescope without a new second factor.

## What disables a rule

- The user has no `multi_factor_auth_rules`, or only empty rules.
- The user option `multi_factor_auth_enabled` is `false`. Leave it unset or
  `true` to keep the rules active.
- The login is a delegation: an application credential or a trust. Both are
  created by an already authenticated user, and they exist so that automation
  can authenticate without a second factor. Limit them with their own
  restrictions and short lifetimes.

Workload identities (SPIFFE, Kubernetes) have no user options.

## Where the rules are not evaluated

The rules apply on `POST /v3/auth/tokens` only. These paths issue tokens
without reading them:

- the passkey login (`webauthn` extension),
- federation logins,
- Kubernetes authentication, EC2 tokens and the other service-specific
  endpoints,
- the OAuth2 and OIDC login pages. They ask for a second factor from every user
  who holds a TOTP credential or a passkey, unless `multi_factor_auth_enabled`
  is `false`, and they ignore the rules.

A user whose rules require a password and TOTP can therefore still obtain a
token with a registered passkey. Treat a passkey as a strong factor on its own,
or do not register one for such a user. Close the other paths at the proxy if
they must not be reachable.

## Avoiding a lockout

- Enrol the TOTP credential first, then set the rule.
- Keep a break-glass administrator that is not bound by a rule that depends on
  a personal device, and protect that account with a separate control.
- Test the rule with the user's own client before it is relied on.

## Related

- [Passkeys](passkeys.md)
- [Audit trail](audit.md)
- [Security guidance](../security.md)
