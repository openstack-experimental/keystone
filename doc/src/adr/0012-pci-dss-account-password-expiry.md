# 12. PCI-DSS requirement: Inactive user accounts are removed/disabled

Date: 2025-11-27

## Status

Accepted

## Context

PCI-DSS contains the following requirement to the IAM system:

If passwords/passphrases are used as the only authentication factor for user
access (i.e., in any single-factor authentication implementation) then either:
• Passwords/passphrases are changed at least once every 90 days, OR
• The security posture of accounts is dynamically analyzed, and real-time
access to resources is automatically determined accordingly.

Python Keystone implements this requirement with the help of the
`conf.security_compliance.password_expires_days` and `password.expires_at`
during the login attempt to identify whether the specified used password is
expired. `user.options.IGNORE_PASSWORD_EXPIRY_OPT` option allows bypassing the
expiration check.

## Decision

For compatibility reasons rust implementation must adhere to the requirement.

Password expiration is performed after verification that the password is valid.

- `password.expires_at_int` (as epoch seconds) or the `password.expires_at` (as
  date time specifies the password expiration. When none is set password is
  considered as valid. Otherwise it is compared against the current time.

- During account password update operation when user is not having the
  `user.options.IGNORE_PASSWORD_EXPIRY_OPT` option enabled the current date time
  plus the `conf.security_compliance.password_expires_days` time is persisted as
  the `password.expires_at_int` property.

- Password expiration MUST NOT be enforced in the password change flow to
  prevent a permanent lock out.

## Consequences

- Administrator account can be deactivated. Separate tooling or documentation
  how to unlock the account must be present.
