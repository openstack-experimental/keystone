# 10. PCI-DSS requirement: Invalid authentication attempts are limited

Date: 2025-11-27

## Status

Accepted

## Context

PCI-DSS contains the following requirement to the IAM system:

Invalid authentication attempts are limited by:

- Locking out the user ID after not more than 10 attempts.
- Setting the lockout duration to a minimum of 30 minutes or until the user's
  identity is confirmed.

Python Keystone implements this requirement with the help of the
`conf.security_compliance.lockout_duration` during the login attempt to identify
whether the user is currently temporarily disabled:

```python

    def _is_account_locked(self, user_id, user_ref):
        """Check if the user account is locked.

        Checks if the user account is locked based on the number of failed
        authentication attempts.

        :param user_id: The user ID
        :param user_ref: Reference to the user object
        :returns Boolean: True if the account is locked; False otherwise

        """
        ignore_option = user_ref.get_resource_option(
            options.IGNORE_LOCKOUT_ATTEMPT_OPT.option_id
        )
        if ignore_option and ignore_option.option_value is True:
            return False

        attempts = user_ref.local_user.failed_auth_count or 0
        max_attempts = CONF.security_compliance.lockout_failure_attempts
        lockout_duration = CONF.security_compliance.lockout_duration
        if max_attempts and (attempts >= max_attempts):
            if not lockout_duration:
                return True
            else:
                delta = datetime.timedelta(seconds=lockout_duration)
                last_failure = user_ref.local_user.failed_auth_at
                if (last_failure + delta) > timeutils.utcnow():
                    return True
                else:
                    self._reset_failed_auth(user_id)
        return False
```

## Decision

For compatibility reasons rust implementation must adhere to the requirement.

During password authentication before validating the password following check
must be applied part of the locked account verification:

- When `conf.security_compliance.lockout_duration` and
  `conf.security_compliance.lockout_failure_attempts` are not set the account is
  NOT locked.

- When `user_options.IGNORE_LOCKOUT_ATTEMPT` is set user account is NOT locked

- When `user.failed_auth_count >= conf.security_compliance.lockout_failure_attempts`
  the account is locked.

- When `user.failed_auth_at + conf.security_compliance.lockout_duration >
now()` account is locked. When the time is `< now()` - reset the counters
  in the database.

- Otherwise the account is NOT locked.

After the authentication is success the `user.failed_auth_at` and
`user.failed_auth_count` are being reset. In the case of failed authentication
such attempt sets the mentioned properties correspondingly.

## Consequences

- Authentication with methods other than username password are not protected.

- Reactivating the temporarily locked account can be performed by the admin or
  domain admin via resetting the `user.failed_auth_count` attribute.
