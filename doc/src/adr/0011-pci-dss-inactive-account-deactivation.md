# 11. PCI-DSS requirement: Inactive user accounts are removed/disabled

Date: 2025-11-27

## Status

Accepted

## Context

PCI-DSS contains the following requirement to the IAM system:

Inactive user accounts are removed or disabled within 90 days of inactivity.

Python Keystone implements this requirement with the help of the
`conf.security_compliance.disable_user_account_days_inactive` during the login
attempt to identify whether the user is currently active or deactivated:

```python

    def enabled(self):
        """Return whether user is enabled or not."""
        if self._enabled:
            max_days = (
                CONF.security_compliance.disable_user_account_days_inactive
            )
            inactivity_exempt = getattr(
                self.get_resource_option(
                    iro.IGNORE_USER_INACTIVITY_OPT.option_id
                ),
                'option_value',
                False,
            )
            last_active = self.last_active_at
            if not last_active and self.created_at:
                last_active = self.created_at.date()
            if max_days and last_active:
                now = timeutils.utcnow().date()
                days_inactive = (now - last_active).days
                if days_inactive >= max_days and not inactivity_exempt:
                    self._enabled = False
        return self._enabled

```

In python Keystone there is no periodic process that deactivates inactive
accounts. Instead it is calculated on demand during the login process and
listint/showing user details. With the new application architecture in Rust it
is possible to implement background processes that disable inactive users. This
allows doing less calculations during user authentication and fetching since it
is possible to rely that the background process deactivates accounts when
necessary.

## Decision

For compatibility reasons rust implementation must adhere to the requirement.

After successful authentication when `user.enabled` attribute is not true the
authentication request must be rejected with `http.Unauthorized`.

Additional background process must be implemented to deactivate inactive
accounts. For this when
`conf.security_compliance.disable_user_account_days_inactive` is set a process
should loop over all user accounts. When the `user.last_active_at +
disable_user_account_days_inactive < now()` presence of the
`user.options.IGNORE_USER_INACTIVITY_OPT` should be checked. When absent the
account must be updated setting `user.enabled` to `false`.

Since it is technically possible that the background process is not running for
any reason the same logic should be applied also when converting the identity
backend data to the internal account representation and applied when the user
data is reported by the backend as active. On the other hand having a separate
background process helps updating account data in the backend and produce audit
records on time without waiting for the on-demand logic to apply. It also allows
disabling accounts in the remote identity backends that are connected with
read/write mode (i.e. SCIM push).

After the successful authentication of the user with password or the federated
workflow the `user.last_active_at` should be set to the current date time.

## Consequences

- Authentication with methods other than username password are not updating the
  `lst_active_at`. Due to that the account that used i.e. application
  credentials for the activation for more than X days would become disabled. This
  requires account to perform periodic login using the password.

- It should be considered to update application credentials workflow to update
  the `user.last_active_at` attribute after successful authentication.

- It could happen that the periodic account deactivation process does not work
  for certain amount of time (i.e due to bugs in the code or the chosen
  frequency) allowing the user to login when it should have been disabled. This
  can be only prevented by applying the same logic during the conversion of the
  database entry to the internal `User` structure the same way like python
  keystone is doing.

- Administrator account can be deactivated. Separate tooling or documentation
  how to unlock the account must be present.
