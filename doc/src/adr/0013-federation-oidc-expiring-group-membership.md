# 13. OpenIDConnect federation: Expiring group membership

Date: 2025-12-09

## Status

Accepted

## Context

Python Keystone uses expiring group membership for the federated users
<https://specs.openstack.org/openstack/keystone-specs/specs/keystone/ussuri/expiring-group-memberships.html>.
Every time the user authenticates using the federated login it's group
membership are persisted in the `expiring_user_group_membership` table instead
of the `user_group_membership`. The table has a non nullable column
`last_verified` which is set to the time of the last user login. The user is
considered to be included as a member of the group for the period of time
specified in the `conf.federation.default_authorization_ttl`. Once the
`user.last_verified + ttl < current_timestamp()` the user is not considered the
member of the group anymore. The intention of this mechanism is to prevent stale
group memberships granting the user privileges.

## Decision

For compatibility reasons rust implementation must implement the same
functionality.

Every time the user authenticates the user group memberships are persisted in
the `expiring_user_group_membership` table.

- Current group membership is being read from the database (ignoring the time
  limitation).

- The group membership that the user should not be having anymore are deleted.

- For the new group memberships corresponding entries are added with the current
  timestamp.

- For all other groups that the user is still member of corresponding records
  are updated to set `last_verified` to the current timestamp.

- Effective role assignments of the user are taking into the consideration
  expiring group memberships through the `list_user_groups` respecting the
  expiring membershipts (independent of the `idp_id`) as
  `expiring_user_group_membership.last_verified > current_timestamp - conf.federation.default_authorization_ttl`.

## Consequences

- The user must login periodically to keep application credentials working when
  corresponding roles are granted through the expiring group membership.

- With the SCIM support the expiring membership should not be necessary.
