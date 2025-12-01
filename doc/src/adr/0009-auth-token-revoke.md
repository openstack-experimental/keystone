# 9. Auth token revocation

Date: 2025-11-18

## Status

Accepted

## Context

Issued tokens are having certain configurable validity. In cases when a user
need to be disabled, the project deactivated, or simply to prevent the token use
after the work has been completed it is necessary to provide the possibility to
invalidate the tokens. Python Keystone provides this possibility and so it is
necessary to implement it in the same way.

Since original functionality is not explicitly documented this ADR will become
the base of such information.

## Decision

Fernet token revocation is implemented based on the `revocation_event` database
table.

The table has following fields:

```
    pub id: i32,
    pub domain_id: Option<String>,
    pub project_id: Option<String>,
    pub user_id: Option<String>,
    pub role_id: Option<String>,
    pub trust_id: Option<String>,
    pub consumer_id: Option<String>,
    pub access_token_id: Option<String>,
    pub issued_before: DateTime,
    pub expires_at: Option<DateTime>,
    pub revoked_at: DateTime,
    pub audit_id: Option<String>,
    pub audit_chain_id: Option<String>,
```

### Token revocation

When a revocation of thecurrently valid token is being requested the record with
the following information is being inserted into the database:

- `audit_id` is populated with the first entry of the token `audit_ids` list.
  When this list is empty an error is being returned.
- `issued_before` is set to the current time with the UTC timezone.
- `revoked_at` is set to the current time with the UTC timezone.
- other fields are left empty.

### Revocation check

A token validation for being revoked is performed based on the presence of the
revocation events in the `revocation_event` table matching the expanded token
properties. This means that before the token revocation is being checked
additional database queries for expanding the scope information including the
roles the token is granting are performed.

Following conditions are combined with the AND condition:

- First element of the token's `audit_ids` property is compared against the
  database record. When this list is empty an error is being returned.
- `token.project_id` is compared against the database record when present.
- `token.user_id` is compared against the database record when present.
- `token.trustor_id` is compared against the database record `user_id` when
  present.
- `token.trustee_id` is compared against the database record `user_id` when
  present.
- `token.trust_id` is compared against the database record `trust_id` when
  present.
- `token.issued_at` is compared against the database record with
  `revocation_event.issued_before >= token.issued_at`.

Python version of the Keystone applies additional match verification for the
selected data on the server side and not in the database query.

- When `revocation_event.domain_id` is set it is compared against
  `token.domain_id` and `token.identity_domain_id`.
- When `revocation_event.role_id` is present it is compared against every of the
  `token.roles`.

After the first non matching result further evaluation is being stopped.
Logically there does not seem to be a reason for such handling and it looks to
be an evolutionary design decision. Following checks can be added into the
single database query with a different logic only comparing the corresponding
fields when the column is not empty.

While following checks allow much higher details of the revocation events in the
context of the usual fernet token revocation it is only going to match on the
`audit_id` and `issued_before`.

### Revocation table purge

In the python Keystone there is no automatic cleanup handling. Due to that
expired records are removed during the revocation check. Records to be expired
are selected using the following logic.

- `expire_delta = CONF.token.expiration + CONF.token.expiration_buffer`
- `oldest = utc.now() - expire_delta`
- `DELETE from revocation_event WHERE revoked_at < oldest`

When both python and rust Keystone versions are deployed in parallel and both
try to delete expired records errors can occur. However, if only rust version is
validating the tokens python version will not perform any backups. Additionally
no errors were reported yet in installations with multiple Keystone instances.
Therefore it is necessary for the rust implementation to do periodic cleanup. It
should be exexcuted with the following query filter:
`revoked_at < (now - (expiration + expiration_buffer))`. Such implementation
must be made optional with possibility to disable this behavior using the config
file.

## Consequences

- Database table with the revocation events must be periodically cleaned up.

- Token validation processing time is increased with the database lookup.

- Expired revocation records are optionally periodically cleaned by the rust
  implementation.
