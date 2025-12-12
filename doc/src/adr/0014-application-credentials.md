# 14. Application Credentials

Date: 2025-12-12

## Status

Accepted

## Context

Application Credentials will have the following characteristics:

- Immutable.

- Allow for optionally setting limits, e.g. 5 Application Credentials per User
  or Project, to prevent abuse of the resource.

- Assigned the set of current roles the creating User has on the Project at
  creation time, or optionally a list of roles that is a subset of the creating
  User's roles on the Project.

- Secret exposed only once at creation time in the create API response.

- Limited ability to manipulate identity objects (see Limitations Imposed)

- Support expiration.

- Are deleted when the associated User is deleted.

Application Credentials will be treated as credentials and not authorization
tokens, as this fits within the keystone model and is consistent with others
APIs providing application authentication. It also avoids the security and
performance implications of creating a new token type that would potentially
never expire and have custom validation.

## Decision

For compatibility reasons rust implementation must implement the same
functionality.

Application Credential Management

Users can create, list, and delete Application Credentials for themselves. For
example, adding an Application Credential:

```
POST /v3/users/{user_id}/application_credentials

{
    "application_credential": {
        "name": "backup",
        "description": "Backup job...",
        "expires_at": "2017-11-06T15:32:17.000000",
        "roles": [
            {"name": "Member"}
        ]
    }
}
```

name must be unique among a User's application credentials, but name is only
guaranteed to be unique under that User. name may be useful for Consumers who
want human readable config files.

description is a long description for storing information about the purpose of
the Application Credential. It is mostly useful in reports or listings of
Application Credential.

`expires_at` is when the Application Credential expires. `null` means that the
Application Credential does not automatically expire. `expires_at` is in ISO
Date Time Format and is assumed to be in UTC if an explicit timezone offset is
not included.

roles is an optional list of role names or ids that is a subset of the roles the
Creating User has on the Project to which they are scoped at creation time.
Roles that the Creating User does not have on the Project are an error.

In the initial implementation, the Application Credential will assume the roles
of the Creating User or the given subset and we will not implement fine-grained
access controls beyond that.

Response example:

```
{
    "application_credential": {
        "id": "aa4541d9-0bc0-44f5-b02d-a9d922df7cbd",
        "secret": "a49670c3c18b9e079b9cfaf51634f563dc8ae3070db2...",
        "name:" "backup",
        "description": "Backup job...",
        "expires_at": "2017-11-06T15:32:17.000000",
        "project_id": "1a6f968a-cebe-4265-9b36-f3ca2801296c",
        "roles": [
            {
                "id": "d49d6689-b0fc-494a-abc6-e2e094131861",
                "name": "Member"
            }
        ]
    }
}
```

The id in the response is the Application Credential identifier and would be
returned in get or list API calls. An id is globally unique to the cloud.

`secret` is a random string and only returned via the create API call. Keystone
will only store a hash of the secret and not the secret itself, so a lost secret
is unrecoverable. Subsequent queries of an Application Credential will not
return the secret field.

`roles` is a list of role names and ids. It is informational and can be used by
the Consumer to verify that the Application Credential inherited the roles from
the User that the Consumer expected. This is not a policy enforcement, it is
simply for human validation.

If the Consumer prefers to generate their own secret, they can do so and provide
it in the create call. Keystone will store a hash of the given secret. Keystone
will return the secret once upon creation in the same way it would if it was
generated, but will not store the secret itself nor return it after the initial
creation.

A Consumer can list their existing Application Credentials:

```
GET /v3/users/{user_id}/application_credentials

{
  "application_credentials": [
    {
        "id": "aa4541d9-0bc0-44f5-b02d-a9d922df7cbd",
        "name:" "backup",
        "description": "Backup job...",
        "expires_at": "2017-11-06T15:32:17.000000",
        "project_id": "1a6f968a-cebe-4265-9b36-f3ca2801296c",
        "roles": [
            {
                "id": "d49d6689-b0fc-494a-abc6-e2e094131861",
                "name": "Member"
            }
        ]
    }
  ]
}
```

A Consumer can get information about a specific existing Application Credential:

```
GET /v3/users/{user_id}/application_credentials/{application_credential_id}

{
  "application_credentials": [
    {
        "id": "aa4541d9-0bc0-44f5-b02d-a9d922df7cbd",
        "name:" "backup",
        "description": "Backup job...",
        "expires_at": "2017-11-06T15:32:17.000000",
        "project_id": "1a6f968a-cebe-4265-9b36-f3ca2801296c",
        "roles": [
            {
                "id": "d49d6689-b0fc-494a-abc6-e2e094131861",
                "name": "Member"
            }
        ]
    }
  ]
}
```

A Consumer can delete one of their own existing Application Credential to
invalidate it:

```
DELETE /v3/users/{user_id}/application_credentials/{application_credential_id}
```

> **Note**
>
> Application Credentials that expire will be deleted. The alternative would be
> to allow them to accumulate for forever in the hopes that keeping them around
> will make investigation as to why an Application is not working easier, but
> the only real benefit to this is providing a different error message. More
> thought and feedback on this are needed, but are not essential for the first
> round of work.

When the Creating User for an Application Credential is deleted, or if their
roles on the Project to which the Application Credential is scoped are
unassigned, that Application Credential is also deleted.

Aside from deletion, Application Credentials are immutable and may not be
modified. Using an Application Credential to Obtain a Token

An Application Credential can be used for authentication to request a scoped
token following Keystone's normal authorization flow. For example:

```
POST /v3/auth/tokens

{
    "auth": {
        "identity": {
            "methods": [
                "application_credential"
            ],
            "application_credential": {
                "id": "aa4541d9-0bc0-44f5-b02d-a9d922df7cbd",
                "secret": "a49670c3c18b9e079b9cfaf51634f563dc8ae3070db2..."
            }
        }
    }
}
```

Keystone will validate the Application Credential by matching a hash of the key
secret associated with the id similar to how Keystone does Password
authentication currently.

If the Application Credential is referred to by name, it will be necessary to
provide either `user_id` or the combination of `user_name` and
`user_domain_name` so that Keystone can look up the Application Credential for
the User.

```
POST /v3/auth/tokens

{
    "auth": {
        "identity": {
            "methods": [
                "application_credential"
            ],
            "application_credential": {
                "name": "backup",
                "user": {
                    "id": "1a6f968a-cebe-4265-9b36-f3ca2801296c"
                },
                "secret": "a49670c3c18b9e079b9cfaf51634f563dc8ae3070db2..."
            }
        }
    }
}
```

As an alternative to the current use of Service Users, a Deployer could create a
single Service User and an Application Credential for each service. Or even
create a Nova user and then give each nova instance it's own Application
Credential. Although at this point the Application Credential does not have the
ability to further limit API use, the ability to start assigning Application
Credentials per-service and performing expiration and rotation may be a
desirable step forward that can be further enhanced with the addition of
restricting an Application Credential's API Access.

## Consequences

This would have a positive security impact:

- Instead of having a Service User for each service, all services can use a
  single Service User and multiple Application Credentials. This decreases the
  attack vector of gaining access to privileged operations by reducing the
  number of accounts to attack.

- Usernames and passwords are kept out of configuration files. While Application
  Credentials are still extremely sensitive, if compromised they do not allow
  attackers to glean service user password conventions from configuration.

- Application Credentials will grow the ability to have limited access, so a
  move to them is a step towards limited access credentials.

- Application Credentials can be gracefully rotated out of use and deleted
  periodically, allowing Consumers and Deployers a mechanism to prevent
  compromised Users without requiring swapping credentials in short amounts of
  time that might cause service interruption or downtime.

- Although we had long considered allowing application credentials to live
  beyond the lifetime of its creating user in order to allow seamless
  application uptime when the user leaves the team, it unfortunately poses too
  high a risk for abuse. Ensuring the application credential is deleted when the
  user is deleted or removed from the project will prevent malicious or lazy
  users from giving themselves access to a project when they should no longer
  have it.

There is an inherent risk with adding a new credential type and changing
authentication details. One such risk would be the allowing of many credentials
for the same User account.

### End user impact

- Consumers who have Applications that monitor or interact with OpenStack
  Services should be able to leverage this feature to improve the overall
  security and manageability of their Applications.
- Consumers can gracefully rotate Application Credentials for an Application
  with no downtime by creating a new Application Credential, updating config
  files to use the new Application Credential, and finally deleting the old
  Application Credential.
- Consumers who do not start using Application Credentials should experience no
  impact.

### Deployers impact

- Deployers only need to enforce security on a single Service User instead of
  multiple.
- Password rotation policies for Service Users no longer require immediately
  redeploying service configuration files. A User password change does not
  affect the existing Application Credential in the various service
  configuration files.
- Deployers can gracefully rotate Application Credentials through a deployment
  with no downtime.
