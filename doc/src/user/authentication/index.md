# Authentication

Keystone supports multiple authentication methods. Password and TOTP use the
v3 token API, while [passkeys](passkeys.md) use the v4 WebAuthn flow.

## Password

Password authentication uses `POST /v3/auth/tokens`:

```console
curl -i -X POST "${KEYSTONE_URL}/v3/auth/tokens" \
  -H 'Content-Type: application/json' \
  -d '{
    "auth": {
      "identity": {
        "methods": ["password"],
        "password": {
          "user": {
            "name": "admin",
            "domain": {"id": "default"},
            "password": "<password>"
          }
        }
      },
      "scope": {
        "project": {
          "name": "admin",
          "domain": {"id": "default"}
        }
      }
    }
  }'
```

Success returns `201 Created`; the token secret is in the
`X-Subject-Token` response header.

## TOTP

TOTP uses the same endpoint with method `totp`. The user supplies an existing
user ID and the current passcode:

```json
{
  "auth": {
    "identity": {
      "methods": ["totp"],
      "totp": {
        "user": {"id": "<user_id>", "passcode": "123456"}
      }
    }
  }
}
```

## Using and Managing Tokens

Send a token as `X-Auth-Token` when calling authenticated APIs. To validate a
token, send it as `X-Subject-Token` to `GET /v3/auth/tokens`; to revoke it, send
the same headers to `DELETE /v3/auth/tokens`.

Other authentication mechanisms have dedicated feature guides. Direct
application-credential authentication is not currently dispatched by the v3
token handler and is therefore not documented as supported.
