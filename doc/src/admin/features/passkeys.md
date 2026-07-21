# Passkey Administration

Passkeys are disabled by default. Configure the WebAuthn relying party before
enabling the feature:

```ini
[webauthn]
enabled = true
driver = raft
relying_party_id = identity.example.com
relying_party_name = Example Cloud
relying_party_origin = https://identity.example.com
fake_credential_hmac_key = <stable-random-secret>
```

`relying_party_id` must be an effective domain of the origin and cannot be
changed without invalidating existing credentials. The origin includes its
scheme and must match the client-visible origin.

Use a random `fake_credential_hmac_key` of at least 16 characters, keep it
stable across restarts, and configure the same value on every node. If it is
unset, Keystone creates a per-process value suitable only for single-node
development; inconsistent decoy identifiers can expose account-existence
differences.

Registration and authentication endpoints are documented in the
[passkey user guide](../../user/authentication/passkeys.md).
