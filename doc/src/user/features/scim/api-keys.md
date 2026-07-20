# API-Key Authentication

SCIM API keys are domain-owned machine credentials accepted only by the SCIM
router. They are not substitutes for v3 Fernet tokens and are rejected by core
v3 and v4 endpoints.

Send the key as a bearer credential:

```text
Authorization: Bearer kscim_<secret>_<checksum>
```

The secret is shown once when an administrator creates or rotates the key. A
client must store it as sensitive material and replace it when the administrator
rotates or revokes the key.

See [SCIM v2 Support](index.md) for supported protocol behavior and the
[administrator guide](../../../admin/features/scim/api-keys.md) for lifecycle and
incident procedures.
