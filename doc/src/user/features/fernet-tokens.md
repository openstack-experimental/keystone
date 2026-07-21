# Fernet Tokens for API Consumers

Fernet is Keystone-NG's default v3 token format. Clients treat the value as an
opaque bearer credential: do not parse it, log it, or depend on its encoded
shape.

Use the token from the `X-Subject-Token` response header as `X-Auth-Token` on
later requests. Validation and revocation use the v3 token operations described
in [Authentication](../authentication/index.md#using-and-managing-tokens).

Tokens expire according to deployment policy and may stop working after
revocation or key-retention changes. Obtain a new token instead of persisting a
Fernet token as a long-lived application secret.

Operators should use the [Fernet administrator guide](../../admin/tokens/fernet.md)
for key setup and rotation.
