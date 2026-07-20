# Security Guidance

- Terminate public TLS at a trusted proxy and isolate the plain HTTP listener.
- Restrict the admin Unix socket and SPIFFE identities to trusted operators.
- Keep the metrics listener on a monitoring network.
- Keep OPA enabled in production and treat the policy bundle as trusted code.
- Store Fernet, credential, OAuth2 signing, audit, and distributed-storage keys
  as secrets; never print their contents during verification.
- Keep `insecure_allow_null_key = false` except during a controlled migration.
- Use PKCS#11 or TPM KEK protection and authenticated transport for production
  distributed storage.
- Configure stable, cluster-wide WebAuthn decoy-key material to prevent account
  enumeration differences between nodes.

The [contributor security model](../contributor/security-model.md) is normative
for scope, delegation, rescope, credentials, tokens, and OPA input. Operator
procedures must not weaken those invariants.
