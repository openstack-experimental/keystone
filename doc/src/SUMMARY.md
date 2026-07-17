# OpenStack Keystone

[Introduction](intro.md)

[Installation](install.md)

---

# Keystone internals

- [Architecture](architecture.md)
  - [Architecture decision records](adr/index.md)
    - [Record architecture decisions](adr/0001-record-architecture-decisions.md)
    - [Open Policy Agent](adr/0002-open-policy-agent.md)
    - [Sea ORM](adr/0003-sea-orm.md)
    - [v4 API](adr/0004-v4-api.md)
    - [Passkey Auth](adr/0005-auth-passkey.md)
    - [Federation IDP](adr/0006-federation-idp.md)
    - [Federation Mapping](adr/0007-federation-mapping.md)
    - [Workload Federation](adr/0008-federation-workload.md)
    - [Auth token revocation](adr/0009-auth-token-revoke.md)
    - [PCI-DSS: Failed Auth Protection](adr/0010-pci-dss-failed-auth-protection.md)
    - [PCI-DSS: Inactive Account Deactivation](adr/0011-pci-dss-inactive-account-deactivation.md)
    - [PCI-DSS: Account Password Expiration](adr/0012-pci-dss-account-password-expiry.md)
    - [Federation OIDC: Expiring Group Membership](adr/0013-federation-oidc-expiring-group-membership.md)
    - [Application Credentials](adr/0014-application-credentials.md)
    - [Kubernetes Auth](adr/0015-kubernetes-auth.md)
    - [Distributed Storage](adr/0016-raft-storage.md)
    - [Distributed Storage v2](adr/0016-v2-raft-storage.md)
    - [Security Context](adr/0017-security-context.md)
    - [Plugin linking](adr/0018-plugin-linking.md)
    - [Credentials API](adr/0019-credentials.md)
    - [Mapping Engine](adr/0020-mapping-engine.md)
    - [Api Key authentication for SCIM](adr/0021-api-key-scim.md)
    - [Rate limiting](adr/0022-rate-limiting.md)
    - [Audit](adr/0023-audit.md)
    - [SCIM v2 Resource Provisioning](adr/0024-scim-v2-provisioning.md)
    - [Dynamic Auth Plugins](adr/0025-dynamic-auth-plugins.md)
    - [OAuth2 / OIDC Provider](adr/0026-oauth2-oidc-provider.md)
    - [LDAP / Identity provider backend](adr/0027-ldap-identity-driver.md)
    - [Quorum-Bypass Emergency Operations](adr/0028-oauth2-quorum-bypass-emergency-rotation.md)
  - [Distributed Encrypted Storage](raft_storage.md)
- [Policy enforcement](policy.md)
- [Security model](security.md)
- [Security architecture review](security-architecture-review.md)
- [Fernet token]()
  - [Token payloads]()

---

# Features

- [Federation](federation/intro.md)
  - [Oidc RP mode](federation/oidc.md)
  - [JWT](federation/jwt.md)
  - [Keycloak](federation/keycloak.md)
  - [Okta](federation/okta.md)
  - [Dex](federation/dex.md)
- [Passkeys](passkey.md)
- [API-Key Authentication (SCIM)](api_key.md)
- [OAuth2 / OIDC Provider](oauth2/user.md)
  - [Administrator Guide](oauth2/admin.md)
- [SCIM v2 Provisioning](scim/admin.md)
  - [RFC 7644 Compatibility](scim/compatibility.md)
- [Kubernetes TokenReview Auth](k8s_auth.md)
- [Mapping Engine](mapping.md)
- [LDAP Identity Backend](ldap.md)

---

# Operations & Deployment

- [Administrator guide](admin.md)

---

# Plugin Development

- [Auth Plugin Development](plugins/auth.md)

---

[API](./swagger-ui.html)
[Performance comparison](performance.md)
[Developer's guide](developer.md)
