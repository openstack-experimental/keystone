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
- [Policy enforcement](policy.md)
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
- [Kubernetes TokenReview Auth](k8s_auth.md)
- [Mapping Engine](mapping.md)

---

[API](./swagger-ui.html)
[Performance comparison](performance.md)
[Developer's guide](developer.md)
