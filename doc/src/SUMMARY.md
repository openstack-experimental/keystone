# OpenStack Keystone

[Introduction](index.md)

---

# Installation Guides

- [Installation](install/index.md)

---

# General Information

- [General information](getting-started/index.md)
  - [Architecture](getting-started/architecture.md)
  - [Compatibility](getting-started/compatibility.md)
  - [Performance comparison](getting-started/performance.md)

---

# User Documentation

- [User guide](user/index.md)
  - [API guide](user/api.md)
  - [Authentication](user/authentication/index.md)
    - [Passkey Authentication](user/authentication/passkeys.md)
  - [Fernet tokens](user/features/fernet-tokens.md)
  - [Federation](user/features/federation/index.md)
    - [OIDC Authorization Code flow](user/features/federation/oidc.md)
    - [JWT authentication](user/features/federation/jwt.md)
  - [OAuth2 / OIDC Provider](user/features/oauth2.md)
  - [SCIM v2 Support](user/features/scim/index.md)
    - [API-Key Authentication](user/features/scim/api-keys.md)
  - [Kubernetes TokenReview Authentication](user/features/kubernetes-auth.md)
  - [Identity Mapping Rules and API](user/features/identity-mapping.md)

---

# Administrator Guides

- [Administrator guide](admin/index.md)
  - [Getting started](admin/getting-started.md)
  - [Configuration](admin/configuration.md)
  - [Operations](admin/operations.md)
  - [Command-line tools](admin/cli/index.md)
    - [`keystone`](admin/cli/keystone.md)
    - [`keystone-manage`](admin/cli/keystone-manage.md)
  - [Security](admin/security.md)
  - [API policy enforcement](admin/policy.md)
  - [Fernet tokens](admin/tokens/fernet.md)
  - [Distributed encrypted storage](admin/storage/distributed.md)
  - [Passkeys](admin/features/passkeys.md)
  - [Federation](admin/features/federation/index.md)
    - [Keycloak](admin/features/federation/keycloak.md)
    - [Okta](admin/features/federation/okta.md)
    - [Dex](admin/features/federation/dex.md)
  - [OAuth2 / OIDC Provider](admin/features/oauth2.md)
  - [SCIM v2 Support](admin/features/scim/index.md)
    - [API-Key Administration](admin/features/scim/api-keys.md)
  - [Kubernetes TokenReview Authentication](admin/features/kubernetes-auth.md)
  - [Identity Mapping Administration](admin/features/identity-mapping.md)
  - [LDAP Identity Backend](admin/features/ldap.md)
  - [Dynamic Authentication Plugins](admin/features/auth-plugins.md)

---

# Configuration Options

- [Configuration reference](configuration/index.md)
  - [Configuration options](configuration/options.md)

---

# API Reference

- [OpenAPI and Swagger UI](./swagger-ui.html)

---

# Contributor Documentation

- [Contributor guide](contributor/index.md)
  - [Local development](contributor/development.md)
  - [Testing](contributor/testing.md)
  - [API development](contributor/api-development.md)
  - [Authentication plugin development](contributor/auth-plugins.md)
  - [Security model](contributor/security-model.md)
  - [Security architecture review](contributor/security-review.md)
  - [Architecture Decision Records](adr/index.md)
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
    - [API Key authentication for SCIM](adr/0021-api-key-scim.md)
    - [Rate limiting](adr/0022-rate-limiting.md)
    - [Audit](adr/0023-audit.md)
    - [SCIM v2 Resource Provisioning](adr/0024-scim-v2-provisioning.md)
    - [Dynamic Auth Plugins](adr/0025-dynamic-auth-plugins.md)
    - [OAuth2 / OIDC Provider](adr/0026-oauth2-oidc-provider.md)
    - [LDAP identity backend](adr/0027-ldap-identity-driver.md)
    - [Quorum-Bypass Emergency Operations](adr/0028-oauth2-quorum-bypass-emergency-rotation.md)
