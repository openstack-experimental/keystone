# Identity and Access Management for clouds

IAM stands for Identity and Access Management. The project began as an extension
to OpenStack Keystone that added better federation growing into a partial
drop-in replacement for it. Because OpenStack does not list Rust as an approved
language, the project has refocused as a general-purpose IAM service that
OpenStack deployers can run alongside Keystone.

## Table of Contents

- [Background](#background)
- [Why a dedicated IAM service](#why-a-dedicated-iam-service)
- [Architecture](#architecture)
- [Documentation](#documentation)
- [Configuration and database](#configuration-and-database)
- [Load test](#load-test)
- [Trying IAM](#trying-iam)
- [Talks](#talks)

## Background

The Python Keystone identity service, maintained upstream by the OpenStack
community, has served the OpenStack ecosystem reliably for years. It handles
authentication, authorization, token issuance, service catalog, project/tenant
management, and federation across thousands of deployments.

However, as we began adding next-generation identity features - such as native
WebAuthn (“passkeys”), modern federation flows, direct OIDC support, JWT login,
workload authorization, restricted tokens and service accounts - it became clear
that certain design and performance limitations of the Python codebase would
hamper their efficient implementation.

The original plan was to implement only the new feature set in Rust and route
the new API paths to it, leaving the Python Keystone service in place for
existing users and workflows. As development progressed, the breadth of the new
functionality, and the opportunity to revisit some existing limitations, led to
a re-implementation of the core identity flows in Rust as well. This brings
Rust's memory safety, concurrency model, performance and modern tooling to the
whole service, not only to the new features.

## Why a dedicated IAM service

A common question is why a cloud needs an IAM service at all when an identity
provider (IdP) such as Keycloak, Entra ID, Okta or Dex can already authenticate
users. The answer is that an IdP and an IAM service solve different halves of
the problem.

An IdP answers **"who are you?"**. It verifies a password, a passkey or an
upstream assertion and hands back a signed statement about an identity. It knows
nothing about the resources in the cloud, so it cannot answer **"what may you do
here?"**. An IAM service owns that second half, and it is hard to move into an
IdP for these reasons:

- **Authorization is resource-aware.** Roles are granted on projects, domains
  and the system, and are then evaluated against the resources of each service
  (compute, networking, storage, ...). An IdP's groups and claims are global to
  the identity, not scoped to a tenant's project. Someone has to track which
  project exists, who may act in it, and what changes when a project is moved or
  deleted. That state lives next to the resources, not in the IdP.
- **Tenancy is a cloud concept.** Domains, projects, role assignments,
  inheritance, implied roles and delegation chains have no equivalent in generic
  OIDC/SAML products. Mapping them onto realms or groups loses the semantics the
  services rely on.
- **Delegation needs a trusted issuer close to the cloud.** Application
  credentials, trusts, restricted tokens, service accounts and token exchange
  let a user hand a bounded slice of their authority to automation or another
  service. The limits must be enforced by the same system that decides
  authorization, and they must stay valid, or be revoked, as assignments change.
- **Services need a catalog and a common token contract.** Every OpenStack
  service validates tokens, resolves endpoints and applies policy through the
  same API. An IdP offers none of this, and replacing it means changing every
  consumer.
- **Revocation and consistency are cloud-wide.** Removing a role, disabling a
  user or deleting a project must take effect for outstanding credentials in
  every service. An IdP session ending does not do that for credentials already
  issued to workloads.
- **Workloads are not people.** Cloud-native services, agents and automation
  authenticate with SPIFFE identities, JWTs and service accounts. They need
  authorization decisions made per request, with auditability, which is outside
  the scope of a user-login product.
- **Operational independence.** The cloud's control plane should keep working
  when an external IdP is slow, unreachable or being migrated. A local IAM
  service can cache and bound that dependency, whereas a design that delegates
  everything to the IdP turns its outage into a cloud outage.

The two are complementary. IAM integrates with external IdPs through OIDC and
federation, so organizations keep their corporate identity source for
authentication, while IAM maps those identities onto cloud tenancy, issues
scoped and delegated credentials, and enforces authorization.

This is why the project is necessary: the existing OpenStack Keystone predates
modern identity standards (OAuth 2.0, OIDC, JWT, SPIFFE) and keeps them at the
edges, while a plain IdP cannot supply the cloud-specific authorization and
delegation model. IAM brings the standards to the core and keeps that model. See
the [vision](doc/src/vision.md) and its
[executive summary](doc/src/vision-executive-summary.md) for the full reasoning.

## Architecture

IAM is a standalone service that speaks the OpenStack Keystone APIs and adds its
own. It can be deployed in two ways:

- **Alongside Python Keystone.** Requests for the new functionality are routed
  to IAM, while Python Keystone continues to serve existing OpenStack services,
  workflows, catalogs, policies and plugins. This allows IAM to be adopted
  incrementally without disturbing existing deployments.
- **On its own.** IAM serves the identity flows it implements directly, for
  deployments that do not need the Python service.

IAM provides the following functionality:

- Native WebAuthn (passkeys) support for passwordless, phishing-resistant MFA.
- A reworked federation service, enabling modern identity brokering and advanced
  federation semantics.
- OIDC Direct, enabling IAM to act as an OpenID Connect (OIDC) provider or to
  integrate natively with external OIDC identity providers.
- JWT login flows, enabling stateless, compact tokens suitable for new
  microservices, CLIs, SDKs and workload-to-workload scenarios.
- Workload authorization, designed for service-to-service authorization in
  cloud-native contexts (not just human users).
- Restricted tokens and service accounts, which allow fine-grained,
  limited-scope credentials for automation, agents and services, with explicit
  constraints and expiry.
- Full OAuth2 OpenID Provider (OP) functionality.

IAM combines the maturity of the Keystone APIs with the safety and performance
of Rust.

## Documentation

The [published documentation](https://cloud-plane.github.io/iam/) uses an
audience-first structure:

- [User documentation](doc/src/user/index.md) covers APIs, authentication, and
  the client side of each user-visible feature.
- [Administrator guides](doc/src/admin/index.md) cover deployment,
  configuration, policy, storage, operations, and the operator side of each
  feature.
- [Contributor documentation](doc/src/contributor/index.md) covers architecture,
  extension points, testing, security invariants, and contribution requirements.
- Separate [installation](doc/src/install/index.md) and
  [configuration reference](doc/src/configuration/index.md) sections keep shared
  material out of audience guides. The
  [CLI documentation](doc/src/admin/cli/index.md) is grouped with operator
  guidance because both commands are administrative tools.

Architecture Decision Records and detailed feature references remain in the
documentation book and are linked from the relevant guide instead of being
duplicated.

## Configuration and database

The configuration parser accepts the OpenStack INI format and supports file,
site-variable file, and environment overrides. IAM also defines sections for its
Rust-specific services. See the
[configuration reference](doc/src/configuration/index.md) for precedence and the
current configuration sections.

IAM uses Sea-ORM for database access, with SQLite, PostgreSQL, and MySQL drivers
available. In a parallel Python/Rust deployment, each implementation manages its
own schema additions; see
[Database migrations](doc/src/install/index.md#database-migrations).

## Load test

IAM ships with an extensive load test suite in `tests/loadtest`, built on the
[Goose](https://book.goose.rs/) framework. It exercises the exposed API with
realistic request mixes, ramping the load up to the configured level, holding it
for the configured time, and reporting response latency and throughput (RPS).

In these tests IAM outperforms the Python Keystone implementation by a factor of
**10-100** and scales better under concurrent load.

## Trying IAM

Trying IAM is as easy as `keystone -c etc/keystone.conf -vv`, provided you have
the Rust build environment or a prebuilt binary.

Alternatively, you can try it with `docker compose -f docker-compose.yaml up`.

## Talks

The project is introduced in detail in these talks:

- [ALASCA tech talk](https://www.youtube.com/watch?v=0Hx4Q22ZNFU)
- [OpenStack Summit 2025](https://www.youtube.com/watch?v=XOHYqE2HRw4&list=PLKqaoAnDyfgr91wN_12nwY321504Ctw1s&index=30)
- Sovereign Cloud Days Saarbruecken 2026
- ALASCA Summit 2026

---

OpenStack and Keystone are trademarks of The Linux Foundation. See the OpenInfra
[trademark policy](https://www.openinfra.org/legal/trademark-policy/). More on
Keystone at <https://www.openstack.org/> and
<https://docs.openstack.org/keystone/latest/>.
