# OpenStack Keystone in Rust

## Table of Contents

- [Project documentation](#documentation)
  - [Installation guide](doc/src/install/index.md)
  - [User documentation](doc/src/user/index.md)
  - [Administrator guides](doc/src/admin/index.md)
    - [CLI documentation](doc/src/admin/cli/index.md)
  - [Configuration reference](doc/src/configuration/index.md)
  - [Contributor documentation](doc/src/contributor/index.md)
- [Configuration](#config)
- [API and OpenAPI](#api--openapi)
- [Database](#database)
- [Load testing](#load-test)
- [Trying Keystone](#trying)
- [Talks](#talks)

The Python Keystone identity service, maintained upstream by the OpenStack
community, has served the OpenStack ecosystem reliably for years.
It handles authentication, authorization, token issuance, service catalog,
project/tenant management, and federation services across thousands of
deployments. However, as we embarked on adding next-generation identity
features—such as native WebAuthn (“passkeys”), modern federation flows, direct
OIDC support, JWT login, workload authorization, restricted tokens and
service-accounts—it became clear that certain design and performance
limitations of the Python codebase would hamper efficient implementation of
these new features.

Consequently, we initiated a project termed “Keystone-NG”: a Rust-based
component that augments rather than fully replaces the existing Keystone
service. The original plan was to implement only the new feature-set in Rust
and route those new API paths to the Rust component, while keeping the core
Python Keystone service in place for existing users and workflows.

As development progressed, however, the breadth of new functionality (and the
opportunity to revisit some of the existing limitations) led to a partial
re-implementation of certain core identity flows in Rust. This allows us to
benefit from Rust's memory safety, concurrency model, performance, and modern
tooling, while still preserving the upstream Keystone Python service as the
canonical “master” identity service, routing only the new endpoints and
capabilities through the Rust component.

In practice, this architecture means:

- The upstream Python Keystone remains the main identity interface, preserving
  backward compatibility, integration with other OpenStack services, existing
  user workflows, catalogs, policies and plugins.

- The Rust “Keystone-NG” component handles new functionality, specifically:

  - Native WebAuthN (passkeys) support for passwordless / phishing-resistant MFA

  - A reworked federation service, enabling modern identity brokering and
    advanced federation semantics OIDC (OpenID Connect) Direct in Keystone,
    enabling Keystone to act as an OIDC Provider or integrate with external
    OIDC identity providers natively JWT login flows, enabling stateless,
    compact tokens suitable for new micro-services, CLI, SDK, and
    workload-to-workload scenarios

  - Workload Authorization, designed for service-to-service authorization in
    cloud native contexts (not just human users)

  - Restricted Tokens and Service Accounts, which allow fine-grained,
    limited‐scope credentials for automation, agents, and service accounts,
    with explicit constraints and expiry

By routing only the new flows through the Rust component we preserve the
stability and ecosystem compatibility of Keystone, while enabling a
forward-looking identity architecture. Over time, additional identity flows
may be migrated or refactored into the Rust component as needed, but our
current objective is to retain the existing Keystone Python implementation as
the trusted, mature baseline and incrementally build the “Keystone-NG” Rust
service as the complement.

We believe this approach allows the best of both worlds: the trusted maturity
of Keystone's Python code-base, combined with the modern, high-safety,
high-performance capabilities of Rust where they matter most.

## Documentation

The [published documentation](https://openstack-experimental.github.io/keystone/)
uses an audience-first structure inspired by Python Keystone:

- [User documentation](doc/src/user/index.md) covers APIs, authentication, and
  the client side of each user-visible feature.
- [Administrator guides](doc/src/admin/index.md) cover deployment,
  configuration, policy, storage, operations, and the operator side of each
  feature.
- [Contributor documentation](doc/src/contributor/index.md) covers architecture,
  extension points, testing, security invariants, and contribution requirements.
- Separate [installation](doc/src/install/index.md) and
  [configuration reference](doc/src/configuration/index.md) sections keep
  shared material out of audience guides. The
  [CLI documentation](doc/src/admin/cli/index.md) is grouped with operator
  guidance because both commands are administrative tools.

Architecture Decision Records and detailed feature references remain in the
documentation book and are linked from the relevant guide instead of being
duplicated.

## Config

The configuration parser accepts the OpenStack INI format and supports file,
site-variable file, and environment overrides. Keystone-NG also defines
sections for its Rust-specific services. See the
[configuration reference](doc/src/configuration/index.md) for precedence and
the current configuration sections.

## API + OpenAPI

The OpenAPI document is built directly from the server routers. The generated
specification is published at
[openapi.yaml](https://openstack-experimental.github.io/keystone/openapi.yaml)
and can be explored through the
[Swagger UI](https://openstack-experimental.github.io/keystone/swagger-ui.html).

## Database

Sea-ORM is used to access the database. SQLite, PostgreSQL, and MySQL drivers
are available. In a parallel Python/Rust deployment, each implementation
manages its own schema additions; see
[Database migrations](doc/src/install/index.md#database-migrations).

## Load test

A very brief load test is implemented in `loadtest` using `Goose` framework.
It generates test load by first incrementally increasing requests up to the
configured amount (defaults to count of the cpu cores), keeps the load for the
configured amount of time while measuring the response latency and the
throughput (RPS).

For every PR load test suite is being executed. It is absolutely clear that the
Rust implementation currently misses certain things original Keystone doe, but
the gap is being closed over the time. However test shows difference of factor
**10-100** which is already remarkable. New tests will appear to have a more
thorough coverage of the exposed API.

## Trying

Trying Keystone (assuming you have the Rust build environment or you are in the
possession of the binary is as easy as `keystone -c etc/keystone.conf -vv`

Alternatively you can try it with `docker compose -f docker-compose.yaml up`.

## Talks

Detailed introduction of the project was given as
* [ALASCA tech talk](https://www.youtube.com/watch?v=0Hx4Q22ZNFU)
* [OpenStack Summit 2025](https://www.youtube.com/watch?v=XOHYqE2HRw4&list=PLKqaoAnDyfgr91wN_12nwY321504Ctw1s&index=30)
