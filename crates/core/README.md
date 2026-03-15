# OpenStack Keystone in Rust

The legacy Keystone identity service (written in Python and maintained upstream
by OpenStack Foundation) has served the OpenStack ecosystem reliably for years.
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

Project documentation can be found [here](https://openstack-experimental.github.io/keystone).
It is a work in progress. Target is to provide a comprehensive documentation of
the new functionality and provide missing insides to the python Keystone
functionality with Architecture Decision Records, Specs, Thread analysis and
many more.

## Config

It is supposed, that the configuration for the python Keystone can be used
without changes also for the rust implementation.

## Api + OpenAPI

OpenAPI are being built directly from the code to guarantee the documentation
matches the implementation.

## Database

Sea-ORM is being used to access database. PostgreSQL and MySQL are supported.
Functional tests [would] test the compatibility.

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
