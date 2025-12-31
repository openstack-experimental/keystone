# OpenStack Keystone in Rust

The legacy Keystone identity service (written in Python and maintained upstream
by OpenStack Foundation) has served the OpenStack ecosystem reliably for years.
It handles authentication, authorization, token issuance, service catalog,
project/tenant management, and federation services across thousands of
deployments. However, as we embarked on adding next-generation identity
features—such as native WebAuthn (“passkeys”), modern federation flows, direct
OIDC support, JWT login, workload authorization, restricted tokens and
service-accounts—it became clear that certain design and performance limitations
of the Python codebase would hamper efficient implementation of these new
features.

Consequently, we initiated a project termed “Keystone-NG”: a Rust-based
component that augments rather than fully replaces the existing Keystone
service. The original plan was to implement only the new feature-set in Rust and
route those new API paths to the Rust component, while keeping the core Python
Keystone service in place for existing users and workflows.

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
    enabling Keystone to act as an OIDC Provider or integrate with external OIDC
    identity providers natively JWT login flows, enabling stateless, compact
    tokens suitable for new micro-services, CLI, SDK, and workload-to-workload
    scenarios

  - Workload Authorization, designed for service-to-service authorization in
    cloud native contexts (not just human users)

  - Restricted Tokens and Service Accounts, which allow fine-grained,
    limited‐scope credentials for automation, agents, and service accounts, with
    explicit constraints and expiry

By routing only the new flows through the Rust component we preserve the
stability and ecosystem compatibility of Keystone, while enabling a
forward-looking identity architecture. Over time, additional identity flows may
be migrated or refactored into the Rust component as needed, but our current
objective is to retain the existing Keystone Python implementation as the
trusted, mature baseline and incrementally build the “Keystone-NG” Rust service
as the complement.

We believe this approach allows the best of both worlds: the trusted maturity of
Keystone's Python code-base, combined with the modern, high-safety,
high-performance capabilities of Rust where they matter most.

## Compatibility

Highest priority is to ensure that this implementation is compatible with the
original python Keystone: authentication issued by Rust implementation is
accepted by the Python Keystone and vice versa. At the same time it is expected,
that the new implementation may implement new features not supported by the
Python implementation. In this case, it is still expected that such features do
not break authentication flows. It must be possible to deploy Python and Rust
implementation in parallel and do request routing on the web server level.

## Database

Adding new features most certainly require having database changes. It is not
expected that such changes interfere with the Python implementation to ensure it
is working correctly.

## API

Also here it is expected that new API resources are going to be added. As above
it is not expected that such changes interfere with the Python implementation to
ensure it is still working correctly and existing clients will not break.
