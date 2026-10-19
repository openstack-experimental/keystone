# Contributor Documentation

This section is for developers changing Keystone-NG itself.

- [Local development](development.md) covers prerequisites and complete local
  environments.
- [Testing](testing.md) lists the supported unit, integration, Raft, and live API
  test workflows.
- [API development](api-development.md) explains crate ownership, handler and
  policy conventions, and OpenAPI generation.
- [Authentication plugin development](auth-plugins.md) documents the WASM
  plugin interface.
- [Security model](security-model.md) is the normative reference for changes to
  authentication, authorization, delegation, tokens, credentials, and policy
  input.
- [Security architecture review](security-review.md) records additional threat
  analysis and proposed gates.
- [Cyber Resilience Act requirements](cra-requirements.md) derives EU CRA
  obligations and compares the Python and Rust implementations.
- [Cybersecurity policy](cybersecurity-policy.md) states the project's CRA role
  (open-source steward) and vulnerability handling.
- [CRA Art. 14 reporting runbook](cra-art14-runbook.md) explains what the
  project gives downstream manufacturers for Art. 14 reporting.
- [Architecture Decision Records](../adr/index.md) contain accepted and proposed
  design decisions.

Read [CONTRIBUTING.md](https://github.com/openstack-experimental/keystone/blob/main/CONTRIBUTING.md)
before submitting a change.
