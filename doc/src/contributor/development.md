# Local Development

Running the complete service locally requires a database and Open Policy Agent
(OPA). Docker Compose and Skaffold provide those dependencies.

## Prerequisites

- Stable Rust toolchain
- `pre-commit`
- `cargo-nextest` for integration profiles
- SPIRE for live API tests
- Optional Skaffold and a Kubernetes cluster for the full deployment

Install repository hooks after cloning:

```console
pre-commit install
```

## Local Build

Always name the crate for crate-specific Cargo commands:

```console
cargo build -p openstack-keystone
cargo check -p openstack-keystone --message-format=short
cargo test -p openstack-keystone
```

## Skaffold

The Skaffold configuration can deploy Keystone-NG, Python Keystone, OPA, the
database, and supporting identity providers to a local Kubernetes cluster:

```console
skaffold dev --default-repo localhost:5000 -p local
```

Use `--cleanup=false` when resources must remain after Skaffold exits. The
repository configuration exposes mixed, Rust-only, and Python-only endpoints;
consult `skaffold.yaml` for the current modules and profiles.

## OpenStackClient

Point an OpenStackClient cloud entry at the deployment's Rust or mixed endpoint
and provide the configured domain, project, username, and password. Use the
generated [OpenAPI reference](../swagger-ui.html) when testing Keystone-NG-only
v4 routes that OSC does not expose.

## Submission

Run the relevant tests, `pre-commit run --all-files`, and
`git diff --check`. Commits use Conventional Commits and must include the DCO
sign-off with `git commit -s`.
