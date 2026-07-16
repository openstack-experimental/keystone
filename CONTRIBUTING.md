# How to contribute

We are really glad you're reading this, because we need volunteer developers to
help this project come to fruition.

## Communications

- [OpenStack contribution guide](https://docs.openstack.org/contributors/index.html)
- [GitHub issues](https://github.com/openstack-experimental/keystone/issues)
- IRC: `chat.oftc.net` channel
  [#openstack-keystone](https://docs.openstack.org/contributors/common/irc.html)
  (we're spread across the globe, hopefully close to your TZ)

## Prerequisites

- Rust toolchain (stable)
- [pre-commit](https://pre-commit.com/) for linting hooks
- [cargo-nextest](https://nexte.st/) for integration tests
- [SPIRE](https://github.com/spiffe/spiffe.io) (`spire-server` and `spire-agent`
  on `$PATH`) for API integration tests
- (Optional) [skaffold](https://skaffold.dev/) and a local Kubernetes cluster
  for full-stack testing
- (Optional)
  [OpenStackClient](https://docs.openstack.org/python-openstackclient/) (`osc`)
  for manual auth flow verification

## Setup

### Pre-commit hooks

Install the pre-commit hooks after cloning:

```console
pre-commit install
```

The hooks run on every commit and enforce the following checks (see
`.pre-commit-config.yaml`):

| Hook               | Purpose                                                                                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pre-commit-hooks` | End-of-file fixes, trailing whitespace, line endings (LF only), BOM removal, shebang checks, merge conflict detection, debug statements, YAML/JSON validation |
| `typos`            | Spell checking                                                                                                                                                |
| `committed`        | Enforces conventional commit message format                                                                                                                   |
| `cargo fmt`        | Rust code formatting                                                                                                                                          |
| `gitleaks`         | Secret/credential detection                                                                                                                                   |

Run hooks manually on all files:

```console
pre-commit run --all-files
```

## Development Commands

| Action            | Command                                                                                                       |
| ----------------- | ------------------------------------------------------------------------------------------------------------- |
| Build workspace   | `cargo build`                                                                                                 |
| Run all tests     | `cargo test`                                                                                                  |
| Single crate      | `cargo <cmd> -p <crate_name>` (e.g. `cargo test -p openstack-keystone`)                                       |
| Specific test     | `cargo test -p <crate_name> <test_path>` (e.g. `cargo test -p openstack-keystone test_module::some_function`) |
| Format            | `cargo fmt`                                                                                                   |
| Lint              | `cargo clippy -p <crate_name> --fix --allow-dirty`                                                            |
| Integration tests | `cargo nextest run -p test_integration` (add e.g. `--profile raft`)                                           |

### API integration tests

Requires a live server and SPIRE installed.

```console
cargo nextest run --profile api -p test_api
```

- The `api` profile starts a live keystone server via `tools/start-api.sh`,
  bootstraps it, and runs the `integration_api_v3` and `integration_api_v4` test
  binaries.
- **Prerequisites**: `spire-server` and `spire-agent` must be on `$PATH`.
- **Server logs**: `/tmp/nextest/keystone/` (the `log_dir` from `[DEFAULT]` in
  the auto-generated keystone.conf)
- **SPIRE logs**: `/tmp/spire-ci-test-harness/server.log` and
  `/tmp/spire-ci-test-harness/agent.log`
- **Server endpoints**:
  - Public API: `http://localhost:8080`
  - Admin socket: `/tmp/nextest/keystone/keystone.sock`
  - Admin auth: `admin` / `password` (domain: `default`, project: `admin`)
- Logs are preserved after test completion. Stop with `./tools/teardown-api.sh`.
  Full cleanup: `rm -rf /tmp/nextest/keystone /tmp/spire-ci-test-harness`.

## Advanced Development Environments

### Skaffold + Kubernetes

For full-stack local testing (Keystone, OPA, database, and Python Keystone), use
[skaffold](https://skaffold.dev/) to deploy to a local Kubernetes cluster. This
is the recommended way to test compatibility with the Python Keystone and run
API tests against a live system.

An image registry accessible by Kubernetes is required. If your K8s doesn't
include one,
[deploy a local registry](https://www.docker.com/blog/how-to-use-your-own-registry-2/).

```console
skaffold dev --default-repo localhost:5000 -p local
```

Add `--cleanup=false` to preserve resources when stopping.

**Exposed endpoints** (add to `/etc/hosts` if needed):

| URL                        | Description                  |
| -------------------------- | ---------------------------- |
| `http://keystone.local`    | Mixed routes (Python + Rust) |
| `http://keystone-rs.local` | Rust version only            |
| `http://keystone-py.local` | Python version only          |

Run API tests against K8s-deployed Keystone:

```console
KEYSTONE_URL=http://keystone-rs.local cargo nextest run --test api
```

**Full build/deploy/verify cycle** (useful for K8s auth and federation tests):

```console
skaffold build --profile local --default-repo localhost:5000 --output-file build.artifacts
skaffold deploy -a build.artifacts
skaffold verify -a build.artifacts
```

**Module-level redeploy** (skip infra like keycloak/dex/selenium):

```console
skaffold deploy -a build.artifacts -m keystone
```

The skaffold config splits into `keystone` and `infra` modules to avoid
redeploying all tracking labels on every change.

**Tempest identity compatibility tests** (advisory, non-blocking): a third
`tempest` module runs the OpenStack tempest identity v3 suite against both
`keystone-rs` and `keystone-py` to track v3 API compatibility gaps. Since
not every v3 operation is implemented by keystone-rs yet, this is run and
reported separately from the main verify suite and never blocks CI:

```console
skaffold verify -m tempest -a build.artifacts -v debug
```

Failing test IDs are printed in each container's log
(`===== FAILED TESTS (target=...) =====`); in CI these are also collected
into a job summary and an uploaded `tempest-identity-results` log artifact.

### OpenStackClient (OSC)

Verify authentication flows with `osc` against a deployed instance. Add
`keystone-rs.local` to `/etc/hosts`, then configure:

```yaml
clouds:
  keystone-skaff:
    auth:
      auth_url: http://keystone-rs.local
      username: admin
      password: password
      user_domain_name: Default
      project_domain_name: Default
      project_name: admin
      domain_id: default
```

## Submitting Changes

This project enforces
[Conventional Commits](https://www.conventionalcommits.org/) via the `committed`
pre-commit hook (`committed.toml`):

- **Style**: `conventional` (type: subject body)
- **Merge commits**: not allowed
- **Exceptions**: `dependabot`, `renovate`, `release-plz` authors are exempt

Always include a Signed-off-by line (`-s` flag):

```console
git commit -s -m "type: brief summary of the change

Detailed description of what changed and its impact."
```

When submitting a PR:

1. Send a
   [GitHub Pull Request](https://github.com/openstack-experimental/keystone/pull/new/main)
2. Include a clear description of changes
3. Ensure all commits are atomic (one feature per commit)
4. Ensure pre-commit hooks pass (`pre-commit run --all-files`)
5. Ensure tests pass (`cargo test` and `cargo nextest run`)
6. Ensure clippy passes (`cargo clippy -p <crate_name> --fix --allow-dirty`)
7. Ensure committed pass (`committed`) rewriting message when necessary

## Workspace Structure

| Path                | Description                                                                                                                                                                                         |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crates/keystone`   | Main service binary and API implementation. API handlers: `src/api/vX`                                                                                                                              |
| `crates/core`       | The "Brain" — provider definitions grouped by domain (Identity, Catalog, Role, Assignment, etc.). Contains `provider_api.rs` (inter-provider interface) and `backend.rs` (backend driver interface) |
| `crates/core-types` | Shared data structures across the workspace                                                                                                                                                         |
| `crates/api-types`  | API request/response models and conversions from `core-types`                                                                                                                                       |
| `crates/storage`    | Distributed storage implementation (OpenRaft)                                                                                                                                                       |
| `crates/storage-crypto` | KEK/DEK primitives shared by the storage engine: `KekProvider` trait, `EnvKek` (dev-mode), AES-GCM cipher/nonce/audit helpers                                                                   |
| `crates/storage-crypto-pkcs11` | `Pkcs11Kek` — production `KekProvider` backed by a non-extractable AES key on a PKCS#11 token/HSM (e.g. SoftHSM2, vendor HSMs)                                                            |
| `crates/storage-crypto-tpm` | `TpmKek` — production `KekProvider` backed by a TPM 2.0 resident AES key                                                                                                                     |
| `crates/*-sql`      | SQL-backed persistence drivers (e.g. `identity-sql`, `catalog-sql`) using Sea-ORM                                                                                                                   |
| `crates/*-raft`     | Raft-backed persistence drivers for distributed storage                                                                                                                                             |
| `crates/config`     | Configuration parsing                                                                                                                                                                               |
| `crates/webauthn`   | WebAuthn/Passkey support extension                                                                                                                                                                  |
| `policy/`           | OPA Rego policy files                                                                                                                                                                               |
| `doc/src/adr/`      | Architecture Decision Records                                                                                                                                                                       |

## Key Design Patterns

- **License**: Every source file must have an Apache-2.0 license header.
- **Domain-Driven Design**: Code is organized by identity domains (Identity,
  Catalog, Role, Assignment, etc.).
- **Sea-ORM**: Database access and migrations.
- **OpenRaft**: Distributed storage backend.
- **Error Handling**: `thiserror` for error types, `Result<T, E>` propagation.
- **Async/Await**: Heavily async, built on `tokio`.
- **Pass by reference** when the receiver doesn't need ownership.
- **Comments**: Code should be reasonably commented.

### Backend trait convention (`backend.rs`)

Backend traits follow a CRUD-like naming pattern:

| Operation     | Method prefix                                                      |
| ------------- | ------------------------------------------------------------------ |
| Create        | `create_<resource>`                                                |
| Read single   | `get_<resource>`                                                   |
| Read multiple | `list_<resources>`                                                 |
| Update        | `update_<resource>` (or specific actions like `add_user_to_group`) |
| Delete        | `delete_<resource>`                                                |

## API Development Rules

### Structure

- One HTTP handler per module.
- Unit tests live in the same module's `tests` submodule.

### Unit test requirements

**CRUD handlers** (at least 3 tests per handler):

1. Valid auth + positive policy decision
2. Valid auth + negative policy decision
3. Invalid auth

**Authentication handlers** (at least 1 test):

1. Successful authentication flow

### Policy Enforcement

Policy rules are OPA Rego files in `policy/`. The policy name passed to
`state.policy_enforcer.enforce()` maps to the Rego `package` identifier with
dots replaced by slashes (e.g. `identity.user.show` →
`policy/identity/user/show.rego` → invoked as `identity/user/show`).

Policy documentation must include the original Rust structure name (e.g.
`UserCreate`) for future updates.

**Input structures** (per ADR-0002):

| Operation | `input.target`       | `input.existing` | Timing          |
| --------- | -------------------- | ---------------- | --------------- |
| Create    | payload (new object) | `null`           | before creation |
| Update    | patch (changes)      | stored resource  | before update   |
| Show      | `null`               | stored resource  | after fetch     |
| Delete    | `null`               | stored resource  | before deletion |
| List      | query parameters     | `null`           | before listing  |

## Spec Documents

Every architectural change requires an ADR in `doc/src/adr/`.

## References

- [CONTRIBUTING.md](CONTRIBUTING.md) — this file
- [developer.md](doc/src/developer.md) — environment setup details (skaffold,
  OSC)
- [.pre-commit-config.yaml](.pre-commit-config.yaml) — linting hooks
- [committed.toml](committed.toml) — commit message rules
