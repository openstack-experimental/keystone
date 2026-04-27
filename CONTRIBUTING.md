# How to contribute

We are really glad you're reading this, because we need volunteer developers to
help this project come to fruition.

Here are some important resources:

- [OpenStack contribution guide](https://docs.openstack.org/contributors/index.html)
- Bugs?
  [GitHub issues](https://github.com/openstack-experimental/keystone/issues)
- IRC: chat.oftc.net channel
  [#openstack-keystone](https://docs.openstack.org/contributors/common/irc.html).
  We're spread across the globe, hopefully close to your TZ.

## Development Commands

- **Build the workspace**: `cargo build`
- **Run all tests**: `cargo test`
- **Run command for single crate**: `cargo XXX -p <crate_name>` (e.g.,
  `cargo test -p openstack-keystone`).
- **Run a specific test**: `cargo test -p <crate_name> <test_path>` (e.g.,
  `cargo test -p openstack-keystone test_module::some_function`)
- Run integration tests: `cargo nextest run` (add e.g., `--profile postgres` to
  use postgres for sql drivers).
- **Linting**: `cargo clippy -p <crate_name> --fix --allow-dirty`
- **Formatting**: `cargo fmt`

## Key Design Patterns

- **License**: Every source file has an apache-2.0 license header.
- **Domain-Driven Design**: The codebase is organized around identity domains
  (Identity, Catalog, Role, Assignment, etc.).
- **Sea-ORM**: Used for database access and migrations.
- **OpenRaft**: Distributed storage
- **Error Handling**: Use `thiserror` for all error types and `Result<T, E>` for
  the error propagation.
- **Async/Await**: The project is heavily asynchronous, built on top of `tokio`.
- **Policy Enforcement**: Uses Open Policy Agent (OPA) logic, with `.rego` files
  located in the `policy/` directory.
- Pass by reference when receiver is not supposed to take ownership.
- Code should be reasonably commented.

## Workspace Structure and principles

- `crates/keystone`: The main service binary and the API implementation.
  - `crates/keystone/src/api/vX` - API handlers for the API version.
- `crates/core`: The "Brain" - defines set of "providers" grouping functionality
  by the corresponding module (feature/domain) just like the python Keystone
  does.
  - The `provider_api.rs` defines the provider interface which is used by
    providers to communicate with each other and are invoked by the API.
  - the `backend.rs` defines the interface that backend drivers (usually
    covering persistence operations for the resource) must implement.
  - `backend.rs` traits implement resource management operations following a
    pattern similar to CRUD:
    - Creation: `create_<resource>`.
    - Retrieval: `get_<resource>`, `list_<resources>`.
    - Modification: `update_<resource>` or specific actions like
      `add_user_to_group`.
    - Deletion: `delete_<resource>`.
- `crates/core-types`: Shared data structures used across the workspace.
- `crates/api-types`: API data models and conversions from `core-types`.
- `crates/storage`: Distributed storage implementation (using Raft).
- `crates-*`: SQL-backed crates (e.g., `identity-sql`, `catalog-sql`) that
  handle persistence for specific domains using Sea-ORM.
- `crates/config`: Configuration parsing.
- `crates/webauthn`: WebAuthn/Passkey support extension.
- `crates/*-sql`: SQL backend drivers for providers.
- `crates/*-raft`: Raft backend drivers for providers.

## API Development rules

- 1 http handler per module.
- Unit tests must be in the same module (tests submodule).
  - for regular API calls (CRUD):
    - at least one unittest with valid authentication and positive policy
      decision.
    - at least one unittest with valid authentication and negative policy
      decision.
    - one unittest with invalid authentication.
  - for authentication handlers:
    - at least one successful unittest.
- Policy Enforcement rules (`state.policy_enforcement.enforce`):
  - For create operation the new object is passed to enforcer before the
    creation.
  - For remove operation first the current state is fetched, it is then passed
    to the policy enforcer followed by the real deletion.
  - For list operation query parameters are passed to the enforcer before
    listing.
  - For show operation current state is fetched and passed to the enforcer
    before returning the result.
  - For update operation current resource state and new state are passed to the
    enforcer.

## Spec documents

- Every architectural change must have the ADR specs located in the
  `doc/src/adr` directory.

## Submitting changes

Please send a
[GitHub Pull Request](https://github.com/openstack-experimental/keystone/pull/new/main)
with a clear list of what you've done (read more about
[pull requests](http://help.github.com/pull-requests/)). Please follow our
coding conventions (below) and make sure all of your commits are atomic (one
feature per commit).

Since our target for the project is to become official OpenStack project we
would require Signed-off in the commit message sometime soon.

Always write a clear log message for your commits. One-line messages are fine
for small changes, but bigger changes should look like this:

    $ git commit -s -m "A brief summary of the commit
    >
    > A paragraph describing what changed and its impact."
