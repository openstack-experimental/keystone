# AGENTS.md

You are a coding agent working on the OpenStack Keystone Rust implementation.

## Core Constraints

- Use `cargo test -p <crate>` for unit tests.
- Use `cargo test -p test_integration` for integration tests,
  `cargo nextest -p test_integration --profile raft` for integration tests with
  raft drivers enabled.
- Always specify crate: `cargo <cmd> -p <crate_name>` when targeting specific
  crates
- Follow Domain-Driven Design: domains (identity, catalog, role, etc.) are in
  separate crates
- Policy files follow convention: `policy/<domain>/<resource>/<action>.rego`

## Workspace Structure

- `crates/keystone/`: Main service binary and API handlers (`src/api/vX/`)
- `crates/core/`: Domain providers and backend trait definitions
- `crates/core-types/`: Shared data structures across workspace
- `crates/api-types/`: API request/response models and conversions
- `crates/*-sql/`: Sea-ORM persistence drivers (e.g., `identity-sql`,
  `catalog-sql`)
- `crates/*-raft/`: OpenRaft distributed storage drivers
- `crates/storage/`: Distributed storage implementation (OpenRaft)
- `crates/config/`: Configuration parsing
- `crates/webauthn/`: WebAuthn/Passkey support extension
- `policy/`: OPA Rego policy files
- `doc/src/adr/`: Architecture Decision Records

## Tooling Commands

- **Build**: `cargo build -p <crate>` or `cargo build` (workspace)
- **Unit tests**: `cargo test -p <crate>`
- **Integration tests (raft)**:
  `cargo nextest run -p test_integration --profile raft`
- **API tests**: `cargo nextest run --profile api -p test_api` (requires SPIRE,
  OPA)
- **Format**: `cargo fmt`
- **Lint**: `cargo clippy -p <crate> --fix --allow-dirty`

## Code Quality Rules

- **Forbidden**: `unwrap()`, `expect()`, `println!`, `unsafe` (workspace lints)
- **Required**: Apache-2.0 license header on every source file
- **Error handling**: Use `thiserror` for error types, propagate with
  `Result<T, E>`
- **Async**: Heavily async codebase, built on `tokio`
- **Pass by reference** when receiver doesn't need ownership

## Backend Trait Convention

Backend traits in `crates/core/src/backend.rs` follow CRUD naming:

- Create: `create_<resource>`
- Read single: `get_<resource>`
- Read multiple: `list_<resources>`
- Update: `update_<resource>`
- Delete: `delete_<resource>`

## API Development

- One HTTP handler per module
- Unit tests live in same module's `tests` submodule
- CRUD handlers require >=3 tests: valid auth + positive/negative policy,
  invalid auth
- Policy enforcement via OPA Rego in `policy/` directory

## Commit Message Rules

- **Format**: Conventional Commits (`type: subject body`) enforced by
  `committed` pre-commit hook
- **Style**: See `committed.toml`: `style="conventional"`
- **Types**: Use standard conventional commit types: `feat`, `fix`, `chore`,
  `docs`, `test`, etc.
- **Scope**: Optional scope in parentheses: `feat(identity): message`
- **Subject line**: <=72 characters, **capitalized**, imperative mood, no period
  at end
- **Body**: <=72 characters per line, each line separated by blank line
- **DCO**: Always include `Signed-off-by:` line using `git commit -s`
- **Merge commits**: Not allowed (`merge_commit = false`)
- **Pre-commit**: Run `committed` hook via `pre-commit run --all-files` to
  validate

## Security Requirements

**MUST READ** doc/src/security.md before any changes to:

- Authentication, authorization, scope, delegation, rescope, reauth
- Tokens, credentials, EC2, application credentials, trusts
- Policy input or OPA integration

Key security invariants from security.md:

- **Security decisions MUST be keyed on authentication chain (immutable), NEVER
  on token scope**
- Delegation facts must come from `sc.authentication_context()`, not scope
- Delegated policy rules must compare to
  `input.credentials.delegated_project_id`
- Scope-drift tripwire:
  `credentials.project_id == credentials.delegated_project_id`
- Effective roles are always bounded by the delegation
- Secrets must be stripped from policy input (no EC2 keys/TOTP seeds in OPA)
- List endpoints must re-check each item individually with per-item read policy

## References

For detailed setup and environment configuration, see:

- CONTRIBUTING.md: Development commands, workspace structure, design patterns
- doc/src/developer.md: Kubernetes/skaffold setup, OSC configuration
- doc/src/security.md: Security model, invariants, and reviewer checklist for
  auth/authorization
- doc/src/adr/: Architecture Decision Records
- .pre-commit-config.yaml: Linting hooks
- committed.toml: Commit message format
