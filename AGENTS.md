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
- When checking code, always run `cargo check --message-format=short` or pipe the
  output to only show errors, e.g., `cargo check 2>&1 | grep -i "error"`.

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
- If a module's `tests` submodule grows past ~2000 lines, split it into
  `<module>/tests.rs` and declare it with
  `#[cfg(test)] #[path = "<module>/tests.rs"] mod tests;` in the parent file.
  Keeps large test suites from inflating the code file every read/edit
  touches (e.g. `crates/core/src/auth.rs`).

## Running `test_api` (live-server API tests)

- `cargo nextest run --profile api -p test_api` spawns SPIRE + OPA + a real
  `keystone` server via `tools/start-api.sh` as a nextest setup script, and by
  default leaves them running after the run finishes (no auto-teardown).
  Re-running without cleanup can pile up stale daemons across sessions; check
  `ps aux | grep -E 'tmp/nextest|spire-ci-test-harness'` and kill leftovers (or
  run `tools/teardown-api.sh`) before starting a fresh run if a prior run was
  interrupted/killed.
- **Never pipe the run through `tail`/`tail -N`** (e.g.
  `cargo nextest run ... | tail -200`). `tail` without `-f` buffers until EOF,
  and the setup script's long-running daemons (keystone/spire/opa) inherit the
  pipe's write fd, so it never closes even after nextest itself exits — the
  whole invocation looks permanently hung even though the test run actually
  finished. Redirect to a file instead
  (`cargo nextest run ... > /tmp/out.log 2>&1 &`) and read the file.
- The `default` domain is seeded directly in the DB at bootstrap, **not**
  created through `POST /v3/domains`. `Oauth2KeyHook` (ADR 0026) only provisions
  a domain's OAuth2 signing keys on the domain-_creation event_, so `default`
  never gets keys and `/v4/oauth2/default/jwks` and
  `/v4/oauth2/default/.well-known/openid-configuration` 404 forever. Tests
  needing real OAuth2 signing/jwks/discovery must create a fresh domain via the
  API first (key provisioning is async — poll before asserting).
- `AuthenticationResult.principal.identity` from
  `authenticate_by_password`/password auth is always `IdentityInfo::User`, never
  `IdentityInfo::Principal` (that variant is for SPIFFE/workload identities
  only). Handler code and its unit-test mocks must agree on this — a mismatch
  here doesn't fail to compile, it 500s silently at runtime with no log line (an
  unlogged `Err(_) => error_page(500, ...)` branch), so crate-level unit tests
  with a mock built the same wrong way won't catch it. Only a live-server
  request through the real password-auth path surfaces it.

## Running loadtests locally (`tests/loadtest`)

- `tools/run-loadtest-local.sh [goose args...]` sets up postgres (docker),
  SPIRE, an embedded-OPA rust `keystone`, bootstraps the admin user, seeds
  data, builds `tests/loadtest`, and runs it against `http://localhost:8080`.
  Extra args are forwarded to `load_test`, e.g.:
  `tools/run-loadtest-local.sh --users 20 --hatch-rate 4 --run-time 30s --report-file reports/run.md`.
  `tools/teardown-loadtest.sh` tears everything down; the runner calls it
  itself at the start of every run, so a stale environment from an
  interrupted run is cleaned up automatically.
- Requires a working `docker` CLI (postgres container). On a podman-only
  host, alias `docker` to `podman` and use fully-qualified image refs
  (`docker.io/postgres:17`) — an unqualified `postgres:17` fails to resolve
  without configured unqualified-search registries.
- `tests/loadtest` is excluded from the main workspace (`exclude` in root
  `Cargo.toml`) — it's a standalone crate. Build it with
  `cd tests/loadtest && cargo build`, never `cargo build -p load_test` from
  the repo root.
- **Never pipe the runner through `tail`** — same root cause as the
  `test_api` warning above: the script backgrounds SPIRE/OPA/keystone
  daemons that inherit the pipe's write fd and never let it close, so the
  whole thing looks hung even after the actual test finished. Run it via
  `nohup ... > /tmp/out.log 2>&1 &` and read the file, or poll with
  `kill -0 <pid>` in a loop.
- `keystone-manage db up` alone is **not** enough against a fresh postgres —
  it only applies versioned migrations for the drivers that ship them
  (credential, federation, k8s-auth, token-restriction, webauthn). Identity,
  role, assignment, resource, catalog etc. use entity-based schema creation
  via `keystone-manage db sync` instead. Run both, `sync` before `up`.
- `openstack_sdk`'s auth-cache (`$HOME/.osc/`, enabled by default, keyed by
  cloud-config hash) survives across server restarts. Since each run
  bootstraps a brand-new admin user, a stale cache entry would make the SDK
  replay a token for a user id that no longer exists in the fresh DB —
  surfaces as widespread, seemingly random 401/500s that have nothing to do
  with the actual server. The runner works around this by pointing
  `load_test` at an isolated `$HOME` (under `STATE_DIR`, wiped every run)
  via `HOME=`/`OS_CLIENT_CONFIG_PATH=` rather than touching your real
  `~/.osc` or `~/.config/openstack`. If you invoke the SDK some other way
  and hit "user cannot be found: `<id>`" against a freshly bootstrapped
  keystone, check `~/.osc` for a stale entry before assuming a real bug.
- `AsyncOpenStack`/`CloudConfig` accepts either a `clouds.yaml` entry
  (`OS_CLOUD=<name>`) or plain `OS_*` auth env vars
  (`OS_AUTH_URL`/`OS_USERNAME`/`OS_PASSWORD`/...) via
  `CloudConfig::from_env()` — `tests/loadtest/src/main.rs`'s
  `load_cloud_config()` prefers the env-var form whenever `OS_AUTH_URL` is
  set, falling back to `OS_CLOUD` + clouds.yaml otherwise, so a clouds.yaml
  file isn't a hard requirement to run the suite.
- Goose logs any non-2xx response into its `ERRORS`/status-code tables at
  the HTTP layer regardless of the transaction's own pass/fail logic.
  Negative-test transactions (wrong password, revoke-then-validate, rescope
  to a nonexistent project) must call `user.set_success(&mut goose.request)`
  once they've confirmed the rejection was the *expected* outcome, or the
  top-line failure percentage reads misleadingly high even though nothing
  is actually broken.
- Loadtest also runs against a keystone deployed via skaffold to local k3s
  (see `doc/src/contributor/development.md` for that setup) — skip
  `tools/run-loadtest-local.sh` entirely and point `load_test` straight at
  the cluster's exposed URL/port with `--host`, using `OS_CLOUD`/`OS_*` env
  vars matching that deployment's admin credentials.
- `tests/loadtest/sample_metrics.sh <output-file> [interval-seconds]` polls
  `kubectl top` (keystone-rs/keystone-py pods + node) and host
  free/loadavg on a loop, for correlating CPU/memory against a concurrent
  loadtest run in the skaffold k3s deployment. Requires metrics-server
  already working (`kubectl top nodes` succeeds standalone). Run it in the
  background bracketing the `load_test` invocation, then `kill` it:
  `./sample_metrics.sh /tmp/metrics.log 3 & SAMPLER=$!; load_test ...; kill "$SAMPLER"`.
  See the script's header comment for the output format and an `awk`
  one-liner to derive per-pod min/max/avg memory from it.

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

**MUST READ** doc/src/contributor/security-model.md before any changes to:

- Authentication, authorization, scope, delegation, rescope, reauth
- Tokens, credentials, EC2, application credentials, trusts
- Policy input or OPA integration

Key security invariants from the contributor security model:

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
- doc/src/contributor/development.md: Kubernetes/skaffold setup, OSC
  configuration
- doc/src/contributor/security-model.md: Security model, invariants, and reviewer
  checklist for auth/authorization
- doc/src/adr/: Architecture Decision Records
- .pre-commit-config.yaml: Linting hooks
- committed.toml: Commit message format
