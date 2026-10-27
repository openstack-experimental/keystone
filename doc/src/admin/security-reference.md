# Security reference

Reference tables for operators and for downstream manufacturers who integrate
Keystone into a product. They complement the checklist in
[Security](security.md) and back the Cyber Resilience Act mapping in
[CRA requirements](../contributor/cra-requirements.md). Every row states
behaviour verified against the code at the time of writing; a row marked
**Gap** is a known weakness, not a recommendation.

- [Secure defaults](#secure-defaults)
- [Interfaces and ports](#interfaces-and-ports)
- [Failure semantics](#failure-semantics)
- [Encryption coverage](#encryption-coverage)
- [Data inventory](#data-inventory)
- [Data removal](#data-removal)
- [Release build hardening](#release-build-hardening)

## Secure defaults

One row per option that weakens the deployment when changed, or that is off by
default and should be turned on.

| Option | Default | Effect of the default | Recommended |
| --- | --- | --- | --- |
| `[fernet_tokens] insecure_allow_null_key`, `[credential] insecure_allow_null_key` | `false` | Keystone refuses to start with the well-known Null Key. | Keep `false`; set `true` only during a controlled key migration. |
| `[distributed_storage] dev_mode` | `false` | KEK source and process hardening pre-flight checks are enforced. | Never set in production. |
| `[distributed_storage] kek_provider` | `env` | The `env` KEK is accepted **only** with `dev_mode = true`, so a production node does not start until `pkcs11` or `tpm` is set explicitly. | `pkcs11` or `tpm`. |
| `[distributed_storage] local_reads_mode` | `disabled` | Every read is linearizable; no stale reads. | Keep `disabled` unless a consumer needs stale `PUBLIC`/`INTERNAL` reads. |
| `[api_policy]` | OPA at `http://localhost:8181` | Every authorised endpoint is evaluated by OPA. | Run OPA beside Keystone; see [policy](policy.md). |
| `[api_policy] enable` | `true` | **Accepted but not read.** The enforcer is always created, so policy cannot be switched off through this key. | Do not rely on it. |
| `[rate_limit_global_ip]`, `[rate_limit_user_auth]` and the other `[rate_limit_*]` sections | `enabled = false`, `burst_size = 100`, `replenish_rate_per_second = 10` | **Gap.** No limiter is active until a section is enabled. Limits are per node and held in memory (ADR 0022). | Enable `[rate_limit_global_ip]` and `[rate_limit_user_auth]` and size them for the deployment. Enabled values outside `1..=100000` stop startup. |
| `[rate_limit_trusted_proxies] trusted_proxies` | empty | No forwarding header is trusted; the peer address is used. | List only the proxies that sanitise the header, and set `trusted_header`. |
| `[interface_admin]` | not configured | The admin interface is not started. When configured it is a Unix socket only, with optional `peer_uid` and `peer_gid` checks. | Configure `peer_uid` or `peer_gid`, and restrict the socket directory. |
| `[interface_internal]` | not configured | No second TCP listener. | Configure only when a separate trust zone is needed. |
| `[DEFAULT] debug` | `false` | No DEBUG log level for the file sink. | Keep `false` in production. |
| `[interface_metrics] http_requests_enabled` | `true` | HTTP request metrics are recorded. | Keep. |

Container images run as the unprivileged user `keystone` (uid and gid 65532).
The reference manifests under `deploy/` run non-root with a read-only root
filesystem and no capabilities; see
[Verifying release artifacts](verify-artifacts.md) for the image digests.

## Interfaces and ports

Keystone does not terminate public TLS. Put a trusted proxy in front of the
public listener.

| Interface | Config section | Default bind | Transport and authentication | Notes |
| --- | --- | --- | --- | --- |
| Public REST | `[interface_public]` | `0.0.0.0:8080` when the section is absent; `0.0.0.0:8081` when the section is present without `tcp_address` | `type = http` (default, plain HTTP, bearer tokens) or `type = spiffe` (mTLS with trust domains) | Set `tcp_address` explicitly. |
| Internal REST | `[interface_internal]` | `0.0.0.0:8080` when the section is present without `tcp_address` | Same `type` choices as public | Disabled when the section is absent. |
| Admin | `[interface_admin]` | Unix socket `/var/lib/keystone/keystone.sock` | SPIFFE mTLS over the socket, plus `peer_uid` and `peer_gid` | `admin_svid` maps a matching SVID to the system admin role. Used for bootstrap. |
| Health and metrics | `[interface_metrics]` | `0.0.0.0:8099` | Plain HTTP, no authentication: `/health`, `/ready`, `/metrics` | Bind to a monitoring network. |
| Raft peer | `[distributed_storage] node_listener_addr` | `0.0.0.0:8081` | gRPC with mTLS, SPIFFE or certificate based | Only with distributed storage. Needs a node-specific port when it shares a host with the public listener. |
| Database | `[database]` | outbound | TLS through system OpenSSL (NET-3) | Operator-managed. |
| OPA | `[api_policy] opa_base_url` | outbound, `http://localhost:8181` | HTTP, or a Unix socket URL | Keep on loopback or a Unix socket. With `opa_policies_path` set, Keystone starts OPA itself. |
| Auth plugins | `[auth_plugins]` | in-process WASM | Capability list and SHA-256 artefact pinning (TOK-10) | Pre-authentication attack surface; load only reviewed plugins. |

The public and internal listeners default to the same port family. The default
for the *public* listener depends on whether its section exists, which is easy
to misread; always set `tcp_address`.

## Failure semantics

Keystone fails closed. A dependency outage denies or stops work; it never
widens access.

| Dependency is unreachable | Behaviour | Signal |
| --- | --- | --- |
| OPA | The decision cannot be made, so the request fails with `500`. Only a real OPA `deny` returns `403`. No request is allowed without a decision. | `/ready` reports the policy engine; the policy `errors_total` metric counts the failure. |
| Database | Requests that need it fail. | `/ready` returns `503` for a degraded database. |
| Audit queue | A provider operation whose `attempt` audit record cannot be queued is **not performed**. Perimeter records are best effort and are dropped and counted when the channel is full. | `keystone_audit_*` metrics; see [Audit trail](features/audit.md). |
| KEK provider (PKCS#11, TPM) | A node cannot unwrap the storage DEK and does not start. | Process exits at startup. |
| Raft quorum | Reads that cannot be confirmed linearizable return `Unavailable` rather than a possibly stale copy. A node with no quorum is not ready. | `keystone_raft_*` metrics; `/ready`. |
| SPIRE agent | A node whose SVID is about to expire drains proposals and halts; it never falls back to an expired SVID. | Node stops; peers log refused SVIDs. |
| Fernet or credential key repository | A missing or Null key stops startup unless `insecure_allow_null_key` is set. | Process exits at startup. |
| Upstream IdP, LDAP | Authentication through that source fails; local sources are unaffected. | Authentication failure metrics and audit `failure` records. |

## Encryption coverage

"At rest" means on the storage Keystone controls. Where Keystone relies on the
database, encryption is the operator's responsibility. Algorithms and FIPS
status are in the
[crypto inventory](../contributor/crypto-inventory.md).

| Data class | Stored in | Protected by Keystone | Operator duty |
| --- | --- | --- | --- |
| Bearer tokens | not stored (Fernet) or signed JWS | Fernet (TOK-1) or ES256/RS256 (TOK-2) | Protect and rotate key repositories. |
| Credential blobs (EC2, TOTP, ...) | SQL database | Fernet encryption of the blob (TOK-1) | Protect the credential key repository. |
| Passwords | SQL database | Salted hashes: bcrypt, scrypt, PBKDF2 (PWD-1…3) | Database access control and backup protection. |
| API keys, OAuth2 client secrets | Raft (default driver) | Argon2id hashes (TOK-7) | None beyond KEK custody. |
| Raft log, state machine, backups | Raft storage | AES-256-GCM under a DEK wrapped by the KEK (STO-1…8) | Choose PKCS#11 or TPM; protect the KEK. |
| Raft peer traffic | network | mTLS (STO-9, STO-12) | Issue and rotate certificates or SVIDs. |
| Audit spool | local disk | HMAC-SHA256 signed, tamper-evident; **not encrypted** (AUD-1) | Restrict the spool directory; use a TLS sink (AUD-4). |
| Identity data (users, groups, projects, assignments, trusts, revocation events, ...) | SQL database | **Not encrypted by Keystone** | Database and backup encryption. |
| Database connections | network | TLS to MySQL and PostgreSQL when configured (NET-3) | Require TLS at the server. |
| Client connections | network | TLS only through a proxy, or SPIFFE mTLS | Terminate TLS in front of the public listener. |

## Data inventory

Personal and security-relevant data Keystone holds or emits. Retention is the
operator's unless a row says otherwise.

| Data | Purpose | Where | Retention |
| --- | --- | --- | --- |
| User name, ID, domain, email and other attributes | Identification and authentication | SQL identity backend, or the external LDAP | Until the user is deleted. See [Data removal](#data-removal). |
| Password hash, failed-attempt counters, last activity | Authentication, lockout | SQL | Until user deletion. |
| Passkey public keys and state | WebAuthn login | Raft | Until removed. |
| Federated identity links | Federation | Federation backend | Until removed. |
| Role assignments, trusts, application credentials | Authorisation and delegation | SQL | Until the owning user or project is deleted (assignments, trusts and application credentials are removed with the user). |
| Revocation events | Token revocation | SQL | Pruned after the token expiry plus `[revoke] expiration_buffer`. |
| Audit records: initiator ID, domain, project, source address, target ID, action, outcome | Accountability and incident forensics | Local signed spool, then the configured sink | Kept until shipped; deleted only after the sink acknowledges, or by `spool_max_segments`. |
| Application logs | Operations | Log sink | Operator-defined. May carry user IDs and source addresses; never bearer tokens. |
| Traces and metrics | Operations | OTLP / Prometheus | Operator-defined. |

Audit records carry identifiers, not names, emails or secrets. Secrets are
stripped from policy input and audit payloads. See
[Audit trail](features/audit.md) and ADR 0023.

## Data removal

What `DELETE /v3/users/{id}` (and the v4 equivalent) removes. The identity
service deletes the user record, then, in the same audited operation, the
user's credentials, application credentials, trusts and role assignments, the
cached user entries, and the identity mapping on domain-specific backends.

| Location | Removed on user delete? | Notes |
| --- | --- | --- |
| User record in the SQL identity backend | Yes | |
| Credentials, application credentials, trusts, role assignments | Yes | Cascade in the identity service. A retry after a partial failure finishes the cascade. |
| In-process user caches | Yes | Per node; other nodes expire entries by TTL. |
| Passkeys, OAuth2 sessions, API keys, federated links | **Gap** | The delete path does not call the removal for these stores. Confirm foreign-key behaviour for your backend and remove them explicitly until the cascade is added. |
| Issued tokens | No (stateless) | Valid until expiry; revoke by user. |
| Revocation events | No | Kept so revocation outlives the user. |
| Audit records | No | Retained by design for accountability; they hold identifiers only. |
| Raft snapshots and log | Indirect | A deleted Raft record leaves the live state, but older log entries and snapshots hold it until Raft log compaction purges them. |
| Database and Raft backups | No | Backups keep the data until the operator expires them. Plan backup retention accordingly. |
| LDAP identity backend | No | Keystone does not write to LDAP; deletion is in the directory. |

Export: Keystone has no bulk personal-data export API. The user record, role
assignments and application credentials can be read through the REST API; the
audit trail can be searched in the sink by `initiator.id` and `target.id`.

## Release build hardening

| Property | Value |
| --- | --- |
| Memory-safe language | Rust. `unsafe_code = "forbid"` workspace-wide; `unwrap`, `expect` and `println!` are denied by lint. |
| Profile | `[profile.release]`: `strip = true`, `debug = false`, `lto = "thin"`. Release archives use `[profile.dist]` (inherits `release`); container images use `--release`. |
| Compiler flags | None overridden. No `RUSTFLAGS`. |
| Linker and loader hardening | The rustc default for `x86_64-unknown-linux-gnu`: position-independent executable, full RELRO with `BIND_NOW`, non-executable stack. Checked by building a sample binary with the project toolchain and reading its ELF headers. |
| Dependency metadata | Release binaries embed `cargo-auditable` data, so installed binaries can be scanned. |
| Supply chain | Release gate (`cargo audit`, `cargo deny`, VEX check), CycloneDX SBOM and OpenVEX attached to each release, build provenance attestation. See [Verifying release artifacts](verify-artifacts.md). |
| Not applied | Stack protector, `-Z` sanitizers and control-flow integrity flags are not used. |

Recheck the linker row against a shipped release binary when the toolchain or
target set changes.
