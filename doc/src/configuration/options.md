# Configuration Options

This reference follows the public fields of `openstack-keystone-config`.
Defaults come from the corresponding Rust `Default` implementation; options
without a usable default are required when their feature is enabled. Consult
the feature guide for constraints and safe production values.

## Service and Interfaces

| Section | Options |
| --- | --- |
| `[DEFAULT]` | `debug`, `log_dir`, `public_endpoint`, `use_stderr`, `use_journal`, `log_rotation_type`, `log_rotate_interval`, `log_rotate_interval_type`, `max_logfile_count` |
| `[database]` | `connection`, `connection_debug` |
| `[interface_public]` | `tcp_address`, listener `type`, and listener-specific TLS/SPIFFE fields |
| `[interface_internal]` | `tcp_address`, listener `type`, `trust_domains`, optional `svid_path` (SVID the listener presents), and TLS content/file fields |
| `[interface_admin]` | `socket_path`, `trust_domains`, `peer_uid`, `peer_gid`, `admin_svid`, optional `svid_path` |
| `[interface_metrics]` | `tcp_address` |
| `[oslo_middleware]` | `enable_proxy_headers_parsing`, `trusted_header`, `trusted_proxies` |

The public interface is enabled by default. Internal and admin interfaces are
optional. The metrics listener defaults to `0.0.0.0:8099`.

## Authentication, Tokens, and Security

| Section | Options |
| --- | --- |
| `[auth]` | `methods` |
| `[token]` | `provider`, `expiration` |
| `[fernet_tokens]` | `key_repository`, `max_active_keys`, `insecure_allow_null_key` |
| `[jws_tokens]` | `key_repository`, `insecure_allow_null_key` |
| `[credential]` | `driver`, `key_repository`, `insecure_allow_null_key` |
| `[application_credential]` | `driver`, `reject_unenforced_access_rules` |
| `[ec2]` | `auth_ttl` |
| `[trust]` | `driver`, `allow_redelegation`, `max_redelegation_count` |
| `[security_compliance]` | inactivity, first-use password change, password-hash reporting, lockout, password age/expiry/regex, and password-history options |
| `[rate_limit_global_ip]` | `enabled`, `burst_size`, `replenish_rate_per_second` |
| `[rate_limit_user_auth]` | `enabled`, `burst_size`, `replenish_rate_per_second` |
| `[rate_limit_trusted_proxies]` | `trusted_proxies`, `trusted_header` |

`insecure_allow_null_key` defaults to `false`. Keep it disabled in production.
See [Fernet tokens](../admin/tokens/fernet.md) and
[Security](../admin/security.md).

## Policy and Domain Providers

| Section | Options |
| --- | --- |
| `[api_policy]` | `enable`, `opa_base_url`, `opa_policies_path` |
| `[identity]` | `driver`, `caching`, `default_domain_id`, `max_password_length`, `password_hashing_algorithm`, `password_hash_rounds`, `user_options_id_name_mapping` |
| `[assignment]` | `driver` |
| `[catalog]` | `driver` |
| `[resource]` | `driver` |
| `[role]` | `driver` |
| `[revoke]` | `driver`, `expiration_buffer` |
| `[idmapping]` | `driver` |
| `[token_restriction]` | `driver` |

OPA policy is enabled by default. See [API policy enforcement](../admin/policy.md).

## Feature Providers

| Section | Options |
| --- | --- |
| `[webauthn]` | `enabled`, `driver`, `relying_party_id`, `relying_party_name`, `relying_party_origin`, `fake_credential_hmac_key` |
| `[federation]` | `driver`, `default_authorization_ttl` |
| `[mapping]` | `driver`, `cluster_salt` |
| `[k8s_auth]` | `driver` |
| `[oauth2]` | signing algorithm and rotation, Argon2 cost, access/ID/refresh/code/device lifetimes, polling interval, session janitor, and token rate-limit options |
| `[api_key]` | `driver`, Argon2 cost, janitor retention, trusted proxy/header, and rate-limit options |
| `[scim_realm]` | `driver` |
| `[scim_resource]` | `driver`, `janitor_deprovisioned_retention_days` |
| `[ldap]` | connection/TLS/pool/query options and user/group attribute mappings documented in the LDAP guide |

See the corresponding pages under [Administrator Guides](../admin/index.md) for
validation rules and complete operational examples. `[mapping].cluster_salt`
is required before mapping-backed authentication (SPIFFE, Kubernetes,
federation, API client) works at all; see
[Identity Mapping Administration](../admin/features/identity-mapping.md) for
that requirement and for rule-matching precision (narrow claim matches,
`is_system` scoping, least-privilege roles) as a security concern distinct
from it.

## Dynamic Plugins and Audit

| Section | Options |
| --- | --- |
| `[auth_plugins]` | `plugins`, `trusted_proxies`, `trusted_header` |
| `[auth_plugin.<name>]` | `path`, `sha256`, `mode`, capabilities, headers, outbound hosts, provisioning/role bounds, route targets, resource limits, rate limits, concurrency, `valid_since` |
| `[auth_plugin_identity]` | `driver` |
| `[audit]` | `enabled` (`true`), `spool_dir` (`/var/lib/keystone/audit`), `hmac_kek_file` (unset: `<spool_dir>/hmac-key.bin`), `node_id` (`$HOSTNAME`, else `unknown-node`; set it, unique per node), `spool_max_segment_bytes` (256 MiB), `spool_max_segment_age_secs` (86400), `spool_max_segments` (unset: keep all), `spool_max_bytes` (unset), `spool_retention_secs` (unset), `perimeter_channel_capacity` (4096), `critical_channel_capacity` (256), `shipper_batch_size` (500), `shipper_poll_interval_secs` (5), `shipper_initial_backoff_secs` (1), `shipper_max_backoff_secs` (60), `spool_drain_timeout_secs` (10), `sink` (none) |

`[audit] enabled` defaults to `true`. Setting it to `false` skips creating the
spool directory, spool lock, HMAC key and writer, and discards audit events;
use it only for development or deployments that do not need an audit trail.

Audit signing key and node identity:

- `node_id` identifies the node in every event, names its spool files and
  keys its signing key, so it must be unique per node. It defaults to the
  `HOSTNAME` environment variable, then the system hostname; Keystone refuses
  to start with auditing enabled if it is empty, unset (the `unknown-node`
  fallback) or contains characters outside `A-Z a-z 0-9 . _ -`.
- `hmac_kek_file` is the keyring holding the audit key-encryption-keys, one per
  key version, created with mode `0600` if missing. It must not be inside
  `spool_dir` (startup fails if it is): whoever can write the spool must not be
  able to read the key that signs it. When unset, the legacy
  `<spool_dir>/hmac-key.bin` is used so existing deployments keep working, and
  a warning is logged. A legacy 32-byte key file is read as key version 1.
- Rotate the signing key with `keystone-manage audit rotate-hmac-key`. It adds a
  new version and makes it current; old versions are kept so events already
  signed stay verifiable. Running servers pick the new version up within about
  30 seconds. Back up the keyring and give the SIEM verifier the updated copy.

Spool and queue limits:

| Option | Default | Description |
| --- | --- | --- |
| `spool_max_segments` | unset | Keep at most this many sealed segments; the oldest are deleted beyond it. |
| `spool_max_bytes` | unset | Keep sealed segments plus room for one full live segment (`spool_max_segment_bytes`) within this many bytes, deleting the oldest sealed segments first. |
| `spool_retention_secs` | unset | Delete sealed segments older than this many seconds. |
| `perimeter_channel_capacity` | `4096` | Capacity of the best-effort perimeter channel; events are dropped and counted when it is full. |
| `critical_channel_capacity` | `256` | Capacity of the fail-closed critical channel; senders wait when it is full. |
| `shipper_batch_size` | `500` | Events handed to the sink per call. |
| `shipper_poll_interval_secs` | `5` | Idle delay between checks for newly sealed segments. |
| `shipper_initial_backoff_secs` | `1` | First retry delay after a sink failure; doubles up to the maximum. |
| `shipper_max_backoff_secs` | `60` | Upper bound for the sink retry delay. |

The three spool limits are unset by default, so no audit record is deleted
unless an operator opts in. They are evaluated at startup and whenever the live
spool rotates. A segment deleted by a limit was never acknowledged by a sink:
each deletion is logged at `ERROR` and counted in
`keystone_audit_spool_retention_deleted_total`.

Audit sink (`[audit] sink`): sealed spool segments are shipped to the sink and
deleted only after the sink has accepted every event.

| `type` | Description |
| --- | --- |
| `none` (default) | No sink; segments stay in `spool_dir` for an external shipper. |
| `stdout` | One JSON line per event on standard output. |
| `syslog` | RFC 5424 messages over TCP, optionally TLS. Requires building Keystone with the `audit-syslog` cargo feature. |

The `syslog` sink takes `endpoint` (`host:port`, required), `tls` (default
`false`), `ca_file` (PEM bundle; defaults to the system trust store),
`app_name` (default `keystone`), `connect_timeout_secs` (default `10`) and
`write_timeout_secs` (default `30`):

```toml
[audit]
sink = { type = "syslog", endpoint = "siem.example.com:6514", tls = true, ca_file = "/etc/keystone/siem-ca.pem" }
```

Each message carries the signed CADF JSON as its `MSG` and is framed with octet
counting (RFC 6587), so the receiver can verify the HMAC as it would from the
spool. Delivery is at-least-once: a failed or timed-out batch is retried with
backoff and the segment is kept until delivery succeeds, so receivers should
deduplicate on the event `id`. TCP has no application acknowledgement; a batch
counts as delivered once it is written and flushed to the peer. If Keystone was
built without `audit-syslog`, configuring this sink makes startup fail.

See [Audit trail](../admin/features/audit.md).

See [Dynamic authentication plugin operations](../admin/features/auth-plugins.md).

## Distributed Storage and Emergency Operations

| Section | Options |
| --- | --- |
| `[distributed_storage]` | `dev_mode`, `kek_provider`, node addresses/ID/path, join retry nodes, PKCS#11/TPM provider fields, and TLS or SPIFFE transport fields |
| `[local_emergency]` | `enabled`, `leaderless_grace_period_seconds`, `gossip_interval_seconds` |

Distributed storage is optional. When enabled in production, use the complete
[distributed-storage runbook](../admin/storage/distributed.md); the option list
alone is not a safe deployment procedure.
