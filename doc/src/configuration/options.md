# Configuration Options

This reference follows the public fields of `openstack-keystone-config`.
Defaults come from the corresponding Rust `Default` implementation; options
without a usable default are required when their feature is enabled. Consult
the feature guide for constraints and safe production values.

## Service and Interfaces

| Section | Options |
| --- | --- |
| `[DEFAULT]` | `debug`, `log_dir`, `public_endpoint`, `use_stderr` |
| `[database]` | `connection` |
| `[interface_public]` | `tcp_address`, listener `type`, and listener-specific TLS/SPIFFE fields |
| `[interface_internal]` | `tcp_address`, listener `type`, `trust_domains`, and TLS content/file fields |
| `[interface_admin]` | `socket_path`, `trust_domains`, `peer_uid`, `peer_gid`, `admin_svid` |
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
| `[oauth2]` | signing algorithm and rotation, Argon2 cost, access/ID/refresh/code/device lifetimes, polling interval, and token rate-limit options |
| `[api_key]` | `driver`, Argon2 cost, janitor retention, trusted proxy/header, and rate-limit options |
| `[scim_realm]` | `driver` |
| `[scim_resource]` | `driver`, `janitor_deprovisioned_retention_days` |
| `[ldap]` | connection/TLS/pool/query options and user/group attribute mappings documented in the LDAP guide |

See the corresponding pages under [Administrator Guides](../admin/index.md) for
validation rules and complete operational examples.

## Dynamic Plugins and Audit

| Section | Options |
| --- | --- |
| `[auth_plugins]` | `plugins`, `trusted_proxies`, `trusted_header` |
| `[auth_plugin.<name>]` | `path`, `sha256`, `mode`, capabilities, headers, outbound hosts, provisioning/role bounds, route targets, resource limits, rate limits, concurrency, `valid_since` |
| `[auth_plugin_identity]` | `driver` |
| `[audit]` | `spool_dir`, `node_id` |

See [Dynamic authentication plugin operations](../admin/features/auth-plugins.md).

## Distributed Storage and Emergency Operations

| Section | Options |
| --- | --- |
| `[distributed_storage]` | `dev_mode`, `kek_provider`, node addresses/ID/path, join retry nodes, PKCS#11/TPM provider fields, and TLS or SPIFFE transport fields |
| `[local_emergency]` | `enabled`, `leaderless_grace_period_seconds`, `gossip_interval_seconds` |

Distributed storage is optional. When enabled in production, use the complete
[distributed-storage runbook](../admin/storage/distributed.md); the option list
alone is not a safe deployment procedure.
