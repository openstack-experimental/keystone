# LDAP Identity Backend

The LDAP identity backend (`crates/identity-driver-ldap`) is a read-only
`IdentityBackend` implementation that reads users and groups directly from an
LDAP directory (OpenLDAP, FreeIPA, Active Directory, etc.). Its `[ldap]`
config section is field-for-field compatible with Python Keystone's
`keystone.conf.ldap` options, so a config file already in use with Python
Keystone works against `keystone-rs` largely unmodified — enabling a
config-only `driver = sql` → `driver = ldap` switch during a rolling upgrade.
See [ADR-0027](adr/0027-ldap-identity-driver.md) for the full design
rationale and the Python-compatibility findings from its implementation
review.

## Enabling the backend

```ini
[identity]
driver = ldap
default_domain_id = default

[ldap]
url = ldaps://ldap.example.com
user = cn=service,dc=example,dc=com
password = servicepassword
suffix = dc=example,dc=com
user_tree_dn = ou=Users,dc=example,dc=com
group_tree_dn = ou=Groups,dc=example,dc=com
```

`[identity] driver` is a single, deployment-wide setting — there is no
per-domain driver selection yet, so a `keystone-rs` deployment runs either
fully against LDAP or fully against SQL, not a mix. All LDAP users and groups
are exposed under the single `default_domain_id` domain, since the LDAP
directory itself has no concept of Keystone domains.

`LdapBackend::new()` performs one real bind against `url`/`user`/`password`
at startup and fails fast if it cannot reach the directory — a misconfigured
`[ldap]` section prevents the server from starting rather than surfacing as
runtime errors on the first request.

## Read-only

Every mutating `IdentityBackend` method (`create_user`, `update_user`,
`delete_user`, `create_group`, `add_user_to_group`, `update_user_password`,
etc.) returns `IdentityProviderError::Readonly`, mapped to an HTTP `403`.
Manage users and groups directly in the directory (or via whatever tool your
organization already uses for that) — Keystone only reads from it.

A few capabilities that don't exist in an LDAP directory at all return
`IdentityProviderError::NotImplemented` (mapped to `500`) rather than
`Readonly`, since there's no LDAP concept to even be read-only about:
`create_service_account`, `find_federated_user`, and the expiring-group-
membership methods. `get_service_account` returns `Ok(None)` unconditionally.

## Configuration reference

### Connection

| Option | Default | Notes |
| --- | --- | --- |
| `url` | `ldap://localhost` | One or more server URLs, comma/whitespace-separated (matches Python's `re.split(r'[\s,]+', ...)`). Each candidate is tried in turn on connect/bind failure. |
| `user` | unset | Service bind DN, used for all read queries. |
| `password` | unset | Service bind password. |
| `use_tls` | `false` | Use StartTLS on the plain `ldap://` connection. Use `ldaps://` in `url` for implicit TLS instead. |
| `tls_cacertfile` / `tls_cacertdir` | unset | Parsed for config compatibility but **not applied** — see [Known limitations](#known-limitations). |
| `tls_req_cert` | `demand` | `demand` \| `allow` \| `try` \| `never`. |
| `connection_timeout` | `-1` (no timeout) | Seconds. |
| `randomize_urls` | `false` | Shuffle the candidate list from `url` before trying servers (matches Python's `random.shuffle`). |
| `pool` / `pool_size` / `pool_retry_max` / `pool_retry_delay` / `pool_connection_timeout` / `pool_connection_lifetime` | `true` / `10` / `3` / `0.1` / `-1` / `600` | Service (read) connection pool. |
| `auth_pool` / `auth_pool_size` / `auth_pool_connection_lifetime` | `true` / `100` / `60` | Dedicated pool for end-user password-auth binds, isolated from the service pool so a burst of failed logins can't starve directory reads. |

### Query

| Option | Default | Notes |
| --- | --- | --- |
| `query_scope` | `one` | `one` (single-level under the tree DN) or `sub` (whole subtree). Governs the scope of **every** read search — `get`, `get_by_name`, and `list` — not just id/DN resolution. |
| `page_size` | `0` (disabled) | Entries per page (RFC 2696) for `list_users`/`list_groups`. |
| `alias_dereferencing` | `default` | Parsed but **not applied** — see [Known limitations](#known-limitations). |
| `chase_referrals` | unset | |
| `debug_level` | `0` | |

### User mapping

| Option | Default |
| --- | --- |
| `user_tree_dn` | `""` (must be set) |
| `user_objectclass` | `inetOrgPerson` |
| `user_id_attribute` | `cn` |
| `user_name_attribute` | `sn` |
| `user_mail_attribute` | `mail` |
| `user_description_attribute` | `description` |
| `user_pass_attribute` | `userPassword` |
| `user_enabled_attribute` | `enabled` |
| `user_enabled_mask` | unset |
| `user_enabled_invert` | `false` |
| `user_enabled_default` | `"True"` |
| `user_additional_attribute_mapping` | `{}` |
| `user_filter` | unset |
| `user_attribute_ignore` | `{default_project_id}` |
| `user_enabled_emulation` | `false` |
| `user_enabled_emulation_dn` | unset |
| `user_enabled_emulation_use_group_config` | `false` |

`user_id_attribute` falls back to the entry's DN (with a logged warning) when
the configured attribute is absent or multi-valued on a given entry, rather
than failing the whole request.

#### Enabled-attribute strategies

`user_enabled_attribute` is interpreted by one of four strategies, evaluated
in the same precedence order as Python Keystone:

1. **Group-membership emulation** (`user_enabled_emulation = true`): a user is
   enabled iff they're a member of `user_enabled_emulation_dn`.
2. **Bitmask** (`user_enabled_mask` set): `enabled = (raw_value & mask) !=
   mask` — the user is enabled unless *all* masked bits are set. This is the
   Active Directory `userAccountControl` convention, where `mask = 2`
   corresponds to the `ACCOUNTDISABLE` bit. `user_enabled_invert` is ignored
   entirely once a mask is configured, matching Python.
3. **Invert** (`user_enabled_invert = true`, no mask): the raw boolean value
   is negated.
4. **Plain boolean**: the raw attribute value is parsed directly.

When `user_enabled_attribute` is absent from an entry, the backend falls back
to parsing `user_enabled_default`, which is why that option is a string
rather than a boolean — under the bitmask strategy it's expected to hold an
integer literal (e.g. `"512"`) instead of `"True"`/`"False"`.

### Group mapping

| Option | Default |
| --- | --- |
| `group_tree_dn` | `""` (must be set) |
| `group_objectclass` | `groupOfNames` |
| `group_id_attribute` | `cn` |
| `group_name_attribute` | `ou` |
| `group_desc_attribute` | `description` |
| `group_member_attribute` | `member` |
| `group_members_are_ids` | `false` |
| `group_attribute_ignore` | `{}` |
| `group_additional_attribute_mapping` | `{}` |
| `group_filter` | unset |
| `group_ad_nesting` | `false` |

`group_members_are_ids` supports directories where `group_member_attribute`
holds Keystone user IDs directly instead of member DNs — most commonly
`posixGroup`'s `memberUid`, which stores POSIX usernames rather than
distinguished names. Leave it `false` for the default `groupOfNames` +
`member` (DN-valued) convention.

`group_ad_nesting` resolves nested Active Directory group membership using
the `LDAP_MATCHING_RULE_IN_CHAIN` (`1.2.840.113556.1.4.1941`) matching rule
in `list_groups_of_user`.

### General

| Option | Default |
| --- | --- |
| `suffix` | `cn=example,cn=com` |

## Known limitations

- **`tls_cacertfile` / `tls_cacertdir` are parsed but not applied.** The
  `ldap3` crate has no ready-made hook for a custom CA trust root short of
  manually constructing a `rustls::ClientConfig`; TLS verification always
  uses the platform/`rustls` default trust store instead. A startup warning
  is logged when either option is set. Work around this by installing the
  directory's CA into the system trust store, or by setting `tls_req_cert =
  never` for a test/lab directory.
- **`alias_dereferencing` is parsed but not applied.** The `ldap3` crate
  (v0.11) has no per-search or per-connection alias-dereferencing control;
  every search uses the underlying client library's default behavior
  regardless of this setting.
- **No per-domain driver selection.** `[identity] driver` is global; running
  some domains against LDAP and others against SQL simultaneously isn't
  supported yet.

## Testing

Beyond crate-level unit tests (`cargo test -p
openstack-keystone-identity-driver-ldap`), the crate ships a `live_tests`
module that exercises the driver's read and authentication paths against a
real OpenLDAP (`slapd`) instance — real network round trips, real schema
validation, real bind/search behavior, not mocks.

Run it via the dedicated nextest profile:

```sh
cargo nextest run -p openstack-keystone-identity-driver-ldap --profile ldap
```

This uses a nextest setup script (`tools/start-ldap-test.sh`) to start a
throwaway local `slapd` on port 3890, seed it from
`crates/identity-driver-ldap/tests/fixtures/base.ldif`, and export
`KEYSTONE_LDAP_TEST_URL`/`_BASE_DN`/`_ADMIN_DN`/`_ADMIN_PW` for the test
binary to pick up. `tools/teardown-ldap-test.sh` stops it afterwards (nextest
does not run teardown scripts automatically, so run it by hand after a manual
`cargo nextest run --profile ldap`).

Under any other profile, `live_tests`' functions skip themselves gracefully
(printing a skip message) rather than failing, since
`KEYSTONE_LDAP_TEST_URL` is only set by the `ldap`/`ci-ldap` profiles — plain
`cargo test` for the crate never requires a live directory.

The fixture directory (`base.ldif`) seeds users and groups covering the
enabled/disabled cases, `groupOfNames` membership, and a `posixGroup` for
exercising `group_members_are_ids`; see the file itself for the full seed
data.
