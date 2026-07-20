# Identity Mapping Administration

Identity mapping rules are owned by domain managers through the v4 API. The
operator is responsible for enabling the mapping engine, supplying stable
cluster-wide configuration, and protecting the boundaries enforced during rule
evaluation. See the [user guide](../../user/features/identity-mapping.md) for
rule semantics, provider claim contracts, examples, and API operations.

## Security considerations

- Rulesets containing `is_system: true` are immutable after creation to prevent
  privilege escalation through later rule mutation.
- `AllOfStrict` with `require_all_keys` prevents a lower-trust assertion from
  suppressing claims used by a higher-priority rule.
- Templates cannot reference `enclosing_domain_id` through `${claims.*}` and
  resolved values are capped at 256 characters.
- Compiled regular expressions use a bounded cache, and claim values accepted
  for evaluation are size limited.

These application safeguards do not replace policy. Operators must restrict
mapping administration to the intended domain managers and review rules that
can produce system-scoped authorization.

The admin interface can also authorize a configured `admin_svid` without a
mapping ruleset. Limit that SVID to administrative workloads, distribute the
configuration consistently, and keep it separate from ordinary SPIFFE mapping
rules.

## Cluster salt

The mapping engine requires `mapping.cluster_salt` before SPIFFE, Kubernetes,
federation, or API-client authentication can use mapping rules. Without it,
mapping-backed authentication fails because Keystone cannot derive a stable
virtual user identifier.

Set a distinct, stable value for every Keystone cluster:

```yaml
mapping:
  cluster_salt: "<random-secret>"
```

Generate the value with a cryptographically secure random source, for example:

```console
openssl rand -hex 32
```

Keystone derives deterministic virtual user IDs with
`HMAC-SHA256(cluster_salt, workload_id || provider_id)`. Reusing a salt across
clusters creates overlapping identifier namespaces. Changing it after virtual
users exist assigns new identifiers to the same workloads and orphans the
previous shadow records.

Store the salt in the deployment secret manager, distribute the same value to
every Keystone node, and include it in backup and disaster-recovery procedures.
Do not store it in a plain ConfigMap.

## Operational checklist

1. Configure the cluster salt consistently on every node.
2. Restrict mapping-rule APIs through OPA policy.
3. Review system mappings and broad regular expressions before enabling them.
4. Monitor mapping failures and shadow-user version mismatches.
5. Treat a planned cluster-salt rotation as an identity migration.
