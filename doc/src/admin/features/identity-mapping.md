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

An unmapped or misconfigured caller (no cluster salt, no matching ruleset,
disabled ruleset) is denied outright — `authenticate_by_mapping` fails closed
and the request never reaches a handler. That is not the risk to guard
against; the real risk is a ruleset that matches *too broadly* and grants
real access to callers it was never meant to cover:

- **Match on the narrowest claim that actually identifies the workload.**
  For SPIFFE sources, match the exact `spiffe.id` of the intended workload
  (`spiffe://<trust-domain>/service/nova-api`), not `spiffe.trust_domain`
  alone — a trust-domain-wide match authorizes *every* workload issued an
  SVID in that trust domain, including ones added later for unrelated
  purposes. The same applies to `MatchesRegex`: a pattern broader than the
  specific workload path it was written for silently grows the set of
  identities a rule accepts as SPIRE registration entries are added.
- **Reserve `is_system: true` for genuine control-plane identities.** A
  system-scoped rule bypasses domain/project boundaries entirely; grant it
  only to the specific control-plane workload that needs it (e.g. a
  service's own auth-token back-channel), never as a default for
  convenience. `flat_spiffe_claims`' derived `spiffe.project_id`/
  `spiffe.instance_id` claims exist so data-plane (per-project) workloads
  can be mapped to project scope instead of system scope.
- **Grant the least-privilege role the caller actually needs.** A
  control-plane SVID that only validates tokens needs the `service` role
  (see `policy/auth/token/show.rego`), not `admin` — `admin` at system
  scope is authorized for every policy-checked operation in the deployment.
- **Review every ruleset change that widens a match or adds `is_system`**
  before it goes live, the same way a firewall-rule or IAM-policy change
  gets reviewed — a broadened rule takes effect immediately for every
  future request matching it, not just new registrations.

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
