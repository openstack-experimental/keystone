# Audit trail

Keystone writes a signed, tamper-evident audit record for every authentication
attempt and every state-changing operation. This page is the operator guide;
the design is in [ADR 0023](../../adr/0023-audit.md).

## What is audited

| Kind | Records | When |
| --- | --- | --- |
| Perimeter | `authenticate` (success, failure, `client_error`) | Login and token-issuing handlers (token, EC2, OAuth2 token, federation JWT/OIDC), plus one completion record for the other authentication surfaces: token validation and revocation (`/v3/auth/tokens`), WebAuthn, Kubernetes auth, API-key (SCIM), vendordata, and requests rejected early (for example `429`). Best effort: records are dropped, and counted, if the in-memory channel is full. |
| Provider | `create`, `update`, `delete`, `enable`, `disable`, `revoke`, ... | Every state-changing provider operation writes an `attempt` record **before** the change and a `success`/`failure` record after it. If the `attempt` record cannot be queued the operation is **not performed** (fail-closed). |

Ordinary validated-token requests to resource endpoints are not recorded at the
perimeter; the mutations they make are audited by the provider records.

A few bookkeeping operations are deliberately not audited because the
authentication that triggers them is: the last-use timestamp and transparent
secret re-hash of an API key, and janitor housekeeping.

## Record format

Records are JSON lines in a CADF-inspired Keystone schema, version `1.1`:

```json
{
  "action": "delete",
  "boot_session_id": "9a1c3f0e-6c0b-4c5d-8f55-2f2c3b6d2a10",
  "correlation_id": "req-3f0c7a3e5b3d4d0f9a52f1c8f1f1e0aa",
  "domain": "0123456789abcdef0123456789abcdef",
  "event_time": "2026-06-16T10:15:00+00:00",
  "hmac_key_version": 1,
  "id": "keystone-0:550e8400-e29b-41d4-a716-446655440000",
  "initiator": {
    "domain_id": "0123456789abcdef0123456789abcdef",
    "host": {"address": "203.0.113.9"},
    "id": "fedcba9876543210fedcba9876543210",
    "project_id": null
  },
  "observer": {"id": "service/security/keystone/keystone-0", "node_id": "keystone-0"},
  "outcome": "failure",
  "outcome_reason": "Conflict",
  "seq": 42,
  "signature": "<hex HMAC-SHA256>",
  "target": {"id": "0123456789abcdef0123456789abcdef", "type_uri": "data/security/identity/user"},
  "version": "1.1"
}
```

* `outcome` is `attempt` (provider record written before the change, CADF
  `pending`), `success`, `failure`, or `client_error` (a rejected request such
  as a rate limit).
* `outcome_reason` is a fixed vocabulary word (an error variant name such as
  `Conflict` or `UserLocked`), never error text.
* `action` is a lowercase verb or a `/`-separated name such as
  `oauth2/refresh_reuse_detected`.
* `initiator.host` carries the client address and, for pre-authentication
  failures, a non-secret identifier such as the EC2 access key id. It is
  **omitted** when empty, whereas `project_id` and `domain_id` are `null`.
* `correlation_id` is the server-generated `x-openstack-request-id`; a
  client-supplied value is discarded.
* Records contain identifiers only: no passwords, tokens, secrets or free text.

## The spool

Records are first written to a local spool in `[audit] spool_dir` (default
`/var/lib/keystone/audit`), so nothing depends on the downstream system being up.

| File | Meaning |
| --- | --- |
| `audit-spool-<node_id>.jsonl` | The live file, appended by Keystone. |
| `audit-spool-<node_id>.jsonl.seg-<timestamp>` | A sealed, immutable segment (sealed at `spool_max_segment_bytes` or `spool_max_segment_age_secs`). |
| `*.quarantine-<timestamp>` | A segment whose signatures did not verify at startup. Keystone never deletes it: investigate it (tampering, a wrong key, disk corruption) and archive or remove it by hand. The metric `keystone_audit_spool_quarantined_total` counts these. |
| `audit-spool-<node_id>.lock` | A lock that keeps two Keystone processes from writing one spool. |
| `hmac-key.bin` | The audit root key (see below). |

The spool grows until segments are shipped. Configure a `sink` so sealed
segments are shipped and deleted once the sink has accepted them; without one,
segments stay in the spool for an external shipper (for example a log
forwarder tailing the directory) and **nothing deletes them** unless you set
`spool_max_segments` (the oldest are then deleted with an `ERROR` log). Plan
disk for `spool_max_segments * spool_max_segment_bytes`.

### Configuration

| Option | Default | Meaning |
| --- | --- | --- |
| `spool_dir` | `/var/lib/keystone/audit` | Spool and key directory. Make it writable by the Keystone user only (for example mode `0700`); Keystone does not change the directory mode. |
| `node_id` | `$HOSTNAME`, else `unknown-node` | Identifies the node in `observer.node_id` and file names. **Must be unique per node**; set it explicitly. `unknown-node` is a placeholder, not a valid production value. |
| `spool_max_segment_bytes` | 256 MiB | Seal the live file at this size. |
| `spool_max_segment_age_secs` | 86400 | Seal the live file after this age. |
| `spool_max_segments` | unset (keep all) | Keep at most this many sealed segments. |
| `spool_drain_timeout_secs` | 10 | Time to write already-queued events on shutdown; the rest are dropped and logged at `ERROR`. |
| `sink` | none | Downstream sink, e.g. `sink = { type = "stdout" }`. |

## Keys

`hmac-key.bin` holds at least 32 random bytes. It is created with mode `0600`
on first start; a file that is too short makes startup fail. Each node derives
its own signing key from it with HKDF-SHA256 and the info string
`keystone-audit-hmac-v1:<node_id>`, so a compromised node cannot forge records
attributed to another node. Back the file up with the same care as the Fernet
keys: without it the spool cannot be verified, with it an attacker can forge
records. The key version in use is exported as `keystone_audit_hmac_key_version`
and stamped on every record (`hmac_key_version`), so old records stay
verifiable; automated rotation is not available yet.

## Verifying records in a SIEM

1. Parse the JSON line.
2. Remove the `signature` key.
3. Serialize the rest in JCS canonical form (RFC 8785).
4. Compute HMAC-SHA256 with the key for `hmac_key_version` (and `node_id`).
5. Compare with `signature`.

Cache every key version you have seen. Reference vectors, including the `host`
cases, are in `tests/audit/hmac_vectors.jsonl`, and
`tools/audit_vectors.py verify` is an independent Python implementation of the
procedure. Cross-check with `outcome`: an `attempt` with no `success`/`failure`
for the same `correlation_id` and target within a few minutes means the process
died or the post-record was lost.

## Monitoring

Keystone exports `keystone_audit_*` metrics on `/metrics` (event, drop,
queue-depth, spool and sink series; see ADR 0023 §Observability). Ready-made
alert rules are in `deploy/prometheus/alert_rules.yaml`; at minimum page on
`keystone_audit_dropped_total`, `keystone_audit_postaudit_dropped_total`,
`keystone_audit_spool_write_failures_total`,
`keystone_audit_spool_quarantined_total` and sink errors.

Accepted risk: records live in memory for a short window before they reach the
spool, and the spool is not fsynced per record, so a hard crash or power loss
can lose the last few milliseconds of records. A graceful shutdown drains the
queue first.
