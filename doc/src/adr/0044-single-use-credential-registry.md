# 44. Single-use credential registry (replay cache)

**Date:** 2026-11-13

## Status

Proposed.

## Reference

Extends ADR 0043 (DPoP, `jti` cache per node) and ADR 0026 (token exchange as
STS, issue #945). Related: ADR 0016-v2 (Raft storage, at-rest encryption), ADR
0022 (rate limiting), ADR 0036 §6.4 (shared validation surfaces), ADR 0041
(session state in Raft). Standards: RFC 9449 §11.1 (DPoP proof replay), RFC 7523
§3 (`jti`), RFC 6238 §5.2 (a TOTP passcode must not be accepted twice).
Regulation: EU Cyber Resilience Act Annex I Part I (secure by default), NIS2
Art. 21 (security of network and information systems, including availability).

## Context

Several credentials must be accepted at most once inside a time window:

- **External assertions** presented to `POST /v4/oauth2/{domain_id}/token` for
  token exchange (ADR 0026, #945). The JWT from the external IdP is the whole
  credential. It carries no second secret, no `ath` and no nonce. The only thing
  that stops a second use is a `jti` check, and a second use mints a full
  Keystone token.
- **TOTP passcodes**, which must not be accepted twice inside the accepted time
  window.
- **DPoP proofs** (ADR 0043), where the cache is defense in depth: a proof is
  bound to method and URL, `/token` additionally requires a server nonce that
  every node accepts, and an attacker who captured the proof of a resource
  request has captured the access token too.

Today only DPoP has a cache, `DpopReplayCache`, a bounded in-memory map that is
**per process**. With N Keystone nodes a captured credential can be used up to N
times inside its window, and a restart empties the cache. ADR 0043 accepts that
for DPoP. It is not acceptable for external assertions, where the credential is
a bearer token with no further binding.

Keystone already has cluster state. The Raft storage (`crates/storage`) offers
an atomic `Mutation::CreateIfAbsent`: the leader applies it, and a batch with a
`CONFLICT` violation is not committed. Records are either durable (Fjall,
encrypted, in snapshots) or ephemeral (`Metadata::ephemeral()`: in memory only,
no disk, encryption or snapshot). WebAuthn ceremony state uses ephemeral records
in time-bucketed keyspaces (`crates/webauthn/src/driver/raft.rs`). A shared
external cache (memcached, Redis) is not used anywhere in the Rust code base.

Ephemeral records are not usable for single-use checks. A snapshot install
clears them (`restore.rs`), and a restarted node resumes from the
`last_applied_log` stored in Fjall without replaying earlier log entries, so its
ephemeral map starts empty. The answer to `CreateIfAbsent` comes from the
leader's apply. A leader that restarted or installed a snapshot inside the
window therefore accepts a replay, and Raft elects leaders by log completeness,
not by ephemeral state.

`StorageApi::drop_keyspace` acts on the local node only and is not replicated.
WebAuthn calls it from the leader, so followers never drop their bucket
keyspaces.

## Decision

### 1. One abstraction, two implementations

A trait in `crates/core` records that a `(scope, id)` pair was used:

```rust
#[async_trait]
pub trait SingleUseStore: Send + Sync {
    /// Record `(scope, id)`. `expires` is the first unix second at which the
    /// entry is dead; it must not be earlier than the last moment the same
    /// credential could still pass verification.
    async fn consume(
        &self,
        scope: &str,
        id: &str,
        expires: i64,
        now: i64,
    ) -> Result<(), SingleUseError>;

    /// Periodic maintenance.
    async fn cleanup(&self, now: i64) -> Result<(), SingleUseError>;
}

pub enum SingleUseError {
    /// Already recorded and not yet expired.
    Replayed,
    /// Local store bounds, or the cluster store's admission limit
    /// (section 3), reached.
    Capacity,
    /// `expires` is in the past or beyond the use case's maximum lifetime;
    /// the caller computed it wrongly.
    InvalidLifetime,
    /// Cluster store cannot be reached, did not answer, or rejected the write
    /// for a reason other than a conflict.
    Unavailable(Box<dyn Error + Send + Sync>),
}
```

Callers own the semantics of scope, id and lifetime:

| Use case           | scope                                  | id                       | `expires`                       |
| ------------------ | -------------------------------------- | ------------------------ | ------------------------------- |
| External assertion | `(domain_id, issuer)`, length-prefixed | `jti`                    | `exp + skew + 1`                |
| TOTP               | `user_id`                              | `{credential_id}:{step}` | end of the last accepted window |
| DPoP proof         | `jkt`                                  | `jti`                    | `iat + window + 1`              |

DPoP proofs at `/token` and DPoP proofs on resource requests are separate use
cases with separate options, defaults and keyspace prefixes (sections 4 and 8).

An external assertion without a `jti` (missing, empty or not a string) is
rejected with `invalid_grant` **before** `consume`. It is never accepted without
a check, and no id is derived from other claims: that would need a hash and a
crypto inventory row. SPIFFE JWT-SVIDs may omit `jti`; such an issuer cannot be
used for token exchange until a derived-id option is decided in its own ADR.

All length prefixes count **bytes**, not characters. The scope is encoded as
`"{len(domain_id)}:{domain_id}{issuer}"` so that `("a","b")` and `("ab","")`
stay apart. No hash is used, so no cryptographic primitive is added and the
crypto inventory does not change.

For TOTP, `step` is the time step that **matched** the passcode, not the current
step: the verifier accepts the current and the previous step, and the same
passcode must be caught whichever step the second attempt is checked in. The
passcode is accepted while the matched step is the current or the previous one,
so `expires = (step + 2) * period`. The id includes the credential so that a
user with several TOTP devices is not blocked by a login with another device in
the same step. Two parallel logins with the same device in the same step share a
passcode and the second is rejected, as RFC 6238 §5.2 requires.

Today `verify_totp` (`crates/core/src/credential/totp.rs`) returns only a
`bool`, and `authenticate_by_totp` (`identity/service.rs`) does not record used
passcodes. A passcode can be replayed inside its window, on any node. The
implementation changes both:

- `verify_totp` returns the matched step, and the identity service returns the
  matched credential id with the authentication result.
- `consume` is called by the code that sees every authentication method of the
  request, not inside `authenticate_by_totp`: the v3 token flow
  (`api/v3/auth/token/common.rs`) and the OAuth2 MFA step
  (`api/v4/oauth2/mfa.rs`). Both entry points use the same helper.
- `period` from the credential blob is capped (proposed 300 s) so that
  `max_lifetime` is bounded by `2 * 300` s.

Every implementation enforces the same preconditions before touching its store:

- `expires > now`, else `InvalidLifetime`.
- `expires - now <= max_lifetime(use case)`, else `InvalidLifetime`. The bound
  is the configured maximum credential age plus skew (assertion `exp` cap, TOTP
  window, DPoP `iat` window). This keeps a caller bug or a missing `exp` cap
  from creating entries, or cluster buckets, far in the future.
- `id` is at most 256 bytes. That is the store's cap; a caller may apply a lower
  one first. DPoP keeps its `MAX_JTI_LEN` of 128 bytes
  (`oauth2_client/dpop.rs`) and rejects with `invalid_dpop_proof`. An assertion
  `jti` over 256 bytes is rejected with `invalid_grant`. In both cases the
  credential is rejected before `consume`, never truncated. The lower cap
  wins.

Implementations:

- **Local**: the bounded in-process cache of #1640 (`ReplayCache`). Its bounds
  are configured per use case (section 2).
- **Cluster**: a Raft-backed store (section 3).

### 2. Local implementation

Keeps the rules of the existing DPoP cache: bounded per scope, per domain (for
assertions) and in total, and **a live entry is never evicted to make room**.
Once a bound is reached, new credentials are refused (`Capacity`). Evicting
would let an attacker flood the cache with fresh scopes, push out the entry of a
captured credential and replay it. The per-domain bound keeps one domain's
tenants from exhausting the total for every other domain. Dead entries are
purged lazily when a bound is about to be hit and by a periodic task.

Bounds are options. The existing DPoP options
`[oauth2] dpop_replay_cache_max_entries` and
`dpop_replay_cache_max_entries_per_key` keep their names and meaning (total, and
per `jkt`) and apply to both DPoP use cases; the existing check that the
per-key value does not exceed the total stays. New options follow the same
shape: `[oauth2] assertion_replay_cache_max_entries`,
`assertion_replay_cache_max_entries_per_domain` and
`assertion_replay_cache_max_entries_per_issuer`, and
`[auth] totp_replay_cache_max_entries` and
`totp_replay_cache_max_entries_per_user`. Each per-scope value must not exceed
its total.

### 3. Cluster implementation

**Records.**

- Key `"{len(scope)}:{scope}{id}"` in a keyspace
  `single_use_{use_case}_{bucket}` with `bucket = expires / 300` (bucket width
  300 s).
- Written with `Mutation::create_if_absent` as a **durable** record:
  `Metadata::new()`, `DataTier::Internal`, empty value. The record goes through
  the normal encrypted Fjall path and is part of snapshots, so it survives a
  restart, a snapshot install and a leader change like any other state.
- Keys are stored in plaintext, as for every other record. They hold only
  identifiers that are not secret (domain id, issuer, `jti`, user id, credential
  id, time step). The value is empty, so the encryption adds integrity only.
- Cost per `consume`, on every node: one AES-GCM encryption of an empty value
  and two small entries (data, meta) in the batch that `apply()` already writes
  and fsyncs once per apply call. No additional fsync.

**Result mapping.**

| Storage result                                   | `SingleUseError` |
| ------------------------------------------------ | ---------------- |
| committed, no violation                          | `Ok`             |
| `CONFLICT` violation                             | `Replayed`       |
| any other violation (`WRITE_RATE_EXCEEDED`, ...) | `Unavailable`    |
| transport error, timeout, no leader              | `Unavailable`    |

Only `CONFLICT` means replay. Mapping any other violation to `Replayed` would
record a replay in the audit trail that did not happen.

**Bucket from `expires`.** The bucket is derived from `expires`, not from the
current time. Every presentation of the same credential has the same `expires`,
so every node resolves it to the same keyspace and one atomic create decides the
question. Time-based buckets as used for WebAuthn state would need a look-back
across keyspaces, which is not atomic. A credential whose `jti` is reused with a
different `exp` lands in another bucket and is not detected. Accepted: the
supported issuers that set `jti` (GitHub Actions, Keycloak) do not do this,
`exp` is signed so a presenter cannot change it, and it is capped.

**Replicated keyspace drop.** A new `Mutation::DropKeyspace { keyspace }` is
committed through Raft and applied on every node:

- Apply drops the keyspace and its data and meta entries if it exists, whether
  empty or not. Apply is serialized, so no write can race the drop. A missing
  keyspace is a no-op, which makes the mutation idempotent.
- Only keyspaces whose name matches an allow-listed prefix registered in the
  storage crate may be dropped. This ADR registers `single_use_`, and the name
  must have the form `single_use_{use_case}_{bucket}` with a numeric bucket. Any
  other keyspace, including core, reserved and other feature keyspaces such as
  `oauth2_keys` or the WebAuthn buckets, is refused as a violation. A bug in
  bucket-name computation therefore cannot reach unrelated state. A feature that
  adopts the mutation later (WebAuthn) registers its own prefix.
- Storage authorization (`grpc/authz.rs`) covers the new mutation like the other
  write mutations.
- A snapshot taken after the drop does not contain the keyspace; a follower that
  installs it gets the same state.

The existing local-only `drop_keyspace` stays for callers that need it.
WebAuthn's bucket cleanup has the same follower leak and can move to the new
mutation; that change is not part of this ADR.

**Cleanup.** Runs on the Raft leader only (`current_leader() == node_id()`).
Every node holds every bucket keyspace locally, so the leader lists its own
keyspaces by prefix instead of probing computed names. `StorageApi` gains a
read-only `list_keyspaces(prefix)` for this (Fjall can list keyspace names). For
each `single_use_{use_case}_{bucket}` with `(bucket + 2) * 300` in the past it
proposes `DropKeyspace`. This needs no look-back range and no watermark: a
bucket missed during an outage, a leader change or a gap is found on the next
tick, and a bucket is never left behind by a bounded probe. A leader change
between ticks only means the next leader proposes the same idempotent drop. No
per-key drain is needed.

**Retention.** One anchor: `expires`. With `bucket = floor(expires / 300)`, the
drop point `(bucket + 2) * 300` lies between `expires + 301` and `expires + 600`
s. An entry is therefore kept at least until `expires`, and dropped between
`expires + 300` and `expires + 600` s on the leader's clock, plus one cleanup
tick. `expires` is at most `max_lifetime` after the write, so an entry lives at
most `max_lifetime + 600` s plus one cleanup tick.

**Clock skew.** Buckets come from the credential's `expires`, but the drop uses
the leader's clock while each verifying node accepts the credential by its own
clock. A credential is replayable after the drop if a verifier's clock is
behind the leader's by more than the 300 s margin (the drop point is at least
`expires + 300` s). The margin is the tolerated skew between any two voters.
Operators must run time synchronization; a node whose clock differs from the
leader's by more than half the margin (150 s) reports it in a metric and a
warning, and the cluster store is documented as unsupported beyond the margin.
`[storage] single_use_cleanup_margin_secs` (default 300) raises the margin for
deployments with poorer synchronization, at the cost of longer retention.

**Admission limit.** The Raft store has no per-scope counter, and a holder of a
valid grant could otherwise turn requests into replicated durable writes. Every
node applies a per-scope admission rate to `consume` before it proposes: a
limiter in the ADR 0022 style keyed on the scope (`(domain_id, issuer)` for
assertions, `user_id` for TOTP, `jkt` for DPoP) plus a per-node cap on in-flight
proposals. A refused request returns `Capacity` and writes nothing. The bound on
cluster-wide entries is therefore `voters * rate * (max_lifetime + 600)`, not a
hard cap, which the section states instead of implying a quota. A bucket-size
metric and alert remain part of the implementation.

**Rolling upgrade (feature gate).** Nodes that do not know `DropKeyspace`
cannot apply it, and a replicated log entry they cannot decode would stop them.
A cluster-wide capability gate controls this:

- Each node advertises a storage feature level in its Raft node information
  (a new field next to `node_id` and `rpc_addr`).
- The leader proposes the committed record "`single_use_v1` enabled" only when
  every voter and learner reports the level. Until then the gate is closed and
  no node proposes `DropKeyspace` or writes `single_use_*` keyspaces.
- With the gate closed, defaults resolve as follows, logged once and exposed in
  the metric: external assertion exchange fails closed with `Unavailable` (the
  exchange is new in the same release and must not run without its check);
  TOTP and DPoP `/token` use `local`, never weaker than before the upgrade; a
  configuration that explicitly selects `raft` waits, with a warning, instead of
  failing start-up. Rule 1 (no silent fallback) applies to explicit
  configuration, not to this transient state.
- The gate opens once and does not close. A node added later must report the
  level or the join is refused. Downgrading below the level after the record is
  committed is unsupported and needs a restore from a backup.

### 4. Per-use-case configuration

The operator chooses the store per use case:

| Option                                                | Default                                              |
| ----------------------------------------------------- | ---------------------------------------------------- |
| `[oauth2] assertion_replay_store = raft \| local`     | `raft` when Raft storage is configured, else `local` |
| `[auth] totp_replay_store = raft \| local`            | same rule                                            |
| `[oauth2] dpop_token_replay_store = raft \| local`    | same rule                                            |
| `[oauth2] dpop_resource_replay_store = local \| raft` | `local`                                              |

The reasoning behind each default is in section 9.

Rules:

1. **No silent fallback.** An explicit `raft` without Raft storage is a start-up
   error. An unset option resolves by the default rule and the result is logged
   once.
2. **Fail closed.** With the cluster store selected, `Unavailable` rejects the
   request. It never degrades to the local cache at run time. `local` is a
   deployment choice, not a fallback.
3. **No "off".** A missing check on assertions or TOTP is a vulnerability, not a
   tuning choice.
4. **Weak combination is loud.**
   - External assertions: when token exchange with external assertions is
     enabled (at least one trusted issuer is configured), `local` is a start-up
     error unless
     `[oauth2] allow_per_node_assertion_replay = true`, **whether or not Raft is
     configured**. A deployment that does not use token exchange is not
     affected and needs no flag. Without Raft, Keystone cannot see other
     processes behind a load balancer, so it cannot tell a single node from
     many. The credential is a bare bearer token, so the operator must state
     that per-node is accepted.
   - TOTP and DPoP `/token`: `local` logs a warning at start-up naming the use
     case and its guarantee (section 7). With Raft, the warning is repeated
     while the cluster has more than one voter. It is a warning, not an error:
     for TOTP the password is a second factor, and for DPoP `/token` the proof
     is useless without the grant it was sent with.
   - DPoP resource requests: `local` is the default and logs nothing. Choosing
     `raft` logs a warning naming the cost (section 8).
5. The resolved store is visible in telemetry and in the audit event of the
   exchange.

Each use case gets its own keyspace prefix, so cleanup and sizing are separate.

### 5. When to record

The order of checks matters more than the store.

For **external assertions**:

1. Verify the credential (signature, `iss`, `aud`, `exp`, age cap).
2. Evaluate the mapping ruleset and require that it **matched** (bound claims
   such as repository or reference passed).
3. Only then call `consume`.
4. Mint the Keystone token.

Recording after step 1 would let any holder of a valid signature fill the store.
GitHub Actions issues a validly signed token with an arbitrary `aud` to any
GitHub user, so a stranger could exhaust the `(domain, issuer)` quota, and the
shared total, with tokens the mapping would reject. With the cluster store the
junk is also replicated to every node. Recording after step 2 limits entries to
tokens that were authorized.

For **TOTP**: call `consume` only after every authentication method in the
request has succeeded (for example password and TOTP), then issue the token.
Recording after the TOTP check alone would let someone who has seen a passcode
but lacks the password burn the step for the real user.

A credential that was recorded and then failed later (minting, database) is
**burned**: the client has to obtain a new one. This is deliberate. The
alternative, releasing the entry on failure, reopens a replay window.

A write can commit while its answer is lost (timeout, leader change). The caller
sees `Unavailable` and fails the request; the client's retry with the same
credential sees `Replayed`. This is the burned case above, not an attack, and
the audit event for `Replayed` must not be read as proof of theft on its own.

Further bounds:

- The quotas count entries, not bytes; the `id` length cap (section 1) bounds
  the bytes.
- The Raft store enforces an admission rate per scope (section 3), in addition
  to the ordering above, `max_lifetime` and rate limiting of the token endpoint
  (ADR 0022). There is no cluster-wide hard cap; the bound is stated in section
  3. A bucket-size metric with an alert is part of the implementation.

### 6. Errors, audit and metrics

| `SingleUseError`  | External assertion (`/token`)      | TOTP                      | DPoP (`/token`, resource request)             |
| ----------------- | ---------------------------------- | ------------------------- | --------------------------------------------- |
| `Replayed`        | 400 `invalid_grant`                | 401, same as bad passcode | 400 / 401 `invalid_dpop_proof` (RFC 9449)     |
| `Capacity`        | 503, `Retry-After`                 | 503, `Retry-After`        | 503, `Retry-After`                            |
| `Unavailable`     | 503, `Retry-After`                 | 503, `Retry-After`        | 503, `Retry-After`                            |
| `InvalidLifetime` | 400 `invalid_grant`, logged as bug | 500, logged as bug        | 400 / 401 `invalid_dpop_proof`, logged as bug |

A `Replayed` result is a signal that a credential leaked or a client misbehaves.
It emits a CADF audit event with the use case, the scope (domain and issuer, or
user), the `jti` or step and the resolved store, and increments a metric
labelled by use case and store. The response body does not say which check
failed beyond the error code.

### 7. Guarantees

| Use case              | `local`                                    | `raft`                                                           |
| --------------------- | ------------------------------------------ | ---------------------------------------------------------------- |
| External assertion    | at most once per node, empty after restart | at most once per cluster while the entry is retained (section 3) |
| TOTP                  | same                                       | same                                                             |
| DPoP `/token`         | per node; nonce is cluster-wide            | at most once per cluster (default with Raft)                     |
| DPoP resource request | per node; proof and token travel together  | at most once per cluster; not recommended (section 8)            |

The `raft` column also assumes the gate (section 3) is open and the voters'
clocks are within the cleanup margin.

Operators must read this table as: `local` bounds replay per node, not per
cluster. The `raft` guarantee holds across restarts, snapshot installs and
leader changes. It does not hold across a restore from a backup older than
`max_lifetime`: entries written after the backup are lost and those credentials
can be replayed until they expire. A restore is an operator action and the
runbook says so.

### 8. DPoP

DPoP is split into two use cases.

- **`/token` proofs** default to `raft` when Raft storage is configured. The
  cost is one Raft write on a rare request, the same as an assertion exchange.
- **Resource-request proofs** stay on `local` (ADR 0043). `raft` is allowed but
  **not recommended**: a Raft write and a durable entry per authenticated API
  request scale with traffic, an outage of the cluster store fails every DPoP
  request closed, and anyone holding one valid token and key can turn request
  volume into consensus writes on every node.

ADR 0043's wording ("the short window bounds the impact") is amended to state
the actual guarantee: at most once per node for resource requests, at most once
per cluster for `/token` on Raft deployments, and for resource requests an
attacker who holds the proof also holds the access token.

`htu` covers scheme, host and path only (RFC 9449 §4.2); neither the query nor
the body is bound. A captured resource request can therefore be replayed on
another node within the `iat` window with a different query or body to the same
method and path. The mitigation is the window length (`max_skew_secs`, default
60 s), not consensus.

### 9. Secure default rationale

The EU Cyber Resilience Act (Annex I, Part I) asks for a secure-by-default
configuration, and NIS2 (Art. 21) treats availability as part of security. A
secure default is not the strongest mechanism everywhere: it handles the known
risks without operator action and states the residual risk, so an operator can
judge the trade-off. This section is that record for each default.

| Use case              | Default (with Raft / without) | Risk handled                                         | Residual risk                                                                                                                   |
| --------------------- | ----------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| External assertion    | `raft` / start-up error       | replay of a bare bearer credential minting a token   | restore from an old backup (section 7); without Raft, per node, only after explicit opt-in                                      |
| TOTP                  | `raft` / `local` + warning    | reuse of an observed passcode across nodes           | without Raft, per node; the password still has to be known                                                                      |
| DPoP `/token`         | `raft` / `local` + warning    | reuse of a captured proof across nodes               | without Raft, per node; a replay also needs the grant (single-use code, rotated refresh token) and a valid nonce                |
| DPoP resource request | `local` / `local`             | replay on the same node; any replay after the window | replay on another node within the window, to the same method and path, with any query or body; attacker already holds the token |

Why the DPoP resource-request default is not `raft`:

- RFC 9449 §11.1 requires only a short acceptance window; a `jti` store is
  something a server may add. `local` already exceeds the standard.
- `raft` would make every DPoP-authenticated API request depend on cluster
  consensus, which turns a Raft outage into a full authentication outage and
  request volume into replicated writes. Both weaken availability more than the
  per-node gap weakens integrity.

Hardening available to operators, documented in the configuration reference:
lower `max_skew_secs`, and set `dpop_resource_replay_store = raft` where the
API traffic and the availability coupling are acceptable.

## Alternatives considered

- **Local cache only.** Rejected for assertions and TOTP: with N nodes the
  guarantee is N uses; the credential is a bearer token. Kept for DPoP and for
  deployments without Raft.
- **Ephemeral Raft records.** Rejected: a snapshot install clears them and a
  restarted node does not rebuild them, so a leader that restarted inside the
  window accepts a replay (see Context).
- **A new record class kept in memory and included in snapshots.** Rejected for
  now. Snapshots alone do not fix restarts, because a node resumes from Fjall's
  `last_applied_log` and never reloads a snapshot at start-up. It would need a
  start-up recovery step (load the class from the last snapshot, re-apply the
  log after it), a copy of the map consistent with the snapshot index, and
  upgrade gating. The saving over durable records is one small encryption and a
  few memtable entries per write, since `apply()` already fsyncs. Can be
  revisited with its own ADR if a benchmark shows Fjall apply is the bottleneck,
  e.g. for DPoP on resource requests.
- **An unencrypted storage tier.** Rejected. The saving is microseconds per
  write, while "all state at rest is encrypted" (ADR 0016-v2) is a rule that is
  easy to audit and an exception would have to be reviewed for every future
  record placed in it. It also adds an unencrypted branch to read, DEK rotation,
  re-encryption, quarantine and restore.
- **Memcached.** Rejected as the only store. It evicts under memory pressure,
  which breaks the no-eviction rule above; a restart or a node loss empties it
  silently; it adds a mandatory service that the project avoids by design, with
  TLS, authentication and audit work. It would fit behind the trait as an
  optional backend.
- **Redis with `noeviction`.** Technically sufficient (`SET NX EX`), but a new
  mandatory dependency. Same position as memcached: possible later behind the
  trait for high-rate cases such as DPoP on resource requests.
- **Raft by default for all DPoP proofs.** Rejected for resource requests:
  write cost scales with API traffic, an outage fails all authenticated
  requests, and request volume becomes cluster write load (section 9). Adopted
  for `/token` proofs.
- **`local` by default for all DPoP proofs (ADR 0043 as written).** Rejected for
  `/token`: the cluster check costs one write on a rare request, so leaving it
  off would not be a defensible secure default.
- **Time-based buckets as in WebAuthn.** Rejected for single-use checks because
  the atomic create guards only one keyspace.
- **Per-key drain before a local drop (WebAuthn pattern).** Rejected: the drop
  does not reach followers, and draining costs one Raft write per entry. The
  replicated `DropKeyspace` removes a bucket in one entry on every node.

## Implementation notes

1. Trait, error type, preconditions, scope helpers and the shared behavioural
   suite (`single_use` in `crates/core`), the replay options and their
   validation. No implementation lands with this step.
2. #1640 on top of step 1: `ReplayCache` implements the trait through a thin
   async wrapper, gains the per-domain bound and passes the shared suite;
   `AssertionReplayCache` builds its scope with `assertion_scope`;
   `DpopReplayCache` becomes a wrapper. Its module documentation is corrected
   to say per node only and to require recording after the mapping match. Then
   the store options and the start-up factory. `raft` is rejected with a clear
   message until step 4.
3. Storage: `Mutation::DropKeyspace` with the prefix allow-list (apply, authz,
   wire format, snapshot and restore tests), `list_keyspaces(prefix)`, the
   feature level in the node information and the capability gate, and a
   membership listing (voters and learners with their levels).
4. Raft implementation, cleanup task, admission limiter, tests against
   `MockStorage` and the cluster harness, including a leader restart and a
   snapshot install inside the window. The same behavioural suite runs against
   both implementations through the trait: boundary at `expires`,
   `InvalidLifetime`, quota without eviction, scope separation.
5. External assertion exchange (#945 step 5) and TOTP move onto the trait, with
   the error mapping, audit event and metric of section 6. The assertion path
   rejects a missing `jti`; the TOTP path follows section 1 (matched step,
   credential id, shared helper, `period` cap). DPoP gets its two
   options; `dpop_replay_store` is not introduced.
6. `require_no_conflict` exists in several Raft drivers; move it to
   `storage-api` rather than add another copy, and make it map only `CONFLICT`
   to a conflict.

## Open questions

- The storage API exposes `current_leader()` and `node_id()` but no membership
  listing. The feature gate (section 3) and the repeated warning in section 4
  rule 4 both need it, so it is added to `StorageApi` (implementation step 3).
- A derived id for issuers that omit `jti` (for example SPIFFE JWT-SVIDs) would
  need a hash and a crypto inventory row; not decided here.
- Deployments with SQL but without Raft only get `local`. A unique-key table in
  the SQL driver could provide a cluster store for them; not evaluated.

## Consequences

- External assertion exchange gets a cluster-wide single-use guarantee on Raft
  deployments that holds across restarts and leader changes, and an explicit,
  acknowledged per-node guarantee elsewhere. An operator cannot get the weaker
  one by accident, with or without Raft.
- A cluster store adds one consensus write per exchange or TOTP login, and a few
  hundred bytes per entry in Fjall on every node (key with domain, issuer and
  `jti`, plus metadata) for at most `max_lifetime + 600` s plus one cleanup
  tick.
- The cluster store needs time synchronization between voters within the cleanup
  margin, and a one-way capability gate during a rolling upgrade.
- Issuers that do not set `jti` cannot be used for token exchange.
- The storage layer gains a replicated keyspace drop that other bucketed state
  (WebAuthn) can adopt.
- Exchange, TOTP and DPoP `/token` availability depend on the cluster store
  when it is selected, which is the default on Raft deployments. A Raft outage
  fails them closed. DPoP resource requests do not depend on it by default.
- Each default and its residual risk is recorded (section 9) as the
  secure-by-default record for CRA and NIS2 assessments.
- A burned credential cannot be retried; clients must obtain a new one.
- The trait lets a Redis-style backend be added later without touching the
  callers.
