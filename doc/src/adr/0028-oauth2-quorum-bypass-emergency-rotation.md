# 28. Quorum-Bypass Emergency Signing-Key Rotation (Amends ADR 0026 §3)

**Date:** 2026-07-15

## Status

Proposed

## Reference

Amends [ADR 0026](0026-oauth2-oidc-provider.md) §3 ("Emergency Rotation and
Signing Key Compromise"), which specifies but does not build:

> As a fallback, an out-of-band emergency rotation can be triggered locally
> on any node via UDS + loopback, without Raft quorum coordination, when the
> cluster is compromised and dual-control is impossible.

Also relevant: [ADR 0016-v2](0016-v2-raft-storage.md) §6.2 (DEK emergency
rotation), which this ADR's normal-path emergency rotation was explicitly
modeled on and which has the identical gap — DEK emergency rotation also
requires Raft quorum, with no local fallback.

## Context

ADR 0026's emergency signing-key rotation
(`keystone-manage oauth2 rotate-signing-key --emergency` +
`confirm-rotate-signing-key`, `crates/keystone/src/api/v4/oauth2/
rotate_signing_key.rs`, `confirm_rotate_signing_key.rs`,
`crates/core/src/oauth2_key/service.rs`) is fully implemented, but every
write in that path — staging the pending key, confirming it, promoting it
to `Primary/Active`, and recording the `revoked_jtis` list — is a Raft
proposal. Raft proposals require quorum to commit.

This is fine for the common case: "signing key compromised, cluster
healthy." It fails exactly in the scenario ADR 0026 §3 called out as the
reason for a fallback: **the Raft cluster has simultaneously lost quorum**
(a majority of nodes down, or network-partitioned) **at the moment a
signing key is suspected compromised**. In that window:

- The operator cannot rotate the key at all through the existing path —
  every proposal blocks indefinitely waiting for a leader/quorum that
  doesn't exist.
- The compromised key keeps validating (and, if an attacker holds it,
  keeps minting forged tokens) for as long as the partition lasts, which
  may be the exact period an attacker engineered by causing the partition
  in the first place.
- "Just wait for quorum" is not an acceptable answer, because the premise
  is that a key is actively being abused *right now*.

No existing mechanism in the codebase models this. ADR 0016-v2's DEK
emergency rotation (§6.2), which this feature explicitly mirrors, has the
same limitation — `rotate-dek --emergency` is also a Raft-gated gRPC call
with dual-control confirmation, with no quorum-bypass path. There is
nothing in this codebase to lift the design from; it has to be worked out
here.

This is why ADR 0026 recorded the requirement but did not build it: it is
a standalone distributed-systems design problem — local-write availability
under partition, reconciliation on rejoin, and a new authentication
boundary — not a follow-up-sized feature.

## Decision

Add a **node-local emergency key path** that operates entirely without
Raft, gated behind a Unix domain socket that only accepts loopback-local
connections, used *only* when an operator has independently confirmed
Raft quorum is unavailable. This section specifies the write path, the
authentication boundary, and the reconciliation semantics required to make
that safe. It intentionally does **not** get built as part of this ADR
being accepted — see "Implementation Status" below.

### 1. Trigger conditions and operator workflow

This path is not a first resort. The existing quorum-based emergency
rotation (ADR 0026 §3) remains the default; this path is reached only
when an operator has already determined that path is unusable:

```
keystone-manage oauth2 rotate-signing-key --domain <domain_id> \
  --emergency --local-quorum-bypass \
  --justification "<free text, required, goes into local audit trail>"
```

- `--local-quorum-bypass` is refused unless the target node's local Raft
  client reports it is *not* part of a functioning quorum (leaderless, or
  has not received a heartbeat within a configurable window). This is a
  guardrail against accidental misuse, not a security control — see
  Threat Model below for why it cannot be trusted as one.
- Dual control is **not required** for this path. ADR 0026 §3's two-operator
  confirmation exists to prevent a single compromised/rogue operator
  credential from unilaterally rotating a key; that control assumes the
  second operator can reach the cluster to confirm. Under partition, a
  second operator may not be reachable at all, and demanding one would
  make the "impossible" case in ADR 0026 §3's own framing literally
  impossible. Single-control is the accepted tradeoff for this path only —
  see Consequences.
- `--justification` is mandatory free text, persisted locally (below) and
  surfaced prominently by the reconciliation step, so the eventual review
  has the operator's own stated reasoning, not just a bare event.

### 2. The UDS auth boundary

A new local-only listener, separate from the existing admin UDS used by
`keystone-manage`:

- **Socket:** `[oauth2] local_emergency_socket_path`, filesystem-permission
  restricted (owner-only, `0600`), created by the `keystone` process at
  startup — not shared with any other subsystem.
- **No mTLS/SPIFFE round-trip.** ADR 0026 §3's normal emergency path
  authenticates via SPIFFE mTLS against the admin UDS, which implicitly
  depends on a reachable SPIRE control plane. The premise of this ADR is
  that the control plane may itself be partitioned or degraded, so this
  path must not depend on it. Authentication is instead **OS-level**: the
  connecting process must be running as a member of a dedicated local
  group (`keystone-emergency`, configurable) verified via `SO_PEERCRED`
  (Linux) — the same mechanism Docker/systemd use to authenticate local
  socket peers without a network round-trip.
- **Why this is not "unauthenticated local-root escalation."** `SO_PEERCRED`
  confirms the connecting process's real UID/GID at the kernel level; it
  cannot be spoofed by a remote attacker without already having local code
  execution as a member of that group. This does **not** eliminate risk —
  see Threat Model — but it is the same trust boundary every other
  loopback-only administrative socket on the host already relies on (e.g.
  systemd's `/run/systemd/private`), not a new category of exposure.
- **Rate- and single-flight-limited.** At most one pending local emergency
  rotation per domain per node at a time; the socket rejects a second
  request while one is pending.

### 3. The local write

1. Generate a fresh keypair in memory (identical crypto path to normal
   rotation, ADR 0026 §3).
2. Write it to a **node-local, non-Raft** store:
   `_local:oauth2:signing_key:<domain_id>:emergency:<rotation_id>`,
   persisted in the node's local FjallDB partition (the same storage
   engine Raft state uses, but written directly, bypassing the Raft log
   entirely — this is the whole point).
3. Mark it `Primary/Active` **for this node's own signing operations
   only**. Other nodes are not informed synchronously (they may be
   unreachable) — see Propagation below.
4. Record the compromised key as locally `revoked` and start a local-only
   JTI revocation list, `_local:oauth2:signing_key:<domain_id>:revoked_jtis`,
   which this node's copy of the ADR 0026 §6 revocation endpoint serves
   immediately, merged with whatever the last-known Raft-replicated
   revocation list contained.
5. Append an entry to a local, tamper-evident audit log
   (`_local:oauth2:emergency:audit:<rotation_id>`, HMAC-chained the same
   way as ADR 0023's audit spool) recording: operator identity (from
   `SO_PEERCRED`), justification text, timestamp, old/new `kid`, and the
   node's Raft term/quorum status at the time of the write. This is the
   record reconciliation and post-incident review depend on.

### 4. Propagation while partitioned

A node that took a local emergency action while cut off from the rest of
the cluster does not silently keep signing alone forever:

- If this node can still reach *any* peers (a network partition need not
  be symmetric or total), it gossips the local emergency key and
  revocation-list delta to reachable peers **out-of-band from Raft** —
  best-effort, not consensus. A receiving peer stores it in the same
  `_local:...:emergency:...` namespace (not promoted to its own
  Raft-replicated state) and, if it is not already using a *different*
  local emergency key for the same domain, adopts this one for its own
  signing so that JWKS served by reachable nodes converges without
  requiring quorum.
- If a receiving peer already staged a *different* local emergency key for
  the same domain (two operators independently declared an emergency on
  two different partitioned segments), it does **not** silently pick one —
  it flags a `LOCAL_EMERGENCY_KEY_CONFLICT` condition, keeps signing with
  its own local key, and surfaces the conflict for manual reconciliation
  (below). Silently choosing is exactly the split-brain risk this design
  must not paper over.

### 5. Reconciliation on quorum rejoin

This is the step that makes the local write safe rather than merely
convenient — a local write is only acceptable because it has a defined,
non-silent path back into cluster-authoritative state:

1. When a node that performed (or adopted) a local emergency rotation
   rejoins a healthy quorum, it does **not** auto-promote its local key to
   the Raft-replicated `Primary/Active` slot. It submits the local
   emergency key as a **proposed** Raft rotation (reusing the normal
   rotation proposal shape, ADR 0026 §3 step 2) and blocks — continuing to
   serve JWKS/tokens with its local key in the meantime — until that
   proposal commits or is explicitly rejected by an operator.
2. **No key ever wins by default.** If exactly one node performed a local
   emergency rotation, its proposal is the obvious candidate and an
   operator confirms it (single command, `keystone-manage oauth2
   reconcile-emergency-key --domain <id> --rotation-id <id> --accept`).
   If multiple nodes performed *conflicting* local rotations
   (`LOCAL_EMERGENCY_KEY_CONFLICT` from step 4 above), reconciliation
   requires an explicit operator choice among the candidates — the system
   refuses to auto-merge two independently-generated keypairs, since
   there is no principled way to know which (if either) actually excludes
   the compromised material an attacker might have used during the split.
3. Once a local emergency key is accepted into Raft, every node's
   previous local-only state
   (`_local:oauth2:signing_key:<domain_id>:emergency:*`) for that domain
   is cleared, and the standard ADR 0026 §3 JTI-revocation and
   CADF-audit-event steps run as normal, with the node-local audit trail
   (step 3.5 above) attached as supplementary evidence, not a replacement
   for the CADF event.
4. Tokens signed by a node during the local-only window remain valid
   under whichever key ultimately wins reconciliation, provided that key
   is what gets published to JWKS; tokens signed under a *rejected*
   candidate key become unverifiable the moment that key is discarded
   (nothing publishes it), which is the intended containment outcome for
   a rejected/conflicting emergency key, not a bug to work around.

## Threat Model

This path deliberately narrows availability guarantees to preserve
containment guarantees, mirroring the fail-closed posture ADR 0026 §6/§11
already established for the ordinary path:

- **This is a genuine expansion of the attack surface**, not a free
  option. Any process that can reach the local socket as a member of the
  `keystone-emergency` group can mint a new signing key without a second
  operator's confirmation. This is why the socket has no network
  reachability (loopback + filesystem-permissioned UDS only) and why the
  group membership is intentionally a separate, narrower grant than
  general node administrative access.
- **Split-brain is possible, not eliminated.** Two operators on two
  genuinely partitioned segments can each declare an emergency and produce
  two different "authoritative-until-reconciled" keys. The design's
  answer is to make that conflict *visible and blocking* (§5.2) rather
  than to guess a resolution — an incorrect automatic merge would be
  worse than a stalled reconciliation an operator has to look at.
- **A local key is not retroactively provable as legitimate.** The local
  audit entry (operator identity via `SO_PEERCRED`, justification,
  timestamp) is evidence for post-incident review, not a cryptographic
  proof the action was authorized by policy the way the Raft-committed
  dual-control path is. Deployments with a low tolerance for this residual
  trust requirement should restrict `keystone-emergency` group membership
  to the smallest possible operator set and treat any use of this path as
  an incident in its own right, reviewed regardless of outcome.

## Consequences

### Positive

- Closes the gap ADR 0026 §3 explicitly flagged: a compromised key can be
  contained even when the cluster cannot reach quorum, instead of bleeding
  forged tokens for the duration of a partition.
- Reconciliation semantics are explicit and non-silent, avoiding the
  common split-brain failure mode of "last writer wins."

### Negative / Risks

- **Weakens dual control** for exactly the rotations most likely to be
  under active adversarial pressure. Accepted because demanding
  reachability of a second operator during a partition would make the
  fallback vacuous.
- **New local trust boundary** (`SO_PEERCRED` + group membership) that
  does not exist anywhere else in the codebase and must be operationally
  hardened (group membership hygiene, host-level access control) by the
  deploying organization — Keystone cannot enforce this from inside the
  process.
- **Conflicting local keys require a human in the loop** to resolve;
  there is no fully automated recovery from a true split-brain emergency
  rotation. This is intentional (see Threat Model) but does mean
  mean-time-to-recovery from that specific scenario includes an operator
  reconciliation step, not just a timer.
- **Additional storage/propagation machinery** (`_local:oauth2:...`
  namespace, best-effort peer gossip, reconciliation proposal type) that
  must be maintained alongside the existing Raft-backed key lifecycle.

## Implementation Status

Not implemented. This ADR records the design so the gap acknowledged in
ADR 0026 §3 has a concrete shape to build against; implementation is a
separate, standalone piece of work given the scope above (new local
storage namespace, new UDS listener and peer-credential auth path,
best-effort gossip protocol, and a new reconciliation Raft proposal type
and CLI command).
