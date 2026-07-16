# 28. Quorum-Bypass Emergency Operations (Amends ADR 0026 §3 and ADR 0016-v2 §6.2)

**Date:** 2026-07-15

## Status

Implemented (2026-07-16) — see [Implementation Status](#implementation-status)
below for the two resolved design gaps and the scope decisions made along the
way.

## Reference

Amends two existing emergency-rotation designs that share an identical, unbuilt
gap:

- [ADR 0026](0026-oauth2-oidc-provider.md) §3 ("Emergency Rotation and Signing
  Key Compromise"), which specifies but does not build:

  > As a fallback, an out-of-band emergency rotation can be triggered locally on
  > any node via UDS + loopback, without Raft quorum coordination, when the
  > cluster is compromised and dual-control is impossible.

- [ADR 0016-v2](0016-v2-raft-storage.md) §6.2 (DEK emergency rotation), whose
  `rotate-dek --emergency` path is also a Raft-gated, dual-control gRPC call
  with no local fallback, and which ADR 0026 §3's design was explicitly modeled
  on.

Both are instances of the same underlying problem: **a Raft-committed emergency
operation cannot execute at the one moment it is most likely to be needed — when
quorum is already lost.** Rather than solve this twice (and inevitably drift
into two slightly different local-bypass mechanisms with two slightly different
failure modes), this ADR defines one quorum-bypass mechanism that both
subsystems instantiate, and that future Raft-gated emergency operations can
adopt without re-deriving the design.

## Context

Every write in both existing emergency paths — staging, confirming, promoting,
and recording revocations for a signing key
(`crates/core/src/oauth2_key/service.rs`) or a DEK (`crates/storage/`,
`RotateDekRequest`) — is a Raft proposal. Raft proposals require quorum to
commit.

That is fine for the common case: "key/DEK compromised, cluster healthy." It
fails exactly in the scenario both ADRs called out as the reason for a fallback:
**Raft has simultaneously lost quorum** (majority of nodes down, or
network-partitioned) **at the moment a key or DEK is suspected compromised**. In
that window:

- The operator cannot rotate anything through the existing paths — every
  proposal blocks indefinitely waiting for a leader/quorum that doesn't exist.
- The compromised key/DEK keeps validating or decrypting (and, if an attacker
  holds it, keeps being useful to them) for as long as the partition lasts —
  possibly a window the attacker engineered by causing the partition in the
  first place.
- "Just wait for quorum" is not an acceptable answer, because the premise is
  that the material is being actively abused _right now_.

No existing mechanism in the codebase models this for either subsystem. This is
why both ADRs recorded the requirement but did not build it: it is a standalone
distributed-systems design problem — local-write availability under partition,
an authentication boundary that does not itself depend on the thing that's
partitioned, and reconciliation on rejoin — not a follow-up-sized feature, and
not one worth designing per-subsystem.

## Decision

Add a **generic node-local emergency write path**, usable by any Raft-gated
emergency operation, that operates entirely without Raft and is authenticated
over the **existing admin UDS** — the same SPIFFE-mTLS Unix-domain-socket
interface (`spiffe_tls_uds`, `[interface_admin]`) that `keystone-manage` already
uses for the ordinary (quorum-requiring) emergency rotation paths in ADR 0026 §3
and ADR 0016-v2 §6.2. This section specifies the generic write path, why the
existing admin UDS is sufficient as the auth boundary, and the reconciliation
semantics required to make a non-Raft write safe. It intentionally does **not**
get built as part of this ADR being accepted — see "Implementation Status"
below.

### 0. Why the existing admin UDS, not a new one

- The admin UDS's SPIFFE mTLS verification is against a **locally cached**
  X.509-SVID and trust bundle, served to `keystone` by the **local**
  `spire-agent` over its own workload-API socket — not a round-trip to a remote
  SPIRE server. A Raft network partition (which affects
  `[distributed_storage] node_cluster_addr` connectivity between nodes) is a
  different network path entirely from a host-local SPIRE agent socket. The two
  failure domains are not the same, and treating "Raft can't reach quorum" as
  evidence "SPIFFE mTLS is unusable" was an unjustified leap.
- The admin UDS listener (`interface_admin` in `keystone.rs`,
  `spiffe_tls_uds::start_axum_app`) **already** enforces a peer-credential check
  — `peer_uid`/`peer_gid` — layered underneath the mTLS handshake. That is the
  same class of local trust boundary the original draft wanted to build from
  scratch (`SO_PEERCRED` against a dedicated group); it already exists, is
  already configured, and is already the boundary every other admin operation
  (client registration, normal signing-key rotation, DEK rotation triggers)
  depends on.
- A second socket would mean a second listener, a second auth path, a second
  `keystone.conf` section, and a second thing to keep in sync with the first —
  for a security property (local-process authentication) the first socket
  already provides. That is complexity this design does not need.

Reusing the admin UDS is therefore the default, not an optimization: this ADR
builds one new _capability_ (Raft-bypassing local writes with reconciliation) on
the _existing_ authentication boundary, rather than building a new boundary too.

**When this would not be sufficient.** If the local `spire-agent` itself is down
or its cached SVID has expired at the same moment quorum is lost — a compound
failure, not the partition scenario this ADR targets — the admin UDS is unusable
regardless of Raft state, with or without this ADR. That is a pre-existing
operational dependency of every admin-UDS-gated operation in the codebase today
(not something this ADR introduces), and is out of scope here: hardening
SPIRE-agent-down resilience, if wanted, is a separate ADR. This design does not
add a second fallback for that compound case, because doing so would reintroduce
exactly the "new trust boundary nobody asked for" cost this section just
rejected.

### 1. Trigger conditions and operator workflow

This path is not a first resort. The existing quorum-based emergency rotation
paths (ADR 0026 §3, ADR 0016-v2 §6.2) remain the default; this path is reached
only when an operator has already determined those are unusable. The CLI shape
is shared across subsystems, with the target resource identifying which:

```
# OAuth2 signing key
keystone-manage oauth2 rotate-signing-key --domain <domain_id> \
  --emergency --local-quorum-bypass \
  --justification "<free text, required, goes into local audit trail>"

# DEK
keystone-manage storage rotate-dek \
  --emergency --local-quorum-bypass \
  --justification "<free text, required, goes into local audit trail>"
```

Both commands connect over the same admin UDS used by their non-bypass
`--emergency` counterparts (SPIFFE mTLS + `peer_uid`/`peer_gid`); the only new
element is the `--local-quorum-bypass` flag and the code path it selects on the
server side.

- `--local-quorum-bypass` is refused unless the target node's local Raft client
  reports it is _not_ part of a functioning quorum (leaderless, or no heartbeat
  within a configurable window). This is a guardrail against accidental misuse,
  not a security control — see Threat Model for why it cannot be trusted as one.
- Dual control is **not required** for this path. Both ADR 0026 §3 and ADR
  0016-v2 §6.2's two-operator confirmation exists to prevent a single
  compromised/rogue operator credential from unilaterally rotating a key/DEK;
  that control assumes the second operator can reach the cluster to confirm.
  Under partition, a second operator may not be reachable at all, and demanding
  one would make the "impossible" case both ADRs' own framing already describes
  literally impossible. Single-control is the accepted tradeoff for this path
  only — see Consequences.
- `--justification` is mandatory free text, persisted locally (below) and
  surfaced prominently by the reconciliation step, so the eventual review has
  the operator's own stated reasoning, not just a bare event.

### 2. The write path (generic, per-subsystem-instantiated)

1. Perform the subsystem-specific generation step in memory: a fresh signing
   keypair (identical crypto path to ADR 0026 §3 normal rotation) or a fresh DEK
   (identical path to ADR 0016-v2 §6 step 1).
2. Write it to a **node-local, non-Raft** store, under a namespace shared across
   subsystems so the reconciliation and gossip machinery (below) is one
   implementation, not two:
   `_local:<subsystem>:<scope_id>:emergency:<rotation_id>`, e.g.
   `_local:oauth2_signing_key:<domain_id>:emergency:<rotation_id>` or
   `_local:dek:cluster:emergency:<rotation_id>` — persisted in the node's local
   FjallDB partition (the same storage engine Raft state uses, but written
   directly, bypassing the Raft log entirely — this is the whole point).
3. Mark it active **for this node's own signing/encryption operations only**.
   Other nodes are not informed synchronously (they may be unreachable) — see
   Propagation below.
4. Record the compromised key/DEK as locally revoked and start (or extend) a
   local-only revocation record under the same namespace convention
   (`_local:oauth2_signing_key:<domain_id>:revoked_jtis` for signing keys;
   `_local:dek:cluster:revoked` for DEKs), merged with whatever the last-known
   Raft-replicated revocation state contained. For OAuth2 this is served
   immediately by the node's copy of the ADR 0026 §6 revocation endpoint; DEKs
   have no external-facing revocation endpoint, so this entry exists for
   audit/reconciliation purposes only.
5. Append an entry to a local, tamper-evident audit log
   (`_local:emergency:audit:<rotation_id>`, HMAC-chained the same way as ADR
   0023's audit spool) recording: subsystem, operator identity (from the admin
   UDS's SPIFFE ID and/or peer uid/gid), justification text, timestamp, old/new
   key identifier, and the node's Raft term/quorum status at the time of the
   write. This is the record reconciliation and post-incident review depend on,
   for either subsystem.

### 3. Propagation while partitioned

A node that took a local emergency action while cut off from the rest of the
cluster does not silently keep operating alone forever:

- If this node can still reach _any_ peers (a network partition need not be
  symmetric or total), it gossips the local emergency key/DEK and
  revocation-state delta to reachable peers **out-of-band from Raft** —
  best-effort, not consensus. A receiving peer stores it in the same
  `_local:...:emergency:...` namespace (not promoted to its own Raft-replicated
  state) and, if it is not already using a _different_ local emergency value for
  the same scope, adopts this one for its own signing/decryption so that
  reachable nodes converge without requiring quorum.
- If a receiving peer already staged a _different_ local emergency value for the
  same scope (two operators independently declared an emergency on two different
  partitioned segments), it does **not** silently pick one — it flags a
  `LOCAL_EMERGENCY_CONFLICT` condition (subsystem-tagged), keeps operating with
  its own local value, and surfaces the conflict for manual reconciliation
  (below). Silently choosing is exactly the split-brain risk this design must
  not paper over.

### 4. Reconciliation on quorum rejoin

This is the step that makes the local write safe rather than merely convenient —
a local write is only acceptable because it has a defined, non-silent path back
into cluster-authoritative state. Generic across both subsystems:

1. When a node that performed (or adopted) a local emergency write rejoins a
   healthy quorum, it does **not** auto-promote its local value to the
   Raft-replicated authoritative slot. It submits the local emergency value as a
   **proposed** Raft rotation (reusing the normal rotation proposal shape for
   that subsystem) and blocks — continuing to serve with its local value in the
   meantime — until that proposal commits or is explicitly rejected by an
   operator.
2. **No value ever wins by default.** If exactly one node performed a local
   emergency write, its proposal is the obvious candidate and an operator
   confirms it with a single, subsystem-specific command
   (`keystone-manage oauth2 reconcile-emergency-key ...` /
   `keystone-manage storage reconcile-emergency-dek ...`). If multiple nodes
   performed _conflicting_ local writes (`LOCAL_EMERGENCY_CONFLICT` from §3),
   reconciliation requires an explicit operator choice among the candidates —
   the system refuses to auto-merge two independently-generated values, since
   there is no principled way to know which (if either) actually excludes the
   compromised material an attacker might have used during the split.
3. Once a local emergency value is accepted into Raft, every node's previous
   local-only state for that scope (`_local:<subsystem>:<scope_id>:emergency:*`)
   is cleared, and the standard subsystem-specific revocation and audit-event
   steps run as normal (ADR 0026 §3 step 5 for signing keys; ADR 0016-v2 §6.2
   step 6 for DEKs), with the node-local audit trail (§2 step 5 above) attached
   as supplementary evidence, not a replacement for the normal audit event.
4. Data/tokens produced by a node during the local-only window remain valid
   under whichever value ultimately wins reconciliation, provided that value is
   what gets published; material produced under a _rejected_ candidate becomes
   unverifiable/undecryptable the moment that candidate is discarded (nothing
   publishes or re-encrypts under it), which is the intended containment outcome
   for a rejected/conflicting emergency candidate, not a bug to work around.
   (For DEKs specifically, this means records written under a rejected local
   emergency DEK must be identified via `dek_version` and re-encrypted under the
   winning key — an operator step, not automatic, mirroring ADR 0016-v2 §6 step
   5's CAS-on-version re-encryption but triggered manually here.)

### 5. Subsystem instantiations

- **OAuth2 signing key (ADR 0026 §3):** as originally scoped in this ADR's first
  draft — see §1-§4 above. `GET /v4/oauth2/{domain_id}/jwks/revocation`
  continues to be the externally-visible surface; the local emergency revocation
  entries feed into it on the node that took the local action.
- **DEK (ADR 0016-v2 §6.2):** the same mechanism applied to the cluster's Data
  Encryption Key. Unlike the signing key, a DEK has no external HTTP surface —
  the "revocation" is purely internal (stop decrypting with it) — and
  reconciliation's re-encryption step is heavier (full CAS-on-version sweep per
  §4.4 above), since DEKs protect data at rest, not externally-verified tokens.
- **Future subsystems:** any future Raft-gated emergency operation should
  instantiate this mechanism (namespace convention, admin-UDS trigger, gossip,
  reconciliation) rather than inventing a parallel one, unless it has a concrete
  reason the generic shape doesn't fit — in which case that reason belongs in
  its own ADR amendment, the same way this one amends 0026 and 0016-v2.

## Threat Model

This path deliberately narrows availability guarantees to preserve containment
guarantees, mirroring the fail-closed posture ADR 0026 §6/§11 and ADR 0016-v2 §1
already established for their ordinary paths:

- **This expands the operations reachable over the admin UDS**, not the set of
  principals who can reach it. Anyone who can already authenticate to the admin
  UDS (SPIFFE mTLS + `peer_uid`/`peer_gid`) — i.e. anyone who could already
  trigger ordinary emergency rotation given quorum — can now also trigger the
  quorum-bypass variant without a second operator's confirmation. Because the
  auth boundary is unchanged from what every other admin-UDS operation already
  relies on, this ADR does not add a new category of exposure; it removes a
  control (dual-control) from an existing one, for the reasons given in §1.
- **Split-brain is possible, not eliminated.** Two operators on two genuinely
  partitioned segments can each declare an emergency and produce two different
  "authoritative-until-reconciled" values for the same scope. The design's
  answer is to make that conflict _visible and blocking_ (§3/§4.2) rather than
  to guess a resolution — an incorrect automatic merge would be worse than a
  stalled reconciliation an operator has to look at.
- **A local write is not retroactively provable as legitimate.** The local audit
  entry (operator identity from the admin UDS handshake, justification,
  timestamp) is evidence for post-incident review, not a cryptographic proof the
  action was authorized by policy the way the Raft-committed dual-control path
  is. Deployments with a low tolerance for this residual trust requirement
  should restrict admin-UDS access to the smallest possible operator set and
  treat any use of `--local-quorum-bypass` as an incident in its own right,
  reviewed regardless of outcome.
- **Compound failure (admin UDS also unusable) is out of scope**, as noted in §0
  — this ADR closes the "Raft partitioned, admin UDS fine" gap, not "everything
  is down at once."

## Implementation Status

Implemented across both subsystems: the shared `local-emergency-store` crate
(namespace, guardrail, gossip decision logic), a Fjall-backed store wired into
`crates/storage`, OAuth2 signing-key and DEK local-write/gossip/reconciliation
paths, and audit wiring. Two design gaps identified during implementation
(not anticipated by the ADR as originally written) were resolved as follows;
both diverge from a literal reading of this ADR and are recorded here rather
than silently.

**Design gap 1: DEK transport.** This ADR (and its originating planning
document) assumed `keystone-manage storage rotate-dek` already shared the
admin-UDS HTTP transport with the OAuth2 CLI commands. It doesn't --
`crates/cli-manage/src/storage/rotate_dek.rs` talks gRPC directly to
`ClusterAdminService` over the internal management network (mTLS/SPIFFE), not
through `interface_admin`. Rather than moving DEK management onto a new HTTP
surface with no precedent, the DEK local-write, gossip, and reconciliation
operations were added as new `ClusterAdminService` RPCs
(`RotateDekLocalEmergency`, `GossipLocalEmergencyCandidate`,
`ListDekLocalEmergencyCandidates`, `ReconcileDekLocalEmergency`),
authenticated the same way `RotateDek`/`ConfirmRotateDek` already are. This is
a smaller, more consistent extension of an existing boundary than introducing
a parallel HTTP admin surface for one operation.

**Design gap 2: audit mechanism.** This ADR describes the local audit entry as
"persisted in the node's local FjallDB partition... HMAC-chained the same way
as ADR 0023's audit spool," but ADR 0023's actual mechanism
(`crates/audit/src/spool.rs`, `dispatcher.rs`) is a filesystem JSONL spool with
independent per-event HMAC (a `seq` field, not a hash chain), not a Fjall
partition. Implemented instead as an ordinary `CadfEvent` through the existing
`AuditDispatcher`/spool pipeline (`OAUTH2_LOCAL_EMERGENCY_KEY_RECONCILED` for
OAuth2; `DEK_ROTATION_LOCAL_EMERGENCY_STAGED`/`_RECONCILED` for DEK, via the
distributed-storage crate's own `AuditForwarder`/`AuditRecord` mechanism,
which predates and is independent of `AuditDispatcher`). A compact
`_local:emergency:audit:<rotation_id>` pointer record (the
`_local:...` namespace convention this ADR specifies) is written in the local
Fjall keyspace on OAuth2 reconciliation, mapping a rotation id to its CADF
event id so reconciliation/audit tooling can find the spool entry without a
full scan; DEK does not need this indirection because its simpler audit
records already embed `rotation_id` directly.

**Other scope decisions:**

- **Staging is audited on the OAuth2 side only if and when reconciled**,
  mirroring the pre-existing, unrelated-to-this-ADR convention that
  `stage_emergency_rotation` (the ordinary Raft-backed emergency path) is
  likewise unaudited until `confirm-rotate-signing-key` succeeds. DEK's own
  audit convention differs (it already audits `RotateDek`'s emergency stage 1)
  and the local-write path follows suit for consistency within that
  subsystem.
- **No admin-UDS-only SPIFFE extractor was built.** No existing HTTP handler
  anywhere in the codebase reads the `Interface::Admin` connection extension;
  every admin-UDS operation today is secured by the ordinary `Auth` extractor
  plus an OPA policy requiring `SystemAdmin`. The OAuth2 local-write,
  list-candidates, and reconcile endpoints reuse that same boundary rather
  than introducing a new one with no precedent.
- **Reconciliation is a per-node operation an operator drives explicitly**,
  not an automatic sweep. An operator must run `list-local-emergency-candidates`
  / `list-dek-local-emergency-candidates` against every node that may hold a
  candidate, then `reconcile-local-emergency-key` /
  `reconcile-dek-local-emergency` against the specific node holding the
  chosen `rotation_id`. There is no cross-node broadcast to clear a candidate
  once a sibling wins reconciliation elsewhere in the cluster -- only the
  node reconciliation was run against clears its own candidates. Gossip (§3)
  guarantees *visibility* of a conflict across nodes, not automatic cleanup
  everywhere once it is resolved.
- **DEK reconciliation additionally guards against a stale target version**:
  if a different rotation already committed to Raft while a candidate sat
  staged (e.g. an operator ran an ordinary `rotate-dek` in the meantime),
  reconciliation refuses rather than installing a DEK at a version that
  collides with or regresses past the live one, and the operator must re-stage
  a fresh local-quorum-bypass candidate instead.

## Consequences

### Positive

- Closes the gap both ADR 0026 §3 and ADR 0016-v2 §6.2 explicitly flagged, once,
  for both subsystems — instead of building (and maintaining) two independent
  local-bypass mechanisms.
- Reuses the existing admin UDS authentication boundary rather than introducing
  a new socket, new OS group, and new peer-credential check to operate and
  audit.
- Reconciliation semantics are explicit and non-silent, avoiding the common
  split-brain failure mode of "last writer wins."

### Negative / Risks

- **Weakens dual control** for exactly the operations most likely to be under
  active adversarial pressure. Accepted because demanding reachability of a
  second operator during a partition would make the fallback vacuous.
- **Conflicting local writes require a human in the loop** to resolve; there is
  no fully automated recovery from a true split-brain emergency write. This is
  intentional (see Threat Model) but does mean mean-time-to-recovery from that
  specific scenario includes an operator reconciliation step, not just a timer.
- **Additional storage/propagation machinery** (`_local:...` namespace
  convention, best-effort peer gossip, reconciliation proposal type) that must
  be maintained alongside the existing Raft-backed lifecycles for both signing
  keys and DEKs, and shared carefully enough between them that a bug fixed in
  one instantiation doesn't linger in the other.
- **Still depends on the local SPIRE agent being healthy**, as it always has for
  every other admin-UDS operation — this ADR does not change that dependency,
  and does not attempt to remove it (see §0).
