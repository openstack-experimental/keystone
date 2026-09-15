# Security Architecture Review: Preemptive Gates, Testing, and Vulnerability Vectors

Status: advisory review (2026-07-09), re-evaluated against `main` on 2026-09-14,
and followed same-day by an implementation pass closing five of the six
re-prioritized items — see §0 for what landed since and what remains. Companion
to [Security model](security-model.md)
(the normative invariant reference) and [Policy enforcement](../admin/policy.md). Where
the two disagree, `security-model.md` wins; this document proposes _additions_, it
does not restate or replace the invariants there.

Disclaimer: This review was performed by Claude Fable model with a human
directions.

## 0. Status at a glance (re-evaluated 2026-09-14)

The review's gates were largely adopted between 2026-07-09 and 2026-09-14. This
section records what actually landed, verified by direct code read against
`main`; the per-vector sections below carry the detail. **Landed** means the
mechanism exists _and_ runs in CI; **partial** means the mechanism exists but
does not yet cover what it was proposed to cover.

| Gate   | Status                    | Evidence                                                                                                                                                    |
| ------ | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A**  | Landed                    | `ci.yml` runs `opa test policy` unconditionally in the main job, not only on `paths: policy/**`                                                              |
| **B1** | Landed                    | `tools/check_policy_handler_coverage.py`, run unconditionally in `ci.yml`; four checks (missing policy / missing test / orphan policy / unenforced handler)  |
| **B2** | **Landed 2026-09-14 (§0a); coverage still partial** | `crates/core/src/api/policy_contract.rs` + `CapturingPolicy`, now with a fifth `check_policy_handler_coverage.py` check making adoption non-optional (shrink-only allowlist). Applied by **19 of 155** `enforce()`-calling handler modules |
| **B3** | **Harness landed, coverage partial** | `get_state_with_real_policy()` (`crates/keystone/src/api/mod.rs`) runs a real `opa run -s` over the actual `policy/` tree. Used by **17 of 155**  |
| **C**  | Landed                    | `tools/check_delegated_policy_scope_drift_tests.py`                                                                                                         |
| **D**  | Landed                    | `test_new_for_scope_delegated_roles_never_exceed_delegation_matrix`, `test_delegation_scope_kind_matrix_roles_never_exceed_delegation` (`crates/core/src/auth/tests.rs`) |
| **E**  | Landed                    | `tools/check_rego_undefined_argument_footgun.py`                                                                                                            |
| **F**  | Landed                    | `fuzz/` (5 targets) + `.github/workflows/fuzz.yml`; `scope_pinning_property` proptest                                                                        |
| **G**  | Landed (scheduled)        | `.cargo/mutants.toml` scoped to `core-types/auth.rs`, `core/auth.rs`, `core/policy.rs` + `mutants.yml` — deliberately not a required per-PR gate             |
| **H**  | **Partial**               | Publish-side cosign keyless signing **and** a verify step landed (`policy-container.yml`). `tools/verify_and_pin_opa_bundle.sh` (2026-09-14) provides the load-side verify-and-pin step as an explicit release tool; **nothing runs it automatically**, and `tools/opa_config.yaml` still defaults to the mutable `:latest` |
| **I**  | Landed                    | `tools/check_event_payload_no_secret_fields.py` + `policy_contract::assert_no_secrets`                                                                       |
| **J**  | Landed                    | `tools/check_security_checklist_sast.py`                                                                                                                    |

Vector status (updated after §0a): **V3, V5, V8a, V9, V10 closed**; **V1, V2
structurally backed** by Gates D/J; **V6 closed for the three endpoints it
named** (the design-level follow-up ADR remains open); **V3a's mechanism is
now a non-optional CI check, coverage remains partial**; **V4's publish side
is signed+verified, a verify-and-pin tool now exists for the load side, but
nothing runs it automatically**. **V7 and V8 are no longer hypothetical** —
the features shipped, so their "when implemented" framing is stale (§V7/§V8).

What the re-evaluation changes about priority: the original top recommendation
(A + B1 + B2) is now two-thirds done. The remaining work is no longer *building*
the input-contract mechanism — it exists and is good — but **making it
non-optional**, which was the point of proposing it as a route sweep (§V3a).

### 0a. Implementation pass (2026-09-14, same day)

The re-evaluation above was followed same-day by an implementation pass
against the §7 "Re-prioritized" list. Five of the six items landed:

| # | Item                                          | Outcome |
| - | ---------------------------------------------- | ------- |
| 1 | Make Gate B2 non-optional                      | **Done.** Fifth check added to `tools/check_policy_handler_coverage.py`: any file calling `.enforce(` must reference `policy_contract` (directly or via a sibling `#[path] tests.rs`), with an explicit, shrink-only `ALLOWLIST_NO_POLICY_CONTRACT` for the 136 pre-existing handlers not yet backfilled. `os_trust/trust/{create,show,list,delete}` and `ec2tokens/create` — the two named uncovered delegation surfaces — got full B2 *and* B3 coverage and are off the allowlist; adoption moved 14→19 of 155. |
| 2 | Ship `access_rules` enforcement                | **Done.** ADR 0037 + `enforce_access_rules()` (`crates/core/src/api/auth.rs`), called from every return path of `Auth::from_request_parts`. Denies a request-rules-restricted application credential's call that no rule permits against Keystone's own service, before OPA policy evaluation. See §V5. |
| 3 | Verify the policy bundle at load, pin by digest | **Partial.** `tools/verify_and_pin_opa_bundle.sh` does the `cosign verify` + digest-pin step as an explicit release-time tool (not wired into a running OPA's load path, since OPA itself still has no native hook — an init-container/admission-check integration is still a deployment-specific follow-up). See §V4. |
| 4 | Rate-limit the three remaining crypto endpoints | **Done.** `check_ip()` added to `v3/ec2tokens/create`, `v3/auth/token/show`, and the federation `jwt::login` / `oidc::callback` handlers. See §V6. |
| 5 | Correct ADR statuses                           | **Done.** ADRs 0022, 0025, 0026 changed from `Proposed` to `Accepted`, each naming the crates/modules that shipped it. See §V7/§V8. |
| 6 | Write the two open property tests              | **Done.** `crates/core/src/auth/tests.rs`'s `delegation_monotonicity_property` module: `app_cred_roles_never_exceed_delegation`, `trust_roles_never_exceed_delegation`, `app_cred_revoked_role_unusable_after_removal`, `trust_revoked_role_unusable_after_removal`, all driving the real `calculate_effective_roles()` over a synthetic 5-role universe. See §V10. |

## 1. Purpose and scope

This is an architecture-level security review of Rust Keystone from the
attacker's point of view. It answers three questions the project asked:

1. Where can **more preemptive security gates** (CI, design-time, structural) be
   added so that a class of bug is caught before merge rather than by review or
   in production?
2. How should the project **test for security gaps** rather than only testing
   the happy path?
3. What **vulnerability vectors** should the project name explicitly and control
   on purpose — through CI jobs, design documents, and penetration testing?

It deliberately does not re-derive the threat model already captured in
`security-model.md`. That document, ADR 0017 (Security Context), and ADR 0002 (OPA)
are the substrate; this review builds on them.

## 2. Assessment of the current posture

The core authorization design is strong and, in the areas that have already been
attacked, well defended:

- **The load-bearing invariant is correct and enforced in depth.** Security
  decisions key on the immutable authentication chain
  (`sc.authentication_context()`), never on the attacker-influenceable token
  scope (`security-model.md` §2, invariants I1–I2). The scope-drift tripwire (I3) is
  enforced _twice_ — once in Rego per delegated policy and once in Rust in
  `TryFrom<&ValidatedSecurityContext> for Credentials`
  (`crates/core/src/policy.rs`), so a future policy that forgets the Rego
  assertion still fails closed.
- **Two-phase validation is structurally sound.** A handler can only ever
  observe a `ValidatedSecurityContext`, obtainable in production solely via
  `new_for_scope()`; `Deref`-only, no `DerefMut`, `pub(crate)` fields, and
  `#[cfg]`-gated test constructors mean an unresolved or mutated context is
  unreachable from an endpoint (ADR 0017).
- **The highest-risk path is explicitly modeled.** EC2-credential redemption
  reconstructing a delegated chain onto a bare project scope (I4/I6,
  OSSA-2026-005 / CVE-2026-33551) is documented down to the individual match
  arm, with the token round-trip regression (`from_security_context` falling
  through to `ProjectScopePayload`) called out and covered.
- **Advisories map to invariants.** `security-model.md` §8 ties each hardening back to
  a real CVE/OSSA, which is exactly the discipline that prevents regression.

The gaps below are therefore not "the design is wrong." They are "the design
depends on humans remembering a checklist, and the checklist is not yet
mechanically enforced," plus a handful of named surfaces that are documented as
open or are newly proposed.

## 3. Vulnerability vectors to control explicitly

Each vector lists the **attack**, the **current state**, and the **control** the
project should commit to (gate / design / pentest). Priority is the review's
opinion, not a mandate.

### V1 — Delegation boundary escape via rescope/reauth (P1, mitigated, keep proving it)

**Attack.** A delegated caller (trust, app-cred, or EC2 credential minted under
one) rescopes or reauthenticates to influence the token scope and act outside
the delegation's fixed project or role set. This is the scope-bind escape class
(OSSA-2026-015, OSSA-2026-005).

**Current state.** Defended by I1–I5. The residual risk is not the existing code
— it is _the next change_. The defense is spread across
`validate_scope_boundaries()`, `calculate_effective_roles()`,
`from_security_context()`, `build_authz_info_from_fernet_token()`, and
`Credentials::try_from`. A change that touches one and forgets another reopens
the class, exactly as the `from_security_context` → `ProjectScopePayload`
fall-through nearly did (I4 history).

**Control.**

- _Testing:_ make the delegation-bound property a **matrix test** that is
  generated, not hand-written — every
  `(AuthenticationContext variant) × (ScopeInfo variant) × (restricted / unrestricted delegation)`
  cell asserted end-to-end through `new_for_scope()`, with the invariant
  "effective roles ⊆ delegation role set" checked mechanically.
  `test_new_for_scope_delegated_roles_never_exceed_delegation_matrix` is the
  seed; the gate is that adding a variant to either enum without adding its row
  fails to compile or fails the test (see Gate D, §4).
- _Design:_ keep V1's controls anchored on `delegated_project_id` (chain), and
  keep the Rust tripwire as the catch-all backstop.

### V2 — Incomplete fan-out on a new auth method or scope shape (P1, structural)

**Attack.** Not an external attacker per se — a contributor adds an auth method
or `ScopeInfo` variant and updates 6 of the 7 places that must change (ADR 0017
lists them). The missed one silently widens authority.

**Current state.** Partially compile-enforced: exhaustive `match` on
`AuthenticationContext` / `ScopeInfo` forces _some_ arms. But projections that
use a catch-all `_ =>` arm (as `Credentials::try_from` does for the
non-delegated cases) or a fall-through default (the `from_security_context` bug)
are **not** caught by the compiler.

**Control.**

- _Design gate:_ forbid wildcard `_ =>` arms in the security-critical
  projections (`Credentials::try_from`, `from_security_context`,
  `build_authz_info_from_fernet_token`, `validate_scope_boundaries`,
  `calculate_effective_roles`). Require every variant named explicitly so a new
  variant is a compile error, not a silent default. Encode as a clippy
  `wildcard_enum_match_arm` allow-list scoped to those files, or a review
  checklist item promoted to a grep-based CI lint (Gate J).
- _Testing:_ the V1 matrix (Gate D) doubles as V2's coverage — a new variant
  with no matrix row is a visible hole.

### V3 — OPA policy correctness, coverage, and fail-open (P1)

**Attack.** A policy is missing, references the wrong input field, hits the Rego
"undefined argument poisons the function" trap (`security-model.md` I2), or the
handler never calls `enforce()` at all. Any of these is an authz bypass that no
Rust type catches.

**Current state.**

_Original finding (2026-07-09):_

- `opa test policy` ran only in `policy-container.yml`, gated on
  `paths: policy/**`. **A Rust-only change that alters which `policy_name` a
  handler enforces, or changes the `Credentials` projection, did not trigger
  the policy test suite.** The two halves of the authz decision were tested in
  separate CI jobs that never both ran on a cross-cutting PR.
- `opa fmt --check` runs in `linters.yml`, but formatting is not correctness.
- There was no gate asserting **every enforced `policy_name` has a matching
  `.rego` rule and a `_test.rego`**, nor that **every CRUD handler calls
  `enforce()`**.
- Fail-closed on OPA error looks correct (`PolicyError` → `forbidden()`), but
  there was no explicit test that an OPA outage / malformed response / timeout
  yields deny, not allow.

_Re-evaluated 2026-09-14: **closed.**_ Gate A runs `opa test policy`
unconditionally in the main `ci.yml` job, so the Rego suite now gates Rust-only
PRs. Gate B1 (`tools/check_policy_handler_coverage.py`) runs unconditionally and
checks all four directions — a dangling `enforce()` name, a policy without a
sibling `_test.rego`, an orphan decision policy no handler references, and a
CRUD handler with no `enforce()` call (with a single reviewed allowlist entry,
`v3/auth/token/create.rs`, which is pre-authn by construction). Gate E covers
the I2 undefined-argument footgun. What remains from this vector is not
existence but *content*, tracked as V3a.

**Control.**

- _Gate A:_ run `opa test policy` in the **main** `ci.yml` matrix (OPA is
  already installed there for the API tests), unconditionally, so a Rust PR that
  changes enforcement is gated by policy tests too.
- _Gate B (coverage checker):_ a small CI script that (1) extracts every
  `enforce("<name>", …)` string literal from the handlers, (2) asserts a
  `policy/**/<name>.rego` rule and a sibling `_test.rego` exist, and (3) asserts
  every handler module implementing a CRUD verb contains an `enforce` call. Fail
  the build on any orphan in either direction.
- _Gate E (Rego footgun lint):_ a `conftest`/`opa`-based check (or a regex gate)
  that flags delegated-policy helpers called with a bare
  `input.target.<x>.project_id` instead of `object.get(..., null)` — the exact
  trap `security-model.md` I2 warns about, where an `undefined` argument makes even
  the "not delegated" fast path undefined.
- _Testing:_ add an explicit "OPA unreachable / returns garbage → request
  denied" integration test.

### V3a — The handler→policy input-contract seam (P1; harnesses landed, Gate B2 now a CI check — 12% adoption)

**Attack.** This is the sharpest and most under-appreciated form of V3, and it
is worth calling out on its own. The authorization decision is `policy(input)`,
where `input = {credentials, target, existing}` is assembled in
`HttpPolicyEnforcer::enforce` (`crates/keystone/src/policy.rs:118`). Only the
**`credentials`** half comes from a tested projection (`Credentials::try_from` +
the Rust tripwire). The **`target`, `existing`, and `policy_name`** are chosen
by each handler, by hand, and the correctness of that choice is asserted nowhere
systematic. A handler that:

- picks the wrong `policy_name` (evaluates `…/show` logic on a `delete`),
- keys the object under the wrong resource name (ADR 0002 mandates
  `{"target": {"<resource>": obj}}`; a typo makes every
  `input.target.<resource>.…` lookup `undefined`, and an `undefined`-driven Rego
  rule can silently allow),
- puts the stored object in `target` instead of `existing` on an update (so an
  ownership check reads the attacker's patch instead of the current row),
- or forgets to strip a secret (I7),

produces a _well-formed request to a correct policy that nonetheless decides on
the wrong document_. `opa test policy` cannot catch this — it tests the policy
against **hand-authored** input that matches the intended contract, not the
input the handler actually emits.

**Current state (2026-07-09).** Three layers exist; only two are tested.

| Layer                                                                                         | Tested today                                                 |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| Rego logic in isolation                                                                       | ✅ `opa test policy` (synthetic input)                       |
| `credentials` (chain) projection                                                              | ✅ `Credentials::try_from` tests + Rust scope-drift tripwire |
| Handler-built `target`/`existing`/`policy_name`, and its **composition** with the real policy | ❌ ad-hoc mock captures only                                 |

The seam is exercised only two ways today, neither sufficient:

- **Ad-hoc mock capture.** A handler test may inject `MockPolicy` and assert on
  the captured arguments — e.g. `test_create_policy_input_omits_password`
  (`crates/keystone/src/api/v4/user/create.rs`) checks `existing.is_none()` and
  that the password is absent from `target`. This is exactly the right idea, but
  it is **opt-in and sparse**: it exists where an author remembered it. The
  delegation-sensitive credential handlers
  (`credential/{create,show,update,delete,list}`, the OSSA-2026-015 surface)
  ship an **empty `#[cfg(test)] mod tests {}`** and assert nothing at the seam.
  And a mock, by construction, **short-circuits the real Rego** — it proves "the
  handler built shape X," never "policy P decides correctly on shape X."
- **Implicit API tests.** `test_api` runs a real OPA, but asserts functional /
  HTTP outcomes; it is not an authorization test suite — it does not sweep
  actor×target authorization matrices, and it does not isolate the input
  contract, so a handler that feeds OPA a subtly-wrong document but still
  returns the expected status on the happy path passes.

**Re-evaluated 2026-09-14: the mechanisms landed; the coverage did not.** Both
proposed harnesses now exist, and both are better than what was asked for:

- **Gate B2** — `crates/core/src/api/policy_contract.rs` provides
  `assert_object_keys` (the ADR 0002 mis-key check), `assert_no_secrets` (I7
  generalized to a recursive denylist of 11 secret-shaped field names), and
  `assert_existing_presence` (the target/existing slotting check), applied to
  `CapturingPolicy`'s recorded calls.
- **Gate B3** — `get_state_with_real_policy()`
  (`crates/keystone/src/api/mod.rs`) spawns a real `opa run -s` over the
  repository's actual `policy/` tree on a private Unix socket and wires it to
  the **production** `HttpPolicyEnforcer`. This is the stronger of the two
  options the review listed (managed subprocess rather than `opa build -t
  wasm`), and it panics rather than degrading if `opa` is missing.

The gap is now **adoption, not capability**, and it is the review's one
materially unfinished recommendation:

| Coverage                                     | Handler modules calling `enforce()` |
| -------------------------------------------- | ----------------------------------- |
| Total                                        | 155                                 |
| Assert the B2 input contract                 | **14 (9%)**                         |
| Exercise the real policy via B3              | **11 (7%)**                         |

Adoption was risk-prioritised, which is the right order — `credential/*` (the
OSSA-2026-015 surface whose test module was empty when this review was written)
now carries both B2 and B3, as do `user/os_ec2/*` and `policy/*`. But two core
delegation surfaces are covered by **neither**:

- **`v3/os_trust/trust/{create,show,list,delete}`** — trusts are one of the
  three delegation mechanisms I1–I5 exist to bound.
- **`v3/ec2tokens/create`** — the redemption endpoint of the crown-jewel
  scenario in §6.1 (OSSA-2026-005 / CVE-2026-33551).

`policy_contract.rs`'s own doc comment calls itself "the uniform, non-opt-in
assertion set." At 9% adoption with no route sweep and no Gate B1 check
requiring a contract test to exist, that is an aspiration rather than a
description: a new handler added today is covered by B1 (it must call
`enforce()`) but nothing requires it to prove *what it passes*. **The remaining
work is the sweep, not the harness** — either enumerate the registered routes
and drive each through `CapturingPolicy`, or (cheaper, and it composes with the
existing checkers) extend `check_policy_handler_coverage.py` with a fifth check:
every handler module containing `.enforce(` must also reference
`policy_contract` in its test module, with an explicit reviewed allowlist for
the exceptions.

The payoff is not hypothetical. `security-model.md` §9 now records a defect
class found in exactly this way — several policies test
`input.credentials.system_scope`, a key nothing ever emits (`Credentials`
serializes it as `system`), making those rules unreachable. It fails closed, so
it is a functional bug rather than a vulnerability, but it is precisely a
handler↔policy contract mismatch that `opa test` cannot see and that the B3
real-`opa run` tests do. Broader B2/B3 adoption is how the rest of that class
gets found.

**Control.** Split the coverage gate (Gate B) into three graduated levels and
make the seam a first-class, non-opt-in test target:

- _Gate B2 (input-contract harness)._ Provide one shared capturing test enforcer
  (a `PolicyEnforcer` double that records every
  `(policy_name, target, existing)`) with a **standard, uniform** assertion set
  applied to every handler, not re-derived per test:
  1. `policy_name` is a member of the known policy set **and** resolves to an
     existing `.rego` (ties to Gate B1);
  2. `target` (and `existing`, when present) is a JSON object whose single outer
     key equals the endpoint's expected resource name (ADR 0002 contract), so a
     mis-key is a test failure, not an `undefined` at runtime;
  3. operation/slot correctness: create/show/delete/list pass `existing: None`;
     update passes `existing: Some(stored)` **and** `target: patch` (never
     swapped);
  4. secret-free: no denylisted field (`blob`, `password`, `*_secret`, TOTP
     seed, token) appears anywhere in `target`/`existing` — the generalized,
     mechanically-checked form of I7. Drive it as a **route-sweep**: enumerate
     the registered routes and push a request through each, so a newly-added
     handler is covered automatically and a handler that never calls `enforce()`
     is a visible failure. This is the piece that converts "someone remembered
     to assert the shape" into "the shape is always asserted."
- _Gate B3 (composition / decision test)._ Evaluate the _handler-produced_ input
  against the _real_ `policy/` bundle, so the test asserts an actual allow/deny
  — the layer a mock can never reach. Today only `HttpPolicyEnforcer` exists
  (OPA over HTTP/unix socket); to make this usable in handler-level and
  `test_api` tests without a hand-maintained live server, add a `PolicyEnforcer`
  implementation that evaluates the compiled bundle **in-process** (OPA already
  compiles a bundle in `policy-container.yml`; `opa build -t wasm` + an
  in-process wasm evaluator, or a managed `opa eval` subprocess, are the two
  options). With that in place, write a dedicated **authorization matrix** per
  endpoint — authorized actor → allow, unauthorized → deny, cross-domain → deny,
  delegated-escape → deny — driven through the real handler and the real policy.
  This is the suite that "targets authorization checks," as distinct from the
  functional API tests that do not.

Gate B1 (existence) is cheap and should land first; B2 (contract) is the highest
value-to-effort item for this specific gap and needs only a shared harness plus
the route sweep; B3 (composition) is the strongest but carries the
in-process-evaluator design cost and can follow.

**Implemented 2026-09-14 (§0a item 1):** the route-sweep alternative this
section proposed (`check_policy_handler_coverage.py`'s check 5) landed instead
of an actual route sweep — cheaper, and it composes with the existing
unconditional CI job rather than adding a new one. It requires any file
calling `.enforce(` to reference `policy_contract` in its own or a sibling
test module, carries a shrink-only `ALLOWLIST_NO_POLICY_CONTRACT` for the 136
pre-existing handlers not yet backfilled, and **cannot regress**: a new
handler with `.enforce(` and no `policy_contract` reference fails CI, full
stop. `os_trust/trust/{create,show,list,delete}` and `ec2tokens/create` — the
two named uncovered core delegation surfaces — were backfilled with both B2
and B3 coverage as part of this change (adoption 14→19 of 155). The
remaining 136 are the honest backlog this table always implied; the gate
now guarantees that backlog only shrinks.

### V4 — OPA policy-bundle supply chain (P2)

**Attack.** The authorization logic is shipped as an OCI artifact
(`opa build … --bundle` → `oras push ghcr.io/…/opa-bundle:latest`,
`policy-container.yml`). Whatever the running Keystone loads _is_ the policy. If
the bundle can be tampered with in the registry, or a stale/rolled-back `latest`
is pulled, every authz decision is attacker-defined — without touching
Keystone's code or the `policy/` tree.

**Current state (2026-07-09).** The bundle is pushed unsigned; there is no
evidence of signature generation or of verification at load time. `latest` is
mutable.

**Re-evaluated 2026-09-14: half-closed.** The publish side landed —
`policy-container.yml` resolves the pushed digest, signs it with cosign keyless
(reusing the job's existing `id-token: write`), and then **verifies its own
signature before the workflow reports success**, so a broken signing setup fails
CI rather than silently shipping an unverifiable bundle. The design-side ask
landed too: `security-model.md` §3 now names the bundle as a trust boundary.

The **consumption** side is still open, and it is the half that actually
defends a running deployment: nothing verifies the signature at load.
`tools/opa_config.yaml` still pulls `…/opa-bundle:latest` — a mutable tag — and
its own comment concedes the point ("OPA's bundle service has no native
cosign/Sigstore verification hook, so that check cannot happen [here]"). A
signature nobody checks stops a careless publisher, not an attacker with
registry write access. The remaining work is a verify-then-serve step in the
deployment path (sidecar or init container that runs `cosign verify` against a
**pinned digest** and only then hands the bundle to OPA), plus pinning by digest
in `opa_config.yaml` and the k8s manifests instead of `:latest`.

**Control.**

- _Gate H:_ sign the bundle at publish (cosign / Sigstore keyless, which fits
  the existing `id-token: write` permission already present in the publish job)
  and **verify the signature + digest at bundle load** in Keystone. Pin by
  digest, not `latest`, in deployment config.
- _Design:_ document the policy bundle as a first-class trust boundary in
  `security-model.md` (today it is implicit) — the running policy is as
  security-critical as the binary, and should have the same provenance bar.

**Implemented 2026-09-14 (§0a item 3), partial:** `tools/verify_and_pin_opa_bundle.sh`
resolves a tag's digest, runs the same `cosign verify` the publish job already
runs on itself, and on success pins `resource` in `tools/opa_config.yaml` (or
any given config) to the verified digest — or, with `--config /dev/null`,
just emits the verified `image@digest` for a deployment's own init-container
check. It is deliberately a release-time tool, not an always-on load hook:
the digest changes on every policy merge, and OPA itself still has no native
Sigstore verification, so "pin by digest" is a promotion action a human or
pipeline chooses to take, not something that runs unattended on every
`opa run`. A deployment that wants continuous rollout from `:latest` still
needs its own init-container/admission-hook `cosign verify` before serving
traffic — this script is exactly that check, packaged for reuse.

### V5 — Application-credential `access_rules` unenforced at request time (P1; closed 2026-09-14, ADR 0037)

**Attack.** An operator creates a restricted app-cred with `access_rules`
limiting it to, say, `GET /v3/servers`. The rules are stored and CRUD'd
(`crates/core-types/src/application_credential/…`, `appcred-driver-sql`) but
**no middleware matches the incoming (service, method, path) against them**, so
the credential can call any endpoint. This is documented as an open gap in
`security-model.md` §5 and §9 — the review flags it as the single highest-impact
_known_ live gap, because it silently converts a control the operator believes
is active into a no-op.

**Current state (2026-07-09).** Advisory only, by the project's own admission.

**Re-evaluated 2026-09-14: still open — and now the review's single most
important outstanding item.** The interim control landed exactly as proposed:
creation warns unconditionally on a non-empty `access_rules` list, and
`application_credential.reject_unenforced_access_rules` (`crates/config/src/application_credentials.rs`,
default `false`) makes it a hard rejection
(`ApplicationCredentialProviderError`, `crates/core-types/src/application_credential/error.rs`).
`security-model.md` §9 documents it.

But **no request-time enforcement exists**. Every `AccessRule` reference in the
tree is still CRUD plumbing — `provider_api.rs`, `backend.rs`, `service.rs`,
the SQL driver, the audit projection — and there is no middleware matching an
incoming `(service, method, path)` against the stored rules before dispatch.
With the flag defaulting to `false` (correctly, for compatibility), the default
deployment still accepts a restriction it will not honour. The fail-loud flag
buys honesty for operators who opt in; it does not close the gap. The ADR and
middleware §5 calls for are unwritten.

**Control.**

- _Design:_ the ADR the gap already calls for — request-matching middleware
  keyed on the app-cred's stored rules, evaluated before handler dispatch.
- _Gate:_ until enforcement lands, add a **startup/CRUD-time warning** (and a
  doc banner) that `access_rules` are not enforced, so operators are not misled.
  Optionally reject creation of an app-cred with non-empty `access_rules` behind
  a config flag, to fail loud rather than silently accept an unenforceable
  restriction.
- _Testing:_ the enforcement middleware, when built, needs the full
  positive/negative matrix (in-scope call allowed, out-of-scope call denied,
  path/method/service each varied) plus a rescope test (rules survive rescope,
  per V1).

**Implemented 2026-09-14 (§0a item 2): closed.** ADR 0037 + `enforce_access_rules()`
(`crates/core/src/api/auth.rs`) landed as the requested "request-matching
middleware," though not as a separate `tower`/`axum` layer — it runs inside
`Auth::from_request_parts`, the extractor every handler already calls, so it
costs no extra authentication round trip and cannot be bypassed by a handler
that forgets to call something. Scope is deliberately narrower than "any
service": Keystone can only self-enforce rules naming its own service
(`identity`), since it has no visibility into requests made to other
services — that half remains `keystonemiddleware`'s job elsewhere, as
designed, not a residual gap. `access_rules_permit()`
(`crates/core-types/src/application_credential/access_rule.rs`) is the pure
matcher (method/service exact match, path via the documented
`{tag}`/`*`/`**` wildcard syntax), unit-tested directly; the enforcement
point is tested through the actual `Auth::from_request_parts` mock-injection
path (matching/non-matching rule, empty/absent rules, wrong-service rule,
non-app-cred auth unaffected). Runs before OPA policy evaluation, not after —
a call outside the rules is rejected without paying for a policy round trip.
Positive/negative/wrong-service coverage exists; the rescope test V5 asked
for is implicit rather than explicit (`enforce_access_rules` reads the rules
from `AuthenticationContext::ApplicationCredential`, which reauthentication
carries unchanged per `security-model.md` §5's table — there is no separate
rescope code path to diverge from).

### V6 — Denial of service on unrate-limited cryptographic endpoints (P2; the three named endpoints closed 2026-09-14)

**Attack.** ADR 0022 phase 1 rate-limits `POST /v3/auth/tokens` by IP (and
optionally per confirmed user). The ADR itself notes that **federation
authenticate endpoints, application-credential flows, EC2 token redemption, and
token validation are not covered** — all perform crypto (signature/hash
verification) and are DoS amplifiers. An attacker hits `/v3/ec2tokens` or an
OIDC `authenticate` endpoint to burn CPU without ever authenticating.

**Current state (2026-07-09).** Global-IP limiter merged (phase 1); per-endpoint
coverage is "follow-up ADR TBD." Also note `governor` is per-node in-memory, so
effective limits are N× in an N-replica deployment (documented consequence).

**Re-evaluated 2026-09-14: partially closed; the original three crypto
endpoints are still open.** `check_ip()` coverage has grown well beyond phase 1
— it now gates `v3/auth/token/create`, the full OAuth2 surface
(`authorize`, `token`, `device`, `device_authorization`, `jwks`,
`jwks_revocation`, `well_known`) and `v4/spiffe`. That is the V8a work plus
more.

The endpoints this vector actually named remain unlimited, verified by direct
read — none of them contains a `check_ip`/rate-limit call:

| Endpoint                                | Expensive work reached unauthenticated |
| --------------------------------------- | -------------------------------------- |
| `v3/ec2tokens/create`                   | HMAC signature verification            |
| `v3/auth/token/show` (token validation) | Fernet/JWS decrypt + verify            |
| federation `authenticate` endpoints     | OIDC/JWT signature verification        |

`ec2tokens` is the notable one: it is both an unrate-limited crypto endpoint
(V6) and the redemption path of the V1 crown-jewel scenario, and it currently
carries neither a rate limit nor a B2/B3 policy-contract test (V3a).

**Control.**

- _Design:_ the promised follow-up ADR extending handler-level limiting to
  federation / app-cred / EC2 / token-validate, with IP governance before the
  crypto step (ADR 0022 Invariant 4, "pre-hash enforcement," generalized to
  "pre-crypto").
- _Testing:_ a load/abuse test per crypto endpoint asserting 429 before the
  expensive path executes; a test that spoofed `X-Forwarded-For` from an
  untrusted peer does not reset the bucket (ADR 0022 Invariant 9).
- _Pentest:_ resource-exhaustion probing of every unauthenticated,
  crypto-bearing endpoint.

**Implemented 2026-09-14 (§0a item 4): the three named endpoints are closed.**
`check_ip()` now gates `v3/ec2tokens/create` (before `verify_signature`),
`v3/auth/token/show` (before the Fernet/JWS decrypt), and the federation
`jwt::login` / `oidc::callback` handlers (before JWKS fetch / JWT
verification) — same posture as `/v3/auth/tokens`: checked first, before any
expensive work. `ec2tokens/create` also closed its V3a gap in the same pass
(§V3a), so it no longer carries neither control. The design-level follow-up
ADR extending `check_ip` coverage more broadly, and the load/abuse and
`X-Forwarded-For`-spoofing tests, remain open — this closes the three
concrete endpoints the vector named, not the general design/testing asks.

### V7 — Dynamic auth plugins: pre-auth attack surface (P1 — now live, no longer hypothetical)

**Attack.** ADR 0025 introduces WASM auth plugins invoked _pre-authentication_
by definition — a remote, unauthenticated party triggers plugin execution and
its `http_fetch` calls at will. Named sub-vectors from the ADR's own threat
model:

- **SSRF** via `http_fetch` (DNS-rebinding / connect-time IP re-validation
  against `allowed_hosts`).
- **Claims injection**: a plugin's response claims shadowing a
  privilege-relevant field — mitigated structurally by outer-keying under
  `plugin_claims.<plugin_name>` (visible already in `Credentials`,
  `crates/core/src/policy.rs`) and a reserved-key denylist.
- **Identity-binding bypass**: a `find_user` that does an unscoped lookup would
  be a full account-takeover; the ADR binds to a per-plugin
  `(plugin_name, external_id)` namespace precisely to prevent it.
- **`route`-mode observation surface**: a router sees raw credential material
  for a _larger_ slice of traffic than any other plugin.
- **Resource exhaustion**: fuel/deadline/memory caps + per-source-IP token
  bucket.

**Current state (2026-07-09).** Design-stage; `AuthenticationContext::WasmPlugin`
and `plugin_claims` projection already exist in the tree, so partial plumbing
has landed ahead of the full mechanism.

**Re-evaluated 2026-09-14: shipped.** This is no longer a design-stage vector —
`auth-plugin-core`, `auth-plugin-runtime`, and `auth-plugin-identity-driver-raft`
are real crates, `crates/core/src/auth_plugin{,_auth,_http,_identity}.rs` carry
the mechanism, and `auth_plugin_startup.rs` / `auth_plugin_http_client.rs` wire
it into the server. The named controls exist: `allowed_hosts` with connect-time
IP validation (`auth_plugin_http.rs`, `host_functions.rs`), a reserved-header
denylist enforced at config load (`crates/config/src/auth_plugins.rs`), and
three of the five fuzz targets cover the host↔guest JSON boundary
(`fuzz_auth_contract_response`, `fuzz_route_contract_response`,
`fuzz_mapping_contract_response`).

Two things follow. First, **ADR 0025 still reads `Status: Proposed`** while the
feature is in `main` — as do ADR 0022 (rate limiting) and ADR 0026 (OAuth2
provider), both equally shipped. That drift matters for a security review that
uses ADR status to judge what is attack surface today: a reader triaging by ADR
status would under-weight three live, internet-facing surfaces. Update the
statuses. Second, this vector's priority is now unconditional — a
pre-authentication WASM execution path reachable by any remote party deserves
the dedicated pentest suite §6.6 describes, on the current code rather than
"when those features ship."

**Control.**

- _Design:_ ADR 0025 is unusually thorough — the review's ask is that its §4–§7
  controls each land with a **test that exercises the failure**, not just the
  intended path (SSRF to a rebinding host is blocked; a fabricated
  `ResolvedIdentityHandle` is rejected; a claim named `is_system` is dropped; a
  `route` target off the allowlist is rejected).
- _Gate:_ fuzz the host↔guest JSON boundary (`AuthPluginRequest` /
  `AuthPluginResponse` / `RouteResponse`) — untrusted guest output parsed by the
  host is a classic memory/logic sink. Add a CI gate that the reserved header
  denylist (`Authorization`, `Cookie`, `X-Auth-Token`, …) cannot be named in
  `exposed_headers` (config-load rejection), tested directly.
- _Pentest:_ treat the plugin invocation path as an internet-facing,
  unauthenticated endpoint — SSRF, request smuggling into `route` targets, and
  rate-limit bypass are the priority scenarios.

### V8 — OAuth2/OIDC provider role (P2 — now live, no longer hypothetical)

**Attack.** Acting as an OAuth2/OIDC _provider_ adds the classic web-authz
surface Keystone did not previously have: open-redirect via `redirect_uri`,
authorization-code interception without PKCE, CSRF on the consent flow,
clickjacking, refresh-token replay.

**Current state (2026-07-09).** ADR 0026 already commits to the right defaults —
exact-match `redirect_uris` (wildcards rejected), mandatory `S256` PKCE for
public clients enforced at CRUD time, HTTPS-only for confidential clients,
refresh-token rotation. The controls are specified; the risk is drift during
implementation.

**Re-evaluated 2026-09-14: shipped, and the implementation was audited.** The
provider is live (`crates/keystone/src/api/v4/oauth2/`: `authorize`, `token`,
`device`, `device_authorization`, `jwks`, `jwks_revocation`, `well_known`), and
V8a below is the record of that audit — the drift risk this vector warned about
was checked, found in one place (device-flow rate limiting), and fixed. ADR 0026
still reads `Status: Proposed`; see V7 on ADR status drift.

**Control.**

- _Testing:_ a negative test per web-authz vector — non-matching `redirect_uri`
  rejected, `plain` PKCE rejected, missing `code_verifier` rejected, reused
  authorization code rejected, rotated refresh token's predecessor invalidated.
- _Pentest:_ standard OAuth2 provider test suite (redirect handling, PKCE
  downgrade, mix-up, token substitution).

### V8a — OAuth2 client enumeration, timing side-channels, and credential-probing (fixed 2026-07-16; P1 device-flow rate-limit gap closed)

**Attack.** Prompted by public research on "OAuth client ID spoofing"
(Proofpoint, July 2026: attackers validate stolen Entra ID credentials at scale
by presenting spoofed/arbitrary `client_id`s to a token endpoint that
distinguishes valid from invalid client IDs, checking passwords without a
successful sign-in ever being logged against a real, registered application —
and without needing that application to actually exist). The generalizable
attack classes are: (a) distinguish "unknown client_id" from "wrong secret" by
response content, status, or timing; (b) probe usernames/passwords through an
endpoint that doesn't require a real, pre-registered relying party; (c)
brute-force short human-facing codes (device `user_code`) with no throttle.

**Current state — verified by direct code read, 2026-07-16.**

| Sub-vector                                                                                                                                    | Verdict                                         | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `client_credentials`/`authorization_code`/`refresh_token`/token-exchange: unknown client_id vs. wrong secret vs. disabled client, by response | Mitigated                                       | `token.rs:376-448` (`client_credentials`), `:580-638` (`authenticate_client`, shared by the other three grants) — `get_by_client_id` runs unconditionally; every rejection branch (unknown `:396`, disabled/deleted `:403,605`, no secret `:419,425`) calls `crypto::generate_dummy_hash()` before returning the same `401 invalid_client` / `"client authentication failed"` body as a real wrong-secret rejection (`:437-448`, `:617-621`)                                                                                                                                                                                                                                                                                                                                      |
| Argon2id timing (unknown client vs. known client, wrong secret)                                                                               | Mitigated (defense-in-depth, residual accepted) | `crypto.rs:81-107` — `generate_dummy_hash()` performs a real Argon2id **hash** (not a cheap early-return) with the same configured cost params as `verify_secret()`'s **verify**; hash and verify are comparable-cost Argon2id operations but not byte-identical code paths, and the DB lookup itself is faster for an unknown client_id than a known one. This residual gap is explicitly called out in-code (`token.rs:387-395`) and bounded by the pre-hash, raw-client_id-keyed rate limiter (`token.rs:367-373`, checked _before_ the DB lookup)                                                                                                                                                                                                                             |
| `client_credentials` grant: existence+grant-type oracle                                                                                       | **Fixed**                                       | `token.rs` now checks `grant_types.contains(ClientCredentials)` **after** secret verification (moved below the `verify_secret`/`generate_dummy_hash` block), matching the shared `authenticate_client()` posture used by the other three grants. Covered by the existing `test_client_without_client_credentials_grant_is_unauthorized_client`                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `/authorize`: unknown client_id vs. unregistered `redirect_uri`                                                                               | Not vulnerable (by design)                      | `authorize.rs:257-302` — messages differ ("unknown or disabled client" vs. "redirect_uri is not registered"), but `client_id` is intentionally public (RFC 6749 §2.2) and client registration is admin/Tier-1/Tier-2-gated per domain (ADR 0020), not a global self-service namespace an outsider can probe cross-tenant the way Entra's is — the precondition that makes Entra's spoofing technique work (any `client_id`, from any tenant, reaches a password check without being registered) does not exist here: every `client_id` presented anywhere must already be a real `OAuth2Client` row in that domain                                                                                                                                                                |
| Human login (`/authorize/login`, `/device/login`): username enumeration                                                                       | Mitigated                                       | `authorize.rs:470-521` — uniform `"invalid username or password"` on both bad-request-shape and `authenticate_by_password` failure; ADR 0010's per-user throttle applies inside `authenticate_by_password` itself regardless of entry point                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| **`/device`, `/device/login`, `/device_authorization`: per-IP rate limiting**                                                                 | **Fixed**                                       | `device.rs`'s `device_login_code` (user_code submission) and `device_login` (password check) and `device_authorization.rs`'s `device_authorization` now call `state.rate_limiters.check_ip()` before any DB lookup or password hashing, mirroring `authorize.rs`'s `/authorize`/`/authorize/login` posture exactly. `/device/consent` intentionally left unguarded, mirroring `authorize_consent`'s precedent (only reachable with an already-authenticated session, so it carries no unauthenticated probing surface of its own). Covered by new tests `test_device_submit_code_rate_limited_by_ip_before_lookup`, `test_device_login_rate_limited_by_ip_before_password_check` (`device.rs`) and `test_rate_limit_returns_429_before_client_lookup` (`device_authorization.rs`) |
| Refresh token lookup                                                                                                                          | Not vulnerable                                  | `oauth2_session/service.rs:70-73,275-287` — lookup key is `SHA-256(bearer)`, an indexed equality read, not a raw-value or prefix comparison; no partial-match timing leak                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

**Control (implemented 2026-07-16).**

- Per-IP `check_ip` rate limiting, identical to
  `/authorize`/`/authorize/login`'s, now gates `/device_authorization`,
  `/device`, and `/device/login`, applied before any DB lookup or password
  hashing — closing the one concrete gap this review found; everything else in
  the OAuth2 provider was already either spec-correct-by-design or carrying a
  matching defense.
- `handle_client_credentials_grant` (`token.rs`) now checks `grant_types` after
  secret verification, so it matches the uniform-response posture of the other
  three grant handlers.
- _Testing:_ negative tests asserting `429` under burst-exhaustion now exist for
  `/device`, `/device/login`, `/device_authorization`, alongside the
  pre-existing `/authorize`/`/token` coverage.
- _Design:_ V6's "endpoints not yet covered by rate limiting" list (ADR 0022
  follow-up) should still be updated to note the device-flow browser endpoints
  are now covered, alongside the federation/app-cred/EC2/ token-validate
  endpoints that remain open.
- _Pentest:_ password-spray `/device/login` across many usernames from a single
  IP; brute-force `/device` `user_code` guessing at volume; attempt to reach a
  password check via any `client_id` value without it being a pre-registered
  `OAuth2Client` row (expected: impossible, confirm it stays that way) — all
  should now hit `429` after one request under a tight burst config, matching
  `/authorize`'s behavior.

### V9 — Secret leakage into policy input, logs, and audit (P2, mitigated)

**Attack.** Decrypted credential blobs (EC2 secret keys, TOTP seeds) reaching
OPA (which logs decisions) or the CADF audit trail.

**Current state (2026-07-09).** I7 strips the blob in
`credential_policy_input()`; secrets are now wrapped with the `secrecy` crate
(recent commit `b35ca42`). Good.

**Re-evaluated 2026-09-14: closed, on both surfaces.** Gate I landed twice over:
`policy_contract::assert_no_secrets` recursively rejects 11 secret-shaped field
names anywhere in `target`/`existing` (and is asserted against `Credentials`
itself in `crates/core/src/policy.rs`), and
`tools/check_event_payload_no_secret_fields.py` runs unconditionally in `ci.yml`
so the ADR 0023 audit projection cannot grow a secret-shaped field. The one
residual is scope of application: `assert_no_secrets` only protects the handlers
that opted into a B2 contract test (see V3a), so widening B2 adoption widens
this guarantee too.

**Control.**

- _Gate I:_ a structural test that serializes a `Credentials` / policy-input
  object built from a secret-bearing credential and asserts the secret bytes do
  not appear in the JSON — run in CI so a future field addition that
  re-introduces a blob is caught. Extend the same assertion to the audit event
  payload (ADR 0023) and to error `Display` impls.
- _Design:_ document "no secret in policy input / audit / logs / error strings"
  as a named invariant (I7 covers policy input; generalize it).

### V10 — Token lifecycle: revocation and version binding (P2; property tests landed 2026-09-14)

**Attack.** A token outliving the authority it was minted under — a role
removed, a trust deleted, a plugin patched to fix a bug, an identity link
revoked. If validation trusts the token's frozen claims over live state, the
window stays open.

**Current state (2026-07-09).** `authorize_by_token` re-expands and re-resolves
roles against live assignments and checks revocation (ADR 0017); ADR 0025 adds
`plugin_sha256` version-binding and bulk `revoke_all`. The design is
revocation-aware.

**Re-evaluated 2026-09-14: open.** The design is unchanged and still sound, but
the property tests this vector asked for were not written. The only `proptest`
suite in the workspace is `scope_pinning_property`
(`crates/core/src/policy.rs`) — the *delegation monotonicity* and *revocation*
properties named in §5.2 remain the two open items on that list. "Authority
removed at T is unusable after T" is still covered only by example-based tests.

**Control.**

- _Testing:_ property test — "role removed at time T ⇒ token issued before T
  cannot exercise that role after T," across each scope shape; likewise trust
  deletion and app-cred expiry mid-token-lifetime.
- _Pentest:_ revocation-window probing.

**Implemented 2026-09-14 (§0a item 6).** `crates/core/src/auth/tests.rs`'s
`delegation_monotonicity_property` module adds both properties this section
asked for, driven through the real `calculate_effective_roles()` (not a
reimplementation) over a synthetic 5-role membership space:

- `app_cred_roles_never_exceed_delegation` / `trust_roles_never_exceed_delegation`
  — the delegation-monotonicity property, for any live-assignment state.
  Trust and app-cred turned out to have genuinely different bounding
  semantics worth pinning down: app-cred resolution is an *intersection*
  (frozen roles ∩ current assignments), while trust resolution is
  *all-or-nothing* (`resolve_trust_roles` denies entirely unless the
  trustor currently holds every delegated role) — the property tests assert
  each function's actual contract rather than a single shared shape.
- `app_cred_revoked_role_unusable_after_removal` /
  `trust_revoked_role_unusable_after_removal` — the revocation property:
  resolve once against a wider "before" assignment set, then again against
  an "after" set with roles removed, asserting the second resolution never
  contains a removed role. This exercises the actual mechanism ("no caching
  across calls, always a live lookup") rather than asserting the property in
  the abstract.

Trust deletion and app-cred expiry mid-token-lifetime (as opposed to role
removal) remain covered only by example-based tests; the pentest asks are
still open.

## 4. Preemptive security gates to add (CI + design)

Summary of the gates referenced above, ordered by value-to-effort. All are
additive to the existing pipeline (`ci.yml`, `linters.yml`, `audit.yml`,
`policy-container.yml`).

| Gate   | What it does                                                                                                                                                                                                           | Catches                                                                                                         | Effort   |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | -------- |
| **A**  | Run `opa test policy` in main `ci.yml`, not only on `policy/**` paths                                                                                                                                                  | V3 — Rust change that breaks policy enforcement merges green today                                              | Low      |
| **B1** | Policy↔handler _existence_ checker (every `enforce(name)` ⇒ `.rego` + `_test.rego`; every CRUD handler ⇒ `enforce`)                                                                                                    | V3 — missing policy, orphan policy, unenforced handler                                                          | Low      |
| **B2** | Handler→policy _input-contract_ harness: a shared capturing enforcer + route-sweep asserting resource-key correctness, target/existing slotting, and secret-free input, on every handler automatically                 | V3a — wrong `policy_name`, mis-keyed resource, target/existing swap, secret leak — none caught by `opa test`    | Med      |
| **B3** | Handler→policy _composition_ test: an in-process real-Rego enforcer feeding handler-built input to the actual bundle, plus a per-endpoint authorization matrix (authorized/unauthorized/cross-domain/delegated-escape) | V3a — handler feeds a subtly-wrong document that a mock accepts but the real policy would decide differently on | Med/High |
| **C**  | Invariant-test presence check: every delegated-auth policy carries a scope-drift negative case; every new scope/auth arm has a matrix row                                                                              | V1/V2 — silent boundary regression                                                                              | Med      |
| **D**  | Generated `(auth method × scope × restricted?)` matrix test through `new_for_scope()` with "roles ⊆ delegation" assertion                                                                                              | V1/V2 — the I4 near-miss class                                                                                  | Med      |
| **E**  | Rego lint for the undefined-argument footgun (`object.get(…, null)` required for delegated helper args)                                                                                                                | V3 — I2 trap                                                                                                    | Low      |
| **F**  | Fuzz `Credentials::try_from`, Fernet token decode, and (when built) the WASM host↔guest JSON boundary — landed 2026-07-30 (`fuzz/`, `.github/workflows/fuzz.yml`): Fernet decode, the WASM boundary, and EC2 signature verification (`fuzz_ec2_signature`, `arbitrary`-derived); `Credentials::try_from`'s scope-pinning invariant is covered by a `proptest` suite in `crates/core/src/policy.rs` instead (structured typed-value invariant, not a byte parser) | V1/V7 — malformed-input logic bugs                                                                              | Med      |
| **G**  | Mutation testing (`cargo-mutants`) scoped to `core`/`core-types` auth+policy modules, to prove the negative tests actually fail on a regression                                                                        | all — verifies the tests have teeth                                                                             | Med      |
| **H**  | Sign the OPA policy bundle (cosign) + verify signature/digest at load                                                                                                                                                  | V4 — policy supply chain                                                                                        | Med      |
| **I**  | Structural "no secret in policy input / audit / error string" serialization test                                                                                                                                       | V9                                                                                                              | Low      |
| **J**  | Grep-based SAST encoding the `security-model.md` §7 checklist (e.g. flag `credentials.project_id` used as a delegation boundary; flag wildcard `_ =>` in the 5 critical projections)                                         | V1/V2                                                                                                           | Low      |

The highest-leverage items are **A**, **B1**, and **B2**. A and B1 close the
structural blind spot where the Rust half and the Rego half of an authorization
decision are validated by different CI jobs that don't both run on a
cross-cutting PR. **B2** closes the seam that neither `opa test` nor the
existing handler mocks cover: whether the handler actually _feeds the policy the
right document_ (V3a). Together they remove the ways an authz bypass can merge
green; B3 then upgrades from "the input shape is right" to "the real policy
decides right on that input," and everything else hardens an already-good
position.

> **Status (2026-09-14, updated same day per §0a).** See §0 for the verified
> per-gate state. A, B1, C, D, E, F, G, I and J are landed and running in CI.
> B2 is now also a non-optional CI check (`check_policy_handler_coverage.py`
> check 5) with a shrink-only backlog allowlist; B3 remains an opt-in harness.
> Applied by 19 and 17 of 155 `enforce()`-calling handler modules
> respectively — the mechanism no longer regresses, but most of the backlog
> is still unbackfilled. H is signed at publish and verified; a verify-and-pin
> tool (`tools/verify_and_pin_opa_bundle.sh`) now exists for the load side,
> but nothing runs it automatically on a live deployment.

### Design-time gates (not CI)

- **Promote the `security-model.md` §7 reviewer checklist into a required PR template
  section** for any diff touching auth/scope/delegation/token/policy, with the
  reviewer ticking each invariant. It exists as prose today; make it a gate on
  the PR.
- **Name new trust boundaries in `security-model.md` as they appear**: the OPA policy
  bundle (V4), the WASM plugin invocation path (V7), and the OAuth2 provider
  surface (V8) are all boundaries the current §3 diagram does not draw.

## 5. Testing strategy for security gaps

The project already tests the happy path well and has good negative coverage in
the hot spots. To find _gaps_ rather than confirm _behavior_:

1. **Negative-test-first, mechanically required.** `security-model.md` §7 already asks
   "are there negative tests proving the escape is blocked?" Gate C makes it
   non-optional for delegated policies and new scope shapes.
2. **Property-based invariants over example-based cases.** Encode the security
   properties as properties, not fixtures:
   - _Delegation monotonicity:_ for any rescope/reauth sequence, effective roles
     never exceed the original delegation's role set.
   - _Scope pinning:_ `delegated_project_id == project_id` holds for every
     delegated `Credentials` the projection can produce (the tripwire, as a
     property, not just a per-policy assertion). **Implemented** 2026-07-30:
     `crates/core/src/policy.rs`'s `scope_pinning_property` `proptest`
     module, covering `ApplicationCredential` and `Trust` delegation across
     the project-id string space.
   - _Delegation monotonicity_ and _revocation_ (authority removed at T is
     unusable after T, V10) remain open — use `proptest` to search the
     input space around these.
3. **Matrix/exhaustiveness tests tied to the enums** (Gate D) so coverage grows
   automatically with the type system. 3a. **Test the handler→policy input
   contract and its composition, not just the policy** (Gates B2/B3, vector
   V3a). `opa test policy` proves the policy is right on the _intended_ input;
   it says nothing about whether the handler emits that input. Assert the
   emitted `(policy_name, target, existing)` uniformly across every handler
   (B2), and — separately from the functional API tests — run a dedicated
   **authorization matrix** (authorized / unauthorized / cross-domain /
   delegated-escape actors per endpoint) through the real handler _and_ the real
   policy (B3). Functional API tests that assert HTTP status on the happy path
   are not authorization tests and must not be counted as such.
4. **Differential testing against Python Keystone.** CI already installs
   `pip install keystone` for cross-verification — extend it to
   authorization-decision differentials on the delegated paths, so a divergence
   from the reference implementation's allow/deny is visible.
5. **Mutation testing** (Gate G) to confirm the negative tests fail when the
   invariant is broken — a negative test that still passes after you delete the
   check is worse than none.
6. **Fuzzing** the untrusted-input parsers (Gate F): Fernet decode, the OPA
   response deserializer, and the WASM boundary. `fuzz/` (cargo-fuzz,
   `.github/workflows/fuzz.yml`, weekly + manual) covers the Fernet
   MessagePack decoder, the three WASM host↔guest JSON boundaries
   (`full_auth`/`route`/`mapping`), and EC2 signature verification
   (`fuzz_ec2_signature`, structured `arbitrary`-derived harness over
   `Ec2SignatureRequest` rather than a flat byte slice, since it's a
   multi-field struct feeding multi-version string-to-sign
   canonicalization). `Credentials::try_from`'s scope-pinning invariant
   (property 2 above) is instead covered by a `proptest` suite
   (`crates/core/src/policy.rs`, `scope_pinning_property` module) sweeping
   the delegation-project/token-scope-project string space for both
   `ApplicationCredential` and `Trust` delegation — a typed-value
   invariant, not a byte parser, so `proptest` fit better than cargo-fuzz
   here.

## 6. Penetration testing targets

A pentest engagement should be handed this prioritized scenario list rather than
"test Keystone." Each maps to a vector above.

1. **Delegation escape (V1).** Mint a restricted app-cred / trust, mint an EC2
   credential under it, redeem at `/v3/ec2tokens`, then rescope/reauth the
   resulting token every way the API allows; assert roles never exceed the
   delegation and scope never leaves the delegation project. This is the
   crown-jewel scenario and maps directly to OSSA-2026-005/015.
2. **List leakage (I8, CVE-2019-19687).** For every list endpoint, confirm
   per-item re-check drops rows the caller cannot individually read.
3. **OPA bypass / supply chain (V3/V4).** Attempt to reach a handler whose
   policy is missing or misnamed; test behavior when OPA is unreachable; assess
   bundle provenance.
4. **Pre-auth DoS (V6).** Resource-exhaust every unauthenticated crypto
   endpoint; attempt `X-Forwarded-For` spoofing to defeat per-IP limits.
5. **App-cred `access_rules` (V5, enforcement landed 2026-09-14).** Mint a
   restricted credential and confirm calls outside its rules are now denied
   (ADR 0037); confirm a rule naming a different service correctly does
   *not* authorize a call against Keystone's own API.
6. **WASM plugins (V7)** and **OAuth2 provider (V8)** — full dedicated suites;
   treat both as internet-facing pre-auth surfaces. Both features have since
   shipped (re-evaluated 2026-09-14), so these are engagements to schedule now,
   not contingencies. V8 has had a code-read audit (V8a); V7 has not.
7. **Token lifecycle (V10).** Revocation-window and version-binding probing.
8. **OAuth2 device-flow rate limiting (V8a, fixed 2026-07-16).** Password-spray
   `/device/login` from a single IP across many usernames; brute-force `/device`
   `user_code` guessing at volume — both should now hit `429` after burst
   exhaustion; re-verify this holds after any future change to
   `device.rs`/`device_authorization.rs`.

## 7. Prioritized recommendation

### Original list (2026-07-09), with outcomes

1. **Gate A + Gate B1 + Gate B2** (§4) — close the split-CI authz blind spot
   _and_ the untested handler→policy input contract (V3a). A + B1 are low
   effort; B2 needs only a shared capturing enforcer and a route sweep, and is
   the single highest value-to-effort item because it makes "the handler feeds
   the policy the right document" a mechanical, non-opt-in test on every handler
   — which `opa test` and the current mocks do not. — **A and B1 done; B2's
   harness done, its sweep not.**
2. **Ship `access_rules` enforcement or fail loud** (V5) — the highest-impact
   _known_ live gap; today a control operators trust is a no-op. — **fail-loud
   flag shipped (opt-in, default off); enforcement not.**
3. **Gate D matrix + Gate G mutation testing** (V1/V2) — convert the "remembered
   checklist" defense of the delegation boundary into a structural one. —
   **done.**
4. **Sign the policy bundle** (V4) — the running policy deserves the same
   provenance bar as the binary. — **signed at publish; not verified at load.**

### Re-prioritized (2026-09-14)

Ordered by what was outstanding as of the re-evaluation, highest value first.
See §0a for the same-day implementation pass that closed five of six.

1. **Make Gate B2 non-optional** (V3a). The mechanism is built and proven; 91%
   of `enforce()`-calling handlers just don't use it. The cheapest closure is a
   fifth check in `tools/check_policy_handler_coverage.py` — a module with
   `.enforce(` must reference `policy_contract` in its tests, with a reviewed
   allowlist — which reuses a script already running unconditionally in CI.
   Backfill `os_trust/trust/*` and `ec2tokens/create` first: both are core
   delegation surfaces with neither B2 nor B3 coverage today. — **done (§0a);
   the check is now unconditional in CI and the two named surfaces are
   backfilled. 136 of 155 remain on the allowlist — the check stops new
   erosion, it doesn't retroactively backfill everything else.**
2. **Ship `access_rules` enforcement** (V5). Unchanged from the original list
   and now the oldest open item. The fail-loud flag made the gap honest for
   operators who set it; the default deployment still accepts a restriction it
   will not honour. This needs the ADR and the request-matching middleware. —
   **done (§0a, ADR 0037).**
3. **Verify the policy bundle at load, and pin by digest** (V4). Half a supply
   chain control is a signature nobody checks. Add verify-then-serve to the
   deployment path and replace `:latest` in `tools/opa_config.yaml` and the k8s
   manifests with a pinned digest. — **partial (§0a): the verify+pin tool
   exists; a deployment must still choose to run it (or the equivalent
   init-container check) since OPA itself has no load hook to automate this
   from.**
4. **Rate-limit the three remaining pre-auth crypto endpoints** (V6):
   `ec2tokens/create`, token validation, and the federation `authenticate`
   paths. The mechanism (`check_ip`) is already in place on eight other
   endpoints, so this is application, not design. — **done (§0a).**
5. **Correct ADR statuses for shipped features** (V7/V8). ADRs 0022, 0025 and
   0026 read `Proposed` while the features are in `main`. A security reader
   triaging by ADR status will under-weight three live surfaces — including a
   pre-authentication WASM execution path. — **done (§0a).**
6. **Write the two open property tests** (V10/§5.2): delegation monotonicity and
   revocation-after-T. `scope_pinning_property` shows the pattern works here. —
   **done (§0a).**

The rest (plugin/OAuth2 pentest suites) should land alongside the features they
protect — which, for V7 and V8, means now rather than later, since both shipped.
