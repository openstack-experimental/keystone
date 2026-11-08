// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! # In-process Rego policy enforcer
//!
//! [`RegorusPolicyEnforcer`] evaluates the very same `policy/` tree that
//! the OPA sidecar consumes, but inside the Keystone process using
//! [`regorus`]. It implements [`PolicyEnforcer`], so it can be used instead
//! of (and coexist in the code base with) the HTTP based OPA enforcer.
//!
//! ## Design
//!
//! * `regorus::Engine` needs `&mut self` for evaluation. The enforcer
//!   therefore never evaluates through a shared engine; it keeps one
//!   [`regorus::CompiledPolicy`] per rule, which is a cheap, `Send + Sync`
//!   handle that builds a throw-away engine for each evaluation.
//! * Loading the complete policy tree into a single engine is rejected by
//!   regorus ("recursion detected": a reference to `data.identity.<rule>`
//!   is treated as a dependency on every rule below `data.identity`). Every
//!   entrypoint package is therefore compiled in its own engine together with
//!   the *helper* packages (modules not defining `allow`).
//! * OPA returns the whole package document (`allow`, `violation`,
//!   `can_see_other_domain_resources`). regorus can only compile a rule
//!   path, so each of the three rules is compiled and evaluated separately.
//! * The compiled set sits in an [`ArcSwap`], so [`RegorusPolicyEnforcer::reload`]
//!   atomically replaces the policies while in-flight evaluations finish on
//!   the old set.

//!
//! ## Policy conventions required by regorus
//!
//! regorus 0.14.1 evaluates the OPA test suites of this repository (567 of
//! 567) and matches OPA on every `with input as` document they contain
//! (`tools/policy-diff.py`) only because the policies follow three rules.
//! Each was found by the differential test, which still guards them:
//!
//! * **Helper packages are not a prefix of an entrypoint package.** Helpers
//!   live in `common.*` (`common.identity`, `common.api_key`, ...). With the
//!   helper in `identity.api_key` and the entrypoint in
//!   `identity.api_key.create`, regorus silently evaluates a later `allow`
//!   body that uses the helper to the wrong value (`violation` came back
//!   empty where OPA reports messages).
//! * **No complete rule (`:=`) with several bodies that may fire at once.**
//!   OPA only evaluates the bodies a decision needs, regorus reorders and
//!   evaluates more, so equal or `null`/value pairs raise "rule conflicts".
//!   `identity.any_domain_id` is therefore a set of candidates
//!   (`_domain_ids`) and the predicates quantify over it.
//! * **Builtins are guarded by their types.** `count(null)` is undefined in
//!   OPA but an error in regorus, so `is_array(x)` precedes `count(x)`.
//!
//! The first two also hold for OPA; the changes are behaviour preserving
//! there (`opa test policy` stays green) and only turn a would-be conflict
//! error into a fail-closed decision.

mod enforcer;
mod loader;

pub use enforcer::RegorusPolicyEnforcer;
pub use loader::{PolicySet, RegorusError};

#[cfg(test)]
mod tests;
