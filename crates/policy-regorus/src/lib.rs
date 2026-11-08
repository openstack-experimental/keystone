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
//! ## Known divergences from OPA (regorus 0.14.1)
//!
//! Running the repository's `*_test.rego` suites (`opa test policy`) with
//! regorus passes 496 of 567 tests. The failures are not exotic builtins but
//! core semantics, which is why this enforcer is experimental and **not**
//! the default:
//!
//! * An entrypoint package nested below a helper package (`identity.x.show`
//!   below `identity`) can evaluate a multi-body helper rule to the wrong
//!   value (`allow` is `false` where OPA says `true`).
//! * Several `:=` complete rules producing the *same* value in one
//!   evaluation are reported as a conflict (`identity.any_domain_id`); OPA
//!   accepts identical values.
//! * Importing many entrypoints into one engine fails with "recursion
//!   detected" (worked around for production with an engine per entrypoint;
//!   it only affects the test harness for suites importing many packages).
//!
//! Do not enable it in production before the differential suite is green.

mod enforcer;
mod loader;

pub use enforcer::RegorusPolicyEnforcer;
pub use loader::{PolicySet, RegorusError};

#[cfg(test)]
mod tests;
