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
//! The [`PolicyEnforcer`] implementation.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use serde_json::{Value, json};
use tracing::{Level, debug};

use openstack_keystone_core::auth::ValidatedSecurityContext;
use openstack_keystone_core::policy::{
    Credentials, PolicyEnforcer, PolicyError, PolicyEvaluationResult, Violation,
    service_delegation_denial,
};

use crate::loader::{Entrypoint, PolicySet, RegorusError};

/// Metrics `transport` label of the in-process evaluation.
const TRANSPORT: &str = "embedded";

/// Policy enforcer evaluating the Rego policies in-process with `regorus`.
pub struct RegorusPolicyEnforcer {
    /// Directory the policies are (re)loaded from.
    path: PathBuf,
    /// The compiled policies.
    policies: ArcSwap<PolicySet>,
}

impl RegorusPolicyEnforcer {
    /// Load and compile the policies from the directory.
    ///
    /// Compiling is CPU bound and takes a few hundred milliseconds for the
    /// complete Keystone tree, call it from `spawn_blocking` when used in an
    /// async context that cannot tolerate that.
    pub fn new(path: &Path) -> Result<Self, RegorusError> {
        Ok(Self {
            path: path.to_path_buf(),
            policies: ArcSwap::from_pointee(PolicySet::load(path)?),
        })
    }

    /// Re-read the policy directory and atomically replace the policies.
    ///
    /// On error the previous policies stay active. Keystone calls this on
    /// `SIGHUP`. Compilation is CPU bound, so an async caller must run it in
    /// `spawn_blocking`.
    pub fn reload(&self) -> Result<(), RegorusError> {
        self.policies.store(Arc::new(PolicySet::load(&self.path)?));
        Ok(())
    }

    /// Number of the loaded entrypoints.
    pub fn len(&self) -> usize {
        self.policies.load().len()
    }

    /// Whether the policy (`identity/role/show`) is loaded.
    pub fn contains(&self, policy_name: &str) -> bool {
        self.policies.load().contains(policy_name)
    }

    /// Whether there are no loaded entrypoints.
    pub fn is_empty(&self) -> bool {
        self.policies.load().is_empty()
    }

    /// Evaluate the policy for the already built OPA input document.
    ///
    /// The result has the same shape as the package document OPA returns.
    pub fn evaluate(
        &self,
        policy_name: &str,
        input: Value,
    ) -> Result<PolicyEvaluationResult, PolicyError> {
        let set = self.policies.load();
        let ep = set.entrypoints.get(policy_name).ok_or_else(|| {
            PolicyError::IO(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("unknown policy {policy_name}"),
            ))
        })?;
        evaluate_entrypoint(ep, input)
    }
}

fn eval_rule(
    policy: &regorus::CompiledPolicy,
    input: &regorus::Value,
) -> Result<regorus::Value, PolicyError> {
    policy
        .eval_with_input(input.clone())
        .map_err(|e| PolicyError::Compilation(eyre_report(e)))
}

fn eyre_report(e: impl std::fmt::Display) -> eyre::Report {
    eyre::eyre!("{e}")
}

fn evaluate_entrypoint(
    ep: &Entrypoint,
    input: Value,
) -> Result<PolicyEvaluationResult, PolicyError> {
    let input = regorus::Value::from(input);
    // `allow` is `default false`; anything but an explicit `true` is a deny.
    let allow = matches!(eval_rule(&ep.allow, &input)?, regorus::Value::Bool(true));
    let can_see_other_domain_resources = match &ep.can_see_other_domain_resources {
        Some(p) => match eval_rule(p, &input)? {
            regorus::Value::Bool(b) => Some(b),
            _ => None,
        },
        None => None,
    };
    // Evaluated on allow too: OPA returns the whole package document and
    // `tools/policy-diff.py` checks for parity.
    let violations = match &ep.violation {
        Some(p) => match eval_rule(p, &input)? {
            regorus::Value::Undefined => None,
            v => {
                let json: Value = serde_json::from_str(
                    &v.to_json_str()
                        .map_err(|e| PolicyError::Compilation(eyre_report(e)))?,
                )?;
                Some(serde_json::from_value::<Vec<Violation>>(json)?)
            }
        },
        None => None,
    };
    Ok(PolicyEvaluationResult {
        allow,
        can_see_other_domain_resources,
        violations,
    })
}

#[async_trait::async_trait]
impl PolicyEnforcer for RegorusPolicyEnforcer {
    #[tracing::instrument(
        name = "policy.enforce",
        skip_all,
        fields(entrypoint = policy_name, result, duration_ms),
        err(Debug),
        level = Level::DEBUG
    )]
    async fn enforce(
        &self,
        policy_name: &'static str,
        credentials: &ValidatedSecurityContext,
        target: Value,
        existing: Option<Value>,
    ) -> Result<PolicyEvaluationResult, PolicyError> {
        let start = Instant::now();
        let span = tracing::Span::current();

        // Mirrors `HttpPolicyEnforcer::enforce`: the same input document and
        // the same pre-flight checks, only the transport differs.
        let result: Result<PolicyEvaluationResult, PolicyError> = (|| {
            let creds: Credentials = credentials.try_into()?;
            if let Some(denial) = service_delegation_denial(policy_name, &creds) {
                return Err(PolicyError::Forbidden(denial));
            }
            let input = json!({
                "credentials": creds,
                "target": target,
                "existing": existing.unwrap_or(Value::Null),
            });
            debug!("checking policy decision with regorus");
            // Evaluation takes microseconds and is CPU bound: run it inline.
            let res = self.evaluate(policy_name, input)?;
            span.record("result", serde_json::to_string(&res)?);
            debug!("authorized={}", res.allow());
            if !res.allow() {
                return Err(PolicyError::Forbidden(res));
            }
            Ok(res)
        })();

        let elapsed = start.elapsed();
        span.record("duration_ms", elapsed.as_millis());
        openstack_keystone_core::policy_metrics::record_decision(TRANSPORT, &result, elapsed);
        result
    }

    async fn health_check(&self) -> Result<(), PolicyError> {
        if self.is_empty() {
            return Err(PolicyError::Dummy);
        }
        Ok(())
    }
}
