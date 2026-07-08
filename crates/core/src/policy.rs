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
//! # Policy enforcement
//!
//! Policy enforcement in Keystone is delegated to the Open Policy Agent. It can
//! be invoked either with the HTTP request or as a WASM module.

use async_trait::async_trait;
use derive_builder::Builder;
#[cfg(any(test, feature = "mock"))]
use mockall::mock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use openstack_keystone_core_types::auth::*;
use openstack_keystone_core_types::trust::Trust;

use crate::auth::ValidatedSecurityContext;
use crate::error::BuilderError;

/// Policy related error.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Module compilation error.
    #[error("module compilation task crashed")]
    Compilation(#[from] eyre::Report),

    /// Dummy policy enforcer cannot be used.
    #[error("dummy (empty) policy enforcer")]
    Dummy,

    /// Forbidden error.
    #[error("{}", .0.violations.as_ref().map(
        |v| v.iter().cloned().map(|x| x.msg)
        .reduce(|acc, s| format!("{acc}, {s}"))
        .unwrap_or_default()
    ).unwrap_or("The request you made requires authentication.".into()))]
    Forbidden(PolicyEvaluationResult),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),

    /// Json serialization error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// The security context must be resolved before the use.
    #[error("security context is not resolved")]
    SecurityContextNotResolved,

    /// A delegated caller's token scope diverged from its own delegation
    /// project. `SecurityContext::validate_scope_boundaries` is supposed to
    /// keep the two pinned equal at all times (OSSA-2026-015); observing a
    /// mismatch here means that invariant did not hold, so the request is
    /// rejected outright rather than handed to the (rego-level) policy
    /// engine, which enforces the same check only per-endpoint. See
    /// `doc/src/security.md` I3.
    #[error("delegated token scope has drifted from its delegation project")]
    ScopeDrift,

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: BuilderError,
    },

    /// Unsupported access scheme.
    #[error("unsupported scheme {0}")]
    UnsupportedScheme(String),

    /// Url parsing error.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
}

#[cfg(feature = "api")]
impl From<PolicyError> for openstack_keystone_api_types::error::KeystoneApiError {
    /// Convert a policy error into a Keystone API error.
    ///
    /// # Parameters
    /// - `error`: The policy error to convert.
    ///
    /// # Returns
    /// - `Self` - The converted `KeystoneApiError`.
    fn from(error: PolicyError) -> Self {
        Self::forbidden(error)
    }
}

#[async_trait]
pub trait PolicyEnforcer: Send + Sync {
    /// Enforces a policy for a given action and credentials.
    ///
    /// # Parameters
    /// - `policy_name`: The name of the policy to enforce.
    /// - `credentials`: The credentials of the user requesting the action.
    /// - `target`: The object the action is acting upon (new object for create,
    ///   patch for update, query params for list, `Value::Null` for
    ///   show/delete).
    /// - `existing`: The existing/stored object before the action (for update
    ///   operations), or `None` for create/list/show/delete.
    ///
    /// # Returns
    /// - `Ok(PolicyEvaluationResult)` if the policy was evaluated successfully.
    /// - `Err(PolicyError)` if an error occurred during enforcement.
    async fn enforce(
        &self,
        policy_name: &'static str,
        credentials: &ValidatedSecurityContext,
        target: Value,
        existing: Option<Value>,
    ) -> Result<PolicyEvaluationResult, PolicyError>;

    /// Performs a health check of the policy enforcer.
    ///
    /// # Returns
    /// - `Ok(())` if the enforcer is healthy.
    /// - `Err(PolicyError)` if the enforcer is unhealthy.
    async fn health_check(&self) -> Result<(), PolicyError> {
        Ok(())
    }
}

//#[async_trait]
//pub trait PolicyEnforcerExt: Send + Sync {
//    /// Enforces a policy for a given action and credentials.
//    ///
//    /// # Parameters
//    /// - `policy_name`: The name of the policy to enforce.
//    /// - `credentials`: The credentials of the user requesting the action.
//    /// - `target`: The target resource of the action.
//    /// - `update`: Optional update data for the resource.
//    ///
//    /// # Returns
//    /// - `Ok(PolicyEvaluationResult)` if the policy was evaluated
// successfully.    /// - `Err(PolicyError)` if an error occurred during
// enforcement.    async fn enforce<C: Into<Credentials>>(
//        &self,
//        policy_name: &'static str,
//        credentials: &C,
//        target: Value,
//        update: Option<Value>,
//    ) -> Result<PolicyEvaluationResult, PolicyError>;
//}

#[cfg(any(test, feature = "mock"))]
mock! {
    pub Policy {}

    #[async_trait]
    impl PolicyEnforcer for Policy {
        async fn enforce(
            &self,
            policy_name: &'static str,
            credentials: &ValidatedSecurityContext,
            target: Value,
            existing: Option<Value>
        ) -> Result<PolicyEvaluationResult, PolicyError>;

        async fn health_check(&self) -> Result<(), PolicyError>;
    }
}

#[derive(Debug, Error)]
#[error("failed to evaluate policy")]
pub enum EvaluationError {
    Serialization(#[from] serde_json::Error),
    Evaluation(#[from] eyre::Report),
}

/// OpenPolicyAgent `Credentials` object.
#[derive(Builder, Serialize, Debug)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct Credentials {
    /// Specifies whether the user is an admin.
    pub is_admin: bool,

    /// User ID.
    pub user_id: String,

    /// List of roles the principal has on the scope.
    #[builder(default)]
    #[serde(default, rename(serialize = "roles"))]
    pub roles: Vec<String>,

    // TODO: replace scope info with a flattened enum
    #[builder(default)]
    #[serde(default)]
    pub project_id: Option<String>,

    #[builder(default)]
    #[serde(default)]
    pub domain_id: Option<String>,

    /// System scope information.
    #[builder(default)]
    #[serde(default)]
    pub system: Option<String>,

    #[builder(default)]
    #[serde(default)]
    pub trust: Option<Trust>,

    /// Canonical auth-method string for this request (e.g. `"password"`,
    /// `"token"`, `"trust"`, `"application_credential"`), from
    /// [`AuthenticationContext::auth_type`]. See [`Self::is_delegated`]
    /// for the derived, rescope-aware delegation flag `.rego` rules
    /// should actually gate on.
    pub auth_type: String,

    /// Whether this request is authenticated via a delegated credential
    /// (trust or application credential), directly or carried forward
    /// through a re-scoped token — [`AuthenticationContext::is_delegated`].
    ///
    /// # Security Note
    ///
    /// Delegated tokens must remain bounded to their delegation
    /// `project_id` (OSSA-2026-015 / ADR 0019 §2). Policies that grant
    /// access based on `user_id` ownership alone must additionally check
    /// this flag together with `project_id` before allowing a delegated
    /// caller to reach a resource.
    pub is_delegated: bool,

    /// For application-credential authentication only: whether the
    /// application credential is `unrestricted` (may be used for
    /// management operations such as creating other application
    /// credentials, trusts, or EC2 credentials). `None` for every other
    /// authentication method.
    ///
    /// # Security Note
    ///
    /// A *restricted* application credential (`unrestricted == false`)
    /// must not be usable to create new credentials that outlive or
    /// escape its own limited role set (OSSA-2026-005 / CVE-2026-33551).
    #[builder(default)]
    #[serde(default)]
    pub unrestricted: Option<bool>,

    /// The immutable project the active delegation (trust or application
    /// credential) is bound to, taken from the authentication chain held
    /// in [`ValidatedSecurityContext`] rather than from the request's
    /// token scope. `None` for non-delegated authentication.
    ///
    /// # Security Note
    ///
    /// Delegation boundary checks (OSSA-2026-015) must anchor on this
    /// chain-derived value, **not** on [`Self::project_id`] (the token
    /// scope), so that a scope rebind can never move a delegated caller's
    /// boundary. Policies should additionally assert `project_id ==
    /// delegated_project_id` for delegated callers as a scope-drift
    /// tripwire — the two are pinned equal at token-issuance time
    /// ([`SecurityContext::validate_scope_boundaries`]), so any divergence
    /// signals a compromised or malformed context and must fail closed.
    #[builder(default)]
    #[serde(default)]
    pub delegated_project_id: Option<String>,

    /// Extra claims a `mode = full_auth` dynamic auth plugin (ADR 0025)
    /// attached to its `authenticate` response, outer-keyed by
    /// `plugin_name` so `.rego` rules index as
    /// `input.credentials.plugin_claims.<plugin_name>.<key>` - never
    /// flattened to the top level, so a plugin-supplied key can never
    /// collide with or shadow a privilege-relevant field above (ADR §7
    /// "Response Payload Bounds"). `None`/absent for every other
    /// authentication method, and for a `WasmPlugin` authentication whose
    /// response carried no claims.
    #[builder(default)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_claims:
        Option<std::collections::HashMap<String, std::collections::HashMap<String, Value>>>,
}

impl TryFrom<&ValidatedSecurityContext> for Credentials {
    type Error = PolicyError;
    /// Convert a token into credentials for policy evaluation.
    ///
    /// # Parameters
    /// - `token`: The token to convert.
    ///
    /// # Returns
    /// - `Self` - The constructed `Credentials` object.
    fn try_from(sc: &ValidatedSecurityContext) -> Result<Self, Self::Error> {
        let mut builder = CredentialsBuilder::default();
        builder.user_id(sc.principal().get_user_id());
        builder.is_admin(sc.is_admin());
        builder.auth_type(sc.authentication_context().auth_type());
        builder.is_delegated(sc.authentication_context().is_delegated());
        // Delegation facts are taken from the authentication chain, not the
        // token scope, so the policy engine sees the delegation's own
        // immutable binding (OSSA-2026-015). See `delegated_project_id`.
        match sc.authentication_context() {
            AuthenticationContext::ApplicationCredential {
                application_credential,
                ..
            } => {
                builder.unrestricted(application_credential.unrestricted);
                builder.delegated_project_id(application_credential.project_id.clone());
            }
            AuthenticationContext::Trust { trust, .. } => {
                if let Some(project_id) = &trust.project_id {
                    builder.delegated_project_id(project_id.clone());
                }
                builder.trust(trust.clone());
            }
            AuthenticationContext::WasmPlugin {
                plugin_name,
                claims,
                ..
            } if !claims.is_empty() => {
                builder.plugin_claims(std::collections::HashMap::from([(
                    plugin_name.clone(),
                    claims.clone(),
                )]));
            }
            _ => {}
        }
        if let Some(authz) = sc.authorization() {
            match &authz.scope {
                ScopeInfo::Domain(domain) => {
                    builder.domain_id(domain.id.clone());
                }
                ScopeInfo::Project { project, .. } => {
                    builder.project_id(project.id.clone());
                }
                ScopeInfo::System(system) => {
                    if system == "system" {
                        builder.system("all");
                    } else {
                        builder.system(system.clone());
                    }
                }
                ScopeInfo::TrustProject(tpi) => {
                    builder.project_id(tpi.project.id.clone());
                    builder.trust(tpi.trust.clone());
                }
                ScopeInfo::Unscoped => {}
            }
            if !matches!(authz.scope, ScopeInfo::Unscoped) {
                if let Some(roles) = &authz.effective_roles() {
                    builder.roles(
                        roles
                            .iter()
                            .filter_map(|role| role.name.clone())
                            .collect::<Vec<_>>(),
                    );
                } else {
                    return Err(PolicyError::SecurityContextNotResolved);
                }
            }
        }
        let cred = builder.build()?;
        // Rust-side scope-drift tripwire (I3): mirrors the check every
        // delegated .rego policy carries individually, but here it covers
        // *every* caller of `Credentials::try_from`, including any future
        // policy that forgets to copy the rego-level assertion.
        // `validate_scope_boundaries` is supposed to keep a delegated
        // caller's scope pinned to its delegation project, so any observed
        // divergence means that upstream invariant broke -- fail closed
        // rather than trust the (already-suspect) request further.
        if let Some(delegated_project_id) = &cred.delegated_project_id
            && let Some(project_id) = &cred.project_id
            && project_id != delegated_project_id
        {
            return Err(PolicyError::ScopeDrift);
        }
        Ok(cred)
    }
}

/// A single violation of a policy.
#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct Violation {
    pub msg: String,
    pub field: Option<String>,
}

/// The OpenPolicyAgent response.
#[derive(Deserialize, Debug)]
pub struct OpaResponse {
    pub result: PolicyEvaluationResult,
}

/// The result of a policy evaluation.
#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct PolicyEvaluationResult {
    /// Whether the user is allowed to perform the request or not.
    pub allow: bool,
    /// Whether the user is allowed to see resources of other domains.
    #[serde(default)]
    pub can_see_other_domain_resources: Option<bool>,
    /// List of violations.
    #[serde(rename = "violation")]
    pub violations: Option<Vec<Violation>>,
}

impl std::fmt::Display for PolicyEvaluationResult {
    /// Format the policy evaluation result as a string.
    ///
    /// # Parameters
    /// - `f`: The formatter to use.
    ///
    /// # Returns
    /// - `std::fmt::Result` - The result of the formatting operation.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        if let Some(violations) = &self.violations {
            for violation in violations {
                if first {
                    first = false;
                } else {
                    write!(f, ", ")?;
                }
                write!(f, "{}", violation.msg)?;
            }
        }
        Ok(())
    }
}

impl PolicyEvaluationResult {
    /// Returns whether the request is allowed.
    ///
    /// # Returns
    /// - `bool` - True if allowed, false otherwise.
    #[must_use]
    pub fn allow(&self) -> bool {
        self.allow
    }

    /// Returns true if the policy evaluation was successful.
    ///
    /// # Returns
    /// - `bool` - True if valid, false otherwise.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.violations
            .as_deref()
            .map(|x| x.is_empty())
            .unwrap_or(false)
    }

    /// Create an allowed evaluation result.
    ///
    /// # Returns
    /// - `Self` - A result indicating the request is allowed.
    #[cfg(any(test, feature = "mock"))]
    pub fn allowed() -> Self {
        Self {
            allow: true,
            can_see_other_domain_resources: None,
            violations: None,
        }
    }

    /// Create an allowed admin evaluation result.
    ///
    /// # Returns
    /// - `Self` - A result indicating the request is allowed for admins.
    #[cfg(any(test, feature = "mock"))]
    pub fn allowed_admin() -> Self {
        Self {
            allow: true,
            can_see_other_domain_resources: Some(true),
            violations: None,
        }
    }

    /// Create a forbidden evaluation result.
    ///
    /// # Returns
    /// - `Self` - A result indicating the request is forbidden.
    #[cfg(any(test, feature = "mock"))]
    pub fn forbidden() -> Self {
        Self {
            allow: false,
            can_see_other_domain_resources: Some(false),
            violations: None,
        }
    }
}
