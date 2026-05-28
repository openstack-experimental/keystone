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

    /// HTTP client error.
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    /// The security context must be resolved before the use.
    #[error("security context is not resolved")]
    SecurityContextNotResolved,

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
    ///   patch for update, query params for list, `Value::Null` for show/delete).
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
    #[serde(rename(serialize = "roles"))]
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
        if let Some(authz) = sc.authorization() {
            match &authz.scope {
                ScopeInfo::Domain(domain) => {
                    builder.domain_id(domain.id.clone());
                }
                ScopeInfo::Project { project, .. } => {
                    builder.project_id(project.id.clone());
                }
                ScopeInfo::System(system) => {
                    builder.system(system.clone());
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
