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
#[cfg(any(test, feature = "mock"))]
use mockall::mock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::token::Token;

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

    /// Json serializaion error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// HTTP client error.
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    /// Url parsing error.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
}

#[cfg(feature = "api")]
impl From<PolicyError> for openstack_keystone_api_types::error::KeystoneApiError {
    fn from(error: PolicyError) -> Self {
        Self::forbidden(error)
    }
}

#[async_trait]
pub trait PolicyEnforcer: Send + Sync {
    async fn enforce(
        &self,
        policy_name: &'static str,
        credentials: &Token,
        target: Value,
        update: Option<Value>,
    ) -> Result<PolicyEvaluationResult, PolicyError>;

    async fn health_check(&self) -> Result<(), PolicyError> {
        Ok(())
    }
}

#[cfg(any(test, feature = "mock"))]
mock! {
    pub Policy {}

    #[async_trait]
    impl PolicyEnforcer for Policy {
        async fn enforce(
            &self,
            policy_name: &'static str,
            credentials: &Token,
            target: Value,
            current: Option<Value>
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
#[derive(Serialize, Debug)]
pub struct Credentials {
    pub user_id: String,
    pub roles: Vec<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub domain_id: Option<String>,
    #[serde(default)]
    pub system: Option<String>,
}

impl From<&Token> for Credentials {
    fn from(token: &Token) -> Self {
        Self {
            user_id: token.user_id().clone(),
            roles: token
                .effective_roles()
                .map(|x| {
                    x.iter()
                        .filter_map(|role| role.name.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            project_id: token.project().map(|val| val.id.clone()),
            domain_id: token.domain().map(|val| val.id.clone()),
            system: None,
        }
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
    #[must_use]
    pub fn allow(&self) -> bool {
        self.allow
    }

    /// Returns true if the policy evaluation was successful.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.violations
            .as_deref()
            .map(|x| x.is_empty())
            .unwrap_or(false)
    }

    #[cfg(any(test, feature = "mock"))]
    pub fn allowed() -> Self {
        Self {
            allow: true,
            can_see_other_domain_resources: None,
            violations: None,
        }
    }

    #[cfg(any(test, feature = "mock"))]
    pub fn allowed_admin() -> Self {
        Self {
            allow: true,
            can_see_other_domain_resources: Some(true),
            violations: None,
        }
    }

    #[cfg(any(test, feature = "mock"))]
    pub fn forbidden() -> Self {
        Self {
            allow: false,
            can_see_other_domain_resources: Some(false),
            violations: None,
        }
    }
}
