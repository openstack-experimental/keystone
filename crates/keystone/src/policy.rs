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
use std::sync::Arc;
use std::time::SystemTime;

#[cfg(test)]
use mockall::mock;
use reqwest::{Client, Url};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tracing::{Level, debug, trace};

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

/// Policy factory.
#[derive(Default)]
pub struct PolicyEnforcer {
    /// Requests client.
    http_client: Option<Arc<Client>>,
    /// OPA url address.
    base_url: Option<Url>,
}

impl PolicyEnforcer {
    #[allow(clippy::needless_update)]
    #[tracing::instrument(name = "policy.http", err)]
    pub async fn http(url: Url) -> Result<Self, PolicyError> {
        let client = Client::builder()
            .tcp_keepalive(std::time::Duration::from_secs(60))
            .gzip(true)
            .deflate(true)
            .build()?;
        Ok(Self {
            http_client: Some(Arc::new(client)),
            base_url: Some(url.join("/v1/data/")?),
        })
    }

    #[tracing::instrument(
        name = "policy.enforce",
        skip_all,
        fields(
            entrypoint = policy_name.as_ref(),
            input,
            result,
            duration_ms
        ),
        err,
        level = Level::DEBUG
    )]
    pub async fn enforce<P: AsRef<str>>(
        &self,
        policy_name: P,
        credentials: impl Into<Credentials>,
        target: Value,
        update: Option<Value>,
    ) -> Result<PolicyEvaluationResult, PolicyError> {
        let start = SystemTime::now();
        let creds: Credentials = credentials.into();
        let input = json!({
            "credentials": creds,
            "target": target,
            "update": update,
        });
        let span = tracing::Span::current();

        trace!("checking policy decision with OPA using http");
        let url = self
            .base_url
            .as_ref()
            .ok_or(PolicyError::Dummy)?
            .join(policy_name.as_ref())?;
        let res: PolicyEvaluationResult = self
            .http_client
            .as_ref()
            .ok_or(PolicyError::Dummy)?
            .post(url)
            .json(&json!({"input": input}))
            .send()
            .await?
            .json::<OpaResponse>()
            .await?
            .result;

        let elapsed = SystemTime::now().duration_since(start).unwrap_or_default();
        span.record("result", serde_json::to_string(&res)?);
        span.record("duration_ms", elapsed.as_millis());
        debug!("authorized={}", res.allow());
        if !res.allow() {
            return Err(PolicyError::Forbidden(res));
        }
        Ok(res)
    }
}

#[cfg(test)]
mock! {
    pub PolicyEnforcer {
        pub async fn enforce(
            &self,
            policy_name: &str,
            credentials: &Token,
            target: Value,
            current: Option<Value>
        ) -> Result<PolicyEvaluationResult, PolicyError>;
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
#[derive(Clone, Deserialize, Debug, JsonSchema, Serialize)]
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

    #[cfg(test)]
    pub fn allowed() -> Self {
        Self {
            allow: true,
            can_see_other_domain_resources: None,
            violations: None,
        }
    }

    #[cfg(test)]
    pub fn allowed_admin() -> Self {
        Self {
            allow: true,
            can_see_other_domain_resources: Some(true),
            violations: None,
        }
    }

    #[cfg(test)]
    pub fn forbidden() -> Self {
        Self {
            allow: false,
            can_see_other_domain_resources: Some(false),
            violations: None,
        }
    }
}
