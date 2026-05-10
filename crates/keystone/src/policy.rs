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
use std::sync::Arc;
use std::time::SystemTime;

use reqwest::{Client, Url};
use serde_json::{Value, json};
use tracing::{debug, trace};

use crate::token::Token;

pub use openstack_keystone_core::policy::*;

/// Policy factory.
pub struct HttpPolicyEnforcer {
    /// Requests client.
    http_client: Arc<Client>,
    /// OPA url address.
    base_url: Url,
    /// OPA health url address.
    health_url: Url,
}

impl HttpPolicyEnforcer {
    #[allow(clippy::needless_update)]
    #[tracing::instrument(name = "policy.http", err)]
    /// Creates a new `HttpPolicyEnforcer`.
    ///
    /// # Parameters
    /// * `url` - The base URL of the OPA server. Can be http/https or the unix socket
    ///
    /// # Returns
    /// A `Result` containing the `HttpPolicyEnforcer` instance, or a
    /// `PolicyError`.
    pub async fn new(url: Url) -> Result<Self, PolicyError> {
        match url.scheme() {
            "http" | "https" => {
                // Communication with OPA over the network IF
                let client = Client::builder()
                    .tcp_keepalive(std::time::Duration::from_secs(60))
                    .gzip(true)
                    .deflate(true)
                    .build()?;
                Ok(Self {
                    http_client: Arc::new(client),
                    base_url: url.join("/v1/data/")?,
                    health_url: url.join("/health")?,
                })
            }
            "unix" => {
                // Communication with OPA over the unix socket
                let client = Client::builder().unix_socket(url.path()).build()?;
                Ok(Self {
                    http_client: Arc::new(client),
                    base_url: "http://localhost/v1/data/".parse()?,
                    health_url: "http://localhost/health".parse()?,
                })
            }
            other => return Err(PolicyError::UnsupportedScheme(other.to_string())),
        }
    }
}

#[async_trait::async_trait]
impl PolicyEnforcer for HttpPolicyEnforcer {
    //#[tracing::instrument(
    //    name = "policy.enforce",
    //    skip_all,
    //    fields(
    //        entrypoint = policy_name.as_ref(),
    //        input,
    //        result,
    //        duration_ms
    //    ),
    //    err,
    //    level = Level::DEBUG
    //)]
    /// Enforces a policy decision using OPA.
    ///
    /// # Parameters
    /// * `policy_name` - The name of the policy to evaluate.
    /// * `credentials` - The token containing the requester's credentials.
    /// * `target` - The target resource for the policy evaluation.
    /// * `update` - Optional update data for the policy evaluation.
    ///
    /// # Returns
    /// A `Result` containing the `PolicyEvaluationResult`, or a `PolicyError`.
    async fn enforce(
        &self,
        policy_name: &'static str,
        credentials: &Token,
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
        let url = self.base_url.join(policy_name.as_ref())?;
        let res: PolicyEvaluationResult = self
            .http_client
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

    /// Performs a health check on the OPA server.
    ///
    /// # Returns
    /// A `Result` indicating success, or a `PolicyError`.
    async fn health_check(&self) -> Result<(), PolicyError> {
        self.http_client
            .get(self.health_url.as_str())
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_constructor() {
        let enforcer = HttpPolicyEnforcer::new("http://foo.bar".parse().unwrap())
            .await
            .unwrap();
        assert_eq!("http://foo.bar/v1/data/", enforcer.base_url.as_str());
        assert_eq!("http://foo.bar/health", enforcer.health_url.as_str());
        let enforcer = HttpPolicyEnforcer::new("unix:///var/test.sock".parse().unwrap())
            .await
            .unwrap();
        assert_eq!("http://localhost/v1/data/", enforcer.base_url.as_str());
        assert_eq!("http://localhost/health", enforcer.health_url.as_str());
        match HttpPolicyEnforcer::new("moz:///var/test.sock".parse().unwrap()).await {
            Err(PolicyError::UnsupportedScheme(s)) => {
                assert_eq!("moz", s);
            }
            _ => {
                panic!("should be unsupported scheme");
            }
        }
    }
}
