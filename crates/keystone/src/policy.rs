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
    pub async fn new(url: Url) -> Result<Self, PolicyError> {
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

    async fn health_check(&self) -> Result<(), PolicyError> {
        self.http_client
            .get(self.health_url.as_str())
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}
