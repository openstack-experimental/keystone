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

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::eyre};
use eyre::Result;
use reqwest::{Client, StatusCode};

use openstack_keystone_api_types::v3::endpoint::*;
use openstack_keystone_config::Config;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client, print_attribute_table};

/// Show a catalog endpoint.
#[derive(Parser)]
pub(super) struct ShowCommand {
    /// The ID of the endpoint to show.
    id: String,
}

impl ShowCommand {
    /// Fetch the endpoint against a pre-built HTTP client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn show_with_client(&self, client: &Client, base_url: &str) -> Result<Endpoint> {
        let res = client
            .get(format!("{base_url}/v3/endpoints/{}", self.id))
            .send()
            .await?;

        if res.status() != StatusCode::OK {
            return Err(eyre!(
                "failed to show endpoint: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        Ok(res.json::<EndpointResponse>().await?.endpoint)
    }
}

#[async_trait]
impl PerformAction for ShowCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let endpoint = self.show_with_client(&client, ADMIN_BASE_URL).await?;

        print_attribute_table(vec![
            ("id", endpoint.id),
            ("interface", endpoint.interface),
            ("service_id", endpoint.service_id),
            ("url", endpoint.url),
            ("enabled", endpoint.enabled.to_string()),
        ]);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use httpmock::{Method, MockServer};
    use reqwest::Client;

    use super::*;

    #[tokio::test]
    async fn test_show_endpoint() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET).path("/v3/endpoints/ep-1");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "endpoint": {
                        "id": "ep-1", "interface": "public", "service_id": "svc-1",
                        "url": "https://example.com", "enabled": true
                    }
                }));
        });

        let client = Client::new();
        let cmd = ShowCommand {
            id: "ep-1".to_string(),
        };
        let result = cmd.show_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().id, "ep-1");
    }

    #[tokio::test]
    async fn test_show_endpoint_not_found() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET).path("/v3/endpoints/missing");
            then.status(404).body("not found");
        });

        let client = Client::new();
        let cmd = ShowCommand {
            id: "missing".to_string(),
        };
        let result = cmd.show_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
