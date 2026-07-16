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
use clap::{Parser, ValueEnum};
use color_eyre::{Report, eyre::eyre};
use eyre::Result;
use reqwest::{Client, StatusCode};

use openstack_keystone_api_types::v3::endpoint::*;
use openstack_keystone_config::Config;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client, print_attribute_table};

#[derive(Clone, Copy, ValueEnum)]
enum BoolArg {
    True,
    False,
}

impl From<BoolArg> for bool {
    fn from(value: BoolArg) -> Self {
        matches!(value, BoolArg::True)
    }
}

/// Update a catalog endpoint.
#[derive(Parser)]
pub(super) struct UpdateCommand {
    /// The ID of the endpoint to update.
    id: String,

    /// New interface (`public`, `internal`, or `admin`).
    #[arg(long)]
    interface: Option<String>,

    /// New region ID.
    #[arg(long)]
    region_id: Option<String>,

    /// New service ID.
    #[arg(long)]
    service_id: Option<String>,

    /// New endpoint URL.
    #[arg(long)]
    url: Option<String>,

    /// Whether the endpoint appears in the service catalog.
    #[arg(long)]
    enabled: Option<BoolArg>,
}

impl UpdateCommand {
    /// Update the endpoint against a pre-built HTTP client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn update_with_client(&self, client: &Client, base_url: &str) -> Result<Endpoint> {
        let mut builder = EndpointUpdateBuilder::default();
        if let Some(interface) = &self.interface {
            builder.interface(interface.clone());
        }
        if let Some(region_id) = &self.region_id {
            builder.region_id(region_id.clone());
        }
        if let Some(service_id) = &self.service_id {
            builder.service_id(service_id.clone());
        }
        if let Some(url) = &self.url {
            builder.url(url.clone());
        }
        if let Some(enabled) = self.enabled {
            builder.enabled(bool::from(enabled));
        }

        let res = client
            .patch(format!("{base_url}/v3/endpoints/{}", self.id))
            .json(&EndpointUpdateRequest {
                endpoint: builder.build()?,
            })
            .send()
            .await?;

        if res.status() != StatusCode::OK {
            return Err(eyre!(
                "failed to update endpoint: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        Ok(res.json::<EndpointResponse>().await?.endpoint)
    }
}

#[async_trait]
impl PerformAction for UpdateCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let updated = self.update_with_client(&client, ADMIN_BASE_URL).await?;

        print_attribute_table(vec![
            ("id", updated.id),
            ("interface", updated.interface),
            ("service_id", updated.service_id),
            ("url", updated.url),
            ("enabled", updated.enabled.to_string()),
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
    async fn test_update_endpoint() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::PATCH).path("/v3/endpoints/ep-1");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "endpoint": {
                        "id": "ep-1", "interface": "internal", "service_id": "svc-1",
                        "url": "https://new.example.com", "enabled": false
                    }
                }));
        });

        let client = Client::new();
        let cmd = UpdateCommand {
            id: "ep-1".to_string(),
            interface: Some("internal".to_string()),
            region_id: None,
            service_id: None,
            url: Some("https://new.example.com".to_string()),
            enabled: Some(BoolArg::False),
        };
        let result = cmd.update_with_client(&client, &base).await;
        assert!(result.is_ok());
        let updated = result.unwrap();
        assert_eq!(updated.interface, "internal");
        assert!(!updated.enabled);
    }

    #[tokio::test]
    async fn test_update_endpoint_error() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::PATCH).path("/v3/endpoints/missing");
            then.status(404).body("not found");
        });

        let client = Client::new();
        let cmd = UpdateCommand {
            id: "missing".to_string(),
            interface: None,
            region_id: None,
            service_id: None,
            url: None,
            enabled: None,
        };
        let result = cmd.update_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
