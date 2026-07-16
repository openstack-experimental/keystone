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
use reqwest::{Client, StatusCode, Url};

use openstack_keystone_api_types::v3::endpoint::*;
use openstack_keystone_config::Config;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client, print_list_table};

/// List catalog endpoints.
#[derive(Parser)]
pub(super) struct ListCommand {
    /// Filter by interface (`public`, `internal`, or `admin`).
    #[arg(long)]
    interface: Option<String>,

    /// Filter by service ID.
    #[arg(long)]
    service_id: Option<String>,

    /// Filter by region ID.
    #[arg(long)]
    region_id: Option<String>,
}

impl ListCommand {
    /// List endpoints against a pre-built HTTP client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn list_with_client(&self, client: &Client, base_url: &str) -> Result<Vec<Endpoint>> {
        let mut params: Vec<(&str, &str)> = Vec::new();
        if let Some(interface) = &self.interface {
            params.push(("interface", interface));
        }
        if let Some(service_id) = &self.service_id {
            params.push(("service_id", service_id));
        }
        if let Some(region_id) = &self.region_id {
            params.push(("region_id", region_id));
        }

        let res = client
            .get(Url::parse_with_params(
                &format!("{base_url}/v3/endpoints"),
                &params,
            )?)
            .send()
            .await?;

        if res.status() != StatusCode::OK {
            return Err(eyre!(
                "failed to list endpoints: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        Ok(res.json::<EndpointList>().await?.endpoints)
    }
}

#[async_trait]
impl PerformAction for ListCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let endpoints = self.list_with_client(&client, ADMIN_BASE_URL).await?;

        print_list_table(
            vec!["ID", "Interface", "Service ID", "URL", "Enabled"],
            endpoints
                .into_iter()
                .map(|endpoint| {
                    vec![
                        endpoint.id,
                        endpoint.interface,
                        endpoint.service_id,
                        endpoint.url,
                        endpoint.enabled.to_string(),
                    ]
                })
                .collect(),
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use httpmock::{Method, MockServer};
    use reqwest::Client;

    use super::*;

    #[tokio::test]
    async fn test_list_endpoints() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET).path("/v3/endpoints");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "endpoints": [
                        { "id": "ep-1", "interface": "public", "service_id": "svc-1",
                          "url": "https://example.com", "enabled": true }
                    ]
                }));
        });

        let client = Client::new();
        let cmd = ListCommand {
            interface: None,
            service_id: None,
            region_id: None,
        };
        let result = cmd.list_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_list_endpoints_with_filters() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/endpoints")
                .query_param("interface", "public")
                .query_param("service_id", "svc-1");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "endpoints": [] }));
        });

        let client = Client::new();
        let cmd = ListCommand {
            interface: Some("public".to_string()),
            service_id: Some("svc-1".to_string()),
            region_id: None,
        };
        let result = cmd.list_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_endpoints_error() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET).path("/v3/endpoints");
            then.status(500).body("internal error");
        });

        let client = Client::new();
        let cmd = ListCommand {
            interface: None,
            service_id: None,
            region_id: None,
        };
        let result = cmd.list_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
