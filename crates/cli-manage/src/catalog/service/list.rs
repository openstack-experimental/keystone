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

use openstack_keystone_api_types::v3::service::*;
use openstack_keystone_config::Config;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client, print_list_table};

/// List catalog services.
#[derive(Parser)]
pub(super) struct ListCommand {
    /// Filter by service name.
    #[arg(long)]
    name: Option<String>,

    /// Filter by service type.
    #[arg(long = "type")]
    r#type: Option<String>,
}

impl ListCommand {
    /// List services against a pre-built HTTP client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn list_with_client(&self, client: &Client, base_url: &str) -> Result<Vec<Service>> {
        let mut params: Vec<(&str, &str)> = Vec::new();
        if let Some(name) = &self.name {
            params.push(("name", name));
        }
        if let Some(r#type) = &self.r#type {
            params.push(("type", r#type));
        }

        let res = client
            .get(Url::parse_with_params(
                &format!("{base_url}/v3/services"),
                &params,
            )?)
            .send()
            .await?;

        if res.status() != StatusCode::OK {
            return Err(eyre!(
                "failed to list services: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        Ok(res.json::<ServiceList>().await?.services)
    }
}

#[async_trait]
impl PerformAction for ListCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let services = self.list_with_client(&client, ADMIN_BASE_URL).await?;

        print_list_table(
            vec!["ID", "Type", "Name", "Enabled"],
            services
                .into_iter()
                .map(|service| {
                    vec![
                        service.id,
                        service.r#type.unwrap_or_default(),
                        service.name.unwrap_or_default(),
                        service.enabled.to_string(),
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
    async fn test_list_services() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET).path("/v3/services");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "services": [
                        { "id": "svc-1", "type": "identity-rs", "enabled": true, "name": "keystone-rs" }
                    ]
                }));
        });

        let client = Client::new();
        let cmd = ListCommand {
            name: None,
            r#type: None,
        };
        let result = cmd.list_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_list_services_with_filters() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/services")
                .query_param("name", "keystone-rs")
                .query_param("type", "identity-rs");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "services": [] }));
        });

        let client = Client::new();
        let cmd = ListCommand {
            name: Some("keystone-rs".to_string()),
            r#type: Some("identity-rs".to_string()),
        };
        let result = cmd.list_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_services_error() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET).path("/v3/services");
            then.status(500).body("internal error");
        });

        let client = Client::new();
        let cmd = ListCommand {
            name: None,
            r#type: None,
        };
        let result = cmd.list_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
