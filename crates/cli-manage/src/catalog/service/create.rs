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

use openstack_keystone_api_types::v3::service::*;
use openstack_keystone_config::Config;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client, print_attribute_table};

/// Create a new catalog service.
#[derive(Parser)]
pub(super) struct CreateCommand {
    /// Service type (e.g. `identity`).
    #[arg(long = "type")]
    r#type: String,

    /// Service name.
    #[arg(long)]
    name: Option<String>,

    /// Whether the service and its endpoints appear in the catalog.
    #[arg(long, default_value_t = true)]
    enabled: bool,
}

impl CreateCommand {
    /// Create the service against a pre-built HTTP client.
    ///
    /// This is the public entry point for tests that inject a mock client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn create_with_client(&self, client: &Client, base_url: &str) -> Result<Service> {
        let mut builder = ServiceCreateBuilder::default();
        builder.r#type(self.r#type.clone()).enabled(self.enabled);
        if let Some(name) = &self.name {
            builder.name(name.clone());
        }

        let res = client
            .post(format!("{base_url}/v3/services"))
            .json(&ServiceCreateRequest {
                service: builder.build()?,
            })
            .send()
            .await?;

        if res.status() != StatusCode::CREATED {
            return Err(eyre!(
                "failed to create service: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        Ok(res.json::<ServiceResponse>().await?.service)
    }
}

#[async_trait]
impl PerformAction for CreateCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let created = self.create_with_client(&client, ADMIN_BASE_URL).await?;

        print_attribute_table(vec![
            ("id", created.id),
            ("type", created.r#type.unwrap_or_default()),
            ("name", created.name.unwrap_or_default()),
            ("enabled", created.enabled.to_string()),
        ]);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use httpmock::{Method, MockServer};
    use reqwest::Client;

    use super::*;

    fn command(r#type: &str, name: Option<&str>) -> CreateCommand {
        CreateCommand {
            r#type: r#type.to_string(),
            name: name.map(str::to_string),
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_create_service() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/services");
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "service": { "id": "svc-1", "type": "identity-rs", "enabled": true, "name": "keystone-rs" }
                }));
        });

        let client = Client::new();
        let cmd = command("identity-rs", Some("keystone-rs"));
        let created = cmd.create_with_client(&client, &base).await;
        assert!(created.is_ok());
        let created = created.unwrap();
        assert_eq!(created.id, "svc-1");
        assert_eq!(created.name.as_deref(), Some("keystone-rs"));
    }

    #[tokio::test]
    async fn test_create_service_without_name() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/services");
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "service": { "id": "svc-2", "type": "identity-rs", "enabled": true }
                }));
        });

        let client = Client::new();
        let cmd = command("identity-rs", None);
        let created = cmd.create_with_client(&client, &base).await;
        assert!(created.is_ok());
        assert_eq!(created.unwrap().id, "svc-2");
    }

    #[tokio::test]
    async fn test_create_service_error() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/services");
            then.status(500).body("internal error");
        });

        let client = Client::new();
        let cmd = command("identity-rs", None);
        let result = cmd.create_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
