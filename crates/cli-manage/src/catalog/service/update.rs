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

use openstack_keystone_api_types::v3::service::*;
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

/// Update a catalog service.
#[derive(Parser)]
pub(super) struct UpdateCommand {
    /// The ID of the service to update.
    id: String,

    /// New service type.
    #[arg(long = "type")]
    r#type: Option<String>,

    /// New service name.
    #[arg(long)]
    name: Option<String>,

    /// Whether the service and its endpoints appear in the catalog.
    #[arg(long)]
    enabled: Option<BoolArg>,
}

impl UpdateCommand {
    /// Update the service against a pre-built HTTP client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn update_with_client(&self, client: &Client, base_url: &str) -> Result<Service> {
        let mut builder = ServiceUpdateBuilder::default();
        if let Some(r#type) = &self.r#type {
            builder.r#type(r#type.clone());
        }
        if let Some(name) = &self.name {
            builder.name(name.clone());
        }
        if let Some(enabled) = self.enabled {
            builder.enabled(bool::from(enabled));
        }

        let res = client
            .patch(format!("{base_url}/v3/services/{}", self.id))
            .json(&ServiceUpdateRequest {
                service: builder.build()?,
            })
            .send()
            .await?;

        if res.status() != StatusCode::OK {
            return Err(eyre!(
                "failed to update service: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        Ok(res.json::<ServiceResponse>().await?.service)
    }
}

#[async_trait]
impl PerformAction for UpdateCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let updated = self.update_with_client(&client, ADMIN_BASE_URL).await?;

        print_attribute_table(vec![
            ("id", updated.id),
            ("type", updated.r#type.unwrap_or_default()),
            ("name", updated.name.unwrap_or_default()),
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
    async fn test_update_service() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::PATCH).path("/v3/services/svc-1");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "service": { "id": "svc-1", "type": "identity-rs", "enabled": false, "name": "renamed" }
                }));
        });

        let client = Client::new();
        let cmd = UpdateCommand {
            id: "svc-1".to_string(),
            r#type: None,
            name: Some("renamed".to_string()),
            enabled: Some(BoolArg::False),
        };
        let result = cmd.update_with_client(&client, &base).await;
        assert!(result.is_ok());
        let updated = result.unwrap();
        assert_eq!(updated.name.as_deref(), Some("renamed"));
        assert!(!updated.enabled);
    }

    #[tokio::test]
    async fn test_update_service_error() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::PATCH).path("/v3/services/missing");
            then.status(404).body("not found");
        });

        let client = Client::new();
        let cmd = UpdateCommand {
            id: "missing".to_string(),
            r#type: None,
            name: None,
            enabled: None,
        };
        let result = cmd.update_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
