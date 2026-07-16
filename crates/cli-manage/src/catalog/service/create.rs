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
use crate::common::{ADMIN_BASE_URL, build_admin_client, print_attribute_table};

/// Create a new catalog service.
///
/// Idempotent: if a service of the given `type` already exists, it is
/// returned as-is instead of erroring.
#[derive(Parser)]
pub struct CreateCommand {
    /// Service type (e.g. `identity`).
    #[arg(long = "type")]
    pub(crate) r#type: String,

    /// Service name.
    #[arg(long)]
    pub(crate) name: Option<String>,

    /// Whether the service and its endpoints appear in the catalog.
    #[arg(long, default_value_t = true)]
    pub(crate) enabled: bool,
}

impl CreateCommand {
    /// Look up existing services by `type` via `GET /v3/services?type=...`.
    async fn find_by_type(&self, client: &Client, base_url: &str) -> Result<Vec<Service>> {
        Ok(client
            .get(Url::parse_with_params(
                &format!("{base_url}/v3/services"),
                &[("type", self.r#type.as_str())],
            )?)
            .send()
            .await?
            .json::<ServiceList>()
            .await?
            .services)
    }

    /// Create the service against a pre-built HTTP client.
    ///
    /// Idempotent: if a service of `type` already exists, it is returned
    /// as-is instead of erroring.
    ///
    /// This is the public entry point for tests that inject a mock client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn create_with_client(&self, client: &Client, base_url: &str) -> Result<Service> {
        if let Some(existing) = self
            .find_by_type(client, base_url)
            .await?
            .into_iter()
            .next()
        {
            return Ok(existing);
        }

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

        if res.status() == StatusCode::CONFLICT {
            // Another process created the service concurrently.
            return self
                .find_by_type(client, base_url)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    eyre!(
                        "service of type '{}' not found after concurrent creation",
                        self.r#type
                    )
                });
        }

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

    fn mock_empty_lookup(server: &MockServer, service_type: &str) {
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/services")
                .query_param("type", service_type);
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "services": [] }));
        });
    }

    #[tokio::test]
    async fn test_create_service() {
        let server = MockServer::start();
        let base = server.base_url();

        mock_empty_lookup(&server, "identity-rs");
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

        mock_empty_lookup(&server, "identity-rs");
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

        mock_empty_lookup(&server, "identity-rs");
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/services");
            then.status(500).body("internal error");
        });

        let client = Client::new();
        let cmd = command("identity-rs", None);
        let result = cmd.create_with_client(&client, &base).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_service_already_exists() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/services")
                .query_param("type", "identity-rs");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "services": [{ "id": "svc-existing", "type": "identity-rs", "enabled": true, "name": "keystone-rs" }]
                }));
        });
        // No POST mock registered: httpmock fails the test if an
        // unmatched request (e.g. an unexpected POST) is made.

        let client = Client::new();
        let cmd = command("identity-rs", Some("keystone-rs"));
        let created = cmd.create_with_client(&client, &base).await;
        assert!(created.is_ok());
        assert_eq!(created.unwrap().id, "svc-existing");
    }

    #[tokio::test]
    async fn test_create_service_conflict_refetches() {
        let server = MockServer::start();
        let base = server.base_url();

        // Lookup stays empty both times (no concurrent creator actually won
        // the race in this test double), so the post-conflict refetch is
        // expected to come up empty and surface as an error - this proves
        // the refetch happens rather than the 409 being swallowed silently.
        let lookup = server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/services")
                .query_param("type", "identity-rs");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "services": [] }));
        });
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/services");
            then.status(409).body("conflict");
        });

        let client = Client::new();
        let cmd = command("identity-rs", Some("keystone-rs"));
        let result = cmd.create_with_client(&client, &base).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not found after concurrent creation")
        );
        assert_eq!(lookup.hits(), 2);
    }
}
