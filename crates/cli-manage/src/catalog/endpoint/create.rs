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
use clap::{ArgGroup, Parser};
use color_eyre::{Report, eyre::eyre};
use eyre::Result;
use reqwest::{Client, StatusCode, Url};

use openstack_keystone_api_types::v3::endpoint::*;
use openstack_keystone_api_types::v3::service::ServiceList;
use openstack_keystone_config::Config;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client, print_attribute_table};

/// Create a new catalog endpoint.
///
/// Idempotent: if an endpoint with the same `service_id` and `interface`
/// already exists, it is returned as-is instead of erroring.
#[derive(Parser)]
#[command(group(
    ArgGroup::new("service_ref")
        .required(true)
        .args(["service_id", "service_name"]),
))]
pub struct CreateCommand {
    /// The ID of the service the endpoint belongs to.
    #[arg(long)]
    pub(crate) service_id: Option<String>,

    /// The name of the service the endpoint belongs to. Resolved to an ID via
    /// `GET /v3/services?name=...`; fails if zero or more than one service
    /// matches.
    #[arg(long)]
    pub(crate) service_name: Option<String>,

    /// The interface (`public`, `internal`, or `admin`).
    #[arg(long)]
    pub(crate) interface: String,

    /// The endpoint URL.
    #[arg(long)]
    pub(crate) url: String,

    /// The ID of the region that contains the endpoint.
    #[arg(long)]
    pub(crate) region_id: Option<String>,

    /// Whether the endpoint appears in the service catalog.
    #[arg(long, default_value_t = true)]
    pub(crate) enabled: bool,
}

impl CreateCommand {
    /// Resolve `--service-name` to a service ID via `GET
    /// /v3/services?name=...`.
    async fn resolve_service_id(&self, client: &Client, base_url: &str) -> Result<String> {
        if let Some(id) = &self.service_id {
            return Ok(id.clone());
        }

        // clap's ArgGroup guarantees exactly one of `service_id`/`service_name`
        // is set, but avoid panicking if that invariant is ever violated
        // (e.g. by constructing `CreateCommand` directly in a test).
        let Some(name) = self.service_name.as_ref() else {
            return Err(eyre!("either --service-id or --service-name must be set"));
        };

        let services = client
            .get(Url::parse_with_params(
                &format!("{base_url}/v3/services"),
                &[("name", name.as_str())],
            )?)
            .send()
            .await?
            .json::<ServiceList>()
            .await?
            .services;

        match services.len() {
            0 => Err(eyre!("no service found with name '{name}'")),
            1 => Ok(services[0].id.clone()),
            n => Err(eyre!(
                "ambiguous service name '{name}': {n} services match, use --service-id instead"
            )),
        }
    }

    /// Look up existing endpoints by `service_id` + `interface` via
    /// `GET /v3/endpoints?service_id=...&interface=...`.
    async fn find_by_service_and_interface(
        &self,
        client: &Client,
        base_url: &str,
        service_id: &str,
    ) -> Result<Vec<Endpoint>> {
        Ok(client
            .get(Url::parse_with_params(
                &format!("{base_url}/v3/endpoints"),
                &[
                    ("service_id", service_id),
                    ("interface", self.interface.as_str()),
                ],
            )?)
            .send()
            .await?
            .json::<EndpointList>()
            .await?
            .endpoints)
    }

    /// Create the endpoint against a pre-built HTTP client.
    ///
    /// Idempotent: if an endpoint with the same `service_id` + `interface`
    /// already exists, it is returned as-is instead of erroring.
    ///
    /// This is the public entry point for tests that inject a mock client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn create_with_client(&self, client: &Client, base_url: &str) -> Result<Endpoint> {
        let service_id = self.resolve_service_id(client, base_url).await?;

        if let Some(existing) = self
            .find_by_service_and_interface(client, base_url, &service_id)
            .await?
            .into_iter()
            .next()
        {
            return Ok(existing);
        }

        let mut builder = EndpointCreateBuilder::default();
        builder
            .service_id(service_id.clone())
            .interface(self.interface.clone())
            .url(self.url.clone())
            .enabled(self.enabled);
        if let Some(region_id) = &self.region_id {
            builder.region_id(region_id.clone());
        }

        let res = client
            .post(format!("{base_url}/v3/endpoints"))
            .json(&EndpointCreateRequest {
                endpoint: builder.build()?,
            })
            .send()
            .await?;

        if res.status() == StatusCode::CONFLICT {
            // Another process created the endpoint concurrently.
            return self
                .find_by_service_and_interface(client, base_url, &service_id)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    eyre!(
                        "'{}' endpoint for service '{}' not found after concurrent creation",
                        self.interface,
                        service_id
                    )
                });
        }

        if res.status() != StatusCode::CREATED {
            return Err(eyre!(
                "failed to create endpoint: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        Ok(res.json::<EndpointResponse>().await?.endpoint)
    }
}

#[async_trait]
impl PerformAction for CreateCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let created = self.create_with_client(&client, ADMIN_BASE_URL).await?;

        print_attribute_table(vec![
            ("id", created.id),
            ("interface", created.interface),
            ("service_id", created.service_id),
            ("url", created.url),
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

    fn command_by_id(service_id: &str) -> CreateCommand {
        CreateCommand {
            service_id: Some(service_id.to_string()),
            service_name: None,
            interface: "public".to_string(),
            url: "https://example.com".to_string(),
            region_id: None,
            enabled: true,
        }
    }

    fn command_by_name(service_name: &str) -> CreateCommand {
        CreateCommand {
            service_id: None,
            service_name: Some(service_name.to_string()),
            interface: "public".to_string(),
            url: "https://example.com".to_string(),
            region_id: None,
            enabled: true,
        }
    }

    fn mock_empty_endpoint_lookup(server: &MockServer, service_id: &str, interface: &str) {
        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/endpoints")
                .query_param("service_id", service_id)
                .query_param("interface", interface);
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "endpoints": [] }));
        });
    }

    #[tokio::test]
    async fn test_create_endpoint_by_service_id() {
        let server = MockServer::start();
        let base = server.base_url();

        mock_empty_endpoint_lookup(&server, "svc-1", "public");
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/endpoints");
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "endpoint": {
                        "id": "ep-1", "interface": "public", "service_id": "svc-1",
                        "url": "https://example.com", "enabled": true
                    }
                }));
        });

        let client = Client::new();
        let cmd = command_by_id("svc-1");
        let created = cmd.create_with_client(&client, &base).await;
        assert!(created.is_ok());
        assert_eq!(created.unwrap().service_id, "svc-1");
    }

    #[tokio::test]
    async fn test_create_endpoint_by_service_name() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/services")
                .query_param("name", "identity-rs");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "services": [{ "id": "svc-1", "type": "identity-rs", "enabled": true, "name": "identity-rs" }]
                }));
        });
        mock_empty_endpoint_lookup(&server, "svc-1", "public");
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/endpoints");
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "endpoint": {
                        "id": "ep-1", "interface": "public", "service_id": "svc-1",
                        "url": "https://example.com", "enabled": true
                    }
                }));
        });

        let client = Client::new();
        let cmd = command_by_name("identity-rs");
        let created = cmd.create_with_client(&client, &base).await;
        assert!(created.is_ok());
        assert_eq!(created.unwrap().service_id, "svc-1");
    }

    #[tokio::test]
    async fn test_create_endpoint_already_exists() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/endpoints")
                .query_param("service_id", "svc-1")
                .query_param("interface", "public");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "endpoints": [{
                        "id": "ep-existing", "interface": "public", "service_id": "svc-1",
                        "url": "https://example.com", "enabled": true
                    }]
                }));
        });
        // No POST mock registered: httpmock fails the test if an
        // unmatched request (e.g. an unexpected POST) is made.

        let client = Client::new();
        let cmd = command_by_id("svc-1");
        let created = cmd.create_with_client(&client, &base).await;
        assert!(created.is_ok());
        assert_eq!(created.unwrap().id, "ep-existing");
    }

    #[tokio::test]
    async fn test_create_endpoint_conflict_refetches() {
        let server = MockServer::start();
        let base = server.base_url();

        // Lookup stays empty both times (no concurrent creator actually won
        // the race in this test double), so the post-conflict refetch is
        // expected to come up empty and surface as an error - this proves
        // the refetch happens rather than the 409 being swallowed silently.
        let lookup = server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/endpoints")
                .query_param("service_id", "svc-1")
                .query_param("interface", "public");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "endpoints": [] }));
        });
        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/endpoints");
            then.status(409).body("conflict");
        });

        let client = Client::new();
        let cmd = command_by_id("svc-1");
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

    #[tokio::test]
    async fn test_create_endpoint_service_name_not_found() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/services")
                .query_param("name", "missing");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "services": [] }));
        });

        let client = Client::new();
        let cmd = command_by_name("missing");
        let result = cmd.create_with_client(&client, &base).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no service found"));
    }

    #[tokio::test]
    async fn test_create_endpoint_service_name_ambiguous() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v3/services")
                .query_param("name", "dup");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "services": [
                        { "id": "svc-1", "type": "identity-rs", "enabled": true, "name": "dup" },
                        { "id": "svc-2", "type": "identity-rs", "enabled": true, "name": "dup" }
                    ]
                }));
        });

        let client = Client::new();
        let cmd = command_by_name("dup");
        let result = cmd.create_with_client(&client, &base).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ambiguous"));
    }

    #[tokio::test]
    async fn test_create_endpoint_error_status() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::POST).path("/v3/endpoints");
            then.status(500).body("internal error");
        });

        let client = Client::new();
        let cmd = command_by_id("svc-1");
        let result = cmd.create_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
