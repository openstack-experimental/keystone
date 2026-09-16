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

use std::path::PathBuf;

use async_trait::async_trait;
use clap::Parser;
use color_eyre::{Report, eyre::eyre};
use eyre::Result;
use reqwest::{Client, StatusCode};

use openstack_keystone_api_types::v4::mapping::{
    MappingRuleSet, MappingRuleSetCreate, MappingRuleSetCreateRequest, MappingRuleSetResponse,
};
use openstack_keystone_config::Config;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client, read_json_file};
use crate::mapping::ruleset::print_ruleset;

/// Create a new mapping ruleset.
///
/// Reads the ruleset payload (`domain_id`, `domain_resolution_mode`,
/// `source`, `rules`, ...) from a JSON file matching the
/// `MappingRuleSetCreate` shape documented in
/// `doc/src/user/features/identity-mapping.md`.
#[derive(Parser)]
pub struct CreateCommand {
    /// Path to a JSON file containing the ruleset creation payload.
    #[arg(long)]
    file: PathBuf,

    /// Override the ruleset ID from the file (auto-generated if neither is
    /// set).
    #[arg(long = "mapping-id")]
    mapping_id: Option<String>,
}

impl CreateCommand {
    /// Create the ruleset against a pre-built HTTP client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn create_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<MappingRuleSet> {
        let mut payload: MappingRuleSetCreate = read_json_file(&self.file).await?;
        if self.mapping_id.is_some() {
            payload.mapping_id = self.mapping_id.clone();
        }

        let res = client
            .post(format!("{base_url}/v4/mappings/rulesets"))
            .json(&MappingRuleSetCreateRequest { mapping: payload })
            .send()
            .await?;

        if res.status() != StatusCode::CREATED {
            return Err(eyre!(
                "failed to create mapping ruleset: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        Ok(res.json::<MappingRuleSetResponse>().await?.mapping)
    }
}

#[async_trait]
impl PerformAction for CreateCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let created = self.create_with_client(&client, ADMIN_BASE_URL).await?;
        print_ruleset(created);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use httpmock::{Method, MockServer};
    use reqwest::Client;
    use tempfile::NamedTempFile;

    use super::*;

    fn write_payload(json: &serde_json::Value) -> NamedTempFile {
        let file = NamedTempFile::new().expect("create temp file");
        std::fs::write(file.path(), json.to_string()).expect("write payload");
        file
    }

    fn sample_payload() -> serde_json::Value {
        serde_json::json!({
            "domain_id": "domain-1",
            "domain_resolution_mode": {"type": "fixed"},
            "enabled": true,
            "source": {"type": "federation", "idp_id": "okta"},
            "rules": [
                {
                    "name": "rule-1",
                    "match": {"all_of": []},
                    "identity": {"user_name": "{sub}"},
                    "authorizations": [],
                    "groups": []
                }
            ]
        })
    }

    #[tokio::test]
    async fn test_create_ruleset() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::POST).path("/v4/mappings/rulesets");
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "mapping": {
                        "mapping_id": "mapping-1",
                        "domain_id": "domain-1",
                        "domain_resolution_mode": {"type": "fixed"},
                        "enabled": true,
                        "source": {"type": "federation", "idp_id": "okta"},
                        "rules": []
                    }
                }));
        });

        let file = write_payload(&sample_payload());
        let client = Client::new();
        let cmd = CreateCommand {
            file: file.path().to_path_buf(),
            mapping_id: None,
        };
        let result = cmd.create_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().mapping_id, "mapping-1");
    }

    #[tokio::test]
    async fn test_create_ruleset_mapping_id_override() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/mappings/rulesets")
                .body_includes("explicit-id");
            then.status(201)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "mapping": {
                        "mapping_id": "explicit-id",
                        "domain_resolution_mode": {"type": "fixed"},
                        "enabled": true,
                        "source": {"type": "federation", "idp_id": "okta"},
                        "rules": []
                    }
                }));
        });

        let file = write_payload(&sample_payload());
        let client = Client::new();
        let cmd = CreateCommand {
            file: file.path().to_path_buf(),
            mapping_id: Some("explicit-id".to_string()),
        };
        let result = cmd.create_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().mapping_id, "explicit-id");
    }

    #[tokio::test]
    async fn test_create_ruleset_bad_file() {
        let client = Client::new();
        let cmd = CreateCommand {
            file: PathBuf::from("/nonexistent/path.json"),
            mapping_id: None,
        };
        let result = cmd.create_with_client(&client, "http://localhost").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_ruleset_error() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::POST).path("/v4/mappings/rulesets");
            then.status(500).body("internal error");
        });

        let file = write_payload(&sample_payload());
        let client = Client::new();
        let cmd = CreateCommand {
            file: file.path().to_path_buf(),
            mapping_id: None,
        };
        let result = cmd.create_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
