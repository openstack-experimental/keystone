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
    MappingRuleSet, MappingRuleSetResponse, MappingRuleSetUpdate, MappingRuleSetUpdateRequest,
};
use openstack_keystone_config::Config;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client, read_json_file};
use crate::mapping::ruleset::print_ruleset;

/// Update a mapping ruleset.
///
/// Reads the mutable-field payload (`allowed_domains`, `enabled`, `rules`)
/// from a JSON file matching the `MappingRuleSetUpdate` shape. `--enabled`
/// overrides the file's `enabled` field, if any.
#[derive(Parser)]
pub struct UpdateCommand {
    /// The ID of the mapping ruleset to update.
    mapping_id: String,

    /// Path to a JSON file containing the ruleset update payload.
    #[arg(long)]
    file: PathBuf,

    /// Toggle the ruleset enabled/disabled, overriding the file's value.
    #[arg(long)]
    enabled: Option<bool>,
}

impl UpdateCommand {
    /// Update the ruleset against a pre-built HTTP client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn update_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<MappingRuleSet> {
        let mut payload: MappingRuleSetUpdate = read_json_file(&self.file).await?;
        if self.enabled.is_some() {
            payload.enabled = self.enabled;
        }

        let res = client
            .put(format!(
                "{base_url}/v4/mappings/rulesets/{}",
                self.mapping_id
            ))
            .json(&MappingRuleSetUpdateRequest { mapping: payload })
            .send()
            .await?;

        if res.status() != StatusCode::OK {
            return Err(eyre!(
                "failed to update mapping ruleset: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        Ok(res.json::<MappingRuleSetResponse>().await?.mapping)
    }
}

#[async_trait]
impl PerformAction for UpdateCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let updated = self.update_with_client(&client, ADMIN_BASE_URL).await?;
        print_ruleset(updated);
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

    #[tokio::test]
    async fn test_update_ruleset() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::PUT)
                .path("/v4/mappings/rulesets/mapping-1");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "mapping": {
                        "mapping_id": "mapping-1",
                        "domain_resolution_mode": {"type": "fixed"},
                        "enabled": false,
                        "source": {"type": "federation", "idp_id": "okta"},
                        "rules": []
                    }
                }));
        });

        let file = write_payload(&serde_json::json!({ "enabled": false }));
        let client = Client::new();
        let cmd = UpdateCommand {
            mapping_id: "mapping-1".to_string(),
            file: file.path().to_path_buf(),
            enabled: None,
        };
        let result = cmd.update_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().enabled);
    }

    #[tokio::test]
    async fn test_update_ruleset_enabled_flag_overrides_file() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::PUT)
                .path("/v4/mappings/rulesets/mapping-1")
                .body_includes(r#""enabled":true"#);
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "mapping": {
                        "mapping_id": "mapping-1",
                        "domain_resolution_mode": {"type": "fixed"},
                        "enabled": true,
                        "source": {"type": "federation", "idp_id": "okta"},
                        "rules": []
                    }
                }));
        });

        let file = write_payload(&serde_json::json!({ "enabled": false }));
        let client = Client::new();
        let cmd = UpdateCommand {
            mapping_id: "mapping-1".to_string(),
            file: file.path().to_path_buf(),
            enabled: Some(true),
        };
        let result = cmd.update_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert!(result.unwrap().enabled);
    }

    #[tokio::test]
    async fn test_update_ruleset_not_found() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::PUT)
                .path("/v4/mappings/rulesets/missing");
            then.status(404).body("not found");
        });

        let file = write_payload(&serde_json::json!({ "enabled": false }));
        let client = Client::new();
        let cmd = UpdateCommand {
            mapping_id: "missing".to_string(),
            file: file.path().to_path_buf(),
            enabled: None,
        };
        let result = cmd.update_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
