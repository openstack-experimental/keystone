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
use reqwest::Client;

use openstack_keystone_api_types::v4::mapping::{MappingRule, MappingRuleSet, RuleMutation};
use openstack_keystone_config::Config;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client, read_json_file};
use crate::mapping::ruleset::print_ruleset;
use crate::mapping::ruleset::rule::mutate_with_client;

/// Update an existing rule within a mapping ruleset.
///
/// Reads the replacement rule definition from a JSON file matching the
/// `MappingRule` shape.
#[derive(Parser)]
pub struct UpdateCommand {
    /// The ID of the mapping ruleset containing the rule.
    mapping_id: String,

    /// The name of the rule to update.
    rule_name: String,

    /// Path to a JSON file containing the replacement rule definition.
    #[arg(long)]
    file: PathBuf,
}

impl UpdateCommand {
    /// Update the rule against a pre-built HTTP client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn update_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<MappingRuleSet> {
        let rule: MappingRule = read_json_file(&self.file)
            .await
            .map_err(|e| eyre!("failed to read rule file: {e}"))?;

        mutate_with_client(
            client,
            base_url,
            &self.mapping_id,
            RuleMutation::Update {
                rule_name: self.rule_name.clone(),
                rule,
            },
        )
        .await
    }
}

#[async_trait]
impl PerformAction for UpdateCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let ruleset = self.update_with_client(&client, ADMIN_BASE_URL).await?;
        print_ruleset(ruleset);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use httpmock::{Method, MockServer};
    use tempfile::NamedTempFile;

    use super::*;

    fn write_rule() -> NamedTempFile {
        let file = NamedTempFile::new().expect("create temp file");
        std::fs::write(
            file.path(),
            serde_json::json!({
                "name": "rule-1",
                "match": {"all_of": []},
                "identity": {"user_name": "{sub}"},
                "authorizations": [],
                "groups": []
            })
            .to_string(),
        )
        .expect("write rule");
        file
    }

    #[tokio::test]
    async fn test_update_rule() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/mappings/rulesets/mapping-1/rules/mutate");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "mapping": {
                        "mapping_id": "mapping-1",
                        "domain_resolution_mode": {"type": "fixed"},
                        "enabled": true,
                        "source": {"type": "federation", "idp_id": "okta"},
                        "rules": [{
                            "name": "rule-1",
                            "match": {"all_of": []},
                            "identity": {"user_name": "{sub}"},
                            "authorizations": [],
                            "groups": []
                        }]
                    }
                }));
        });

        let file = write_rule();
        let client = Client::new();
        let cmd = UpdateCommand {
            mapping_id: "mapping-1".to_string(),
            rule_name: "rule-1".to_string(),
            file: file.path().to_path_buf(),
        };
        let result = cmd.update_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().rules.len(), 1);
    }

    #[tokio::test]
    async fn test_update_rule_error() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/mappings/rulesets/mapping-1/rules/mutate");
            then.status(500).body("internal error");
        });

        let file = write_rule();
        let client = Client::new();
        let cmd = UpdateCommand {
            mapping_id: "mapping-1".to_string(),
            rule_name: "rule-1".to_string(),
            file: file.path().to_path_buf(),
        };
        let result = cmd.update_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
