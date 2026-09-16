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
use color_eyre::Report;
use eyre::Result;
use reqwest::Client;

use openstack_keystone_api_types::v4::mapping::{MappingRuleSet, RuleMutation};
use openstack_keystone_config::Config;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client};
use crate::mapping::ruleset::print_ruleset;
use crate::mapping::ruleset::rule::mutate_with_client;

/// Delete a rule from a mapping ruleset.
#[derive(Parser)]
pub struct DeleteCommand {
    /// The ID of the mapping ruleset containing the rule.
    mapping_id: String,

    /// The name of the rule to delete.
    rule_name: String,
}

impl DeleteCommand {
    /// Delete the rule against a pre-built HTTP client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn delete_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<MappingRuleSet> {
        mutate_with_client(
            client,
            base_url,
            &self.mapping_id,
            RuleMutation::Delete {
                rule_name: self.rule_name.clone(),
            },
        )
        .await
    }
}

#[async_trait]
impl PerformAction for DeleteCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let ruleset = self.delete_with_client(&client, ADMIN_BASE_URL).await?;
        print_ruleset(ruleset);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use httpmock::{Method, MockServer};

    use super::*;

    #[tokio::test]
    async fn test_delete_rule() {
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
                        "rules": []
                    }
                }));
        });

        let client = Client::new();
        let cmd = DeleteCommand {
            mapping_id: "mapping-1".to_string(),
            rule_name: "rule-1".to_string(),
        };
        let result = cmd.delete_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert!(result.unwrap().rules.is_empty());
    }

    #[tokio::test]
    async fn test_delete_rule_error() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::POST)
                .path("/v4/mappings/rulesets/mapping-1/rules/mutate");
            then.status(500).body("internal error");
        });

        let client = Client::new();
        let cmd = DeleteCommand {
            mapping_id: "mapping-1".to_string(),
            rule_name: "rule-1".to_string(),
        };
        let result = cmd.delete_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
