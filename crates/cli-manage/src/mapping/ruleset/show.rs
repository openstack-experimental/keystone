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

use openstack_keystone_api_types::v4::mapping::{MappingRuleSet, MappingRuleSetResponse};
use openstack_keystone_config::Config;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client};
use crate::mapping::ruleset::print_ruleset;

/// Show a mapping ruleset.
#[derive(Parser)]
pub struct ShowCommand {
    /// The ID of the mapping ruleset to show.
    mapping_id: String,
}

impl ShowCommand {
    /// Fetch the ruleset against a pre-built HTTP client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn show_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<MappingRuleSet> {
        let res = client
            .get(format!(
                "{base_url}/v4/mappings/rulesets/{}",
                self.mapping_id
            ))
            .send()
            .await?;

        if res.status() != StatusCode::OK {
            return Err(eyre!(
                "failed to show mapping ruleset: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        Ok(res.json::<MappingRuleSetResponse>().await?.mapping)
    }
}

#[async_trait]
impl PerformAction for ShowCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let ruleset = self.show_with_client(&client, ADMIN_BASE_URL).await?;
        print_ruleset(ruleset);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use httpmock::{Method, MockServer};
    use reqwest::Client;

    use super::*;

    #[tokio::test]
    async fn test_show_ruleset() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v4/mappings/rulesets/mapping-1");
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
        let cmd = ShowCommand {
            mapping_id: "mapping-1".to_string(),
        };
        let result = cmd.show_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().mapping_id, "mapping-1");
    }

    #[tokio::test]
    async fn test_show_ruleset_not_found() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v4/mappings/rulesets/missing");
            then.status(404).body("not found");
        });

        let client = Client::new();
        let cmd = ShowCommand {
            mapping_id: "missing".to_string(),
        };
        let result = cmd.show_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
