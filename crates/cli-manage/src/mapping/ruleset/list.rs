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

use openstack_keystone_api_types::v4::mapping::{MappingRuleSet, MappingRuleSetList};
use openstack_keystone_config::Config;

use crate::PerformAction;
use crate::common::{ADMIN_BASE_URL, build_admin_client, print_list_table};

/// List mapping rulesets.
#[derive(Parser)]
pub struct ListCommand {
    /// Filter by domain ID.
    #[arg(long = "domain-id")]
    domain_id: Option<String>,

    /// Filter by enabled/disabled state.
    #[arg(long)]
    enabled: Option<bool>,
}

impl ListCommand {
    /// List rulesets against a pre-built HTTP client.
    #[cfg_attr(not(test), doc(hidden))]
    pub async fn list_with_client(
        &self,
        client: &Client,
        base_url: &str,
    ) -> Result<Vec<MappingRuleSet>> {
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(domain_id) = &self.domain_id {
            params.push(("domain_id", domain_id.clone()));
        }
        if let Some(enabled) = self.enabled {
            params.push(("enabled", enabled.to_string()));
        }

        let res = client
            .get(Url::parse_with_params(
                &format!("{base_url}/v4/mappings/rulesets"),
                &params,
            )?)
            .send()
            .await?;

        if res.status() != StatusCode::OK {
            return Err(eyre!(
                "failed to list mapping rulesets: {} ({})",
                res.status(),
                res.text().await.unwrap_or_default()
            ));
        }

        Ok(res.json::<MappingRuleSetList>().await?.mappings)
    }
}

#[async_trait]
impl PerformAction for ListCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        let client = build_admin_client(config).await?;
        let rulesets = self.list_with_client(&client, ADMIN_BASE_URL).await?;

        print_list_table(
            vec!["Mapping ID", "Domain ID", "Source", "Enabled", "Rules"],
            rulesets
                .into_iter()
                .map(|ruleset| {
                    vec![
                        ruleset.mapping_id,
                        ruleset.domain_id.unwrap_or_default(),
                        serde_json::to_string(&ruleset.source).unwrap_or_default(),
                        ruleset.enabled.to_string(),
                        ruleset.rules.len().to_string(),
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
    async fn test_list_rulesets() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET).path("/v4/mappings/rulesets");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({
                    "mappings": [
                        {
                            "mapping_id": "mapping-1",
                            "domain_resolution_mode": {"type": "fixed"},
                            "enabled": true,
                            "source": {"type": "federation", "idp_id": "okta"},
                            "rules": []
                        }
                    ]
                }));
        });

        let client = Client::new();
        let cmd = ListCommand {
            domain_id: None,
            enabled: None,
        };
        let result = cmd.list_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_list_rulesets_with_filters() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET)
                .path("/v4/mappings/rulesets")
                .query_param("domain_id", "domain-1")
                .query_param("enabled", "true");
            then.status(200)
                .header("content-type", "application/json")
                .json_body_obj(&serde_json::json!({ "mappings": [] }));
        });

        let client = Client::new();
        let cmd = ListCommand {
            domain_id: Some("domain-1".to_string()),
            enabled: Some(true),
        };
        let result = cmd.list_with_client(&client, &base).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_rulesets_error() {
        let server = MockServer::start();
        let base = server.base_url();

        server.mock(|when, then| {
            when.method(Method::GET).path("/v4/mappings/rulesets");
            then.status(500).body("internal error");
        });

        let client = Client::new();
        let cmd = ListCommand {
            domain_id: None,
            enabled: None,
        };
        let result = cmd.list_with_client(&client, &base).await;
        assert!(result.is_err());
    }
}
