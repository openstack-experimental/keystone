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
//! `keystone-manage mapping ruleset rule` subcommand.
//!
//! Imperative single-rule mutations against a ruleset, via the
//! `/rules/mutate` endpoint (`RuleMutation::{Insert,Update,Delete}`).

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::{Report, eyre::eyre};
use eyre::Result;
use reqwest::{Client, StatusCode};

use openstack_keystone_api_types::v4::mapping::{
    MappingRuleSet, MappingRuleSetResponse, RuleMutation, RuleMutationsRequest,
};
use openstack_keystone_config::Config;

mod delete;
mod insert;
mod update;

use crate::PerformAction;
use crate::mapping::ruleset::rule::delete::DeleteCommand;
use crate::mapping::ruleset::rule::insert::InsertCommand;
use crate::mapping::ruleset::rule::update::UpdateCommand;

#[derive(Parser)]
pub(super) struct RuleCommand {
    #[command(subcommand)]
    command: RuleCommands,
}

#[async_trait]
impl PerformAction for RuleCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        match self.command {
            RuleCommands::Insert(e) => e.take_action(config).await,
            RuleCommands::Update(e) => e.take_action(config).await,
            RuleCommands::Delete(e) => e.take_action(config).await,
        }
    }
}

#[derive(Subcommand)]
enum RuleCommands {
    /// Insert a new rule into a ruleset.
    Insert(InsertCommand),
    /// Update an existing rule within a ruleset.
    Update(UpdateCommand),
    /// Delete a rule from a ruleset.
    Delete(DeleteCommand),
}

/// Send a single mutation against a ruleset and return the updated ruleset.
async fn mutate_with_client(
    client: &Client,
    base_url: &str,
    mapping_id: &str,
    mutation: RuleMutation,
) -> Result<MappingRuleSet> {
    let res = client
        .post(format!(
            "{base_url}/v4/mappings/rulesets/{mapping_id}/rules/mutate"
        ))
        .json(&RuleMutationsRequest {
            mutations: vec![mutation],
        })
        .send()
        .await?;

    if res.status() != StatusCode::OK {
        return Err(eyre!(
            "failed to mutate mapping ruleset rule: {} ({})",
            res.status(),
            res.text().await.unwrap_or_default()
        ));
    }

    Ok(res.json::<MappingRuleSetResponse>().await?.mapping)
}
