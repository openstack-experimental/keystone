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
//! `keystone-manage mapping ruleset` subcommand.

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::Report;

use openstack_keystone_api_types::v4::mapping::MappingRuleSet;
use openstack_keystone_config::Config;

use crate::common::print_attribute_table;

pub(crate) mod create;
mod delete;
mod list;
pub(crate) mod rule;
mod show;
mod update;

use crate::PerformAction;
use crate::mapping::ruleset::create::CreateCommand;
use crate::mapping::ruleset::delete::DeleteCommand;
use crate::mapping::ruleset::list::ListCommand;
use crate::mapping::ruleset::rule::RuleCommand;
use crate::mapping::ruleset::show::ShowCommand;
use crate::mapping::ruleset::update::UpdateCommand;

/// Print a single mapping ruleset as an attribute table.
///
/// The nested `source`, `domain_resolution_mode`, and `rules` fields don't
/// fit a flat two-column table, so they're rendered as their JSON
/// representation.
pub(crate) fn print_ruleset(ruleset: MappingRuleSet) {
    print_attribute_table(vec![
        ("mapping_id", ruleset.mapping_id),
        ("domain_id", ruleset.domain_id.unwrap_or_default()),
        (
            "source",
            serde_json::to_string(&ruleset.source).unwrap_or_default(),
        ),
        (
            "domain_resolution_mode",
            serde_json::to_string(&ruleset.domain_resolution_mode).unwrap_or_default(),
        ),
        ("enabled", ruleset.enabled.to_string()),
        (
            "rules",
            serde_json::to_string_pretty(&ruleset.rules).unwrap_or_default(),
        ),
    ]);
}

#[derive(Parser)]
pub(super) struct RulesetCommand {
    #[command(subcommand)]
    command: RulesetCommands,
}

#[async_trait]
impl PerformAction for RulesetCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        match self.command {
            RulesetCommands::Create(e) => e.take_action(config).await,
            RulesetCommands::Show(e) => e.take_action(config).await,
            RulesetCommands::List(e) => e.take_action(config).await,
            RulesetCommands::Update(e) => e.take_action(config).await,
            RulesetCommands::Delete(e) => e.take_action(config).await,
            RulesetCommands::Rule(e) => e.take_action(config).await,
        }
    }
}

#[derive(Subcommand)]
enum RulesetCommands {
    /// Create a new mapping ruleset.
    Create(CreateCommand),
    /// Show a mapping ruleset.
    Show(ShowCommand),
    /// List mapping rulesets.
    List(ListCommand),
    /// Update a mapping ruleset.
    Update(UpdateCommand),
    /// Delete a mapping ruleset.
    Delete(DeleteCommand),
    /// Imperative single-rule mutations (insert/update/delete).
    Rule(RuleCommand),
}
