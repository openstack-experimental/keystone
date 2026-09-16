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
//! # Mapping subcommand of the keystone-manage cli.

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::Report;

use openstack_keystone_config::Config;

pub(crate) mod ruleset;

use crate::PerformAction;
use crate::mapping::ruleset::RulesetCommand;

/// Unified mapping engine ruleset management.
///
/// Manages mapping rulesets directly against the admin API, e.g. to finish
/// control-plane setup for federation/SPIFFE/K8s/API-key/OAuth2 identity
/// sources in dev environments.
#[derive(Parser)]
pub struct MappingCommand {
    #[command(subcommand)]
    command: MappingCommands,
}

#[async_trait]
impl PerformAction for MappingCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        match self.command {
            MappingCommands::Ruleset(e) => e.take_action(config).await,
        }
    }
}

#[derive(Subcommand)]
enum MappingCommands {
    /// Mapping rulesets.
    Ruleset(RulesetCommand),
}
