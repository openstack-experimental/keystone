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
//! `keystone-manage catalog endpoint` subcommand.

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::Report;

use openstack_keystone_config::Config;

mod create;
mod delete;
mod list;
mod show;
mod update;

use crate::PerformAction;
use crate::catalog::endpoint::create::CreateCommand;
use crate::catalog::endpoint::delete::DeleteCommand;
use crate::catalog::endpoint::list::ListCommand;
use crate::catalog::endpoint::show::ShowCommand;
use crate::catalog::endpoint::update::UpdateCommand;

#[derive(Parser)]
pub(super) struct EndpointCommand {
    #[command(subcommand)]
    command: EndpointCommands,
}

#[async_trait]
impl PerformAction for EndpointCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        match self.command {
            EndpointCommands::Create(e) => e.take_action(config).await,
            EndpointCommands::Show(e) => e.take_action(config).await,
            EndpointCommands::List(e) => e.take_action(config).await,
            EndpointCommands::Update(e) => e.take_action(config).await,
            EndpointCommands::Delete(e) => e.take_action(config).await,
        }
    }
}

#[derive(Subcommand)]
enum EndpointCommands {
    /// Create a new catalog endpoint.
    Create(CreateCommand),
    /// Show a catalog endpoint.
    Show(ShowCommand),
    /// List catalog endpoints.
    List(ListCommand),
    /// Update a catalog endpoint.
    Update(UpdateCommand),
    /// Delete a catalog endpoint.
    Delete(DeleteCommand),
}
