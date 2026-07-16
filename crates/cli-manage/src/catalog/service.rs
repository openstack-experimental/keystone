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
//! `keystone-manage catalog service` subcommand.

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::Report;

use openstack_keystone_config::Config;

pub(crate) mod create;
mod delete;
mod list;
mod show;
mod update;

use crate::PerformAction;
use crate::catalog::service::create::CreateCommand;
use crate::catalog::service::delete::DeleteCommand;
use crate::catalog::service::list::ListCommand;
use crate::catalog::service::show::ShowCommand;
use crate::catalog::service::update::UpdateCommand;

#[derive(Parser)]
pub(super) struct ServiceCommand {
    #[command(subcommand)]
    command: ServiceCommands,
}

#[async_trait]
impl PerformAction for ServiceCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        match self.command {
            ServiceCommands::Create(e) => e.take_action(config).await,
            ServiceCommands::Show(e) => e.take_action(config).await,
            ServiceCommands::List(e) => e.take_action(config).await,
            ServiceCommands::Update(e) => e.take_action(config).await,
            ServiceCommands::Delete(e) => e.take_action(config).await,
        }
    }
}

#[derive(Subcommand)]
enum ServiceCommands {
    /// Create a new catalog service.
    Create(CreateCommand),
    /// Show a catalog service.
    Show(ShowCommand),
    /// List catalog services.
    List(ListCommand),
    /// Update a catalog service.
    Update(UpdateCommand),
    /// Delete a catalog service.
    Delete(DeleteCommand),
}
