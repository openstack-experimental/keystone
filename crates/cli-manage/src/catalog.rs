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
//! # Catalog subcommand of the keystone-manage cli.

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::Report;

use openstack_keystone_config::Config;

mod endpoint;
mod service;

use crate::PerformAction;
use crate::catalog::endpoint::EndpointCommand;
use crate::catalog::service::ServiceCommand;

/// Service catalog (service/endpoint) management.
///
/// Registers services and endpoints directly against the admin API, outside
/// of the `bootstrap` flow — e.g. to register additional services in tests
/// or dev environments.
#[derive(Parser)]
pub struct CatalogCommand {
    #[command(subcommand)]
    command: CatalogCommands,
}

#[async_trait]
impl PerformAction for CatalogCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        match self.command {
            CatalogCommands::Service(e) => e.take_action(config).await,
            CatalogCommands::Endpoint(e) => e.take_action(config).await,
        }
    }
}

#[derive(Subcommand)]
enum CatalogCommands {
    /// Catalog services.
    Service(ServiceCommand),
    /// Catalog service endpoints.
    Endpoint(EndpointCommand),
}
