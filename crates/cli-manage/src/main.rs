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
//! Keystone manage executable.
#![allow(clippy::print_stdout)]

use std::path::PathBuf;

use async_trait::async_trait;
use clap::Parser;
use color_eyre::Report;

use openstack_keystone_config::Config;

mod bootstrap;
mod credential;
mod db;
mod storage;

use crate::bootstrap::*;
use crate::credential::*;
use crate::db::*;
use crate::storage::*;

/// OpenStack Keystone management CLI.
///
/// Administrative CLI to manage the keystone server.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the keystone config file.
    #[arg(
        global = true,
        short,
        long,
        default_value = "/etc/keystone/keystone.conf"
    )]
    config: PathBuf,

    /// Command.
    #[command(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    /// Bootstrap.
    Bootstrap(BootstrapCommand),

    /// Credential encryption key management (ADR 0019 §4).
    Credential(CredentialCommand),

    /// Database management commands.
    Db(DbCommand),

    /// Distributed storage management.
    Storage(StorageCommand),
}

#[async_trait]
pub trait PerformAction {
    async fn take_action(self, config: &Config) -> Result<(), Report>;
}

#[allow(clippy::print_stdout)]
#[tokio::main]
async fn main() -> Result<(), Report> {
    let args = Args::parse();
    let cfg = Config::load_all(args.config)?;
    match args.command {
        Command::Bootstrap(x) => x.take_action(&cfg).await?,
        Command::Credential(x) => x.take_action(&cfg).await?,
        Command::Db(x) => x.take_action(&cfg).await?,
        Command::Storage(x) => x.take_action(&cfg).await?,
    }
    Ok(())
}
