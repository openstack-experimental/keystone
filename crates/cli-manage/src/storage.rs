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
//! # Storage subcommand of the keystone-manage cli.

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::eyre::OptionExt;
use color_eyre::{Report, eyre::WrapErr};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use openstack_keystone_config::{Config, DistributedStorageConfiguration};
use openstack_keystone_distributed_storage::protobuf::raft::cluster_admin_service_client::ClusterAdminServiceClient;

mod demote;
mod init;
mod join;
mod list_peers;
mod promote;
mod remove_peer;

use crate::PerformAction;
use crate::storage::demote::DemoteCommand;
use crate::storage::init::InitCommand;
use crate::storage::join::JoinCommand;
use crate::storage::list_peers::ListPeersCommand;
use crate::storage::promote::PromoteCommand;
use crate::storage::remove_peer::RemovePeerCommand;

/// Distributed storage.
///
/// Built-in distributed storage backed by the RAFT consensus protocol and the
/// `fjall` KV database for the persistence.
#[derive(Parser)]
pub struct StorageCommand {
    #[command(subcommand)]
    command: StorageCommands,
}

#[async_trait]
impl PerformAction for StorageCommand {
    async fn take_action(self, config: &Config) -> Result<(), Report> {
        match self.command {
            StorageCommands::Demote(e) => e.take_action(config).await,
            StorageCommands::Init(e) => e.take_action(config).await,
            StorageCommands::Join(e) => e.take_action(config).await,
            StorageCommands::ListPeers(e) => e.take_action(config).await,
            StorageCommands::Promote(e) => e.take_action(config).await,
            StorageCommands::RemovePeer(e) => e.take_action(config).await,
        }
    }
}

#[derive(Subcommand)]
enum StorageCommands {
    Demote(DemoteCommand),
    Init(InitCommand),
    Join(JoinCommand),
    ListPeers(ListPeersCommand),
    Promote(PromoteCommand),
    RemovePeer(RemovePeerCommand),
}

pub async fn get_grpc_client_tls_config(
    cfg: &DistributedStorageConfiguration,
) -> Result<Option<ClientTlsConfig>, Report> {
    if !cfg.disable_tls {
        let tls_config = cfg
            .tls_configuration
            .as_ref()
            .ok_or_eyre("mTLS configuration missing")?;
        let identity = Identity::from_pem(
            std::fs::read_to_string(&tls_config.tls_cert_file)
                .wrap_err("reading client cert file")?,
            std::fs::read_to_string(&tls_config.tls_key_file)
                .wrap_err("reading client cert key file")?,
        );
        let mut config = ClientTlsConfig::new().identity(identity);
        if let Some(ca) = &tls_config.tls_client_ca_file {
            // ca for validation of the "server"
            config = config.ca_certificate(Certificate::from_pem(std::fs::read_to_string(&ca)?));
        }
        return Ok(Some(config));
    }
    Ok(None)
}

async fn get_grpc_client(
    cfg: &DistributedStorageConfiguration,
) -> Result<ClusterAdminServiceClient<Channel>, Report> {
    let channel = if let Some(tls_config) = get_grpc_client_tls_config(cfg).await? {
        Channel::builder(format!("https://{}", cfg.cluster_addr).parse()?).tls_config(tls_config)?
    } else {
        Channel::builder(format!("http://{}", cfg.cluster_addr).parse()?)
    };
    let client = ClusterAdminServiceClient::new(channel.connect().await?);
    Ok(client)
}
