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
use color_eyre::{Report, eyre::OptionExt};
use secrecy::ExposeSecret;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Uri};

use openstack_keystone_config::Config;
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

/// Prepare the [ClientTlsConfig].
///
/// # Parameters
/// - `config`: The Keystone [`Config`] instance.
///
/// # Returns
/// A `Result` containing the `ClientTlsConfig`.
pub async fn get_grpc_client_tls_config(config: &Config) -> Result<ClientTlsConfig, Report> {
    let identity = Identity::from_pem(
        config
            .distributed_storage
            .as_ref()
            .and_then(|x| x.tls_configuration.tls_cert_content.as_ref())
            .or(config
                .listener
                .tls_configuration
                .as_ref()
                .and_then(|x| x.tls_cert_content.as_ref()))
            .ok_or_eyre("TLS cert file missing")?
            .expose_secret(),
        config
            .distributed_storage
            .as_ref()
            .and_then(|x| x.tls_configuration.tls_key_content.as_ref())
            .or(config
                .listener
                .tls_configuration
                .as_ref()
                .and_then(|x| x.tls_key_content.as_ref()))
            .ok_or_eyre("TLS key file missing")?
            .expose_secret(),
    );
    let mut tls_client_config = ClientTlsConfig::new().identity(identity);
    if let Some(cert_ca) = config
        .distributed_storage
        .as_ref()
        .and_then(|x| x.tls_configuration.tls_client_ca_content.as_ref())
        .or(config
            .listener
            .tls_configuration
            .as_ref()
            .and_then(|x| x.tls_client_ca_content.as_ref()))
    {
        tls_client_config =
            tls_client_config.ca_certificate(Certificate::from_pem(cert_ca.expose_secret()));
    };
    Ok(tls_client_config)
}

async fn get_grpc_client(
    cfg: &Config,
    addr: Option<Uri>,
) -> Result<ClusterAdminServiceClient<Channel>, Report> {
    let ep = Channel::builder(
        addr.unwrap_or(
            cfg.distributed_storage
                .as_ref()
                .ok_or_eyre("distributed storage configuration missing")?
                .cluster_addr
                .clone(),
        ),
    )
    .tls_config(get_grpc_client_tls_config(cfg).await?)?;
    let client = ClusterAdminServiceClient::new(ep.connect().await?);
    Ok(client)
}
