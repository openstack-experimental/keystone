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
use tonic::transport::{Channel, Uri};

use openstack_keystone_config::{Config, RaftTlsConfiguration};
use openstack_keystone_distributed_storage::{
    network::{get_client_tls_config, get_spiffe_grpc_channel},
    protobuf::raft::cluster_admin_service_client::ClusterAdminServiceClient,
};

mod backup;
mod clear_quarantine;
mod confirm_rotate_dek;
mod demote;
mod init;
mod join;
mod list_dek_local_emergency_candidates;
mod list_peers;
mod metrics;
mod promote;
mod reconcile_dek_local_emergency;
mod remove_peer;
mod restore;
mod rotate_dek;

use crate::PerformAction;
use crate::storage::backup::BackupCommand;
use crate::storage::clear_quarantine::ClearQuarantineCommand;
use crate::storage::confirm_rotate_dek::ConfirmRotateDekCommand;
use crate::storage::demote::DemoteCommand;
use crate::storage::init::InitCommand;
use crate::storage::join::JoinCommand;
use crate::storage::list_dek_local_emergency_candidates::ListDekLocalEmergencyCandidatesCommand;
use crate::storage::list_peers::ListPeersCommand;
use crate::storage::metrics::MetricsCommand;
use crate::storage::promote::PromoteCommand;
use crate::storage::reconcile_dek_local_emergency::ReconcileDekLocalEmergencyCommand;
use crate::storage::remove_peer::RemovePeerCommand;
use crate::storage::restore::RestoreCommand;
use crate::storage::rotate_dek::RotateDekCommand;

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
            StorageCommands::Backup(e) => e.take_action(config).await,
            StorageCommands::ClearQuarantine(e) => e.take_action(config).await,
            StorageCommands::ConfirmRotateDek(e) => e.take_action(config).await,
            StorageCommands::Demote(e) => e.take_action(config).await,
            StorageCommands::Init(e) => e.take_action(config).await,
            StorageCommands::Join(e) => e.take_action(config).await,
            StorageCommands::ListPeers(e) => e.take_action(config).await,
            StorageCommands::Metrics(e) => e.take_action(config).await,
            StorageCommands::Promote(e) => e.take_action(config).await,
            StorageCommands::RemovePeer(e) => e.take_action(config).await,
            StorageCommands::Restore(e) => e.take_action(config).await,
            StorageCommands::RotateDek(e) => e.take_action(config).await,
            StorageCommands::ListDekLocalEmergencyCandidates(e) => e.take_action(config).await,
            StorageCommands::ReconcileDekLocalEmergency(e) => e.take_action(config).await,
        }
    }
}

#[derive(Subcommand)]
enum StorageCommands {
    Backup(BackupCommand),
    ClearQuarantine(ClearQuarantineCommand),
    ConfirmRotateDek(ConfirmRotateDekCommand),
    Demote(DemoteCommand),
    Init(InitCommand),
    Join(JoinCommand),
    ListPeers(ListPeersCommand),
    Metrics(MetricsCommand),
    Promote(PromoteCommand),
    RemovePeer(RemovePeerCommand),
    Restore(RestoreCommand),
    RotateDek(RotateDekCommand),
    ListDekLocalEmergencyCandidates(ListDekLocalEmergencyCandidatesCommand),
    ReconcileDekLocalEmergency(ReconcileDekLocalEmergencyCommand),
}

async fn get_grpc_client(
    cfg: &Config,
    addr: Option<Uri>,
) -> Result<ClusterAdminServiceClient<Channel>, Report> {
    let ds = cfg
        .distributed_storage
        .as_ref()
        .ok_or_eyre("distributed storage configuration missing")?;

    let target_addr = addr.unwrap_or_else(|| ds.node_cluster_addr.clone());

    let channel = match &ds.tls_configuration {
        RaftTlsConfiguration::Spiffe(spiffe_cfg) => {
            get_spiffe_grpc_channel(target_addr, &spiffe_cfg.trust_domains).await?
        }
        RaftTlsConfiguration::Tls(_) => {
            let tls_config = get_client_tls_config(cfg)?;
            Channel::builder(target_addr)
                .tls_config(tls_config)?
                .connect()
                .await?
        }
    };

    Ok(ClusterAdminServiceClient::new(channel))
}
