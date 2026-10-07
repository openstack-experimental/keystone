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

use std::collections::BTreeSet;
use std::future::Future;

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::{
    Report,
    eyre::{WrapErr, eyre},
};
use tonic::Status;
use tonic::transport::{Channel, Uri};

use openstack_keystone_config::LoadedConfig;
use openstack_keystone_distributed_storage::{
    app::{LEADER_ENDPOINT_HEADER, LEADER_ID_HEADER},
    config::{DistributedStorageConfiguration, RaftTlsConfiguration},
    network::{get_client_tls_config, get_spiffe_grpc_channel},
    protobuf::raft::{MetricsResponse, cluster_admin_service_client::ClusterAdminServiceClient},
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
mod status;

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
use crate::storage::status::StatusCommand;

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
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
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
            StorageCommands::Status(e) => e.take_action(config).await,
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
    Status(StatusCommand),
    ListDekLocalEmergencyCandidates(ListDekLocalEmergencyCandidatesCommand),
    ReconcileDekLocalEmergency(ReconcileDekLocalEmergencyCommand),
}

/// The `[distributed_storage]` section, when configured.
fn ds_config(cfg: &LoadedConfig) -> Option<&DistributedStorageConfiguration> {
    cfg.view().section::<DistributedStorageConfiguration>()
}

/// Connect to the cluster admin gRPC service.
///
/// With `as_node` the SPIFFE client presents the storage node's own SVID (the
/// `Node` role); otherwise it presents the workload's sole SVID, which is the
/// `storage-operator` identity on an operator workload.
async fn get_grpc_client(
    cfg: &LoadedConfig,
    addr: Option<Uri>,
    as_node: bool,
) -> Result<ClusterAdminServiceClient<Channel>, Report> {
    let ds = cfg
        .view()
        .require::<DistributedStorageConfiguration>()
        .wrap_err("distributed storage configuration missing")?;

    let target_addr = addr.unwrap_or_else(|| ds.node_cluster_addr.clone());

    let channel = match &ds.tls_configuration {
        RaftTlsConfiguration::Spiffe(spiffe_cfg) => {
            get_spiffe_grpc_channel(
                target_addr,
                &spiffe_cfg.trust_domains,
                as_node.then(|| spiffe_cfg.own_svid_path()).as_deref(),
            )
            .await?
        }
        RaftTlsConfiguration::Tls(_) => {
            let tls_config = get_client_tls_config(ds)?;
            Channel::builder(target_addr)
                .tls_config(tls_config)?
                .connect()
                .await?
        }
    };

    Ok(ClusterAdminServiceClient::new(channel))
}

/// Leader redirects a single command follows before giving up.
const MAX_LEADER_REDIRECTS: usize = 3;

/// The leader a non-leader pointed at, from the `Unavailable` + leader-hint
/// headers a node answers leader-only RPCs with.
///
/// Membership stores bare `host:port` addresses; `https://` is assumed when
/// the hint carries no scheme (the SPIFFE channel rewrites it to its own
/// transport either way).
fn leader_hint(status: &Status) -> Option<(u64, Uri)> {
    if status.code() != tonic::Code::Unavailable {
        return None;
    }
    let md = status.metadata();
    let addr = md.get(LEADER_ENDPOINT_HEADER)?.to_str().ok()?;
    let id = md.get(LEADER_ID_HEADER)?.to_str().ok()?.parse().ok()?;
    Some((id, node_uri(addr).ok()?))
}

/// Turns a final RPC failure into a report, explaining a leader redirect
/// that could not be followed.
fn rpc_error(status: Status) -> Report {
    match leader_hint(&status) {
        Some((id, uri)) => eyre!(
            "the contacted node is not the Raft leader; the leader is node {id} at {uri} \
             (retry with --cluster-addr {uri})"
        ),
        None if status.code() == tonic::Code::Unavailable => eyre!(
            "{}: no Raft leader is known right now (election in progress?); retry shortly",
            status.message()
        ),
        None => Report::new(status),
    }
}

/// Runs a leader-only RPC, starting at `addr` (default: this host's
/// `node_cluster_addr`) and following leader redirects.
///
/// `op` receives a fresh client per attempt and may be called again against
/// the leader, so it must rebuild its request each time.
async fn call_leader<T, F, Fut>(
    cfg: &LoadedConfig,
    addr: Option<Uri>,
    as_node: bool,
    mut op: F,
) -> Result<T, Report>
where
    F: FnMut(ClusterAdminServiceClient<Channel>) -> Fut,
    Fut: Future<Output = Result<T, Status>>,
{
    let mut target = addr;
    let mut redirects = 0;
    loop {
        let client = get_grpc_client(cfg, target.clone(), as_node).await?;
        match op(client).await {
            Ok(v) => return Ok(v),
            Err(status) => match leader_hint(&status) {
                Some((id, uri)) if redirects < MAX_LEADER_REDIRECTS => {
                    tracing::info!(leader_id = id, leader = %uri, "retrying against the Raft leader");
                    redirects += 1;
                    target = Some(uri);
                }
                _ => return Err(rpc_error(status)),
            },
        }
    }
}

/// Voter ids of a membership (union of a joint configuration's sets).
fn voters(metrics: &MetricsResponse) -> BTreeSet<u64> {
    metrics
        .membership
        .iter()
        .flat_map(|m| m.configs.iter())
        .flat_map(|set| set.node_ids.keys().copied())
        .collect()
}

/// Bare `host:port` (as stored in the membership) or full URI to a URI.
fn node_uri(addr: &str) -> Result<Uri, Report> {
    let uri = if addr.contains("://") {
        addr.parse()
    } else {
        format!("https://{addr}").parse()
    };
    uri.wrap_err_with(|| format!("invalid node address {addr:?}"))
}

/// Connects to the Raft leader, starting from `addr` (default: this host's
/// `node_cluster_addr`), and returns the client with the leader's own
/// metrics.
///
/// Membership commands compute the new voter set from the leader's view,
/// not from a possibly lagging follower's.
async fn connect_leader(
    cfg: &LoadedConfig,
    addr: Option<Uri>,
) -> Result<(ClusterAdminServiceClient<Channel>, MetricsResponse), Report> {
    let mut target = addr;
    let mut expected_leader = None;
    for _ in 0..=MAX_LEADER_REDIRECTS {
        let mut client = get_grpc_client(cfg, target.clone(), false).await?;
        let metrics = client.metrics(()).await.map_err(rpc_error)?.into_inner();
        let Some(leader) = metrics.current_leader else {
            return Err(eyre!(
                "no Raft leader is known right now (election in progress?); retry shortly"
            ));
        };
        if expected_leader == Some(leader) {
            return Ok((client, metrics));
        }
        let leader_addr = metrics
            .membership
            .as_ref()
            .and_then(|m| m.nodes.get(&leader))
            .map(|n| n.rpc_addr.clone())
            .ok_or_else(|| eyre!("leader node {leader} is missing from the membership"))?;
        expected_leader = Some(leader);
        target = Some(node_uri(&leader_addr)?);
    }
    Err(eyre!("the Raft leader kept changing; retry shortly"))
}

#[cfg(test)]
mod tests {
    use tonic::metadata::MetadataValue;

    use super::*;

    fn redirect(addr: &str, id: &str) -> Status {
        let mut status = Status::unavailable("not the leader; retry against the leader");
        status.metadata_mut().insert(
            LEADER_ENDPOINT_HEADER,
            MetadataValue::try_from(addr).unwrap(),
        );
        status
            .metadata_mut()
            .insert(LEADER_ID_HEADER, MetadataValue::try_from(id).unwrap());
        status
    }

    #[test]
    fn test_leader_hint_bare_addr_gets_https() {
        let (id, uri) = leader_hint(&redirect("node-1:8300", "1")).unwrap();
        assert_eq!(id, 1);
        assert_eq!(uri, "https://node-1:8300".parse::<Uri>().unwrap());
    }

    #[test]
    fn test_leader_hint_keeps_scheme() {
        let (_, uri) = leader_hint(&redirect("http://node-1:8300/", "1")).unwrap();
        assert_eq!(uri.scheme_str(), Some("http"));
    }

    #[test]
    fn test_leader_hint_requires_unavailable_and_headers() {
        assert!(leader_hint(&Status::unavailable("leader unknown")).is_none());
        let other = Status::with_metadata(
            tonic::Code::Internal,
            "boom",
            redirect("node-1:8300", "1").metadata().clone(),
        );
        assert!(leader_hint(&other).is_none());
        assert!(leader_hint(&redirect("node-1:8300", "not-a-number")).is_none());
    }

    #[test]
    fn test_rpc_error_names_leader() {
        let msg = rpc_error(redirect("node-1:8300", "1")).to_string();
        assert!(msg.contains("node 1"), "{msg}");
        assert!(msg.contains("https://node-1:8300"), "{msg}");
    }
}
