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
//! Test SPIFFE mTLS connectivity to the Raft gRPC layer.
//!
//! This test runs inside a Kubernetes pod with the SPIFFE CSI workload API
//! mounted. It performs three checks:
//!
//! 1. Fetches an SVID from the SPIFFE workload API and prints the SPIFFE ID
//!    (proves the SPIRE agent is reachable and the SpiffeID CRD matched).
//! 2. Builds a SPIFFE gRPC channel to the Raft port of `keystone-rs-0` and
//!    calls the `Metrics` RPC (proves SPIFFE client→server mTLS handshake).
//! 3. Reads the cluster membership from the `Metrics` response and prints peer
//!    count (proves the SPIFFE IDs of both peers passed validation).
//! 4. Verifies that connections without valid SPIFFE IDs are rejected.

use eyre::{Result, eyre};
use spiffe::X509Source;

use openstack_keystone_distributed_storage::network::get_spiffe_grpc_channel;

const RAFT_GRPC_ENDPOINT: &str =
    "http://keystone-rs-0.keystone-rs-internal.default.svc.cluster.local:8300";

/// Fetch the workload SVID via the SPIFFE workload API and print the SPIFFE ID.
async fn verify_spiffe_svid() -> Result<()> {
    tracing::info!("Fetching SVID from SPIFFE workload API...");
    let source = X509Source::new()
        .await
        .map_err(|e| eyre!("SPIFFE X509Source init failed: {e}"))?;

    let svid = source
        .svid()
        .map_err(|e| eyre!("Failed to get SVID: {e}"))?;

    tracing::info!("SPIFFE SVID ID: {}", svid.spiffe_id());
    Ok(())
}

/// Build a SPIFFE gRPC channel and call the `Metrics` RPC on the Raft port.
async fn verify_raft_grpc(trust_domains: &[String]) -> Result<()> {
    tracing::info!(
        "Connecting to Raft gRPC via SPIFFE mTLS (trust domains: {:?})...",
        trust_domains
    );

    let grpc_url = RAFT_GRPC_ENDPOINT
        .parse()
        .map_err(|e| eyre!("invalid URI: {e}"))?;
    let channel = get_spiffe_grpc_channel(grpc_url, trust_domains)
        .await
        .map_err(|e| {
            tracing::error!("SPIFFE gRPC channel creation failed: {e}");
            eyre!("SPIFFE Raft gRPC connect failed: {e}")
        })?;

    let mut client =
        openstack_keystone_distributed_storage::protobuf::raft::cluster_admin_service_client::ClusterAdminServiceClient::new(channel);

    let response = client.metrics(()).await.map_err(|e| {
        tracing::error!("Metrics RPC failed: {e:?}");
        eyre!("Metrics RPC call failed: {e}")
    })?;

    let metrics = response.into_inner();

    let membership = metrics
        .membership
        .ok_or_else(|| eyre!("no membership in Metrics response"))?;

    let peer_count = membership.nodes.len();
    tracing::info!(
        peer_count,
        leader = ?metrics.current_leader,
        "Raft Metrics RPC succeeded"
    );

    if peer_count == 0 {
        return Err(eyre!(
            "Raft cluster membership reports 0 nodes — is the cluster initialized?"
        ));
    }

    Ok(())
}

/// Verify that a plain (non-SPIFFE) connection to the Raft port is rejected.
async fn verify_plain_tls_rejected() -> Result<()> {
    tracing::info!("Verifying that plain/non-SPIFFE connections are rejected...");

    let channel: tonic::transport::Channel =
        tonic::transport::Endpoint::try_from(RAFT_GRPC_ENDPOINT)
            .map_err(|e| eyre!("invalid URI: {e}"))?
            .connect()
            .await
            .map_err(|e| {
                tracing::info!("Plain HTTP connect failed (expected): {e}");
                eyre!("Plain connect failed as expected: {e}")
            })?;

    let mut client =
        openstack_keystone_distributed_storage::protobuf::raft::cluster_admin_service_client::ClusterAdminServiceClient::new(channel);

    let result = client.metrics(()).await;

    match result {
        Err(e) => {
            tracing::info!("Plain connection rejected (expected): code={}", e.code());
            assert!(
                matches!(
                    e.code(),
                    tonic::Code::InvalidArgument
                        | tonic::Code::Internal
                        | tonic::Code::Unauthenticated
                        | tonic::Code::PermissionDenied
                ),
                "non-SPIFFE connection should be rejected, got: {}",
                e.code()
            );
            Ok(())
        }
        Ok(_) => Err(eyre!(
            "Plain connection was NOT rejected — SPIFFE mTLS enforcement broken"
        )),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,spiffe=info")),
        )
        .with_writer(std::io::stdout)
        .init();

    let trust_domains = std::env::var("OS_DISTRIBUTED_STORAGE__TRUST_DOMAINS")
        .unwrap_or_else(|_| "example.org".to_string())
        .split(',')
        .map(String::from)
        .collect::<Vec<_>>();

    tracing::info!("=== SPIFFE Raft Network Test ===");
    tracing::info!("Trust domains: {:?}", trust_domains);

    verify_spiffe_svid().await?;
    tracing::info!("✓ SVID fetched successfully");

    verify_raft_grpc(&trust_domains).await?;
    tracing::info!("✓ Raft Metrics via SPIFFE gRPC succeeded");

    verify_plain_tls_rejected().await?;
    tracing::info!("✓ Plain connection correctly rejected");

    tracing::info!("=== All tests passed ✓ ===");
    Ok(())
}
