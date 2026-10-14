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
//! Opt-in stale local reads (ADR 0016-v2 §3).
//!
//! The scenario that tells a local read from a `ReadIndex` one: once the
//! other two voters are gone the survivor has no quorum, so a linearizable
//! read fails while a local read of Tier 0/1 data is still served.

use openstack_keystone_distributed_storage::ReadConsistency;
use openstack_keystone_distributed_storage::config::LocalReadsMode;

use super::harness::*;
use super::*;
use crate::common::make_sensitive_env;

const LOCAL_READ_ENABLED_PORT_BASE: u16 = 2300;
const LOCAL_READ_DISABLED_PORT_BASE: u16 = 2350;

/// Builds a three node cluster, writes one Internal and one Sensitive record
/// plus a prefix of each, waits until node 3 applied them and kills nodes 1
/// and 2, leaving node 3 without a quorum.
async fn quorumless_survivor(
    port: u16,
    mode: LocalReadsMode,
) -> Result<(Vec<RestartableNode>, std::sync::Arc<Storage>)> {
    let mut nodes = start_three_node_cluster_with(port, |config| {
        config.local_reads_mode = mode;
        // Keep a failing linearizable read from retrying for seconds.
        config.ensure_linearizable_retries = 2;
        config.ensure_linearizable_retry_delay_ms = 50;
    })
    .await?;

    let leader = nodes[0].storage().clone();
    set_value_retrying(&leader, "pub:a", "internal-a").await?;
    set_value_retrying(&leader, "pub:b", "internal-b").await?;
    leader
        .set_value(
            "sec:a".to_string(),
            make_sensitive_env("secret-a")?,
            None,
            None,
        )
        .await?;

    let index = leader
        .last_log_index()
        .ok_or_else(|| eyre::eyre!("leader must have a log"))?;
    let survivor = nodes[2].storage().clone();
    assert!(
        poll_until(Duration::from_millis(100), 300, || {
            survivor.last_log_index() >= Some(index)
        })
        .await,
        "node 3 did not apply the writes"
    );

    nodes[0].kill().await;
    nodes[1].kill().await;
    Ok((nodes, survivor))
}

/// With `local_reads_mode = "local_for_public"` a consumer can ask for a local
/// read of Tier 0/1 data and gets it without a quorum, while the default read
/// and Tier 2 data still require one.
#[serial_test::serial]
#[test]
fn test_local_read_serves_public_data_without_quorum() {
    TypeConfig::run(test_local_read_serves_public_data_without_quorum_inner()).unwrap();
}

async fn test_local_read_serves_public_data_without_quorum_inner() -> Result<()> {
    let (_nodes, survivor) =
        quorumless_survivor(LOCAL_READ_ENABLED_PORT_BASE, LocalReadsMode::LocalForPublic).await?;

    // The default stays linearizable: no quorum, no answer.
    assert!(survivor.get_by_key(b"pub:a", None).await.is_err());
    assert!(survivor.prefix(b"pub:", None).await.is_err());

    // Tier 1 point read and prefix scan are served locally.
    let got = survivor
        .get_by_key_with_consistency(b"pub:a", None, ReadConsistency::Local)
        .await?
        .ok_or_else(|| eyre::eyre!("local read lost pub:a"))?;
    assert_eq!("internal-a", got.try_deserialize::<String>()?.data);
    let scan = survivor
        .prefix_with_consistency(b"pub:", None, ReadConsistency::Local)
        .await?;
    assert_eq!(
        vec!["pub:a", "pub:b"],
        scan.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>()
    );
    // A key that is not there is just absent.
    assert!(
        survivor
            .get_by_key_with_consistency(b"pub:missing", None, ReadConsistency::Local)
            .await?
            .is_none()
    );

    // Tier 2 data is never served locally: the request falls back to
    // ReadIndex, which fails without a quorum.
    assert!(
        survivor
            .get_by_key_with_consistency(b"sec:a", None, ReadConsistency::Local)
            .await
            .is_err(),
        "a Sensitive record must not be served by a local read"
    );
    // One Sensitive record in the range sends the whole scan the same way.
    assert!(
        survivor
            .prefix_with_consistency(b"", None, ReadConsistency::Local)
            .await
            .is_err(),
        "a scan covering a Sensitive record must not be served locally"
    );
    Ok(())
}

/// With the default `local_reads_mode = "disabled"` a `Local` request is
/// ignored and every read stays linearizable.
#[serial_test::serial]
#[test]
fn test_local_read_ignored_when_disabled() {
    TypeConfig::run(test_local_read_ignored_when_disabled_inner()).unwrap();
}

async fn test_local_read_ignored_when_disabled_inner() -> Result<()> {
    let (_nodes, survivor) =
        quorumless_survivor(LOCAL_READ_DISABLED_PORT_BASE, LocalReadsMode::Disabled).await?;

    assert!(
        survivor
            .get_by_key_with_consistency(b"pub:a", None, ReadConsistency::Local)
            .await
            .is_err()
    );
    assert!(
        survivor
            .prefix_with_consistency(b"pub:", None, ReadConsistency::Local)
            .await
            .is_err()
    );
    Ok(())
}
