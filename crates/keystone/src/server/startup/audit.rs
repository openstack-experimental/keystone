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

//! Audit dispatcher bootstrap (ADR 0023 / ADR 0016-v2 §3.1). The generic
//! machinery lives in [`cadf::runtime`]; this module supplies Keystone's
//! identity and wires the raft storage audit spool into the same sink.

use std::sync::Arc;

use color_eyre::eyre::{Report, Result};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use cadf::runtime::ExtraSegmentSource;
use cadf::{AuditDispatcher, ServiceIdentity};
use openstack_keystone_distributed_storage::config::DistributedStorageConfiguration;

/// Identity under which Keystone writes audit records: the HKDF label of the
/// per-node signing key and the `keystone_audit_*` metric prefix derive from
/// it, so it must not change without a key migration and alert-rule update.
pub const AUDIT_SERVICE: ServiceIdentity = ServiceIdentity::new("keystone");

/// Start the audit pipeline for Keystone.
///
/// The raft storage layer keeps its own signed audit spool (ADR 0016-v2
/// §3.1) with a different key hierarchy and record shape. Its sealed
/// segments are shipped verbatim through the same sink, so one sink
/// configuration covers both producers.
pub async fn init(
    cfg: &Config,
    ds: Option<&DistributedStorageConfiguration>,
    token: &CancellationToken,
) -> Result<(Arc<AuditDispatcher>, Option<JoinHandle<()>>), Report> {
    let extra_sources = ds
        .map(|ds| ExtraSegmentSource {
            dir: ds
                .audit_spool_dir
                .clone()
                .unwrap_or_else(|| ds.path.join("audit-spool")),
            file_prefix: format!("raft-audit-{}.jsonl.seg-", ds.node_id),
            source: "raft-audit".to_string(),
        })
        .into_iter()
        .collect();
    Ok(cadf::runtime::init(&AUDIT_SERVICE, &cfg.audit, extra_sources, token).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuditSinkConfig;
    use std::time::Duration;

    fn test_config(spool_dir: std::path::PathBuf) -> Config {
        let mut cfg = Config::default();
        cfg.audit.spool_dir = Some(spool_dir);
        cfg.audit.node_id = "test-node".into();
        cfg
    }

    /// The default spool and key locations still derive from Keystone's
    /// identity, so existing deployments keep finding their data.
    #[tokio::test]
    async fn init_writes_under_the_keystone_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path().to_path_buf());
        let token = CancellationToken::new();
        let (dispatcher, writer) = init(&cfg, None, &token).await.expect("init audit");
        assert!(cfg.audit.hmac_kek_path(&AUDIT_SERVICE).exists());
        token.cancel();
        super::super::shutdown::await_audit_writer(writer, &cfg).await;
        drop(dispatcher);
    }

    /// The raft storage audit spool is shipped through the same sink: a
    /// sealed `raft-audit-<node>` segment is delivered and removed, the live
    /// file is left alone.
    #[tokio::test]
    async fn raft_audit_segments_are_shipped_through_the_sink() {
        let tmp = tempfile::tempdir().unwrap();
        let raft_spool = tmp.path().join("raft-spool");
        std::fs::create_dir_all(&raft_spool).unwrap();
        let sealed = raft_spool.join("raft-audit-7.jsonl.seg-000001");
        std::fs::write(
            &sealed,
            "{\"record\":{},\"key_version\":1,\"hmac\":\"00\"}\n",
        )
        .unwrap();
        let live = raft_spool.join("raft-audit-7.jsonl");
        std::fs::write(&live, "{\"live\":true}\n").unwrap();

        let mut cfg = test_config(tmp.path().join("spool"));
        cfg.audit.sink = AuditSinkConfig::Stdout;
        cfg.audit.shipper_poll_interval_secs = 1;
        let ds = DistributedStorageConfiguration {
            node_id: 7,
            audit_spool_dir: Some(raft_spool.clone()),
            ..Default::default()
        };
        let token = CancellationToken::new();
        let (_dispatcher, writer) = init(&cfg, Some(&ds), &token).await.unwrap();

        for _ in 0..100 {
            if !sealed.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        token.cancel();
        super::super::shutdown::await_audit_writer(writer, &cfg).await;

        assert!(!sealed.exists(), "acknowledged segment is removed");
        assert!(live.exists(), "the live raft spool is never touched");
    }
}
