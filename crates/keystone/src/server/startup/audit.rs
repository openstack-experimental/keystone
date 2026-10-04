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

//! Audit dispatcher bootstrap (ADR 0023 / ADR 0016-v2 §3.1): KEK
//! load-or-generate, per-node key derivation, spool replay, spool writers.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use color_eyre::eyre::{Report, Result, WrapErr};
use secrecy::{ExposeSecret, SecretBox};
use tokio::spawn;
use tokio::task::{JoinHandle, spawn_blocking};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::AuditSinkConfig;
use crate::config::Config;
use openstack_keystone_audit::spool::{
    SpoolLock, run_spool_writer, seal_previous_spool, verify_sealed_spool,
};
use openstack_keystone_audit::{
    AuditDispatcher, AuditSink, HmacKeyStore, ShipperConfig, SpoolConfig, StdoutSink,
    derive_audit_hmac_key, run_segment_shipper,
};

/// Version tag stamped on audit HMAC keys (ADR 0023 / ADR 0016-v2 §3.1).
const AUDIT_HMAC_KEY_VERSION: u64 = 1;

/// `MultiKeyStore` holds every key version seen during this process lifetime.
///
/// Currently only one version exists; the map is pre-populated with the
/// current key so `verify_sealed_spool` can verify events signed by it. When
/// key rotation is implemented, callers MUST insert the new version before
/// calling `refresh_hmac_key` on the dispatcher — spool events written
/// before the rotation still carry the old version number and must remain
/// verifiable during the drain window (ADR 0023 §"Key Rotation").
struct MultiKeyStore(HashMap<u64, Arc<[u8]>>);

impl HmacKeyStore for MultiKeyStore {
    fn get_key(&self, version: u64) -> Option<Arc<[u8]>> {
        self.0.get(&version).map(Arc::clone)
    }
}

/// Load the persisted 32-byte key-encryption-key (KEK) from `kek_file`, or
/// generate one from `/dev/urandom` and persist it atomically with `0600`
/// permissions if the file does not exist.
///
/// The KEK is not the HMAC signing key — a per-node key is derived from it
/// via HKDF-Expand (see [`derive_audit_hmac_key`]). Persisting the KEK lets a
/// restart re-derive the same per-node key and replay the spool.
///
/// The returned `SecretBox` zeroizes the bytes on drop.
fn load_or_generate_kek(kek_file: &Path) -> Result<SecretBox<Vec<u8>>, Report> {
    let bytes = match std::fs::read(kek_file) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                return Err(eyre::eyre!(
                    "audit KEK at {} is {} bytes — expected 32; \
                     delete the file to regenerate",
                    kek_file.display(),
                    bytes.len()
                ));
            }
            bytes
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use std::fs::OpenOptions;
            use std::io::{Read as _, Write as _};
            use std::os::unix::fs::OpenOptionsExt;
            let mut raw = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut raw))
                .wrap_err("failed to generate audit KEK from /dev/urandom")?;
            // Write to a temp file with restricted permissions, then
            // atomically rename. Avoids both a world-readable key file and a
            // TOCTOU window where two processes each generate independent keys.
            let tmp_path = kek_file.with_extension("tmp");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
                .wrap_err("failed to create temporary audit KEK file")?;
            file.write_all(&raw).wrap_err("failed to write audit KEK")?;
            std::fs::rename(&tmp_path, kek_file).wrap_err("failed to finalize audit KEK file")?;
            info!(path = %kek_file.display(), "generated new audit KEK");
            raw.to_vec()
        }
        Err(e) => {
            return Err(e).wrap_err("failed to read audit KEK; fix permissions or delete the file");
        }
    };
    Ok(SecretBox::new(Box::new(bytes)))
}

/// Load or generate the persisted audit HMAC key-encryption-key (KEK),
/// derive the per-node signing key, build the `AuditDispatcher`, seal the
/// spool left by the previous run, spawn the single spool writer, and verify
/// the sealed spool in the background. See ADR 0023 / ADR 0016-v2 §3.1.
///
/// With `[audit] enabled = false` nothing is created on disk: a
/// [`AuditDispatcher::disabled`] dispatcher is returned together with no
/// writer handle.
///
/// Cancelling `token` makes the writer drain already-queued events (bounded
/// by `[audit] spool_drain_timeout_secs`) and exit; the returned handle
/// resolves once it has, and the spool lock is released.
pub async fn init(
    cfg: &Config,
    token: &CancellationToken,
) -> Result<(Arc<AuditDispatcher>, Option<JoinHandle<()>>), Report> {
    let audit_cfg = cfg.audit.clone();
    if !audit_cfg.enabled {
        warn!("audit framework is disabled ([audit] enabled = false): audit events are discarded");
        return Ok((AuditDispatcher::disabled(audit_cfg.node_id.as_str()), None));
    }
    let spool_dir = audit_cfg.spool_dir.clone();
    let node_id = audit_cfg.node_id.clone();
    std::fs::create_dir_all(&spool_dir).wrap_err("failed to create audit spool directory")?;

    // Exclusive per-node spool lock for the process lifetime; fails fast if
    // another Keystone already owns this spool_dir/node_id.
    let spool_lock = SpoolLock::acquire(&spool_dir, node_id.as_str())
        .wrap_err("failed to lock the audit spool")?;

    // Seal the previous run's live spool BEFORE the writer starts, so the
    // writer begins on a fresh file and nothing reads a file being appended.
    let sealed = seal_previous_spool(&spool_dir, node_id.as_str())
        .wrap_err("failed to seal the previous audit spool")?;

    let audit_kek = load_or_generate_kek(&spool_dir.join("hmac-key.bin"))?;

    // Derive the per-node signing key:
    //   HKDF-Expand(KEK, info="keystone-audit-hmac-v1:{node_id}", L=32)
    // Per ADR 0023 / ADR 0016-v2 §3.1: per-node derivation ensures a
    // compromised node cannot forge records attributed to other nodes.
    let audit_hmac_key: Arc<[u8]> =
        Arc::from(derive_audit_hmac_key(audit_kek.expose_secret(), node_id.as_str()).as_slice());

    let (audit_dispatcher, audit_receivers) = AuditDispatcher::new(
        node_id.as_str(),
        Uuid::new_v4().to_string(),
        Arc::clone(&audit_hmac_key),
        AUDIT_HMAC_KEY_VERSION,
    );

    // One writer drains both QoS channels. It owns the spool lock: it runs
    // until shutdown is requested or the dispatcher is dropped, so the lock
    // lives as long as the spool is in use.
    let spool_cfg = SpoolConfig {
        max_segment_bytes: audit_cfg.spool_max_segment_bytes,
        max_segment_age: Duration::from_secs(audit_cfg.spool_max_segment_age_secs),
        max_segments: audit_cfg.spool_max_segments,
        drain_timeout: Duration::from_secs(audit_cfg.spool_drain_timeout_secs),
        metrics: Arc::clone(audit_dispatcher.metrics()),
    };
    let spool_bytes = audit_dispatcher.spool_bytes_handle();
    let writer_dir = spool_dir.clone();
    let writer_node_id = node_id.clone();
    let shutdown = token.clone().cancelled_owned();

    // Verify the sealed segment at rest in the background: it can be large
    // and must not delay startup. Nothing is re-dispatched. The shipper only
    // starts once verification is done, so a tampered segment is quarantined
    // before a sink can see it.
    let verification = sealed.map(|segment| {
        let mut key_store = MultiKeyStore(HashMap::new());
        key_store
            .0
            .insert(AUDIT_HMAC_KEY_VERSION, Arc::clone(&audit_hmac_key));
        let dispatcher = Arc::clone(&audit_dispatcher);
        let node_id = node_id.clone();
        spawn_blocking(move || {
            if let Err(error) =
                verify_sealed_spool(&segment, node_id.as_str(), &dispatcher, &key_store)
            {
                warn!(%error, segment = %segment.display(), "audit spool verification failed");
            }
        })
    });

    let sink: Option<Arc<dyn AuditSink>> = match audit_cfg.sink {
        AuditSinkConfig::None => None,
        AuditSinkConfig::Stdout => Some(Arc::new(StdoutSink)),
    };
    let shipper_metrics = Arc::clone(audit_dispatcher.metrics());
    let shipper_bytes = Arc::clone(&spool_bytes);
    let shipper_dir = spool_dir.clone();
    let shipper_node_id = node_id.clone();
    let shipper_shutdown = token.clone().cancelled_owned();
    let shipper = async move {
        let Some(sink) = sink else {
            return;
        };
        if let Some(verification) = verification {
            let _ = verification.await;
        }
        run_segment_shipper(
            shipper_dir,
            shipper_node_id,
            sink,
            ShipperConfig {
                metrics: shipper_metrics,
                ..ShipperConfig::default()
            },
            shipper_bytes,
            shipper_shutdown,
        )
        .await;
    };

    // The writer and shipper share one task that owns the spool lock, so the
    // lock lives until both have stopped.
    let writer = spawn(async move {
        let _spool_lock = spool_lock;
        tokio::join!(
            run_spool_writer(
                audit_receivers.perimeter,
                audit_receivers.critical,
                writer_dir,
                writer_node_id,
                spool_cfg,
                spool_bytes,
                shutdown,
            ),
            shipper,
        );
    });

    Ok((audit_dispatcher, Some(writer)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_audit::spool::spool_path;
    use openstack_keystone_audit::{CadfEvent, CadfEventPayload, Initiator, Observer, Target};
    use std::path::PathBuf;

    fn test_config(spool_dir: PathBuf) -> Config {
        let mut cfg = Config::default();
        cfg.audit.spool_dir = spool_dir;
        cfg.audit.node_id = "test-node".into();
        cfg
    }

    #[tokio::test]
    async fn init_audit_generates_and_reuses_kek() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path().to_path_buf());

        let token = CancellationToken::new();
        let (dispatcher, writer) = init(&cfg, &token)
            .await
            .expect("first init generates a KEK");
        let kek_file = tmp.path().join("hmac-key.bin");
        let generated = std::fs::read(&kek_file).expect("KEK file was written");
        assert_eq!(generated.len(), 32);

        // The first init's writer holds the spool lock for as long as the
        // dispatcher lives, so a concurrent second init must be refused.
        let Err(err) = init(&cfg, &CancellationToken::new()).await else {
            panic!("spool is locked; second init must fail");
        };
        assert!(format!("{err:#}").contains("locked"), "got: {err:#}");

        // Once the first instance is shut down, a restart on the same
        // spool_dir must reuse the persisted KEK rather than silently
        // regenerating it (which would invalidate any spooled events signed
        // with the old key).
        token.cancel();
        writer
            .expect("writer is started when audit is enabled")
            .await
            .expect("writer exits on shutdown");
        drop(dispatcher);
        init(&cfg, &CancellationToken::new())
            .await
            .expect("restart after shutdown reuses the KEK");
        let reused = std::fs::read(&kek_file).unwrap();
        assert_eq!(generated, reused);
    }

    #[tokio::test]
    async fn init_audit_rejects_wrong_length_kek() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path().to_path_buf());
        std::fs::create_dir_all(&cfg.audit.spool_dir).unwrap();
        std::fs::write(cfg.audit.spool_dir.join("hmac-key.bin"), b"too-short").unwrap();

        match init(&cfg, &CancellationToken::new()).await {
            Ok(_) => panic!("expected init_audit to reject a wrong-length KEK"),
            Err(e) => assert!(e.to_string().contains("expected 32")),
        }
    }

    fn test_event(dispatcher: &AuditDispatcher) -> CadfEvent {
        CadfEventPayload::new(
            format!("{}:{}", dispatcher.node_id(), Uuid::new_v4()),
            "1.0".to_string(),
            Uuid::new_v4().to_string(),
            chrono::Utc::now().to_rfc3339(),
            "authenticate".to_string(),
            "success".to_string(),
            None,
            Initiator::new("unknown".to_string(), None, None, None),
            Target {
                id: "keystone".to_string(),
                type_uri: "service/security/keystone/auth".to_string(),
            },
            Observer {
                node_id: dispatcher.node_id().to_string(),
                id: format!("service/security/keystone/{}", dispatcher.node_id()),
            },
        )
        .sign(dispatcher)
    }

    /// Graceful shutdown must flush every queued event to the spool even
    /// though the dispatcher (and thus the channel senders) stays alive, as
    /// it does in the running server.
    #[tokio::test]
    async fn shutdown_flushes_queued_events_to_spool() {
        const PERIMETER: usize = 300;
        const CRITICAL: usize = 100;

        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path().to_path_buf());
        let token = CancellationToken::new();
        let (dispatcher, writer) = init(&cfg, &token).await.expect("init audit");

        for _ in 0..PERIMETER {
            dispatcher.dispatch(test_event(&dispatcher));
        }
        for _ in 0..CRITICAL {
            dispatcher
                .dispatch_critical(test_event(&dispatcher))
                .await
                .expect("critical channel is open");
        }

        token.cancel();
        super::super::shutdown::await_audit_writer(writer, &cfg).await;

        let spooled = std::fs::read_to_string(spool_path(tmp.path(), "test-node"))
            .expect("live spool exists")
            .lines()
            .count();
        assert_eq!(spooled, PERIMETER + CRITICAL);
        assert_eq!(dispatcher.dropped_count(), 0);
        // The writer released the spool lock, so a restart can take it.
        init(&cfg, &CancellationToken::new())
            .await
            .expect("spool lock released after shutdown");
    }

    /// With auditing disabled startup must not touch the spool directory, so
    /// an unwritable `spool_dir` is not an error and events are accepted.
    #[tokio::test]
    async fn init_disabled_skips_spool_and_accepts_events() {
        let tmp = tempfile::tempdir().unwrap();
        // A regular file where the directory should be: creating the spool
        // directory beneath it would fail.
        let blocker = tmp.path().join("not-a-dir");
        std::fs::write(&blocker, b"").unwrap();
        let mut cfg = test_config(blocker.join("audit"));
        cfg.audit.enabled = false;

        let (dispatcher, writer) = init(&cfg, &CancellationToken::new())
            .await
            .expect("disabled audit must not need a writable spool_dir");
        assert!(writer.is_none());
        assert!(!dispatcher.is_enabled());
        assert!(!cfg.audit.spool_dir.exists());
        dispatcher
            .dispatch_critical(test_event(&dispatcher))
            .await
            .expect("critical dispatch succeeds when disabled");
        dispatcher.dispatch(test_event(&dispatcher));

        // The same unwritable path fails when auditing is enabled.
        cfg.audit.enabled = true;
        assert!(init(&cfg, &CancellationToken::new()).await.is_err());
    }
}
