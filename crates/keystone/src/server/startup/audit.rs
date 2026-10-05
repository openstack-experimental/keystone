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

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use color_eyre::eyre::{Report, Result, WrapErr};
use tokio::spawn;
use tokio::task::{JoinHandle, spawn_blocking};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::AuditSinkConfig;
use crate::config::Config;
use cadf::spool::{SpoolLock, run_spool_writer, seal_previous_spool, verify_sealed_spool};
use cadf::{
    AuditDispatcher, AuditSink, HmacKeyring, ShipperConfig, SpoolConfig, StdoutSink,
    run_raw_segment_shipper, run_segment_shipper,
};

/// How often the running server checks the keyring file for a rotation made
/// by `keystone-manage audit rotate-hmac-key`.
const KEY_RELOAD_INTERVAL: Duration = Duration::from_secs(30);

/// Switch the dispatcher to a newer key version when the keyring file on disk
/// has one, until `shutdown` resolves. Rotation only ever adds versions, so
/// events signed before the switch stay verifiable.
async fn run_key_reloader(
    dispatcher: Arc<AuditDispatcher>,
    kek_path: PathBuf,
    node_id: String,
    mut active_version: u64,
    reload_interval: Duration,
    shutdown: impl Future<Output = ()>,
) {
    let mut tick = tokio::time::interval(reload_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return,
            _ = tick.tick() => {}
        }
        let path = kek_path.clone();
        let loaded = spawn_blocking(move || HmacKeyring::load(&path)).await;
        match loaded {
            Ok(Ok(Some(keyring))) if keyring.current_version() > active_version => {
                let version = keyring.current_version();
                dispatcher.refresh_hmac_key(
                    Arc::from(keyring.current_node_key(&node_id).as_slice()),
                    version,
                );
                info!(
                    from = active_version,
                    to = version,
                    "rotated audit HMAC signing key"
                );
                active_version = version;
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                warn!(%error, "failed to reload the audit HMAC keyring; keeping the current key");
            }
            Err(error) => warn!(%error, "audit HMAC keyring reload task failed"),
        }
    }
}

/// Resolve `path` to an absolute form with symlinks and `..` removed, for a
/// containment check. The longest existing ancestor is canonicalized and the
/// not yet existing remainder (a key file about to be created) is appended
/// lexically, so `spool/../key`, `/link/key` and a missing file all compare
/// correctly.
fn resolve_path(path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut remainder = Vec::new();
    let mut existing = absolute.as_path();
    loop {
        match existing.canonicalize() {
            Ok(mut resolved) => {
                // The remainder does not exist, so `..` in it can only be
                // resolved lexically.
                for part in remainder.iter().rev() {
                    if *part == std::ffi::OsStr::new("..") {
                        resolved.pop();
                    } else if *part != "." {
                        resolved.push(part);
                    }
                }
                return Ok(resolved);
            }
            Err(_) => match (existing.parent(), existing.file_name()) {
                (Some(parent), Some(name)) => {
                    remainder.push(name);
                    existing = parent;
                }
                // `file_name` is `None` for a trailing `..`.
                (Some(parent), None) => {
                    remainder.push(std::ffi::OsStr::new(".."));
                    existing = parent;
                }
                _ => return Ok(absolute),
            },
        }
    }
}

/// Refuse a key file inside the spool directory and warn when the legacy
/// default location is in use.
///
/// Whoever can write the spool must not also be able to read the key that
/// signs it, otherwise they could tamper with the records and re-sign them.
fn check_kek_location(cfg: &openstack_keystone_config::AuditConfig) -> Result<(), Report> {
    let Some(explicit) = &cfg.hmac_kek_file else {
        warn!(
            path = %cfg.hmac_kek_path().display(),
            "audit HMAC key is stored inside spool_dir; set `[audit] hmac_kek_file` to a \
             location that spool writers cannot read"
        );
        return Ok(());
    };
    let key = resolve_path(explicit).wrap_err("cannot resolve [audit] hmac_kek_file")?;
    let spool = resolve_path(&cfg.spool_dir).wrap_err("cannot resolve [audit] spool_dir")?;
    if key.starts_with(&spool) {
        return Err(eyre::eyre!(
            "[audit] hmac_kek_file {} must not be inside spool_dir {}",
            key.display(),
            spool.display()
        ));
    }
    Ok(())
}

/// Build the syslog sink from its `[audit] sink` options.
#[cfg(feature = "audit-syslog")]
fn build_syslog_sink(
    endpoint: String,
    tls: bool,
    ca_file: Option<std::path::PathBuf>,
    app_name: String,
    connect_timeout_secs: u64,
    write_timeout_secs: u64,
    node_id: &str,
) -> Result<Arc<dyn AuditSink>, Report> {
    use cadf::{SyslogSink, SyslogSinkConfig};
    if !tls {
        warn!(
            "audit syslog sink {endpoint} runs without TLS: audit records cross the network \
             in clear text and can be read or altered in transit"
        );
    }
    let mut cfg = SyslogSinkConfig::new(endpoint, node_id);
    cfg.tls = tls;
    cfg.ca_file = ca_file;
    cfg.app_name = app_name;
    cfg.connect_timeout = Duration::from_secs(connect_timeout_secs);
    cfg.write_timeout = Duration::from_secs(write_timeout_secs);
    let sink = SyslogSink::new(cfg).wrap_err("invalid audit syslog sink configuration")?;
    Ok(Arc::new(sink))
}

/// Without the `audit-syslog` feature the sink is unavailable; refuse to
/// start rather than silently accumulating an unshipped spool.
#[cfg(not(feature = "audit-syslog"))]
fn build_syslog_sink(
    _endpoint: String,
    _tls: bool,
    _ca_file: Option<std::path::PathBuf>,
    _app_name: String,
    _connect_timeout_secs: u64,
    _write_timeout_secs: u64,
    _node_id: &str,
) -> Result<Arc<dyn AuditSink>, Report> {
    Err(eyre::eyre!(
        "[audit] sink type \"syslog\" requires Keystone to be built with the \
         `audit-syslog` feature"
    ))
}

/// Load or generate the persisted audit HMAC keyring, derive the per-node
/// signing key, build the `AuditDispatcher`, seal the
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
    audit_cfg.validate_node_id().map_err(|e| eyre::eyre!(e))?;
    let spool_dir = audit_cfg.spool_dir.clone();
    let node_id = audit_cfg.node_id.clone();
    let kek_path = audit_cfg.hmac_kek_path();
    check_kek_location(&audit_cfg)?;
    std::fs::create_dir_all(&spool_dir).wrap_err("failed to create audit spool directory")?;

    // Exclusive per-node spool lock for the process lifetime; fails fast if
    // another Keystone already owns this spool_dir/node_id.
    let spool_lock = SpoolLock::acquire(&spool_dir, node_id.as_str())
        .wrap_err("failed to lock the audit spool")?;

    // Seal the previous run's live spool BEFORE the writer starts, so the
    // writer begins on a fresh file and nothing reads a file being appended.
    let sealed = seal_previous_spool(&spool_dir, node_id.as_str())
        .wrap_err("failed to seal the previous audit spool")?;

    let keyring =
        HmacKeyring::load_or_create(&kek_path).wrap_err("failed to load the audit HMAC keyring")?;
    let hmac_key_version = keyring.current_version();

    // Per-node signing key:
    //   HKDF-Expand(KEK, info="keystone-audit-hmac-v1:{node_id}", L=32)
    // Per ADR 0023 / ADR 0016-v2 §3.1: per-node derivation ensures a
    // compromised node cannot forge records attributed to other nodes.
    let audit_hmac_key: Arc<[u8]> =
        Arc::from(keyring.current_node_key(node_id.as_str()).as_slice());

    let (audit_dispatcher, audit_receivers) = AuditDispatcher::with_capacities(
        node_id.as_str(),
        Uuid::new_v4().to_string(),
        Arc::clone(&audit_hmac_key),
        hmac_key_version,
        audit_cfg.perimeter_channel_capacity,
        audit_cfg.critical_channel_capacity,
    );

    // One writer drains both QoS channels. It owns the spool lock: it runs
    // until shutdown is requested or the dispatcher is dropped, so the lock
    // lives as long as the spool is in use.
    let spool_cfg = SpoolConfig {
        max_segment_bytes: audit_cfg.spool_max_segment_bytes,
        max_segment_age: Duration::from_secs(audit_cfg.spool_max_segment_age_secs),
        max_segments: audit_cfg.spool_max_segments,
        max_bytes: audit_cfg.spool_max_bytes,
        retention: audit_cfg.spool_retention_secs.map(Duration::from_secs),
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
        // Every key version in the keyring, so segments signed before a
        // rotation still verify.
        let key_store = keyring.key_store(node_id.as_str());
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
        AuditSinkConfig::Syslog {
            endpoint,
            tls,
            ca_file,
            app_name,
            connect_timeout_secs,
            write_timeout_secs,
        } => Some(build_syslog_sink(
            endpoint,
            tls,
            ca_file,
            app_name,
            connect_timeout_secs,
            write_timeout_secs,
            node_id.as_str(),
        )?),
    };
    // A zero interval or backoff would turn the shipper into a busy loop
    // against a failing sink, so each is raised to one second and the
    // ceiling never sits below the starting backoff.
    let initial_backoff = Duration::from_secs(audit_cfg.shipper_initial_backoff_secs.max(1));
    let shipper_cfg = ShipperConfig {
        batch_size: audit_cfg.shipper_batch_size.max(1),
        poll_interval: Duration::from_secs(audit_cfg.shipper_poll_interval_secs.max(1)),
        initial_backoff,
        max_backoff: Duration::from_secs(audit_cfg.shipper_max_backoff_secs).max(initial_backoff),
        metrics: Arc::clone(audit_dispatcher.metrics()),
    };
    // The raft storage layer keeps its own signed audit spool (ADR 0016-v2
    // §3.1) with a different key hierarchy and record shape. Its sealed
    // segments are shipped verbatim through the same sink, so one sink
    // configuration covers both producers.
    let raft_shipper = sink
        .clone()
        .zip(cfg.distributed_storage.as_ref())
        .map(|(sink, ds)| {
            let dir = ds
                .audit_spool_dir
                .clone()
                .unwrap_or_else(|| ds.path.join("audit-spool"));
            run_raw_segment_shipper(
                dir,
                format!("raft-audit-{}.jsonl.seg-", ds.node_id),
                "raft-audit".to_string(),
                sink,
                shipper_cfg.clone(),
                token.clone().cancelled_owned(),
            )
        });
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
            shipper_cfg,
            shipper_bytes,
            shipper_shutdown,
        )
        .await;
    };

    // The writer and shipper share one task that owns the spool lock, so the
    // lock lives until both have stopped.
    let reloader = run_key_reloader(
        Arc::clone(&audit_dispatcher),
        kek_path,
        node_id.clone(),
        hmac_key_version,
        KEY_RELOAD_INTERVAL,
        token.clone().cancelled_owned(),
    );
    let writer = spawn(async move {
        let _spool_lock = spool_lock;
        tokio::join!(
            reloader,
            async move {
                if let Some(raft_shipper) = raft_shipper {
                    raft_shipper.await;
                }
            },
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
    use cadf::spool::{HmacKeyStore, spool_path};
    use cadf::{CadfEvent, CadfEventPayload, Initiator, Observer, Target};
    use std::path::PathBuf;

    fn test_config(spool_dir: PathBuf) -> Config {
        let mut cfg = Config::default();
        cfg.audit.spool_dir = spool_dir;
        cfg.audit.node_id = "test-node".into();
        cfg
    }

    #[test]
    fn kek_location_check_sees_through_dotdot_and_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let spool = tmp.path().join("spool");
        std::fs::create_dir_all(&spool).unwrap();
        let mut cfg = test_config(spool.clone());

        // `..` that lands back inside the spool.
        cfg.audit.hmac_kek_file = Some(tmp.path().join("other/../spool/key.bin"));
        assert!(check_kek_location(&cfg.audit).is_err());

        // A symlink pointing into the spool.
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&spool, &link).unwrap();
        cfg.audit.hmac_kek_file = Some(link.join("key.bin"));
        assert!(check_kek_location(&cfg.audit).is_err());

        // A sibling directory is fine, even if it does not exist yet.
        cfg.audit.hmac_kek_file = Some(tmp.path().join("keys/key.bin"));
        assert!(check_kek_location(&cfg.audit).is_ok());
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
        assert!(!generated.is_empty());

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
            Ok(_) => panic!("expected init_audit to reject a malformed key file"),
            Err(e) => assert!(
                format!("{e:#}").contains("neither a 32-byte legacy key"),
                "got: {e:#}"
            ),
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

    #[tokio::test]
    async fn init_rejects_unset_or_unsafe_node_id() {
        let tmp = tempfile::tempdir().unwrap();
        for bad in [openstack_keystone_config::UNKNOWN_NODE_ID, "../escape", ""] {
            let mut cfg = test_config(tmp.path().to_path_buf());
            cfg.audit.node_id = bad.to_string();
            let Err(err) = init(&cfg, &CancellationToken::new()).await else {
                panic!("node_id {bad:?} must be rejected");
            };
            assert!(format!("{err:#}").contains("node_id"), "got: {err:#}");
        }
    }

    #[tokio::test]
    async fn init_rejects_key_file_inside_spool_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = test_config(tmp.path().join("spool"));
        cfg.audit.hmac_kek_file = Some(tmp.path().join("spool").join("keys").join("k"));
        let Err(err) = init(&cfg, &CancellationToken::new()).await else {
            panic!("a key file inside spool_dir must be rejected");
        };
        assert!(
            format!("{err:#}").contains("must not be inside"),
            "got: {err:#}"
        );
    }

    #[tokio::test]
    async fn init_uses_configured_key_file_outside_spool() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = test_config(tmp.path().join("spool"));
        let key_file = tmp.path().join("keys").join("audit.keyring");
        cfg.audit.hmac_kek_file = Some(key_file.clone());
        let (_dispatcher, writer) = init(&cfg, &CancellationToken::new()).await.unwrap();
        assert!(key_file.exists());
        assert!(!tmp.path().join("spool").join("hmac-key.bin").exists());
        drop(writer);
    }

    /// A rotation done out of process (`keystone-manage audit
    /// rotate-hmac-key`) must start signing with the new key version, while
    /// the previous version stays resolvable for verification.
    #[tokio::test]
    async fn running_server_switches_to_a_rotated_key() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.keyring");
        let keyring = HmacKeyring::load_or_create(&path).unwrap();
        let key: Arc<[u8]> = Arc::from(keyring.current_node_key("test-node").as_slice());
        let (dispatcher, _rx) = AuditDispatcher::new(
            "test-node",
            Uuid::new_v4().to_string(),
            key,
            keyring.current_version(),
        );

        let token = CancellationToken::new();
        let reloader = tokio::spawn(run_key_reloader(
            Arc::clone(&dispatcher),
            path.clone(),
            "test-node".to_string(),
            keyring.current_version(),
            Duration::from_millis(20),
            token.clone().cancelled_owned(),
        ));

        assert_eq!(test_event(&dispatcher).payload().hmac_key_version(), 1);
        assert_eq!(HmacKeyring::rotate(&path).unwrap(), 2);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let event = test_event(&dispatcher);
        assert_eq!(event.payload().hmac_key_version(), 2);
        let rotated = HmacKeyring::load(&path).unwrap().unwrap();
        let store = rotated.key_store("test-node");
        let key = store.get_key(2).unwrap();
        assert!(dispatcher.verify_hmac(&event, &key));

        token.cancel();
        reloader.await.unwrap();
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
        cfg.distributed_storage =
            Some(openstack_keystone_config::DistributedStorageConfiguration {
                node_id: 7,
                audit_spool_dir: Some(raft_spool.clone()),
                ..Default::default()
            });
        let token = CancellationToken::new();
        let (_dispatcher, writer) = init(&cfg, &token).await.unwrap();

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
