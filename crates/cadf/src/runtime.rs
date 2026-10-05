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
//! load-or-generate, per-node key derivation, spool sealing and replay
//! verification, the single spool writer, the sink shipper and the HMAC key
//! reloader.
//!
//! A service calls [`init`] once at startup with its [`ServiceIdentity`] and
//! its [`AuditConfig`] and gets back the [`AuditDispatcher`] to emit events
//! on, plus the handle of the background task that must be awaited on
//! shutdown.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::{JoinHandle, spawn_blocking};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

use crate::spool::{SpoolLock, run_spool_writer, seal_previous_spool, verify_sealed_spool};
use crate::{
    AuditConfig, AuditDispatcher, AuditSink, AuditSinkConfig, HmacKeyring, KeyringError,
    ServiceIdentity, SinkError, SpoolError, StdoutSink, run_raw_segment_shipper,
    run_segment_shipper,
};

/// How often the running service checks the keyring file for a rotation made
/// out of process (for example `keystone-manage audit rotate-hmac-key`).
pub const KEY_RELOAD_INTERVAL: Duration = Duration::from_secs(30);

/// Errors raised while bootstrapping the audit runtime.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The spool directory could not be created.
    #[error("failed to create audit spool directory")]
    CreateSpoolDir(#[source] std::io::Error),

    /// The signing key file is inside the spool directory.
    #[error("[audit] hmac_kek_file {key} must not be inside spool_dir {spool}")]
    KeyInsideSpool { key: PathBuf, spool: PathBuf },

    /// The HMAC keyring could not be loaded or created.
    #[error("failed to load the audit HMAC keyring")]
    Keyring(#[source] KeyringError),

    /// The per-node spool lock could not be taken.
    #[error("failed to lock the audit spool")]
    Lock(#[source] SpoolError),

    /// The configured `node_id` is unset or unsafe to use in file names.
    #[error("{0}")]
    NodeId(String),

    /// A path from the configuration could not be resolved.
    #[error("cannot resolve [audit] {option}")]
    ResolvePath {
        option: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// The spool left by the previous run could not be sealed.
    #[error("failed to seal the previous audit spool")]
    Seal(#[source] SpoolError),

    /// The configured sink could not be built.
    #[error("invalid audit syslog sink configuration")]
    Sink(#[source] SinkError),

    /// The configuration asks for a sink this build does not provide.
    #[error("[audit] sink type \"{0}\" requires the `{1}` feature")]
    SinkUnavailable(&'static str, &'static str),
}

/// A directory of sealed segments written by another producer in the same
/// process, shipped verbatim through the configured sink.
///
/// Keystone uses this for the raft storage audit spool (ADR 0016-v2 §3.1),
/// which has its own key hierarchy and record shape.
#[derive(Clone, Debug)]
pub struct ExtraSegmentSource {
    /// Directory holding the segments.
    pub dir: PathBuf,
    /// File name prefix of the sealed segments, up to the segment counter.
    pub file_prefix: String,
    /// Label identifying the producer in logs and metrics.
    pub source: String,
}

/// Running audit pipeline: the dispatcher to emit on and the task to await.
pub type AuditRuntime = (Arc<AuditDispatcher>, Option<JoinHandle<()>>);

/// Switch the dispatcher to a newer key version when the keyring file on disk
/// has one, until `shutdown` resolves. Rotation only ever adds versions, so
/// events signed before the switch stay verifiable.
pub async fn run_key_reloader(
    service: ServiceIdentity,
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
                    Arc::from(keyring.current_node_key(&service, &node_id).as_slice()),
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
fn resolve_path(path: &Path) -> std::io::Result<PathBuf> {
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
pub fn check_kek_location(
    service: &ServiceIdentity,
    cfg: &AuditConfig,
) -> Result<(), RuntimeError> {
    let Some(explicit) = &cfg.hmac_kek_file else {
        warn!(
            path = %cfg.hmac_kek_path(service).display(),
            "audit HMAC key is stored inside spool_dir; set `[audit] hmac_kek_file` to a \
             location that spool writers cannot read"
        );
        return Ok(());
    };
    let key = resolve_path(explicit).map_err(|source| RuntimeError::ResolvePath {
        option: "hmac_kek_file",
        source,
    })?;
    let spool =
        resolve_path(&cfg.spool_dir(service)).map_err(|source| RuntimeError::ResolvePath {
            option: "spool_dir",
            source,
        })?;
    if key.starts_with(&spool) {
        return Err(RuntimeError::KeyInsideSpool { key, spool });
    }
    Ok(())
}

/// Build the syslog sink from its `[audit] sink` options.
#[cfg(feature = "syslog")]
fn build_syslog_sink(
    service: &ServiceIdentity,
    sink: AuditSinkConfig,
    node_id: &str,
) -> Result<Arc<dyn AuditSink>, RuntimeError> {
    use crate::{SyslogSink, SyslogSinkConfig};
    let AuditSinkConfig::Syslog {
        endpoint,
        tls,
        ca_file,
        app_name,
        connect_timeout_secs,
        write_timeout_secs,
    } = sink
    else {
        return Err(RuntimeError::SinkUnavailable("syslog", "syslog"));
    };
    if !tls {
        warn!(
            "audit syslog sink {endpoint} runs without TLS: audit records cross the network \
             in clear text and can be read or altered in transit"
        );
    }
    let app_name = app_name.unwrap_or_else(|| service.name().to_string());
    let mut cfg = SyslogSinkConfig::new(endpoint, node_id, app_name);
    cfg.tls = tls;
    cfg.ca_file = ca_file;
    cfg.connect_timeout = Duration::from_secs(connect_timeout_secs);
    cfg.write_timeout = Duration::from_secs(write_timeout_secs);
    let sink = SyslogSink::new(cfg).map_err(RuntimeError::Sink)?;
    Ok(Arc::new(sink))
}

/// Without the `syslog` feature the sink is unavailable; refuse to start
/// rather than silently accumulating an unshipped spool.
#[cfg(not(feature = "syslog"))]
fn build_syslog_sink(
    _service: &ServiceIdentity,
    _sink: AuditSinkConfig,
    _node_id: &str,
) -> Result<Arc<dyn AuditSink>, RuntimeError> {
    Err(RuntimeError::SinkUnavailable("syslog", "syslog"))
}

/// Load or generate the persisted audit HMAC keyring, derive the per-node
/// signing key, build the `AuditDispatcher`, seal the spool left by the
/// previous run, spawn the single spool writer, and verify the sealed spool in
/// the background. See ADR 0023 / ADR 0016-v2 §3.1.
///
/// With `[audit] enabled = false` nothing is created on disk: a
/// [`AuditDispatcher::disabled`] dispatcher is returned together with no
/// writer handle.
///
/// `extra_sources` are sealed segments written by other producers in the same
/// process; they are shipped verbatim through the same sink.
///
/// Cancelling `token` makes the writer drain already-queued events (bounded
/// by `[audit] spool_drain_timeout_secs`) and exit; the returned handle
/// resolves once it has, and the spool lock is released.
pub async fn init(
    service: &ServiceIdentity,
    audit_cfg: &AuditConfig,
    extra_sources: Vec<ExtraSegmentSource>,
    token: &CancellationToken,
) -> Result<AuditRuntime, RuntimeError> {
    let service = *service;
    let audit_cfg = audit_cfg.clone();
    if !audit_cfg.enabled {
        warn!("audit framework is disabled ([audit] enabled = false): audit events are discarded");
        return Ok((AuditDispatcher::disabled(audit_cfg.node_id.as_str()), None));
    }
    audit_cfg.validate_node_id().map_err(RuntimeError::NodeId)?;
    let spool_dir = audit_cfg.spool_dir(&service);
    let node_id = audit_cfg.node_id.clone();
    let kek_path = audit_cfg.hmac_kek_path(&service);
    check_kek_location(&service, &audit_cfg)?;
    std::fs::create_dir_all(&spool_dir).map_err(RuntimeError::CreateSpoolDir)?;

    // Exclusive per-node spool lock for the process lifetime; fails fast if
    // another process already owns this spool_dir/node_id.
    let spool_lock =
        SpoolLock::acquire(&spool_dir, node_id.as_str()).map_err(RuntimeError::Lock)?;

    // Seal the previous run's live spool BEFORE the writer starts, so the
    // writer begins on a fresh file and nothing reads a file being appended.
    let sealed = seal_previous_spool(&spool_dir, node_id.as_str()).map_err(RuntimeError::Seal)?;

    let keyring = HmacKeyring::load_or_create(&kek_path).map_err(RuntimeError::Keyring)?;
    let hmac_key_version = keyring.current_version();

    // Per-node signing key:
    //   HKDF-Expand(KEK, info="{service}-audit-hmac-v1:{node_id}", L=32)
    // Per ADR 0023 / ADR 0016-v2 §3.1: per-node derivation ensures a
    // compromised node cannot forge records attributed to other nodes.
    let audit_hmac_key: Arc<[u8]> = Arc::from(
        keyring
            .current_node_key(&service, node_id.as_str())
            .as_slice(),
    );

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
    let spool_cfg = audit_cfg.spool_config(Arc::clone(audit_dispatcher.metrics()));
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
        let key_store = keyring.key_store(&service, node_id.as_str());
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

    let shipper_cfg = audit_cfg.shipper_config(Arc::clone(audit_dispatcher.metrics()));
    let sink: Option<Arc<dyn AuditSink>> = match audit_cfg.sink {
        AuditSinkConfig::None => None,
        AuditSinkConfig::Stdout => Some(Arc::new(StdoutSink)),
        syslog @ AuditSinkConfig::Syslog { .. } => {
            Some(build_syslog_sink(&service, syslog, node_id.as_str())?)
        }
    };
    let extra_shippers: Vec<_> = sink
        .iter()
        .flat_map(|sink| {
            extra_sources.iter().map(|extra| {
                run_raw_segment_shipper(
                    extra.dir.clone(),
                    extra.file_prefix.clone(),
                    extra.source.clone(),
                    Arc::clone(sink),
                    shipper_cfg.clone(),
                    token.clone().cancelled_owned(),
                )
            })
        })
        .collect();
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

    // The writer, shipper and reloader share one task that owns the spool
    // lock, so the lock lives until all of them have stopped.
    let reloader = run_key_reloader(
        service,
        Arc::clone(&audit_dispatcher),
        kek_path,
        node_id.clone(),
        hmac_key_version,
        KEY_RELOAD_INTERVAL,
        token.clone().cancelled_owned(),
    );
    let writer = tokio::spawn(async move {
        let _spool_lock = spool_lock;
        tokio::join!(
            reloader,
            futures_join_all(extra_shippers),
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

/// Drive every future to completion concurrently, without pulling in a
/// `futures` dependency for one call site.
async fn futures_join_all<F>(futures: Vec<F>)
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut set = tokio::task::JoinSet::new();
    for future in futures {
        set.spawn(future);
    }
    while set.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spool::{HmacKeyStore, spool_path};
    use crate::{CadfEvent, CadfEventPayload, Initiator, Observer, Target};

    const SERVICE: ServiceIdentity = ServiceIdentity::new("testsvc");

    fn test_config(spool_dir: PathBuf) -> AuditConfig {
        AuditConfig {
            spool_dir: Some(spool_dir),
            node_id: "test-node".into(),
            ..Default::default()
        }
    }

    async fn init_with(
        cfg: &AuditConfig,
        token: &CancellationToken,
    ) -> Result<AuditRuntime, RuntimeError> {
        init(&SERVICE, cfg, Vec::new(), token).await
    }

    /// Render an error with its whole source chain, like `{:#}` on a report.
    fn chain(error: &dyn std::error::Error) -> String {
        let mut out = error.to_string();
        let mut source = error.source();
        while let Some(inner) = source {
            out.push_str(": ");
            out.push_str(&inner.to_string());
            source = inner.source();
        }
        out
    }

    #[test]
    fn kek_location_check_sees_through_dotdot_and_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let spool = tmp.path().join("spool");
        std::fs::create_dir_all(&spool).unwrap();
        let mut cfg = test_config(spool.clone());

        // `..` that lands back inside the spool.
        cfg.hmac_kek_file = Some(tmp.path().join("other/../spool/key.bin"));
        assert!(check_kek_location(&SERVICE, &cfg).is_err());

        // A symlink pointing into the spool.
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&spool, &link).unwrap();
        cfg.hmac_kek_file = Some(link.join("key.bin"));
        assert!(check_kek_location(&SERVICE, &cfg).is_err());

        // A sibling directory is fine, even if it does not exist yet.
        cfg.hmac_kek_file = Some(tmp.path().join("keys/key.bin"));
        assert!(check_kek_location(&SERVICE, &cfg).is_ok());
    }

    #[tokio::test]
    async fn init_generates_and_reuses_kek() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path().to_path_buf());

        let token = CancellationToken::new();
        let (dispatcher, writer) = init_with(&cfg, &token)
            .await
            .expect("first init generates a KEK");
        let kek_file = tmp.path().join("hmac-key.bin");
        let generated = std::fs::read(&kek_file).expect("KEK file was written");
        assert!(!generated.is_empty());

        // The first init's writer holds the spool lock for as long as the
        // dispatcher lives, so a concurrent second init must be refused.
        let Err(err) = init_with(&cfg, &CancellationToken::new()).await else {
            panic!("spool is locked; second init must fail");
        };
        assert!(chain(&err).contains("locked"), "got: {}", chain(&err));

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
        init_with(&cfg, &CancellationToken::new())
            .await
            .expect("restart after shutdown reuses the KEK");
        let reused = std::fs::read(&kek_file).unwrap();
        assert_eq!(generated, reused);
    }

    #[tokio::test]
    async fn init_rejects_wrong_length_kek() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path().to_path_buf());
        std::fs::create_dir_all(cfg.spool_dir(&SERVICE)).unwrap();
        std::fs::write(cfg.spool_dir(&SERVICE).join("hmac-key.bin"), b"too-short").unwrap();

        match init_with(&cfg, &CancellationToken::new()).await {
            Ok(_) => panic!("expected init to reject a malformed key file"),
            Err(e) => assert!(
                chain(&e).contains("neither a 32-byte legacy key"),
                "got: {}",
                chain(&e)
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
                id: "testsvc".to_string(),
                type_uri: "service/security/testsvc/auth".to_string(),
            },
            Observer {
                node_id: dispatcher.node_id().to_string(),
                id: format!("service/security/testsvc/{}", dispatcher.node_id()),
            },
        )
        .sign(dispatcher)
    }

    /// Graceful shutdown must flush every queued event to the spool even
    /// though the dispatcher (and thus the channel senders) stays alive, as
    /// it does in a running service.
    #[tokio::test]
    async fn shutdown_flushes_queued_events_to_spool() {
        const PERIMETER: usize = 300;
        const CRITICAL: usize = 100;

        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path().to_path_buf());
        let token = CancellationToken::new();
        let (dispatcher, writer) = init_with(&cfg, &token).await.expect("init audit");

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
        writer
            .expect("writer is started")
            .await
            .expect("writer exits on shutdown");

        let spooled = std::fs::read_to_string(spool_path(tmp.path(), "test-node"))
            .expect("live spool exists")
            .lines()
            .count();
        assert_eq!(spooled, PERIMETER + CRITICAL);
        assert_eq!(dispatcher.dropped_count(), 0);
        // The writer released the spool lock, so a restart can take it.
        init_with(&cfg, &CancellationToken::new())
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
        cfg.enabled = false;

        let (dispatcher, writer) = init_with(&cfg, &CancellationToken::new())
            .await
            .expect("disabled audit must not need a writable spool_dir");
        assert!(writer.is_none());
        assert!(!dispatcher.is_enabled());
        assert!(!cfg.spool_dir(&SERVICE).exists());
        dispatcher
            .dispatch_critical(test_event(&dispatcher))
            .await
            .expect("critical dispatch succeeds when disabled");
        dispatcher.dispatch(test_event(&dispatcher));

        // The same unwritable path fails when auditing is enabled.
        cfg.enabled = true;
        assert!(init_with(&cfg, &CancellationToken::new()).await.is_err());
    }

    #[tokio::test]
    async fn init_rejects_unset_or_unsafe_node_id() {
        let tmp = tempfile::tempdir().unwrap();
        for bad in [crate::UNKNOWN_NODE_ID, "../escape", ""] {
            let mut cfg = test_config(tmp.path().to_path_buf());
            cfg.node_id = bad.to_string();
            let Err(err) = init_with(&cfg, &CancellationToken::new()).await else {
                panic!("node_id {bad:?} must be rejected");
            };
            assert!(chain(&err).contains("node_id"), "got: {}", chain(&err));
        }
    }

    #[tokio::test]
    async fn init_rejects_key_file_inside_spool_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = test_config(tmp.path().join("spool"));
        cfg.hmac_kek_file = Some(tmp.path().join("spool").join("keys").join("k"));
        let Err(err) = init_with(&cfg, &CancellationToken::new()).await else {
            panic!("a key file inside spool_dir must be rejected");
        };
        assert!(
            chain(&err).contains("must not be inside"),
            "got: {}",
            chain(&err)
        );
    }

    #[tokio::test]
    async fn init_uses_configured_key_file_outside_spool() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = test_config(tmp.path().join("spool"));
        let key_file = tmp.path().join("keys").join("audit.keyring");
        cfg.hmac_kek_file = Some(key_file.clone());
        let (_dispatcher, writer) = init_with(&cfg, &CancellationToken::new()).await.unwrap();
        assert!(key_file.exists());
        assert!(!tmp.path().join("spool").join("hmac-key.bin").exists());
        drop(writer);
    }

    /// A rotation done out of process must start signing with the new key
    /// version, while the previous version stays resolvable for verification.
    #[tokio::test]
    async fn running_service_switches_to_a_rotated_key() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.keyring");
        let keyring = HmacKeyring::load_or_create(&path).unwrap();
        let key: Arc<[u8]> = Arc::from(keyring.current_node_key(&SERVICE, "test-node").as_slice());
        let (dispatcher, _rx) = AuditDispatcher::new(
            "test-node",
            Uuid::new_v4().to_string(),
            key,
            keyring.current_version(),
        );

        let token = CancellationToken::new();
        let reloader = tokio::spawn(run_key_reloader(
            SERVICE,
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
        let store = rotated.key_store(&SERVICE, "test-node");
        let key = store.get_key(2).unwrap();
        assert!(dispatcher.verify_hmac(&event, &key));

        token.cancel();
        reloader.await.unwrap();
    }

    /// An extra producer's sealed segments are shipped through the same sink:
    /// a sealed segment is delivered and removed, the live file is left alone.
    #[tokio::test]
    async fn extra_segments_are_shipped_through_the_sink() {
        let tmp = tempfile::tempdir().unwrap();
        let extra_spool = tmp.path().join("extra-spool");
        std::fs::create_dir_all(&extra_spool).unwrap();
        let sealed = extra_spool.join("raft-audit-7.jsonl.seg-000001");
        std::fs::write(
            &sealed,
            "{\"record\":{},\"key_version\":1,\"hmac\":\"00\"}\n",
        )
        .unwrap();
        let live = extra_spool.join("raft-audit-7.jsonl");
        std::fs::write(&live, "{\"live\":true}\n").unwrap();

        let mut cfg = test_config(tmp.path().join("spool"));
        cfg.sink = AuditSinkConfig::Stdout;
        cfg.shipper_poll_interval_secs = 1;
        let token = CancellationToken::new();
        let extra = ExtraSegmentSource {
            dir: extra_spool.clone(),
            file_prefix: "raft-audit-7.jsonl.seg-".to_string(),
            source: "raft-audit".to_string(),
        };
        let (_dispatcher, writer) = init(&SERVICE, &cfg, vec![extra], &token).await.unwrap();

        for _ in 0..100 {
            if !sealed.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        token.cancel();
        writer.expect("writer is started").await.unwrap();

        assert!(!sealed.exists(), "acknowledged segment is removed");
        assert!(live.exists(), "the live extra spool is never touched");
    }
}
