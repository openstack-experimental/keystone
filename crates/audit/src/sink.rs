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
//! Downstream audit sinks and the segment shipper (ADR 0023, #1317).
//!
//! The spool is the durable buffer in front of the sink. [`run_segment_shipper`]
//! hands each sealed segment, oldest first, to an [`AuditSink`] in batches.
//! Only once the sink has accepted every line of a segment is the segment
//! *acknowledged*, i.e. deleted from the spool. A crash or failure before that
//! point leaves the segment on disk and it is delivered again, so delivery is
//! at-least-once; consumers deduplicate on the event `id`.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, error, info, warn};

use crate::metrics::AuditMetrics;
use crate::spool::{SpoolError, list_segments, quarantine_segment};
use crate::types::CadfEvent;

/// Error returned by an [`AuditSink`].
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("sink I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sink serialization error: {0}")]
    Json(#[from] serde_json::Error),
    /// Any other delivery failure (e.g. a network sink's transport error).
    #[error("sink delivery failed: {0}")]
    Delivery(String),
}

/// A destination for audit events.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Deliver `events`. Returning `Ok` is the acknowledgement: the shipper
    /// treats the batch as durably accepted. On `Err` the whole segment is
    /// retried later, so a sink may see an event more than once.
    async fn write_batch(&self, events: &[CadfEvent]) -> Result<(), SinkError>;
}

/// Writes each event as one JSON line to the process's standard output, for
/// log shippers that collect container output.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdoutSink;

#[async_trait]
impl AuditSink for StdoutSink {
    async fn write_batch(&self, events: &[CadfEvent]) -> Result<(), SinkError> {
        use std::io::Write;
        let mut buf = Vec::new();
        for event in events {
            serde_json::to_writer(&mut buf, event)?;
            buf.push(b'\n');
        }
        let mut out = std::io::stdout().lock();
        out.write_all(&buf)?;
        out.flush()?;
        Ok(())
    }
}

/// Tuning for [`run_segment_shipper`].
#[derive(Debug, Clone)]
pub struct ShipperConfig {
    /// Events handed to the sink per call.
    pub batch_size: usize,
    /// How often to look for newly sealed segments when idle.
    pub poll_interval: Duration,
    /// First retry delay after a sink failure; doubles up to `max_backoff`.
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    /// Counters the shipper updates (shipped/skipped events, sink errors,
    /// quarantined segments).
    pub metrics: Arc<AuditMetrics>,
}

impl Default for ShipperConfig {
    fn default() -> Self {
        Self {
            batch_size: 500,
            poll_interval: Duration::from_secs(5),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            metrics: Arc::new(AuditMetrics::default()),
        }
    }
}

/// Result of attempting to ship one segment.
#[derive(Debug)]
enum ShipOutcome {
    /// Fully delivered and removed from the spool.
    Acked,
    /// The segment vanished (retention deleted it); nothing to do.
    Gone,
    /// Delivered, but some lines were unparsable; segment quarantined.
    Quarantined,
}

/// Failure while shipping a segment; the segment is left in place.
#[derive(Debug, thiserror::Error)]
enum ShipError {
    #[error(transparent)]
    Sink(#[from] SinkError),
    #[error(transparent)]
    Spool(#[from] SpoolError),
}

async fn ship_segment(
    path: &Path,
    sink: &dyn AuditSink,
    cfg: &ShipperConfig,
    spool_bytes: &AtomicU64,
) -> Result<ShipOutcome, ShipError> {
    let file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ShipOutcome::Gone),
        Err(e) => return Err(SpoolError::Io(e).into()),
    };
    let size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let mut lines = BufReader::new(file).lines();
    let mut batch = Vec::with_capacity(cfg.batch_size);
    let mut shipped = 0usize;
    let mut skipped = 0usize;

    loop {
        let line = lines.next_line().await.map_err(SpoolError::Io)?;
        let done = line.is_none();
        if let Some(line) = line
            && !line.trim().is_empty()
        {
            match serde_json::from_str::<CadfEvent>(&line) {
                Ok(event) => batch.push(event),
                Err(e) => {
                    warn!(segment = %path.display(), error = %e, "unparsable audit spool line");
                    skipped += 1;
                }
            }
        }
        if !batch.is_empty() && (done || batch.len() >= cfg.batch_size) {
            sink.write_batch(&batch).await?;
            shipped += batch.len();
            cfg.metrics
                .shipped_events
                .add(["shipped"], batch.len() as u64);
            batch.clear();
        }
        if done {
            break;
        }
    }

    if skipped > 0 {
        cfg.metrics.shipped_events.add(["skipped"], skipped as u64);
        quarantine_segment(path)?;
        cfg.metrics.spool_quarantined.inc();
        spool_bytes.fetch_sub(size, Ordering::Relaxed);
        warn!(segment = %path.display(), shipped, skipped, "segment shipped with unparsable lines and quarantined");
        return Ok(ShipOutcome::Quarantined);
    }

    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ShipOutcome::Gone),
        Err(e) => return Err(SpoolError::Io(e).into()),
    }
    spool_bytes.fetch_sub(size, Ordering::Relaxed);
    info!(segment = %path.display(), events = shipped, size_bytes = size, "audit segment acknowledged by sink");
    Ok(ShipOutcome::Acked)
}

/// Background worker: ships sealed segments to `sink` and acknowledges them.
///
/// Segments are processed oldest first, one at a time. A sink failure is
/// logged at `ERROR` and retried with exponential backoff; the segment stays
/// on disk until a full pass succeeds. Runs until `shutdown` resolves; a
/// segment in flight at that point is left unacknowledged and delivered again
/// on the next start. `spool_bytes` is the shared `keystone_audit_spool_bytes`
/// counter, reduced as segments are acknowledged.
pub async fn run_segment_shipper(
    spool_dir: PathBuf,
    node_id: String,
    sink: Arc<dyn AuditSink>,
    cfg: ShipperConfig,
    spool_bytes: Arc<AtomicU64>,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    let mut backoff = cfg.initial_backoff;
    loop {
        let wait = match ship_pending(&spool_dir, &node_id, sink.as_ref(), &cfg, &spool_bytes).await
        {
            Ok(()) => {
                backoff = cfg.initial_backoff;
                cfg.poll_interval
            }
            Err(e) => {
                if matches!(e, ShipError::Sink(_)) {
                    cfg.metrics.sink_errors.inc();
                }
                error!(error = %e, retry_in = ?backoff, "failed to ship audit segment; will retry");
                let wait = backoff;
                backoff = (backoff * 2).min(cfg.max_backoff);
                wait
            }
        };
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            () = tokio::time::sleep(wait) => {}
        }
    }
    debug!("audit segment shipper stopped");
}

async fn ship_pending(
    spool_dir: &Path,
    node_id: &str,
    sink: &dyn AuditSink,
    cfg: &ShipperConfig,
    spool_bytes: &AtomicU64,
) -> Result<(), ShipError> {
    for segment in list_segments(spool_dir, node_id)? {
        ship_segment(&segment, sink, cfg, spool_bytes).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tempfile::tempdir;
    use uuid::Uuid;

    use super::*;
    use crate::spool::{segment_prefix, spool_path, spool_total_bytes};
    use crate::types::{CadfEventPayload, Initiator, Observer, Target};

    #[derive(Default)]
    struct RecordingSink {
        ids: Mutex<Vec<String>>,
        fail_next: Mutex<u32>,
    }

    #[async_trait]
    impl AuditSink for RecordingSink {
        async fn write_batch(&self, events: &[CadfEvent]) -> Result<(), SinkError> {
            {
                let mut fail = self.fail_next.lock().unwrap();
                if *fail > 0 {
                    *fail -= 1;
                    return Err(SinkError::Delivery("down".into()));
                }
            }
            self.ids
                .lock()
                .unwrap()
                .extend(events.iter().map(|e| e.id().to_string()));
            Ok(())
        }
    }

    fn event(n: usize) -> CadfEvent {
        let (dispatcher, _rx) = crate::AuditDispatcher::new(
            "node-1",
            Uuid::new_v4().to_string(),
            Arc::from(b"testkey".as_slice()),
            1,
        );
        dispatcher.finalize_event(CadfEventPayload::new(
            format!("node-1:{n}-{}", Uuid::new_v4()),
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
                node_id: "node-1".to_string(),
                id: "service/security/keystone/node-1".to_string(),
            },
        ))
    }

    fn write_segment(dir: &Path, suffix: &str, lines: &[String]) -> PathBuf {
        let path = dir.join(format!("{}{suffix}", segment_prefix("node-1")));
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        path
    }

    fn lines(events: &[CadfEvent]) -> Vec<String> {
        events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect()
    }

    fn cfg() -> ShipperConfig {
        ShipperConfig {
            batch_size: 2,
            poll_interval: Duration::from_millis(10),
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(20),
            metrics: Arc::new(AuditMetrics::default()),
        }
    }

    #[tokio::test]
    async fn acks_segments_in_order_and_deletes_them() {
        let dir = tempdir().unwrap();
        let first: Vec<_> = (0..5).map(event).collect();
        let second: Vec<_> = (5..6).map(event).collect();
        let a = write_segment(dir.path(), "20260101T000000000Z", &lines(&first));
        let b = write_segment(dir.path(), "20260102T000000000Z", &lines(&second));
        let live = spool_path(dir.path(), "node-1");
        std::fs::write(&live, "live\n").unwrap();
        let bytes = Arc::new(AtomicU64::new(
            spool_total_bytes(dir.path(), "node-1").unwrap(),
        ));
        let sink = RecordingSink::default();

        ship_pending(dir.path(), "node-1", &sink, &cfg(), &bytes)
            .await
            .unwrap();

        let want: Vec<String> = first
            .iter()
            .chain(&second)
            .map(|e| e.id().to_string())
            .collect();
        assert_eq!(*sink.ids.lock().unwrap(), want);
        assert!(!a.exists() && !b.exists());
        assert!(live.exists(), "live spool is never shipped or deleted");
        assert_eq!(bytes.load(Ordering::Relaxed), 5, "only the live spool left");
    }

    #[tokio::test]
    async fn sink_failure_keeps_segment_until_retry_succeeds() {
        let dir = tempdir().unwrap();
        let events: Vec<_> = (0..3).map(event).collect();
        let seg = write_segment(dir.path(), "20260101T000000000Z", &lines(&events));
        let bytes = AtomicU64::new(0);
        let sink = RecordingSink::default();
        *sink.fail_next.lock().unwrap() = 1;

        assert!(
            ship_pending(dir.path(), "node-1", &sink, &cfg(), &bytes)
                .await
                .is_err()
        );
        assert!(seg.exists(), "unacknowledged segment must stay on disk");

        ship_pending(dir.path(), "node-1", &sink, &cfg(), &bytes)
            .await
            .unwrap();
        assert!(!seg.exists());
        assert_eq!(sink.ids.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn unparsable_lines_quarantine_the_segment() {
        let dir = tempdir().unwrap();
        let events: Vec<_> = (0..2).map(event).collect();
        let mut l = lines(&events);
        l.push("not json".into());
        let seg = write_segment(dir.path(), "20260101T000000000Z", &l);
        let bytes = AtomicU64::new(0);
        let sink = RecordingSink::default();
        let cfg = cfg();

        ship_pending(dir.path(), "node-1", &sink, &cfg, &bytes)
            .await
            .unwrap();

        assert_eq!(cfg.metrics.shipped_events.get(["shipped"]), 2);
        assert_eq!(cfg.metrics.shipped_events.get(["skipped"]), 1);
        assert_eq!(cfg.metrics.spool_quarantined.get(), 1);
        assert_eq!(sink.ids.lock().unwrap().len(), 2, "valid lines still ship");
        assert!(!seg.exists());
        let quarantined = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().contains(".quarantine-"));
        assert!(quarantined);
    }

    #[tokio::test]
    async fn shipper_task_retries_and_stops_on_shutdown() {
        let dir = tempdir().unwrap();
        let events: Vec<_> = (0..3).map(event).collect();
        let seg = write_segment(dir.path(), "20260101T000000000Z", &lines(&events));
        let sink = Arc::new(RecordingSink::default());
        *sink.fail_next.lock().unwrap() = 2;
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let shipper_cfg = cfg();
        let metrics = Arc::clone(&shipper_cfg.metrics);
        let task = tokio::spawn(run_segment_shipper(
            dir.path().to_path_buf(),
            "node-1".to_string(),
            sink.clone(),
            shipper_cfg,
            Arc::new(AtomicU64::new(0)),
            async move {
                rx.await.ok();
            },
        ));
        for _ in 0..200 {
            if !seg.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!seg.exists(), "segment acked after the sink recovers");
        assert_eq!(metrics.sink_errors.get(), 2, "one per failed attempt");
        assert_eq!(metrics.shipped_events.get(["shipped"]), 3);
        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("shipper stops on shutdown")
            .unwrap();
    }
}
