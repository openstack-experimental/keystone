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
//! Spool writer, rotation and startup verification for CADF audit events.
//!
//! Each node owns one spool directory (guarded by [`SpoolLock`]) holding:
//!
//! - the live spool `audit-spool-{node}.jsonl`, appended by the single
//!   [`run_spool_writer`] task that merges the critical and perimeter channels;
//! - sealed, immutable segments `audit-spool-{node}.jsonl.seg-<timestamp>`,
//!   produced by size/age rotation and by sealing the previous run's live spool
//!   at startup ([`seal_previous_spool`]).
//!
//! Sealed segments are what a downstream sink consumes (see [`crate::sink`]);
//! they are never re-dispatched into the live spool, which previously made
//! "replay" a self-loop. At startup the previous run's
//! segment is HMAC-verified at rest ([`verify_sealed_spool`]); a segment with
//! corrupted or tampered lines is quarantined.

use std::future::Future;
use std::io::{BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{error, info, warn};

use crate::dispatcher::AuditDispatcher;
use crate::metrics::AuditMetrics;
use crate::types::CadfEvent;

/// How often buffered perimeter events are flushed and fsynced.
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);

/// How often (in spool lines) verification logs progress.
const VERIFY_PROGRESS_EVERY: usize = 100_000;

/// Error variants for spool operations.
#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    /// An I/O error on the spool.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A spool line is not valid JSON.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// The spool is already locked by another process.
    #[error("audit spool {} is locked by another process", .0.display())]
    Locked(PathBuf),
}

/// Advisory exclusive lock on a node's audit spool, held for the lifetime of
/// the value (released on drop or process exit).
///
/// Guards against two processes sharing one `spool_dir`/`node_id`,
/// which would interleave appends and replay each other's events. The lock is
/// taken on a sidecar `audit-spool-{node_id}.lock` file rather than the spool
/// itself, because the spool is renamed during replay.
#[derive(Debug)]
pub struct SpoolLock {
    /// The sidecar file holding the advisory lock; dropped with the lock.
    _file: std::fs::File,
}

impl SpoolLock {
    /// Acquire the lock without blocking.
    ///
    /// Fails with [`SpoolError::Locked`] if another process holds it.
    pub fn acquire(spool_dir: &Path, node_id: &str) -> Result<Self, SpoolError> {
        let lock_path = spool_path(spool_dir, node_id).with_extension("lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(SpoolError::Locked(lock_path)),
            Err(std::fs::TryLockError::Error(e)) => Err(SpoolError::Io(e)),
        }
    }
}

/// Trait for looking up historical HMAC keys by version during verification.
///
/// The key store MUST retain all versions for at least
/// `max(spool_drain_timeout + SIEM_lag_budget, 24h)` per ADR 0023.
pub trait HmacKeyStore: Send + Sync {
    fn get_key(&self, version: u64) -> Option<Arc<[u8]>>;
}

/// Returns the live spool file path for a given node.
pub fn spool_path(spool_dir: &Path, node_id: &str) -> PathBuf {
    spool_dir.join(format!("audit-spool-{node_id}.jsonl"))
}

pub(crate) fn segment_prefix(node_id: &str) -> String {
    format!("audit-spool-{node_id}.jsonl.seg-")
}

/// Rotation and retention policy for the spool writer.
#[derive(Debug, Clone)]
pub struct SpoolConfig {
    /// Upper bound on the time spent draining queued events after shutdown
    /// is requested. Events still queued at the deadline are dropped and
    /// logged at `ERROR` with their count.
    pub drain_timeout: Duration,
    /// Keep the sealed segments plus one full live segment
    /// (`max_segment_bytes`) within this many bytes, deleting the oldest
    /// sealed segments first. `None` means no size cap. The live spool itself
    /// is never deleted.
    pub max_bytes: Option<u64>,
    /// Rotate once the live spool is this old.
    pub max_segment_age: Duration,
    /// Rotate once the live spool reaches this many bytes.
    pub max_segment_bytes: u64,
    /// Keep at most this many sealed segments, deleting the oldest. `None`
    /// keeps all of them.
    pub max_segments: Option<usize>,
    /// Counters the writer updates (write failures, retention deletions).
    pub metrics: Arc<AuditMetrics>,
    /// Delete sealed segments older than this (by modification time). `None`
    /// keeps them regardless of age.
    pub retention: Option<Duration>,
}

impl Default for SpoolConfig {
    fn default() -> Self {
        Self {
            drain_timeout: Duration::from_secs(10),
            max_bytes: None,
            max_segment_age: Duration::from_secs(24 * 60 * 60),
            max_segment_bytes: 256 * 1024 * 1024,
            max_segments: None,
            metrics: Arc::new(AuditMetrics::default()),
            retention: None,
        }
    }
}

/// Sealed segments of a node's spool, oldest first.
pub fn list_segments(spool_dir: &Path, node_id: &str) -> Result<Vec<PathBuf>, SpoolError> {
    let prefix = segment_prefix(node_id);
    let mut segments = Vec::new();
    for entry in std::fs::read_dir(spool_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        // The timestamp suffix has no '.', which excludes quarantined
        // (`.quarantine-<ts>`) copies of a segment.
        if let Some(rest) = name.to_str().and_then(|n| n.strip_prefix(&prefix))
            && !rest.contains('.')
        {
            segments.push(entry.path());
        }
    }
    segments.sort();
    Ok(segments)
}

/// Total bytes held by the node's live spool and sealed segments.
pub fn spool_total_bytes(spool_dir: &Path, node_id: &str) -> Result<u64, SpoolError> {
    let mut total = std::fs::metadata(spool_path(spool_dir, node_id))
        .map(|m| m.len())
        .unwrap_or(0);
    for segment in list_segments(spool_dir, node_id)? {
        total += std::fs::metadata(segment)?.len();
    }
    Ok(total)
}

fn unique_segment_path(spool_dir: &Path, node_id: &str) -> PathBuf {
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ");
    let base = spool_dir.join(format!("{}{ts}", segment_prefix(node_id)));
    let mut candidate = base.clone();
    let mut n = 0u32;
    while candidate.exists() {
        n += 1;
        candidate = PathBuf::from(format!("{}-{n}", base.display()));
    }
    candidate
}

/// Seal the previous run's live spool as an immutable segment.
///
/// MUST run (under the [`SpoolLock`]) before the spool writer is spawned, so
/// the writer starts on a fresh live spool and nothing reads a file that is
/// still being appended to. Returns the segment path, or `None` if there was
/// nothing to seal.
pub fn seal_previous_spool(spool_dir: &Path, node_id: &str) -> Result<Option<PathBuf>, SpoolError> {
    let live = spool_path(spool_dir, node_id);
    match std::fs::metadata(&live) {
        Ok(m) if m.len() > 0 => {
            let segment = unique_segment_path(spool_dir, node_id);
            std::fs::rename(&live, &segment)?;
            info!(
                segment = %segment.display(),
                size_bytes = m.len(),
                "sealed previous-run audit spool"
            );
            Ok(Some(segment))
        }
        Ok(_) => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Appends events to the live spool with a persistent buffered handle.
pub struct SpoolWriter {
    /// The retention and rotation limits to enforce.
    cfg: SpoolConfig,
    /// Whether the buffer holds events not yet on disk.
    dirty: bool,
    /// This node's spool directory.
    dir: PathBuf,
    /// The live spool file, buffered and flushed periodically.
    file: Option<BufWriter<std::fs::File>>,
    /// The node this spool belongs to.
    node_id: String,
    /// When the current segment was opened.
    opened_at: Instant,
    /// The live spool file.
    path: PathBuf,
    /// Bytes written to the current segment.
    segment_bytes: u64,
    /// Shared gauge of the spool's total size in bytes.
    total_bytes: Arc<AtomicU64>,
}

/// Open the spool writer: create the directory, seed the `spool_bytes` gauge
/// with what is already on disk, open the live spool and enforce retention.
///
/// Called at startup (off the async runtime, see `crate::runtime::init`);
/// an error here must fail the service start, because a writer that cannot
/// open its spool would silently drop every event.
pub fn start_spool_writer(
    dir: PathBuf,
    node_id: String,
    cfg: SpoolConfig,
    total_bytes: Arc<AtomicU64>,
) -> Result<SpoolWriter, SpoolError> {
    std::fs::create_dir_all(&dir)?;
    let path = spool_path(&dir, &node_id);
    total_bytes.store(spool_total_bytes(&dir, &node_id)?, Ordering::Relaxed);
    let mut writer = SpoolWriter {
        cfg,
        dirty: false,
        dir,
        file: None,
        node_id,
        opened_at: Instant::now(),
        path,
        segment_bytes: 0,
        total_bytes,
    };
    writer.open()?;
    writer.enforce_retention()?;
    Ok(writer)
}

impl SpoolWriter {
    /// Append one event. The record (including its newline) is a single
    /// buffer handed to the writer in one `write_all`. `durable` flushes and
    /// fsyncs before returning (used for critical events).
    fn append(&mut self, event: &CadfEvent, durable: bool) -> Result<(), SpoolError> {
        let mut line = serde_json::to_string(event)?;
        line.push('\n');
        let len = line.len() as u64;

        if self.file.is_none() {
            self.open()?;
        }
        if self.should_rotate(len) {
            self.rotate()?;
        }
        let Some(file) = self.file.as_mut() else {
            return Err(std::io::Error::other("spool file is not open").into());
        };
        file.write_all(line.as_bytes())?;
        self.segment_bytes += len;
        self.total_bytes.fetch_add(len, Ordering::Relaxed);
        self.dirty = true;
        if durable {
            self.sync()?;
        }
        Ok(())
    }

    /// Delete sealed segments that exceed the configured count, total size or
    /// age limits, oldest first. Every deletion is logged at `ERROR` (the
    /// records were never acknowledged by a sink) and counted.
    fn enforce_retention(&self) -> Result<(), SpoolError> {
        if self.cfg.max_segments.is_none()
            && self.cfg.max_bytes.is_none()
            && self.cfg.retention.is_none()
        {
            return Ok(());
        }
        let mut segments =
            std::collections::VecDeque::from(list_segments(&self.dir, &self.node_id)?);
        // Total bytes still held: every remaining segment plus room for the
        // live spool to grow to a full segment, so the size cap also holds
        // between rotations.
        let mut held = self.cfg.max_segment_bytes.max(self.segment_bytes);
        let mut sizes = Vec::with_capacity(segments.len());
        for segment in &segments {
            let size = std::fs::metadata(segment).map(|m| m.len()).unwrap_or(0);
            held += size;
            sizes.push(size);
        }
        let mut sizes = std::collections::VecDeque::from(sizes);
        let now = std::time::SystemTime::now();

        while let Some(segment) = segments.front() {
            let size = sizes.front().copied().unwrap_or(0);
            let reason = if self
                .cfg
                .max_segments
                .is_some_and(|max| segments.len() > max)
            {
                Some("max_segments")
            } else if self.cfg.max_bytes.is_some_and(|max| held > max) {
                Some("max_bytes")
            } else if self.cfg.retention.is_some_and(|retention| {
                std::fs::metadata(segment)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|modified| now.duration_since(modified).ok())
                    .is_some_and(|age| age > retention)
            }) {
                Some("retention")
            } else {
                None
            };
            let Some(reason) = reason else {
                break;
            };
            std::fs::remove_file(segment)?;
            held = held.saturating_sub(size);
            dec_spool_bytes(&self.total_bytes, size);
            self.cfg.metrics.spool_retention_deleted.inc();
            error!(
                segment = %segment.display(),
                size_bytes = size,
                limit = reason,
                "audit spool retention limit reached: deleted the oldest sealed segment \
                 that no sink had acknowledged"
            );
            segments.pop_front();
            sizes.pop_front();
        }
        Ok(())
    }

    fn open(&mut self) -> Result<(), SpoolError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.segment_bytes = file.metadata()?.len();
        self.opened_at = Instant::now();
        self.file = Some(BufWriter::new(file));
        Ok(())
    }

    /// Seal the live spool as a segment and start a fresh one.
    fn rotate(&mut self) -> Result<(), SpoolError> {
        self.sync()?;
        self.file = None;
        let segment = unique_segment_path(&self.dir, &self.node_id);
        std::fs::rename(&self.path, &segment)?;
        info!(
            segment = %segment.display(),
            size_bytes = self.segment_bytes,
            "rotated audit spool"
        );
        self.open()?;
        self.enforce_retention()
    }

    fn should_rotate(&self, incoming: u64) -> bool {
        self.segment_bytes > 0
            && (self.segment_bytes + incoming > self.cfg.max_segment_bytes
                || self.opened_at.elapsed() >= self.cfg.max_segment_age)
    }

    /// Flush the buffer and `fdatasync` the live spool.
    fn sync(&mut self) -> Result<(), SpoolError> {
        if let Some(file) = self.file.as_mut() {
            file.flush()?;
            file.get_ref().sync_data()?;
        }
        self.dirty = false;
        Ok(())
    }
}

/// Background worker: drains the critical and perimeter channels to the
/// per-node JSONL spool.
///
/// A single task owns the file, so lines cannot interleave. Critical events
/// are flushed and fsynced before the next event is taken; perimeter events
/// are buffered and flushed/fsynced every 500ms. `spool_bytes` is kept equal
/// to the total size of the live spool and sealed segments (the
/// `keystone_audit_spool_bytes` gauge).
///
/// The writer must already be open: startup opens it via
/// [`start_spool_writer`] and fails the service start if it cannot.
///
/// The writer stops when both channels are closed (the dispatcher was
/// dropped) or when `shutdown` resolves. On `shutdown` it closes the channels
/// and drains what is already queued, critical events first, for at most
/// `cfg.drain_timeout`; events still queued at the deadline are dropped and
/// logged at `ERROR`. Either way it ends with a final fsync.
pub async fn run_spool_writer(
    mut perimeter: mpsc::Receiver<CadfEvent>,
    mut critical: mpsc::Receiver<CadfEvent>,
    mut writer: SpoolWriter,
    shutdown: impl Future<Output = ()>,
) {
    let drain_timeout = writer.cfg.drain_timeout;

    let mut flush_tick = interval(FLUSH_INTERVAL);
    flush_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut perimeter_open = true;
    let mut critical_open = true;
    let mut shutdown_requested = false;
    tokio::pin!(shutdown);

    while perimeter_open || critical_open {
        tokio::select! {
            biased;
            () = &mut shutdown => {
                shutdown_requested = true;
                break;
            }
            event = critical.recv(), if critical_open => match event {
                Some(event) => log_append(writer.append(&event, true), &writer.path, &event, &writer.cfg.metrics),
                None => critical_open = false,
            },
            event = perimeter.recv(), if perimeter_open => match event {
                Some(event) => log_append(writer.append(&event, false), &writer.path, &event, &writer.cfg.metrics),
                None => perimeter_open = false,
            },
            _ = flush_tick.tick() => {
                if writer.dirty
                    && let Err(e) = writer.sync()
                {
                    error!(path = %writer.path.display(), error = %e, "failed to sync audit spool");
                }
            }
        }
    }

    if shutdown_requested {
        drain_on_shutdown(&mut writer, &mut critical, &mut perimeter, drain_timeout);
    }

    if let Err(e) = writer.sync() {
        error!(path = %writer.path.display(), error = %e, "failed to sync audit spool on shutdown");
    }
    info!(path = %writer.path.display(), "audit spool writer shutting down");
}

/// Close both channels (so senders get an error instead of queueing more) and
/// write out whatever is already buffered, critical first, until empty or
/// `timeout` elapses. Once closed, `try_recv` only yields what was queued
/// before the close, so the loop terminates even if senders are still alive.
fn drain_on_shutdown(
    writer: &mut SpoolWriter,
    critical: &mut mpsc::Receiver<CadfEvent>,
    perimeter: &mut mpsc::Receiver<CadfEvent>,
    timeout: Duration,
) {
    critical.close();
    perimeter.close();
    let deadline = Instant::now() + timeout;
    let mut drained = 0usize;
    loop {
        if Instant::now() >= deadline {
            let dropped = critical.len() + perimeter.len();
            if dropped > 0 {
                error!(
                    path = %writer.path.display(),
                    drained,
                    dropped,
                    critical_dropped = critical.len(),
                    timeout = ?timeout,
                    "audit drain deadline reached; queued events dropped"
                );
            }
            return;
        }
        let (event, durable) = match critical.try_recv() {
            Ok(event) => (event, true),
            Err(_) => match perimeter.try_recv() {
                Ok(event) => (event, false),
                Err(_) => break,
            },
        };
        log_append(
            writer.append(&event, durable),
            &writer.path,
            &event,
            &writer.cfg.metrics,
        );
        drained += 1;
    }
    if drained > 0 {
        info!(drained, "drained queued audit events on shutdown");
    }
}

fn log_append(
    result: Result<(), SpoolError>,
    path: &Path,
    event: &CadfEvent,
    metrics: &AuditMetrics,
) {
    if let Err(e) = result {
        metrics.spool_write_failures.inc();
        error!(
            path = %path.display(),
            error = %e,
            event_id = %event.id(),
            "failed to write audit event to spool"
        );
    }
}

/// Counts from [`verify_sealed_spool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyStats {
    /// Lines that did not; if non-zero the segment was quarantined.
    pub skipped: usize,
    /// Lines that parsed and passed the node-id and HMAC checks.
    pub verified: usize,
}

/// Reduce the shared spool-bytes gauge by `bytes`, saturating at zero.
///
/// The gauge is seeded once when the spool writer starts (see
/// [`start_spool_writer`]); everything that removes segment bytes — shipper
/// acks, quarantines, retention deletions — reduces it through this helper.
/// Saturation keeps a double-accounted size from wrapping the gauge into a
/// near-2^64 reading.
pub(crate) fn dec_spool_bytes(spool_bytes: &AtomicU64, bytes: u64) {
    let mut current = spool_bytes.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_sub(bytes);
        match spool_bytes.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

/// Verify a sealed segment at rest.
///
/// For each line: parse as `CadfEvent`, check `observer.node_id` equals
/// `expected_node_id` (mismatch is a tamper indicator), and verify the HMAC
/// with the key version recorded in the event. Nothing is re-dispatched. If
/// any line fails, the segment is renamed to `<segment>.quarantine-<ts>` and
/// stays on disk for investigation.
///
/// Blocking; run it off the async runtime for large segments.
pub fn verify_sealed_spool(
    path: &Path,
    expected_node_id: &str,
    dispatcher: &AuditDispatcher,
    key_store: &dyn HmacKeyStore,
) -> Result<VerifyStats, SpoolError> {
    let size = std::fs::metadata(path)?.len();
    info!(path = %path.display(), size_bytes = size, "verifying sealed audit spool");
    let reader = std::io::BufReader::new(std::fs::File::open(path)?);

    let mut verified = 0usize;
    let mut skipped = 0usize;

    for (line_no, line_result) in reader.lines().enumerate() {
        if line_no > 0 && line_no % VERIFY_PROGRESS_EVERY == 0 {
            info!(
                lines = line_no,
                verified, skipped, "audit spool verification in progress"
            );
        }
        let line = match line_result {
            Ok(l) if l.trim().is_empty() => continue,
            Ok(l) => l,
            Err(e) => {
                warn!(line = line_no + 1, error = %e, "spool line read error — skipping");
                skipped += 1;
                continue;
            }
        };

        let event: CadfEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                warn!(line = line_no + 1, error = %e, "spool line parse error — skipping");
                skipped += 1;
                continue;
            }
        };

        if event.payload().observer().node_id() != expected_node_id {
            warn!(
                line = line_no + 1,
                event_id = %event.id(),
                event_node = %event.payload().observer().node_id(),
                expected_node = %expected_node_id,
                "spool event node_id mismatch (tamper indicator)"
            );
            skipped += 1;
            continue;
        }

        let key_version = event.payload().hmac_key_version();
        match key_store.get_key(key_version) {
            None => {
                warn!(
                    line = line_no + 1,
                    event_id = %event.id(),
                    hmac_key_version = key_version,
                    "HMAC key version not found — skipping spool event"
                );
                skipped += 1;
            }
            Some(key) if !dispatcher.verify_hmac(&event, &key) => {
                warn!(
                    line = line_no + 1,
                    event_id = %event.id(),
                    "HMAC verification failed (tamper indicator)"
                );
                skipped += 1;
            }
            Some(_) => verified += 1,
        }
    }

    let metrics = dispatcher.metrics();
    metrics.spool_verified.add(["verified"], verified as u64);
    metrics.spool_verified.add(["invalid"], skipped as u64);
    if skipped > 0 {
        quarantine_segment(path)?;
        metrics.spool_quarantined.inc();
        // The writer seeded the gauge with this segment's bytes; a
        // quarantined copy is no longer shippable spool content.
        dec_spool_bytes(&dispatcher.spool_bytes_handle(), size);
    }
    info!(verified, skipped, "audit spool verification complete");
    Ok(VerifyStats { skipped, verified })
}

/// Rename a segment to `<segment>.quarantine-<timestamp>`.
pub(crate) fn quarantine_segment(path: &Path) -> Result<(), SpoolError> {
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let quarantine = PathBuf::from(format!("{}.quarantine-{ts}", path.display()));
    std::fs::rename(path, &quarantine)?;
    warn!(
        original = %path.display(),
        quarantine = %quarantine.display(),
        "audit spool segment quarantined due to corrupted/tampered lines"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use tempfile::tempdir;
    use uuid::Uuid;

    use super::*;
    use crate::dispatcher::AuditDispatcher;
    use crate::types::{CadfEventPayload, Initiator, Observer, Target};

    struct MapKeyStore(HashMap<u64, Arc<[u8]>>);

    impl HmacKeyStore for MapKeyStore {
        fn get_key(&self, version: u64) -> Option<Arc<[u8]>> {
            self.0.get(&version).cloned()
        }
    }

    fn make_dispatcher(
        node: &str,
        key: Arc<[u8]>,
    ) -> (
        Arc<AuditDispatcher>,
        crate::dispatcher::AuditChannelReceivers,
    ) {
        AuditDispatcher::new(node, Uuid::new_v4().to_string(), key, 1)
    }

    fn make_payload(dispatcher: &AuditDispatcher) -> CadfEventPayload {
        CadfEventPayload::new(
            format!("{}:{}", dispatcher.node_id(), Uuid::new_v4()),
            "1.0".to_string(),
            Uuid::new_v4().to_string(),
            chrono::Utc::now().to_rfc3339(),
            "authenticate".to_string(),
            crate::types::Outcome::Success,
            None,
            Initiator::new("unknown".to_string(), None, None, None),
            Target::new("keystone", "service/security/keystone/auth"),
            Observer::new(
                dispatcher.node_id(),
                format!("service/security/keystone/{}", dispatcher.node_id()),
            ),
        )
    }

    #[test]
    fn spool_lock_is_exclusive_and_released_on_drop() {
        let dir = tempdir().unwrap();
        let first = SpoolLock::acquire(dir.path(), "node-1").unwrap();
        assert!(matches!(
            SpoolLock::acquire(dir.path(), "node-1"),
            Err(SpoolError::Locked(_))
        ));
        // A different node's spool is independent.
        let _other = SpoolLock::acquire(dir.path(), "node-2").unwrap();
        drop(first);
        SpoolLock::acquire(dir.path(), "node-1").unwrap();
    }

    /// A live spool path that cannot be opened (a directory) must make the
    /// start fail, not open a writer that can never write.
    #[test]
    fn start_spool_writer_fails_when_the_live_spool_cannot_be_opened() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(spool_path(dir.path(), "node-1")).unwrap();
        assert!(
            start_spool_writer(
                dir.path().to_path_buf(),
                "node-1".to_string(),
                SpoolConfig::default(),
                Arc::new(AtomicU64::new(0)),
            )
            .is_err(),
            "open(O_APPEND) on a directory must fail"
        );
    }

    fn event(dispatcher: &AuditDispatcher) -> CadfEvent {
        dispatcher.finalize_event(make_payload(dispatcher))
    }

    fn append_line(path: &Path, event: &CadfEvent) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(f, "{}", serde_json::to_string(event).unwrap()).unwrap();
    }

    fn key_store(key: &Arc<[u8]>) -> MapKeyStore {
        MapKeyStore(HashMap::from([(1u64, Arc::clone(key))]))
    }

    fn live_lines(dir: &Path, node: &str) -> usize {
        std::fs::read_to_string(spool_path(dir, node))
            .map(|c| c.lines().count())
            .unwrap_or(0)
    }

    /// Run the writer over `critical`/`perimeter` events and wait for it to
    /// finish (channels closed).
    async fn write_all(
        dir: &Path,
        cfg: SpoolConfig,
        critical: Vec<CadfEvent>,
        perimeter: Vec<CadfEvent>,
    ) -> Arc<AtomicU64> {
        let (ptx, prx) = mpsc::channel(1024);
        let (ctx, crx) = mpsc::channel(1024);
        let bytes = Arc::new(AtomicU64::new(0));
        let writer_bytes = Arc::clone(&bytes);
        let dir = dir.to_path_buf();
        let task = tokio::spawn(async move {
            let writer = start_spool_writer(dir, "node-1".to_string(), cfg, writer_bytes)
                .expect("a fresh tempdir spool opens");
            run_spool_writer(prx, crx, writer, std::future::pending()).await
        });
        for e in critical {
            ctx.send(e).await.unwrap();
        }
        for e in perimeter {
            ptx.send(e).await.unwrap();
        }
        drop((ptx, ctx));
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("writer exits once both channels close")
            .unwrap();
        bytes
    }

    #[tokio::test]
    async fn writer_merges_both_channels_into_whole_lines() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", key);
        let critical = (0..200).map(|_| event(&dispatcher)).collect();
        let perimeter = (0..200).map(|_| event(&dispatcher)).collect();

        write_all(dir.path(), SpoolConfig::default(), critical, perimeter).await;

        let contents = std::fs::read_to_string(spool_path(dir.path(), "node-1")).unwrap();
        let mut count = 0;
        for line in contents.lines() {
            serde_json::from_str::<CadfEvent>(line).expect("every line is a whole record");
            count += 1;
        }
        assert_eq!(count, 400);
    }

    #[tokio::test]
    async fn writer_rotates_by_size_and_tracks_bytes() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", key);
        let one = serde_json::to_string(&event(&dispatcher)).unwrap().len() as u64 + 1;
        let cfg = SpoolConfig {
            // Room for ~3 events per segment.
            max_segment_bytes: one * 3 + one / 2,
            ..SpoolConfig::default()
        };
        let events = (0..10).map(|_| event(&dispatcher)).collect();

        let bytes = write_all(dir.path(), cfg, events, vec![]).await;

        let segments = list_segments(dir.path(), "node-1").unwrap();
        assert!(segments.len() >= 3, "got {} segments", segments.len());
        let mut total = 0;
        for segment in &segments {
            let n = std::fs::read_to_string(segment).unwrap().lines().count();
            assert!(n <= 3, "segment holds {n} events");
            total += n;
        }
        assert_eq!(total + live_lines(dir.path(), "node-1"), 10);
        assert_eq!(
            bytes.load(Ordering::Relaxed),
            spool_total_bytes(dir.path(), "node-1").unwrap()
        );
    }

    /// Run the writer with `shutdown` already resolved while the channels stay
    /// open (senders alive), so everything queued goes through the drain path.
    async fn shutdown_with_queue(
        dir: &Path,
        cfg: SpoolConfig,
        critical: Vec<CadfEvent>,
        perimeter: Vec<CadfEvent>,
    ) {
        let (ptx, prx) = mpsc::channel(1024);
        let (ctx, crx) = mpsc::channel(1024);
        for e in critical {
            ctx.send(e).await.unwrap();
        }
        for e in perimeter {
            ptx.send(e).await.unwrap();
        }
        let writer = start_spool_writer(
            dir.to_path_buf(),
            "node-1".to_string(),
            cfg,
            Arc::new(AtomicU64::new(0)),
        )
        .expect("a fresh tempdir spool opens");
        tokio::time::timeout(
            Duration::from_secs(10),
            run_spool_writer(prx, crx, writer, std::future::ready(())),
        )
        .await
        .expect("writer returns on shutdown even with live senders");
        // Closed on drain: late senders get an error, not an unbounded queue.
        assert!(ctx.send(event_for_late_sender()).await.is_err());
        drop(ptx);
    }

    fn event_for_late_sender() -> CadfEvent {
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", key);
        event(&dispatcher)
    }

    #[tokio::test]
    async fn shutdown_drains_queued_events_within_deadline() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", key);
        let critical = (0..10).map(|_| event(&dispatcher)).collect();
        let perimeter = (0..10).map(|_| event(&dispatcher)).collect();

        shutdown_with_queue(dir.path(), SpoolConfig::default(), critical, perimeter).await;

        assert_eq!(live_lines(dir.path(), "node-1"), 20);
    }

    #[tokio::test]
    async fn shutdown_drops_events_past_zero_deadline() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", key);
        let critical = (0..10).map(|_| event(&dispatcher)).collect();
        let cfg = SpoolConfig {
            drain_timeout: Duration::ZERO,
            ..SpoolConfig::default()
        };

        shutdown_with_queue(dir.path(), cfg, critical, vec![]).await;

        assert_eq!(live_lines(dir.path(), "node-1"), 0);
    }

    #[tokio::test]
    async fn writer_enforces_segment_retention() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", key);
        let one = serde_json::to_string(&event(&dispatcher)).unwrap().len() as u64 + 1;
        let cfg = SpoolConfig {
            max_segment_bytes: one, // one event per segment
            max_segments: Some(2),
            ..SpoolConfig::default()
        };
        let events = (0..8).map(|_| event(&dispatcher)).collect();

        let bytes = write_all(dir.path(), cfg, events, vec![]).await;

        assert_eq!(list_segments(dir.path(), "node-1").unwrap().len(), 2);
        assert_eq!(
            bytes.load(Ordering::Relaxed),
            spool_total_bytes(dir.path(), "node-1").unwrap()
        );
    }

    #[tokio::test]
    async fn writer_enforces_size_cap_and_counts_deletions() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", key);
        let one = serde_json::to_string(&event(&dispatcher)).unwrap().len() as u64 + 1;
        let metrics = Arc::new(AuditMetrics::default());
        let cfg = SpoolConfig {
            max_segment_bytes: one, // one event per segment
            max_bytes: Some(one * 3),
            metrics: Arc::clone(&metrics),
            ..SpoolConfig::default()
        };
        let events = (0..8).map(|_| event(&dispatcher)).collect();

        let bytes = write_all(dir.path(), cfg, events, vec![]).await;

        let total = spool_total_bytes(dir.path(), "node-1").unwrap();
        assert!(total <= one * 3, "spool is {total} bytes, cap {}", one * 3);
        assert_eq!(bytes.load(Ordering::Relaxed), total);
        assert!(metrics.spool_retention_deleted.get() >= 4);
    }

    #[tokio::test]
    async fn writer_deletes_segments_older_than_retention() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", key);
        // An old sealed segment left by an earlier run.
        let old = dir
            .path()
            .join(format!("{}20200101T000000000Z", segment_prefix("node-1")));
        std::fs::write(&old, b"{}\n").unwrap();
        let long_ago = std::time::SystemTime::now() - Duration::from_secs(7200);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
        let metrics = Arc::new(AuditMetrics::default());
        let cfg = SpoolConfig {
            retention: Some(Duration::from_secs(3600)),
            metrics: Arc::clone(&metrics),
            ..SpoolConfig::default()
        };

        write_all(dir.path(), cfg, vec![event(&dispatcher)], vec![]).await;

        assert!(!old.exists(), "segment past retention must be deleted");
        assert_eq!(metrics.spool_retention_deleted.get(), 1);
    }

    #[test]
    fn append_failure_is_counted() {
        let metrics = AuditMetrics::default();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", key);
        let event = event(&dispatcher);
        log_append(
            Err(SpoolError::Io(std::io::Error::other("disk full"))),
            Path::new("/spool"),
            &event,
            &metrics,
        );
        log_append(Ok(()), Path::new("/spool"), &event, &metrics);
        assert_eq!(metrics.spool_write_failures.get(), 1);
    }

    #[test]
    fn seal_moves_previous_spool_to_segment() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", key);
        assert_eq!(seal_previous_spool(dir.path(), "node-1").unwrap(), None);

        append_line(&spool_path(dir.path(), "node-1"), &event(&dispatcher));
        let segment = seal_previous_spool(dir.path(), "node-1")
            .unwrap()
            .expect("non-empty spool is sealed");
        assert!(!spool_path(dir.path(), "node-1").exists());
        assert_eq!(list_segments(dir.path(), "node-1").unwrap(), vec![segment]);
    }

    /// Regression for #1315: the previous run's events must not be fed back
    /// into the live spool (that made the old replay loop forever).
    #[tokio::test]
    async fn restart_neither_loses_nor_duplicates_events() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", Arc::clone(&key));
        let first_run = (0..5).map(|_| event(&dispatcher)).collect();
        write_all(dir.path(), SpoolConfig::default(), first_run, vec![]).await;

        // Restart: seal, start a writer, verify.
        let segment = seal_previous_spool(dir.path(), "node-1").unwrap().unwrap();
        let second_run = (0..2).map(|_| event(&dispatcher)).collect();
        write_all(dir.path(), SpoolConfig::default(), second_run, vec![]).await;
        let stats = verify_sealed_spool(&segment, "node-1", &dispatcher, &key_store(&key)).unwrap();

        assert_eq!(
            stats,
            VerifyStats {
                skipped: 0,
                verified: 5
            }
        );
        assert_eq!(live_lines(dir.path(), "node-1"), 2);
        assert_eq!(
            std::fs::read_to_string(&segment).unwrap().lines().count(),
            5
        );
    }

    #[test]
    fn corrupted_line_quarantines_segment() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", Arc::clone(&key));
        let path = spool_path(dir.path(), "node-1");
        append_line(&path, &event(&dispatcher));
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, "{{not valid json}}").unwrap();
        let segment = seal_previous_spool(dir.path(), "node-1").unwrap().unwrap();

        // Seed the gauge the way start_spool_writer does at writer startup:
        // the sealed segment still counts until verification disposes of it.
        let bytes = dispatcher.spool_bytes_handle();
        bytes.store(
            spool_total_bytes(dir.path(), "node-1").unwrap(),
            Ordering::Relaxed,
        );
        assert!(bytes.load(Ordering::Relaxed) > 0);

        let stats = verify_sealed_spool(&segment, "node-1", &dispatcher, &key_store(&key)).unwrap();

        assert_eq!(
            stats,
            VerifyStats {
                skipped: 1,
                verified: 1
            }
        );
        assert!(!segment.exists());
        // Quarantined copies are not listed as sealed segments.
        assert!(list_segments(dir.path(), "node-1").unwrap().is_empty());
        let metrics = dispatcher.metrics();
        assert_eq!(metrics.spool_verified.get(["verified"]), 1);
        assert_eq!(metrics.spool_verified.get(["invalid"]), 1);
        assert_eq!(metrics.spool_quarantined.get(), 1);
        // The quarantined segment's bytes must leave the gauge: it now holds
        // exactly what is still on disk as live spool or sealed segments.
        assert_eq!(
            bytes.load(Ordering::Relaxed),
            spool_total_bytes(dir.path(), "node-1").unwrap(),
            "gauge must match what is left on disk"
        );
        assert_eq!(bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn node_id_mismatch_quarantines_segment() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", Arc::clone(&key));
        append_line(&spool_path(dir.path(), "node-1"), &event(&dispatcher));
        let segment = seal_previous_spool(dir.path(), "node-1").unwrap().unwrap();

        let stats = verify_sealed_spool(&segment, "node-2", &dispatcher, &key_store(&key)).unwrap();

        assert_eq!(
            stats,
            VerifyStats {
                skipped: 1,
                verified: 0
            }
        );
        assert!(!segment.exists());
    }

    #[test]
    fn wrong_hmac_key_quarantines_segment() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", Arc::clone(&key));
        append_line(&spool_path(dir.path(), "node-1"), &event(&dispatcher));
        let segment = seal_previous_spool(dir.path(), "node-1").unwrap().unwrap();
        let other: Arc<[u8]> = Arc::from(b"other-key".as_slice());

        let stats =
            verify_sealed_spool(&segment, "node-1", &dispatcher, &key_store(&other)).unwrap();

        assert_eq!(stats.skipped, 1);
    }

    /// Rewrite the `outcome` of the one spooled line, keeping its signature.
    fn tamper_outcome(path: &Path) {
        let content = std::fs::read_to_string(path).unwrap();
        std::fs::write(
            path,
            content.replace("\"outcome\":\"success\"", "\"outcome\":\"failure\""),
        )
        .unwrap();
    }

    #[test]
    fn hmac_tampered_line_quarantines_segment() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", Arc::clone(&key));
        append_line(&spool_path(dir.path(), "node-1"), &event(&dispatcher));
        tamper_outcome(&spool_path(dir.path(), "node-1"));
        let segment = seal_previous_spool(dir.path(), "node-1").unwrap().unwrap();

        let stats = verify_sealed_spool(&segment, "node-1", &dispatcher, &key_store(&key)).unwrap();

        // The line still parses and names the right node: only the HMAC can
        // tell it was altered.
        assert_eq!((stats.verified, stats.skipped), (0, 1));
        assert!(!segment.exists(), "tampered segment must be renamed");
        assert_eq!(
            dispatcher.metrics().spool_quarantined.get(),
            1,
            "quarantine must be counted"
        );
    }

    #[test]
    fn missing_key_version_quarantines_segment() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", Arc::clone(&key));
        append_line(&spool_path(dir.path(), "node-1"), &event(&dispatcher));
        let segment = seal_previous_spool(dir.path(), "node-1").unwrap().unwrap();
        // The event is signed with key version 1; the store only knows 2.
        let store = MapKeyStore(HashMap::from([(2u64, Arc::clone(&key))]));

        let stats = verify_sealed_spool(&segment, "node-1", &dispatcher, &store).unwrap();

        assert_eq!((stats.verified, stats.skipped), (0, 1));
        assert!(!segment.exists());
    }

    #[test]
    fn untampered_segment_verifies_and_stays() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", Arc::clone(&key));
        append_line(&spool_path(dir.path(), "node-1"), &event(&dispatcher));
        append_line(&spool_path(dir.path(), "node-1"), &event(&dispatcher));
        let segment = seal_previous_spool(dir.path(), "node-1").unwrap().unwrap();

        let stats = verify_sealed_spool(&segment, "node-1", &dispatcher, &key_store(&key)).unwrap();

        assert_eq!((stats.verified, stats.skipped), (2, 0));
        assert!(segment.exists());
    }
}
