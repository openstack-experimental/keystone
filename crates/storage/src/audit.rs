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
//! Audit log infrastructure (ADR 0016-v2 §3.1, Phase 8).
//!
//! ## Design
//!
//! Each storage node derives a per-node, per-epoch `AuditHmacKey` from the
//! active DEK (`DekEpoch::derive_audit_key`). Audit records are serialised to
//! JSON, signed with `HMAC-SHA256(AuditHmacKey, record_json)` and appended to
//! a durable, fsynced, size-bounded JSONL spool on local disk. An external
//! shipper tails the spool and forwards it to the SIEM.
//!
//! The key rotates with every DEK epoch swap: the state machine calls
//! [`AuditForwarder::rotate_key`] after installing a new epoch. Every spool
//! line carries the `key_version` actually used to sign it, so a verifier
//! selects the key by that field.
//!
//! Emitting a record is non-blocking (a bounded channel feeds a single writer
//! task) so audit emission never stalls write operations. Records that cannot
//! be queued or written are counted in `keystone_raft_audit_dropped_total`.
//!
//! ## Spool format
//!
//! One JSON object per line: `{"record": {...}, "key_version": N,
//! "hmac": "<hex>"}`. `hmac` covers the exact serialised `record` object
//! (compact `serde_json` encoding of [`AuditRecord`], in field order).
//! The spool is not encrypted at rest; protect the directory with
//! filesystem permissions (files are created `0600`).

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use openstack_keystone_metrics::{Counter, Gauge, write_metric_header};
use openstack_keystone_storage_crypto::AuditHmacKey;
use serde::Serialize;
use tokio::sync::mpsc;

/// Capacity of the in-process audit channel feeding the spool writer.
const CHANNEL_CAPACITY: usize = 1024;

/// Fraction (percent) of the spool bound at which a `CRITICAL` alert is
/// logged (ADR §3.1).
const SPOOL_ALERT_PERCENT: u64 = 90;

/// Number of key epochs retained for signing (current + previous), so a
/// record stamped just before an epoch swap is still signed by its own epoch.
const RETAINED_KEY_EPOCHS: usize = 2;

/// Disk spool settings.
#[derive(Debug, Clone)]
pub struct AuditSpoolConfig {
    /// Directory holding the live spool file and sealed segments.
    pub dir: PathBuf,
    /// Raft node id; part of the spool file names.
    pub node_id: u64,
    /// Upper bound on the total spool size (live + sealed segments).
    pub max_bytes: u64,
}

/// A signed audit record.
#[derive(Serialize, Clone, Debug)]
pub struct AuditRecord {
    /// UTC epoch seconds.
    pub timestamp: u64,
    /// Event classification, e.g. `"DEK_ROTATION"`, `"QUARANTINE_CLEARED"`.
    pub event_type: String,
    /// Operator identity (SPIFFE SVID or TLS SAN; `"unknown"` when
    /// unavailable).
    pub actor: String,
    /// Raft node that generated this record.
    pub node_id: u64,
    /// Active DEK epoch version at the time of the event.
    pub dek_version: u32,
    /// Arbitrary structured context for the event.
    pub details: serde_json::Value,
}

impl AuditRecord {
    /// Create a record stamped with the current wall-clock time.
    pub fn now(
        event_type: impl Into<String>,
        actor: impl Into<String>,
        node_id: u64,
        dek_version: u32,
        details: serde_json::Value,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            timestamp,
            event_type: event_type.into(),
            actor: actor.into(),
            node_id,
            dek_version,
            details,
        }
    }
}

/// Signing keys by DEK epoch version.
struct KeyRing {
    keys: BTreeMap<u32, AuditHmacKey>,
}

impl KeyRing {
    /// Key for `version`, falling back to the newest key when that epoch is
    /// unknown (e.g. a record stamped with a not-yet-installed version).
    /// Returns the version actually selected.
    fn select(&self, version: u32) -> Option<(u32, &AuditHmacKey)> {
        match self.keys.get(&version) {
            Some(k) => Some((version, k)),
            None => self.keys.iter().next_back().map(|(v, k)| (*v, k)),
        }
    }
}

/// Shared metrics for the audit spool.
#[derive(Default)]
struct AuditMetrics {
    spool_bytes: Gauge,
    dropped_total: Counter,
}

/// Background task that signs audit records and appends them to the spool.
///
/// `AuditForwarder` is cheaply cloneable — all clones share the same channel
/// sender, key ring and metrics.
#[derive(Clone)]
pub struct AuditForwarder {
    tx: mpsc::Sender<AuditRecord>,
    keys: Arc<Mutex<KeyRing>>,
    metrics: Arc<AuditMetrics>,
}

impl AuditForwarder {
    /// Spawn the writer background task and return the handle.
    ///
    /// `key_version` is the DEK epoch version `key` was derived from. The
    /// returned `JoinHandle` is detached; callers should store it only if
    /// they want structured shutdown.
    pub fn spawn(
        key_version: u32,
        key: AuditHmacKey,
        spool: AuditSpoolConfig,
    ) -> std::io::Result<(Self, tokio::task::JoinHandle<()>)> {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let keys = Arc::new(Mutex::new(KeyRing {
            keys: BTreeMap::from([(key_version, key)]),
        }));
        let metrics = Arc::new(AuditMetrics::default());
        let writer = SpoolWriter::open(spool, metrics.clone())?;
        let handle = tokio::spawn(forwarder_task(rx, keys.clone(), writer, metrics.clone()));
        Ok((Self { tx, keys, metrics }, handle))
    }

    /// Submit a record for signing and spooling (non-blocking).
    ///
    /// If the channel is full the record is dropped, counted and logged at
    /// `ERROR` — audit emission must not block storage writes.
    pub fn emit(&self, record: AuditRecord) {
        if let Err(e) = self.tx.try_send(record) {
            self.metrics.dropped_total.inc();
            tracing::error!(error = %e, "AUDIT: record dropped — writer channel full or closed");
        }
    }

    /// Install the signing key for a newly active DEK epoch.
    ///
    /// Called from the state machine after every DEK epoch swap. Only the
    /// most recent [`RETAINED_KEY_EPOCHS`] keys are kept.
    pub fn rotate_key(&self, version: u32, new_key: AuditHmacKey) {
        let mut ring = self.keys.lock().unwrap_or_else(|p| p.into_inner());
        ring.keys.insert(version, new_key);
        while ring.keys.len() > RETAINED_KEY_EPOCHS {
            ring.keys.pop_first();
        }
    }

    /// Records dropped since startup (channel overflow or spool write
    /// failure).
    pub fn dropped_total(&self) -> u64 {
        self.metrics.dropped_total.get()
    }

    /// Current total spool size in bytes.
    pub fn spool_bytes(&self) -> i64 {
        self.metrics.spool_bytes.get()
    }

    /// Render the audit spool metrics in Prometheus text format.
    pub fn format_prometheus_text(&self) -> String {
        let mut out = String::new();
        write_metric_header(
            &mut out,
            "keystone_raft_audit_spool_bytes",
            "Total size of the raft audit spool (live file plus sealed segments).",
            "gauge",
        );
        self.metrics
            .spool_bytes
            .write_line(&mut out, "keystone_raft_audit_spool_bytes");
        write_metric_header(
            &mut out,
            "keystone_raft_audit_dropped_total",
            "Audit records dropped (channel overflow or spool write failure).",
            "counter",
        );
        self.metrics
            .dropped_total
            .write_line(&mut out, "keystone_raft_audit_dropped_total");
        out
    }
}

/// Durable JSONL spool with segment rotation and a total size bound.
struct SpoolWriter {
    dir: PathBuf,
    node_id: u64,
    max_bytes: u64,
    segment_bytes: u64,
    file: File,
    live_bytes: u64,
    sealed: Vec<(PathBuf, u64)>,
    alerted: bool,
    metrics: Arc<AuditMetrics>,
}

fn live_path(dir: &Path, node_id: u64) -> PathBuf {
    dir.join(format!("raft-audit-{node_id}.jsonl"))
}

fn segment_prefix(node_id: u64) -> String {
    format!("raft-audit-{node_id}.jsonl.seg-")
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

impl SpoolWriter {
    fn open(cfg: AuditSpoolConfig, metrics: Arc<AuditMetrics>) -> std::io::Result<Self> {
        fs::create_dir_all(&cfg.dir)?;
        let prefix = segment_prefix(cfg.node_id);
        let mut sealed = Vec::new();
        for entry in fs::read_dir(&cfg.dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                sealed.push((entry.path(), entry.metadata()?.len()));
            }
        }
        sealed.sort();
        let path = live_path(&cfg.dir, cfg.node_id);
        let file = open_append(&path)?;
        let live_bytes = file.metadata()?.len();
        let writer = Self {
            segment_bytes: (cfg.max_bytes / 8).max(1),
            dir: cfg.dir,
            node_id: cfg.node_id,
            max_bytes: cfg.max_bytes,
            file,
            live_bytes,
            sealed,
            alerted: false,
            metrics,
        };
        writer.publish_bytes();
        Ok(writer)
    }

    fn total_bytes(&self) -> u64 {
        self.live_bytes + self.sealed.iter().map(|(_, n)| n).sum::<u64>()
    }

    fn publish_bytes(&self) {
        self.metrics
            .spool_bytes
            .set(i64::try_from(self.total_bytes()).unwrap_or(i64::MAX));
    }

    /// Append one line and fsync it before returning.
    fn append(&mut self, line: &str) -> std::io::Result<()> {
        if self.live_bytes >= self.segment_bytes {
            self.seal()?;
        }
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.sync_data()?;
        self.live_bytes += line.len() as u64 + 1;
        self.enforce_bound();
        self.publish_bytes();
        Ok(())
    }

    fn seal(&mut self) -> std::io::Result<()> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let sealed = self
            .dir
            .join(format!("{}{nanos:039}", segment_prefix(self.node_id)));
        fs::rename(live_path(&self.dir, self.node_id), &sealed)?;
        self.sealed.push((sealed, self.live_bytes));
        self.file = open_append(&live_path(&self.dir, self.node_id))?;
        self.live_bytes = 0;
        Ok(())
    }

    /// Drop the oldest sealed segments while over the bound; alert at 90%.
    fn enforce_bound(&mut self) {
        while self.total_bytes() > self.max_bytes && !self.sealed.is_empty() {
            let (path, len) = self.sealed.remove(0);
            match fs::remove_file(&path) {
                Ok(()) => tracing::error!(
                    path = %path.display(),
                    bytes = len,
                    "AUDIT: spool bound exceeded — oldest sealed segment deleted \
                     before delivery was confirmed; audit completeness lost"
                ),
                Err(e) => tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "AUDIT: failed to delete oldest sealed spool segment"
                ),
            }
        }
        let over = self.total_bytes() * 100 >= self.max_bytes * SPOOL_ALERT_PERCENT;
        if over && !self.alerted {
            tracing::error!(
                used = self.total_bytes(),
                capacity = self.max_bytes,
                "CRITICAL: audit spool at {SPOOL_ALERT_PERCENT}% of capacity — the SIEM \
                 shipper is not draining it; oldest records will be deleted (ADR §3.1)"
            );
        }
        self.alerted = over;
    }
}

async fn forwarder_task(
    mut rx: mpsc::Receiver<AuditRecord>,
    keys: Arc<Mutex<KeyRing>>,
    mut writer: SpoolWriter,
    metrics: Arc<AuditMetrics>,
) {
    while let Some(record) = rx.recv().await {
        let json = match serde_json::to_string(&record) {
            Ok(j) => j,
            Err(e) => {
                metrics.dropped_total.inc();
                tracing::error!(error = %e, "AUDIT: failed to serialise record");
                continue;
            }
        };
        let signed = {
            let ring = keys.lock().unwrap_or_else(|p| p.into_inner());
            ring.select(record.dek_version)
                .map(|(v, k)| (v, k.sign(json.as_bytes())))
        };
        let (key_version, hmac) = match signed {
            Some((v, Ok(mac))) => (v, mac),
            Some((_, Err(e))) => {
                metrics.dropped_total.inc();
                tracing::error!(error = %e, "AUDIT: failed to sign record");
                continue;
            }
            None => {
                metrics.dropped_total.inc();
                tracing::error!("AUDIT: no signing key available");
                continue;
            }
        };
        let hmac_hex: String = hmac.iter().map(|b| format!("{b:02x}")).collect();
        // `json` is a complete JSON object, so it is embedded verbatim: the
        // HMAC then covers exactly the bytes a verifier extracts.
        let line =
            format!(r#"{{"record":{json},"key_version":{key_version},"hmac":"{hmac_hex}"}}"#);
        if let Err(e) = writer.append(&line) {
            metrics.dropped_total.inc();
            tracing::error!(error = %e, event_type = record.event_type, "AUDIT: spool write failed; record lost");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn key(b: u8) -> AuditHmacKey {
        AuditHmacKey::from_raw([b; 32])
    }

    fn hex(mac: [u8; 32]) -> String {
        mac.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn spool_lines(dir: &Path, node_id: u64) -> Vec<serde_json::Value> {
        let mut paths: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        paths.sort();
        let mut out = Vec::new();
        for p in paths {
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if !name.starts_with(&format!("raft-audit-{node_id}.jsonl")) {
                continue;
            }
            for l in fs::read_to_string(&p).unwrap().lines() {
                let mut v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["raw"] = serde_json::Value::String(l.to_string());
                out.push(v);
            }
        }
        out
    }

    async fn wait_for_lines(dir: &Path, n: usize) -> Vec<serde_json::Value> {
        for _ in 0..100 {
            let lines = spool_lines(dir, 1);
            if lines.len() >= n {
                return lines;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        spool_lines(dir, 1)
    }

    fn cfg(dir: &Path, max_bytes: u64) -> AuditSpoolConfig {
        AuditSpoolConfig {
            dir: dir.to_path_buf(),
            node_id: 1,
            max_bytes,
        }
    }

    #[tokio::test]
    async fn post_rotation_records_verify_under_new_epoch_key() {
        let dir = tempfile::tempdir().unwrap();
        let (fwd, _h) = AuditForwarder::spawn(1, key(1), cfg(dir.path(), 1 << 20)).unwrap();
        fwd.emit(AuditRecord::now("A", "op", 1, 1, serde_json::json!({})));
        fwd.rotate_key(2, key(2));
        fwd.emit(AuditRecord::now("B", "op", 1, 2, serde_json::json!({})));
        // Late record stamped with the previous epoch is still signed by it.
        fwd.emit(AuditRecord::now("C", "op", 1, 1, serde_json::json!({})));

        let lines = wait_for_lines(dir.path(), 3).await;
        assert_eq!(lines.len(), 3);
        for (line, expect_version, expect_key) in
            [(&lines[0], 1u64, 1u8), (&lines[1], 2, 2), (&lines[2], 1, 1)]
        {
            assert_eq!(line["key_version"], expect_version);
            // The HMAC covers the exact record bytes as written, not a
            // re-serialisation of the parsed value.
            let raw = line["raw"].as_str().unwrap();
            let record = raw
                .strip_prefix(r#"{"record":"#)
                .and_then(|r| r.split_once(r#","key_version":"#))
                .map(|(rec, _)| rec)
                .unwrap();
            let mac = key(expect_key).sign(record.as_bytes()).unwrap();
            assert_eq!(line["hmac"], hex(mac));
        }
    }

    #[tokio::test]
    async fn unknown_epoch_falls_back_to_newest_key_and_reports_it() {
        let dir = tempfile::tempdir().unwrap();
        let (fwd, _h) = AuditForwarder::spawn(1, key(1), cfg(dir.path(), 1 << 20)).unwrap();
        fwd.emit(AuditRecord::now("A", "op", 1, 9, serde_json::json!({})));
        let lines = wait_for_lines(dir.path(), 1).await;
        assert_eq!(lines[0]["key_version"], 1);
    }

    #[tokio::test]
    async fn only_recent_key_epochs_are_retained() {
        let dir = tempfile::tempdir().unwrap();
        let (fwd, _h) = AuditForwarder::spawn(1, key(1), cfg(dir.path(), 1 << 20)).unwrap();
        fwd.rotate_key(2, key(2));
        fwd.rotate_key(3, key(3));
        let ring = fwd.keys.lock().unwrap();
        assert_eq!(ring.keys.keys().copied().collect::<Vec<_>>(), vec![2, 3]);
    }

    #[test]
    fn spool_is_bounded_and_drops_oldest_segment() {
        let dir = tempfile::tempdir().unwrap();
        let metrics = Arc::new(AuditMetrics::default());
        // 800-byte bound -> 100-byte segments.
        let mut w = SpoolWriter::open(cfg(dir.path(), 800), metrics.clone()).unwrap();
        let line = "x".repeat(99);
        for _ in 0..50 {
            w.append(&line).unwrap();
        }
        assert!(w.total_bytes() <= 800 + 100);
        assert_eq!(
            metrics.spool_bytes.get(),
            i64::try_from(w.total_bytes()).unwrap()
        );
        assert!(!w.sealed.is_empty());
    }

    #[test]
    fn reopening_spool_accounts_existing_segments() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut w =
                SpoolWriter::open(cfg(dir.path(), 800), Arc::new(AuditMetrics::default())).unwrap();
            for _ in 0..5 {
                w.append(&"y".repeat(99)).unwrap();
            }
        }
        let metrics = Arc::new(AuditMetrics::default());
        let w = SpoolWriter::open(cfg(dir.path(), 800), metrics.clone()).unwrap();
        assert_eq!(w.total_bytes(), 500);
        assert_eq!(metrics.spool_bytes.get(), 500);
    }
}
