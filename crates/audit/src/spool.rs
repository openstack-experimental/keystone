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
//! Spool writer and startup replay for at-least-once CADF delivery.
//!
//! Each node writes to its own per-node JSONL file. On startup, the file is
//! replayed, each event HMAC-verified and `observer.node_id` checked against
//! the expected node before re-dispatch. Corrupted or tampered lines are
//! skipped; if any such lines exist the file is quarantined after replay.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::dispatcher::AuditDispatcher;
use crate::types::CadfEvent;

/// Error variants for spool operations.
#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Trait for looking up historical HMAC keys by version during spool replay.
///
/// The key store MUST retain all versions for at least
/// `max(spool_drain_timeout + SIEM_lag_budget, 24h)` per ADR 0023.
pub trait HmacKeyStore: Send + Sync {
    fn get_key(&self, version: u64) -> Option<Arc<[u8]>>;
}

/// Returns the spool file path for a given node.
pub fn spool_path(spool_dir: &Path, node_id: &str) -> PathBuf {
    spool_dir.join(format!("audit-spool-{node_id}.jsonl"))
}

/// Background worker: drains a channel to the per-node JSONL spool file.
///
/// Appends one JSON line per event. On shutdown (channel closed), drains
/// with a 10-second timeout before exiting.
pub async fn run_spool_writer(
    mut receiver: mpsc::Receiver<CadfEvent>,
    spool_dir: PathBuf,
    node_id: String,
) {
    let path = spool_path(&spool_dir, &node_id);

    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        error!(path = %parent.display(), error = %e, "failed to create spool directory");
        return;
    }

    loop {
        // Use a timeout on recv so we can detect shutdown and drain promptly.
        match tokio::time::timeout(Duration::from_secs(10), receiver.recv()).await {
            Ok(Some(event)) => {
                if let Err(e) = append_event_to_spool(&path, &event) {
                    error!(
                        path = %path.display(),
                        error = %e,
                        event_id = %event.id(),
                        "failed to write audit event to spool"
                    );
                }
            }
            Ok(None) => {
                // Channel closed — drain complete.
                info!(path = %path.display(), "audit spool writer shutting down");
                break;
            }
            Err(_timeout) => {
                // No events within timeout window — loop back and wait again.
            }
        }
    }
}

fn append_event_to_spool(path: &Path, event: &CadfEvent) -> Result<(), SpoolError> {
    let line = serde_json::to_string(event)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Replay a spool file at startup.
///
/// For each line:
/// - Parse as `CadfEvent`.
/// - Verify HMAC using the key version embedded in the event.
/// - Verify `observer.node_id` matches `expected_node_id`.
/// - Re-dispatch via `dispatcher.dispatch_critical()`.
///
/// Corrupted or tampered lines are skipped (logged as warnings). If any
/// lines were skipped the file is quarantined after replay.
///
/// Returns the count of successfully replayed events.
pub async fn replay_spool(
    path: &Path,
    expected_node_id: &str,
    dispatcher: &Arc<AuditDispatcher>,
    key_store: &dyn HmacKeyStore,
) -> Result<usize, SpoolError> {
    if !path.exists() {
        return Ok(0);
    }

    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);

    let mut replayed = 0usize;
    let mut skipped = 0usize;

    for (line_no, line_result) in reader.lines().enumerate() {
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

        // node_id tamper check — per ADR: mismatch is a tamper indicator.
        if event.payload().observer().node_id != expected_node_id {
            warn!(
                line = line_no + 1,
                event_id = %event.id(),
                event_node = %event.payload().observer().node_id,
                expected_node = %expected_node_id,
                "spool event node_id mismatch — quarantining (tamper indicator)"
            );
            skipped += 1;
            continue;
        }

        // HMAC verification against the key version recorded in the event.
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
                continue;
            }
            Some(key) => {
                if !dispatcher.verify_hmac(&event, &key) {
                    warn!(
                        line = line_no + 1,
                        event_id = %event.id(),
                        "HMAC verification failed — skipping spool event (tamper indicator)"
                    );
                    skipped += 1;
                    continue;
                }
            }
        }

        match dispatcher.dispatch_critical(event).await {
            Ok(()) => replayed += 1,
            Err(e) => {
                error!(error = %e, "critical channel dead during spool replay — aborting");
                return Ok(replayed);
            }
        }
    }

    if skipped > 0 {
        quarantine_spool(path)?;
    } else if replayed > 0 || path.exists() {
        // Clean replay (no tampered/corrupted lines): remove the file so the
        // spool writer starts fresh.  Without this, every restart re-replays
        // all previously delivered events and the file grows without bound.
        if let Err(e) = std::fs::remove_file(path) {
            // Non-fatal: warn and continue.  The spool writer will append to
            // the existing file; duplicate events on the next restart are
            // preferable to blocking startup.
            warn!(path = %path.display(), error = %e, "failed to remove spool file after clean replay");
        }
    }

    info!(replayed, skipped, "spool replay complete");
    Ok(replayed)
}

/// Rename the spool file to a `.quarantine-<timestamp>` path.
fn quarantine_spool(path: &Path) -> Result<(), SpoolError> {
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let quarantine = path.with_extension(format!("jsonl.quarantine-{ts}"));
    std::fs::rename(path, &quarantine)?;
    warn!(
        original = %path.display(),
        quarantine = %quarantine.display(),
        "spool file quarantined due to corrupted/tampered lines"
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
            "default".to_string(),
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
    }

    #[tokio::test]
    async fn replay_valid_events() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", Arc::clone(&key));

        // Write two events to spool.
        let path = spool_path(dir.path(), "node-1");
        for _ in 0..2 {
            let event = dispatcher.finalize_event(make_payload(&dispatcher));
            append_event_to_spool(&path, &event).unwrap();
        }

        // Replay into a fresh dispatcher (same key).
        let (dispatcher2, mut rx2) = make_dispatcher("node-1", Arc::clone(&key));
        let key_store = MapKeyStore(HashMap::from([(1u64, Arc::clone(&key))]));
        let replayed = replay_spool(&path, "node-1", &dispatcher2, &key_store)
            .await
            .unwrap();
        assert_eq!(replayed, 2);

        // Both events should have been dispatched to the critical channel.
        assert!(rx2.critical.try_recv().is_ok());
        assert!(rx2.critical.try_recv().is_ok());
    }

    #[tokio::test]
    async fn corrupted_line_is_skipped_and_file_quarantined() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", Arc::clone(&key));

        let path = spool_path(dir.path(), "node-1");
        // Write one valid event, then a corrupted line.
        let event = dispatcher.finalize_event(make_payload(&dispatcher));
        append_event_to_spool(&path, &event).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, "{{not valid json}}").unwrap();

        let (dispatcher2, _rx2) = make_dispatcher("node-1", Arc::clone(&key));
        let key_store = MapKeyStore(HashMap::from([(1u64, Arc::clone(&key))]));
        let replayed = replay_spool(&path, "node-1", &dispatcher2, &key_store)
            .await
            .unwrap();
        assert_eq!(replayed, 1);
        // Original spool should be gone (quarantined).
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn node_id_mismatch_triggers_quarantine() {
        let dir = tempdir().unwrap();
        let key: Arc<[u8]> = Arc::from(b"testkey".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-1", Arc::clone(&key));

        let path = spool_path(dir.path(), "node-1");
        let event = dispatcher.finalize_event(make_payload(&dispatcher));
        append_event_to_spool(&path, &event).unwrap();

        // Replay with a different expected node_id.
        let (dispatcher2, _rx2) = make_dispatcher("node-2", Arc::clone(&key));
        let key_store = MapKeyStore(HashMap::from([(1u64, Arc::clone(&key))]));
        let replayed = replay_spool(&path, "node-2", &dispatcher2, &key_store)
            .await
            .unwrap();
        assert_eq!(replayed, 0);
        assert!(!path.exists());
    }
}
