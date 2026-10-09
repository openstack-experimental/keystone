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

//! Per-partition read quarantine after repeated decrypt failures.

use super::*;

/// Fjall meta key prefix for persisted quarantine markers.
///
/// Full key layout is `_meta:quarantine:<partition>:<node_id>`: partition
/// comes first so that `ClearQuarantine` can prefix-scan and remove every
/// reporting node's entry for a partition in one pass.
pub(super) const QUARANTINE_META_PREFIX: &str = "_meta:quarantine:";

/// Sliding window for GCM failure counting.
pub(super) const QUARANTINE_WINDOW: Duration = Duration::from_secs(60);

/// Number of GCM failures within `QUARANTINE_WINDOW` that triggers quarantine.
pub(super) const QUARANTINE_THRESHOLD: usize = 3;

/// Builds the Fjall meta key for a quarantine marker.
pub(super) fn quarantine_meta_key(partition: &str, node_id: u64) -> String {
    format!("{QUARANTINE_META_PREFIX}{partition}:{node_id}")
}

/// Per-partition GCM decryption failure tracker with automatic quarantine.
///
/// A partition accumulates failure `Instant`s in a 60-second sliding window.
/// At three failures the partition is marked quarantined locally and — best
/// effort — the fact is proposed via Raft so it is committed cluster-wide
/// (ADR 0016-v2 §10 invariant 5). The in-memory `quarantined` set (which
/// gates local reads) only ever reflects *this* node's own quarantine state;
/// records reported by other nodes are persisted for audit visibility but
/// never block local reads, since GCM failures reflect node-local storage
/// corruption, not a cluster-wide data problem.
pub(super) struct QuarantineTracker {
    pub(super) failures: Mutex<HashMap<String, VecDeque<Instant>>>,
    pub(super) quarantined: Mutex<HashSet<String>>,
}

impl QuarantineTracker {
    /// Clears quarantine state for a partition (operator-initiated recovery).
    pub(super) fn clear(&self, partition: &str) {
        self.quarantined
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(partition);
        self.failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(partition);
    }

    /// Directly marks a partition quarantined without threshold bookkeeping.
    ///
    /// Used when applying a Raft-committed `Quarantine` mutation reported by
    /// this node itself — idempotent with respect to `record_failure`, which
    /// already set the same in-memory state synchronously.
    pub(super) fn force_quarantine(&self, partition: &str) {
        self.quarantined
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(partition.to_string());
    }

    /// Initialise from Fjall meta, loading any persisted quarantine markers.
    ///
    /// Only markers reported by `node_id` (this node) are loaded into the
    /// blocking `quarantined` set; markers from other nodes are logged for
    /// visibility but otherwise ignored.
    pub(super) fn from_meta(meta: &Keyspace, node_id: u64) -> Result<Self, crate::StoreError> {
        let mut quarantined = HashSet::new();

        // Collect first, then mutate: `insert`/`remove` below (legacy-key
        // migration) must not run against a live prefix iterator.
        let entries: Vec<Vec<u8>> = meta
            .prefix(QUARANTINE_META_PREFIX.as_bytes())
            .filter_map(|item| item.into_inner().ok())
            .map(|(k, _)| k.to_vec())
            .collect();

        for key_bytes in entries {
            let Ok(key_str) = String::from_utf8(key_bytes.clone()) else {
                continue;
            };
            let Some(rest) = key_str.strip_prefix(QUARANTINE_META_PREFIX) else {
                continue;
            };

            let (partition, reporting_node) = match rest.rsplit_once(':') {
                Some((partition, node_id_str)) => {
                    let Ok(reporting_node) = node_id_str.parse::<u64>() else {
                        continue;
                    };
                    (partition.to_string(), reporting_node)
                }
                None => {
                    // Pre-migration marker (`_meta:quarantine:<partition>`,
                    // no node-id suffix). These predate cluster-wide
                    // quarantine propagation and were always node-local
                    // (each node owns its own Fjall DB), so treat this as
                    // this node's own marker and rewrite it to the
                    // node-scoped key format. Left as-is it would silently
                    // fail to load on every future restart (no colon to
                    // split on), quietly ending a quarantine that's still
                    // supposed to be in effect.
                    tracing::warn!(
                        partition = rest,
                        "migrating pre-upgrade quarantine marker to node-scoped key format"
                    );
                    let _ = meta.insert(quarantine_meta_key(rest, node_id), b"1");
                    let _ = meta.remove(&key_bytes);
                    (rest.to_string(), node_id)
                }
            };

            if reporting_node == node_id {
                quarantined.insert(partition.clone());
                tracing::error!(
                    partition,
                    "SECURITY: partition is quarantined (loaded from persistent state)"
                );
            } else {
                tracing::info!(
                    partition,
                    reporting_node,
                    "quarantine record from another cluster node (informational only)"
                );
            }
        }
        Ok(Self {
            failures: Mutex::new(HashMap::new()),
            quarantined: Mutex::new(quarantined),
        })
    }

    pub(super) fn is_quarantined(&self, partition: &str) -> bool {
        self.quarantined
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(partition)
    }

    /// Partitions this node currently has quarantined, sorted by name.
    pub(super) fn quarantined_partitions(&self) -> Vec<String> {
        let mut partitions: Vec<String> = self
            .quarantined
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect();
        partitions.sort();
        partitions
    }

    /// Records a GCM failure for a partition; returns `true` if newly
    /// quarantined.
    pub(super) fn record_failure(&self, partition: &str) -> bool {
        if self.is_quarantined(partition) {
            return false;
        }

        let now = Instant::now();
        let mut failures = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        let window = failures.entry(partition.to_string()).or_default();

        // Evict timestamps outside the sliding window.
        window.retain(|&t| now.duration_since(t) < QUARANTINE_WINDOW);
        window.push_back(now);
        let count = window.len();

        match count {
            1 => {
                tracing::warn!(
                    partition,
                    "SECURITY: GCM tag verification failure (1/{QUARANTINE_THRESHOLD}); \
                     possible data corruption or tampering"
                );
            }
            2 => {
                tracing::error!(
                    partition,
                    "SECURITY: GCM tag verification failure (2/{QUARANTINE_THRESHOLD}); \
                     possible active attack"
                );
            }
            _ => {
                tracing::error!(
                    partition,
                    count,
                    "SECURITY: GCM failures reached threshold — quarantining partition"
                );
                drop(failures);
                self.quarantined
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(partition.to_string());
                return true;
            }
        }
        false
    }
}

impl FjallStateMachine {
    /// Returns `true` if the given keyspace partition is currently quarantined.
    pub fn is_quarantined(&self, partition: &str) -> bool {
        self.quarantine.is_quarantined(partition)
    }

    /// Persists the quarantine marker to local Fjall meta (synchronous,
    /// restart-durable on this node) and signals the background forwarding
    /// task to propose the same fact via Raft for cluster-wide visibility
    /// (ADR 0016-v2 §10 invariant 5).
    pub(super) fn persist_and_signal_quarantine(&self, partition: &str) {
        let key = quarantine_meta_key(partition, self.node_id);
        let _ = self.meta.insert(key, b"1");
        let _ = self
            .quarantine_tx
            .try_send((self.node_id, partition.to_string()));
    }

    /// Partitions this node currently has quarantined (reads blocked),
    /// sorted by name.
    pub fn quarantined_partitions(&self) -> Vec<String> {
        self.quarantine.quarantined_partitions()
    }

    /// Records a GCM tag-verification failure and, if the failure count just
    /// crossed the quarantine threshold, persists and signals it.
    pub(super) fn record_quarantine_failure(&self, partition: &str) {
        self.raft_prometheus_metrics.gcm_failures_total.inc();
        if self.quarantine.record_failure(partition) {
            self.persist_and_signal_quarantine(partition);
        }
    }
}
