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
//! Each storage node derives a per-node `AuditHmacKey` from the KEK at startup.
//! Audit records are serialised to canonical JSON, signed with
//! `HMAC-SHA256(AuditHmacKey, record_json)`, and forwarded to a SIEM endpoint.
//!
//! The `AuditForwarder` runs as an in-process background task.  Emitting a
//! record is non-blocking (fire-and-forget into an async channel) so audit
//! emission never stalls write operations.
//!
//! SIEM forwarding is stubbed in this phase: records are logged at `INFO` level
//! with their HMAC appended.  A future phase will add TCP/TLS delivery and
//! local encrypted buffering.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use openstack_keystone_storage_crypto::AuditHmacKey;
use serde::Serialize;
use tokio::sync::{Mutex, mpsc};

/// Capacity of the in-process audit channel.
///
/// At 90% usage an `ERROR` is emitted — audit completeness is a security
/// property (ADR §3.1) so persistent backpressure warrants operator attention.
/// Callers that find the channel full drop the record and log a `WARN`.
const CHANNEL_CAPACITY: usize = 1024;
const CHANNEL_WARN_THRESHOLD: usize = CHANNEL_CAPACITY * 9 / 10;

/// A signed audit record.
#[derive(Serialize, Clone)]
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

/// Background task that signs and forwards audit records.
///
/// Records are submitted via [`AuditForwarder::emit`] (non-blocking).
/// The forwarder task serialises each record to canonical JSON, computes
/// `HMAC-SHA256(AuditHmacKey, json)`, and logs the result.
///
/// `AuditForwarder` is cheaply cloneable — all clones share the same channel
/// sender and signing key, so they all enqueue to the same background task.
///
/// The `AuditHmacKey` is behind a `Mutex` so it can be rotated atomically
/// when a new DEK epoch is installed.
#[derive(Clone)]
pub struct AuditForwarder {
    tx: mpsc::Sender<AuditRecord>,
    /// Shared key — can be rotated without restarting the forwarder task.
    key: Arc<Mutex<AuditHmacKey>>,
}

impl AuditForwarder {
    /// Spawn the forwarder background task and return the handle.
    ///
    /// The returned `JoinHandle` is detached; callers should store it only if
    /// they want structured shutdown.
    pub fn spawn(key: AuditHmacKey) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let key = Arc::new(Mutex::new(key));
        let key_clone = key.clone();
        let handle = tokio::spawn(forwarder_task(rx, key_clone));
        (Self { tx, key }, handle)
    }

    /// Submit a record for signing and forwarding (non-blocking).
    ///
    /// If the channel is at capacity the record is dropped and a `WARN` is
    /// emitted — audit emission must not block storage writes.
    pub fn emit(&self, record: AuditRecord) {
        let used = CHANNEL_CAPACITY - self.tx.capacity();
        if used >= CHANNEL_WARN_THRESHOLD {
            tracing::error!(
                used,
                capacity = CHANNEL_CAPACITY,
                "AUDIT: forwarder channel near capacity — records may be dropped; \
                 audit completeness is a security property (ADR §3.1)"
            );
        }
        if let Err(e) = self.tx.try_send(record) {
            tracing::warn!(error = %e, "AUDIT: record dropped — channel full");
        }
    }

    /// Replace the signing key (e.g., after KEK rotation).
    pub async fn rotate_key(&self, new_key: AuditHmacKey) {
        *self.key.lock().await = new_key;
    }
}

async fn forwarder_task(mut rx: mpsc::Receiver<AuditRecord>, key: Arc<Mutex<AuditHmacKey>>) {
    while let Some(record) = rx.recv().await {
        let json = match serde_json::to_string(&record) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, "AUDIT: failed to serialise record");
                continue;
            }
        };
        let hmac = {
            let k = key.lock().await;
            match k.sign(json.as_bytes()) {
                Ok(mac) => mac,
                Err(e) => {
                    tracing::error!(error = %e, "AUDIT: failed to sign record");
                    continue;
                }
            }
        };
        let hmac_hex: String = hmac.iter().map(|b| format!("{b:02x}")).collect();
        tracing::info!(
            event_type = record.event_type,
            actor = record.actor,
            node_id = record.node_id,
            dek_version = record.dek_version,
            hmac = hmac_hex,
            "AUDIT: {}",
            json,
        );
    }
}
