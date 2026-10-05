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
//! `AuditDispatcher` — dual-channel QoS dispatch with HMAC-SHA256 signing.
//!
//! The dispatcher owns two `mpsc` channels:
//! - `perimeter` (capacity 4096): best-effort, drops on full.
//! - `critical` (capacity 256): fail-closed, blocks until sent.
//!
//! HMAC signing uses JCS canonical form (RFC 8785): all payload fields
//! serialized with keys in lexicographic order, compact, no extra whitespace,
//! `null`-valued optional fields included. This is the sole canonical form;
//! SIEMs must reproduce it exactly for verification.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::sync::mpsc;
use tracing::error;

use crate::metrics::AuditMetrics;
use crate::types::{CadfEvent, CadfEventPayload};

type HmacSha256 = Hmac<Sha256>;

/// Default capacity of the best-effort perimeter channel.
pub const DEFAULT_PERIMETER_CHANNEL_CAPACITY: usize = 4096;
/// Default capacity of the fail-closed critical channel.
pub const DEFAULT_CRITICAL_CHANNEL_CAPACITY: usize = 256;

/// Returned when the critical channel's receiver has been dropped.
#[derive(Debug, thiserror::Error)]
#[error("audit critical channel is dead")]
pub struct AuditChannelDead;

/// Receivers returned by `AuditDispatcherBuilder::build`.
pub struct AuditChannelReceivers {
    pub perimeter: mpsc::Receiver<CadfEvent>,
    pub critical: mpsc::Receiver<CadfEvent>,
}

/// Central audit dispatcher.
pub struct AuditDispatcher {
    perimeter_sender: mpsc::Sender<CadfEvent>,
    critical_sender: mpsc::Sender<CadfEvent>,
    pub(crate) node_id: Arc<str>,
    hmac_key_and_version: ArcSwap<(Arc<[u8]>, u64)>,
    pub(crate) boot_session_id: String,
    seq_counter: AtomicU64,
    pub(crate) dropped_count: Arc<AtomicU64>,
    last_drop_log_time: AtomicU64,
    log_baseline: std::time::Instant,
    pub(crate) postaudit_dropped_count: Arc<AtomicU64>,
    pub(crate) events_total: Arc<AtomicU64>,
    pub(crate) spool_bytes: Arc<AtomicU64>,
    /// When `false` every dispatch is a successful no-op.
    enabled: bool,
    metrics: Arc<AuditMetrics>,
}

impl AuditDispatcher {
    /// Create a no-op dispatcher for use in tests.
    ///
    /// The channel receivers are dropped immediately; all events dispatched
    /// will be silently discarded.
    #[cfg(any(test, feature = "testing"))]
    pub fn noop() -> Arc<Self> {
        let key: Arc<[u8]> = Arc::from(b"noop-test-key".as_slice());
        let (dispatcher, _receivers) =
            Self::new("noop-node", uuid::Uuid::new_v4().to_string(), key, 0);
        dispatcher
    }

    /// Create a dispatcher for deployments with auditing disabled
    /// (`[audit] enabled = false`).
    ///
    /// Unlike [`AuditDispatcher::noop`] this never reports a dead channel:
    /// both [`dispatch`](Self::dispatch) and
    /// [`dispatch_critical`](Self::dispatch_critical) succeed and discard the
    /// event, so fail-closed provider auditing does not reject operations.
    /// Nothing is written to disk and no counter is incremented.
    pub fn disabled(node_id: impl Into<Arc<str>>) -> Arc<Self> {
        let key: Arc<[u8]> = Arc::from(b"audit-disabled".as_slice());
        let (dispatcher, _receivers) = Self::build(
            false,
            node_id,
            uuid::Uuid::new_v4().to_string(),
            key,
            0,
            DEFAULT_PERIMETER_CHANNEL_CAPACITY,
            DEFAULT_CRITICAL_CHANNEL_CAPACITY,
        );
        dispatcher
    }

    /// Whether events are actually recorded.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Create a new dispatcher. Returns the dispatcher and its two channel
    /// receivers for the background spool workers.
    pub fn new(
        node_id: impl Into<Arc<str>>,
        boot_session_id: String,
        hmac_key: Arc<[u8]>,
        hmac_key_version: u64,
    ) -> (Arc<Self>, AuditChannelReceivers) {
        Self::with_capacities(
            node_id,
            boot_session_id,
            hmac_key,
            hmac_key_version,
            DEFAULT_PERIMETER_CHANNEL_CAPACITY,
            DEFAULT_CRITICAL_CHANNEL_CAPACITY,
        )
    }

    /// Like [`AuditDispatcher::new`] with explicit channel capacities.
    ///
    /// A capacity of `0` is raised to `1` (a Tokio channel needs at least one
    /// slot).
    pub fn with_capacities(
        node_id: impl Into<Arc<str>>,
        boot_session_id: String,
        hmac_key: Arc<[u8]>,
        hmac_key_version: u64,
        perimeter_capacity: usize,
        critical_capacity: usize,
    ) -> (Arc<Self>, AuditChannelReceivers) {
        Self::build(
            true,
            node_id,
            boot_session_id,
            hmac_key,
            hmac_key_version,
            perimeter_capacity,
            critical_capacity,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        enabled: bool,
        node_id: impl Into<Arc<str>>,
        boot_session_id: String,
        hmac_key: Arc<[u8]>,
        hmac_key_version: u64,
        perimeter_capacity: usize,
        critical_capacity: usize,
    ) -> (Arc<Self>, AuditChannelReceivers) {
        let (perimeter_tx, perimeter_rx) = mpsc::channel(perimeter_capacity.max(1));
        let (critical_tx, critical_rx) = mpsc::channel(critical_capacity.max(1));
        let dispatcher = Arc::new(Self {
            perimeter_sender: perimeter_tx,
            critical_sender: critical_tx,
            node_id: node_id.into(),
            hmac_key_and_version: ArcSwap::new(Arc::new((hmac_key, hmac_key_version))),
            boot_session_id,
            seq_counter: AtomicU64::new(0),
            dropped_count: Arc::new(AtomicU64::new(0)),
            last_drop_log_time: AtomicU64::new(0),
            log_baseline: std::time::Instant::now(),
            postaudit_dropped_count: Arc::new(AtomicU64::new(0)),
            events_total: Arc::new(AtomicU64::new(0)),
            spool_bytes: Arc::new(AtomicU64::new(0)),
            enabled,
            metrics: Arc::new(AuditMetrics::default()),
        });
        let receivers = AuditChannelReceivers {
            perimeter: perimeter_rx,
            critical: critical_rx,
        };
        (dispatcher, receivers)
    }

    /// Finalize an unsigned payload: fill `seq`, `boot_session_id`,
    /// `hmac_key_version`, then compute the HMAC signature.
    ///
    /// Called by `CadfEventPayload::sign`.
    pub(crate) fn finalize_event(&self, partial: CadfEventPayload) -> CadfEvent {
        let guard = self.hmac_key_and_version.load();
        let (key, version) = guard.as_ref();
        let completed = CadfEventPayload {
            seq: self.seq_counter.fetch_add(1, Ordering::SeqCst),
            boot_session_id: self.boot_session_id.clone(),
            hmac_key_version: *version,
            ..partial
        };
        let sig = compute_hmac_sha256(&completed, key);
        CadfEvent {
            event: completed,
            signature: sig,
        }
    }

    /// Best-effort dispatch to the perimeter channel. Drops if full.
    ///
    /// Floor-rate logs: at least once per second, and on every 1024th drop.
    pub fn dispatch(&self, event: CadfEvent) {
        if !self.enabled {
            return;
        }
        let cid = event.correlation_id().to_string();
        if self.perimeter_sender.try_send(event).is_ok() {
            self.events_total.fetch_add(1, Ordering::Relaxed);
        } else {
            let count = self.dropped_count.fetch_add(1, Ordering::Relaxed);
            let now_us = self.log_baseline.elapsed().as_micros() as u64;
            let should_log = count.is_multiple_of(1024)
                || (self.last_drop_log_time.load(Ordering::Relaxed) + 1_000_000) <= now_us;
            if should_log {
                self.last_drop_log_time.store(now_us, Ordering::Relaxed);
                error!(
                    dropped_count = count,
                    correlation_id = %cid,
                    "audit channel full, event dropped (best-effort)"
                );
            }
        }
    }

    /// Fail-closed dispatch to the critical channel. Blocks until sent.
    pub async fn dispatch_critical(&self, event: CadfEvent) -> Result<(), AuditChannelDead> {
        if !self.enabled {
            return Ok(());
        }
        self.critical_sender
            .send(event)
            .await
            .map_err(|_| AuditChannelDead)?;
        self.events_total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Rotate the HMAC key.
    ///
    /// MUST be called from a single serialized context (dedicated key-rotation
    /// task). Concurrent invocations produce version collisions (two different
    /// keys sharing the same version), breaking SIEM verification. The version
    /// number is supplied by the caller, not derived here, to make the
    /// serialization requirement explicit.
    ///
    /// # Key retention gap (ADR 0023 §"Key Rotation")
    ///
    /// This method atomically swaps the **active** signing key but does NOT
    /// retain the previous key version. Any spool events that were signed with
    /// the old key version and have not yet been drained will fail HMAC
    /// verification during the next `verify_sealed_spool` call unless the
    /// caller separately persists old key versions in its `HmacKeyStore`.
    ///
    /// Callers performing key rotation MUST:
    /// 1. Persist the new key to stable storage under `new_version`.
    /// 2. Retain the old key(s) in their `HmacKeyStore` for at least
    ///    `max(spool_drain_timeout + SIEM_lag_budget, 24 h)`.
    /// 3. Only increment `new_version` monotonically (never reuse a version).
    pub fn refresh_hmac_key(&self, new_key: Arc<[u8]>, new_version: u64) {
        self.hmac_key_and_version
            .store(Arc::new((new_key, new_version)));
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn boot_session_id(&self) -> &str {
        &self.boot_session_id
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    pub fn postaudit_dropped_count(&self) -> u64 {
        self.postaudit_dropped_count.load(Ordering::Relaxed)
    }

    /// Shared handle to the post-audit drop counter, so the provider event
    /// dispatcher can feed the exported metric.
    pub fn postaudit_dropped_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.postaudit_dropped_count)
    }

    /// Record a post-audit outcome loss (called by the CADF hook when the
    /// critical channel is dead).
    pub fn record_postaudit_drop(&self) {
        self.postaudit_dropped_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Total bytes in the live spool and sealed segments, maintained by the
    /// spool writer.
    pub fn spool_bytes(&self) -> u64 {
        self.spool_bytes.load(Ordering::Relaxed)
    }

    /// Shared handle the spool writer keeps up to date.
    pub fn spool_bytes_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.spool_bytes)
    }

    /// Counters maintained by the spool writer, verifier and shipper.
    pub fn metrics(&self) -> &Arc<AuditMetrics> {
        &self.metrics
    }

    /// Version of the HMAC key currently signing events.
    pub fn hmac_key_version(&self) -> u64 {
        self.hmac_key_and_version.load().1
    }

    /// Events currently queued in the `(perimeter, critical)` channels.
    pub fn channel_depths(&self) -> (usize, usize) {
        (
            self.perimeter_sender.max_capacity() - self.perimeter_sender.capacity(),
            self.critical_sender.max_capacity() - self.critical_sender.capacity(),
        )
    }

    /// Events accepted into a channel (drops excluded).
    pub fn events_total(&self) -> u64 {
        self.events_total.load(Ordering::Relaxed)
    }

    /// Verify an event's signature using a specific key (for spool replay).
    ///
    /// The comparison is constant-time, and a signature that is not valid hex
    /// of the right length simply fails verification.
    pub fn verify_hmac(&self, event: &CadfEvent, key: &[u8]) -> bool {
        let Some(signature) = crate::keyring::decode_hex(&event.signature) else {
            return false;
        };
        let canonical = jcs_canonical(&event.event);
        let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
            return false;
        };
        mac.update(canonical.as_bytes());
        mac.verify_slice(&signature).is_ok()
    }
}

/// Compute HMAC-SHA256 over the JCS-canonical (RFC 8785) serialization of
/// `payload`.
///
/// JCS requires object keys sorted lexicographically (Unicode code point
/// order) and compact form (no extra whitespace).
///
/// # Field inclusion
///
/// Fields follow their individual `serde` annotations.  Most `Option`-typed
/// fields (`outcome_reason`, `Initiator.project_id`, `Initiator.domain_id`)
/// serialize as `null` when `None`.  `Initiator.host` uses
/// `skip_serializing_if = "Option::is_none"` and is **omitted entirely**
/// when absent — not set to `null`.  SIEMs MUST reproduce this exact
/// behavior: re-serialize the received JSON (after removing `signature`)
/// without inserting absent fields.
///
/// We achieve key ordering by round-tripping through `serde_json::Value`
/// and sorting object keys recursively before re-serializing. This is
/// correct for flat and nested JSON objects.
pub(crate) fn compute_hmac_sha256(payload: &CadfEventPayload, key: &[u8]) -> String {
    let canonical = jcs_canonical(payload);
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts any key length; keys are always 32-byte HKDF-derived");
    mac.update(canonical.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Serialize `payload` to JCS-canonical JSON (RFC 8785 §3.2.3):
/// object keys sorted lexicographically at every nesting level.
/// See `compute_hmac_sha256` for the field-inclusion rules (notably
/// `Initiator.host` is omitted, not null'd, when absent).
fn jcs_canonical(payload: &CadfEventPayload) -> String {
    #[allow(clippy::expect_used)]
    let value = payload
        .to_wire_value()
        .expect("CadfEventPayload is always serializable");
    sort_json_keys(value).to_string()
}

/// Recursively sort object keys in a `serde_json::Value`.
fn sort_json_keys(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            // BTreeMap maintains lexicographic order.
            let sorted: serde_json::Map<String, Value> = map
                .into_iter()
                .map(|(k, v)| (k, sort_json_keys(v)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect();
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_json_keys).collect()),
        other => other,
    }
}

// hex encoding helper (avoids an extra crate dependency — inline impl)
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Initiator, Observer, Target};
    use uuid::Uuid;

    fn make_dispatcher() -> Arc<AuditDispatcher> {
        let key: Arc<[u8]> = Arc::from(b"test-key-32-bytes-0123456789abcd".as_slice());
        let (d, _rx) = AuditDispatcher::new("node-1", Uuid::new_v4().to_string(), key, 1);
        d
    }

    #[test]
    fn channel_capacities_are_configurable() {
        let key: Arc<[u8]> = Arc::from(b"test-key-32-bytes-0123456789abcd".as_slice());
        let (d, _rx) =
            AuditDispatcher::with_capacities("node-1", Uuid::new_v4().to_string(), key, 1, 2, 1);
        for _ in 0..5 {
            d.dispatch(make_payload(&d).sign(&d));
        }
        // Two fit in the perimeter channel; the other three are dropped.
        assert_eq!(d.dropped_count(), 3);
    }

    #[tokio::test]
    async fn disabled_dispatcher_accepts_and_discards_events() {
        let d = AuditDispatcher::disabled("node-1");
        assert!(!d.is_enabled());
        d.dispatch(make_payload(&d).sign(&d));
        d.dispatch_critical(make_payload(&d).sign(&d))
            .await
            .expect("a disabled dispatcher never reports a dead channel");
        assert_eq!(d.events_total(), 0);
        assert_eq!(d.dropped_count(), 0);
    }

    fn make_payload(dispatcher: &AuditDispatcher) -> CadfEventPayload {
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
    }

    #[test]
    fn finalize_fills_seq_and_boot_session_id() {
        let dispatcher = make_dispatcher();
        let payload = make_payload(&dispatcher);
        let event = dispatcher.finalize_event(payload);
        assert_eq!(event.seq(), 0);
        assert_eq!(event.boot_session_id(), dispatcher.boot_session_id());
        assert!(!event.signature().is_empty());
    }

    #[test]
    fn seq_is_monotonically_increasing() {
        let dispatcher = make_dispatcher();
        let e1 = dispatcher.finalize_event(make_payload(&dispatcher));
        let e2 = dispatcher.finalize_event(make_payload(&dispatcher));
        assert_eq!(e2.seq(), e1.seq() + 1);
    }

    #[test]
    fn verify_hmac_succeeds_for_fresh_event() {
        let key: Arc<[u8]> = Arc::from(b"test-key-32-bytes-0123456789abcd".as_slice());
        let (dispatcher, _rx) =
            AuditDispatcher::new("node-1", Uuid::new_v4().to_string(), Arc::clone(&key), 1);
        let event = dispatcher.finalize_event(make_payload(&dispatcher));
        assert!(dispatcher.verify_hmac(&event, &key));
    }

    #[test]
    fn verify_hmac_fails_for_tampered_signature() {
        let key: Arc<[u8]> = Arc::from(b"test-key-32-bytes-0123456789abcd".as_slice());
        let (dispatcher, _rx) =
            AuditDispatcher::new("node-1", Uuid::new_v4().to_string(), Arc::clone(&key), 1);
        let mut event = dispatcher.finalize_event(make_payload(&dispatcher));
        event.signature = "deadbeef".to_string();
        assert!(!dispatcher.verify_hmac(&event, &key));
    }

    #[test]
    fn verify_hmac_rejects_malformed_signatures() {
        let key: Arc<[u8]> = Arc::from(b"test-key-32-bytes-0123456789abcd".as_slice());
        let (dispatcher, _rx) =
            AuditDispatcher::new("node-1", Uuid::new_v4().to_string(), Arc::clone(&key), 1);
        let good = dispatcher.finalize_event(make_payload(&dispatcher));
        for bad in [
            "",
            "zz",
            "not hex at all",
            // Right length, wrong content.
            &"00".repeat(32),
            // Valid prefix of the real signature.
            &good.signature[..good.signature.len() - 2],
            // Non-ASCII must not panic while slicing.
            "\u{e9}\u{e9}",
        ] {
            let mut event = good.clone();
            event.signature = bad.to_string();
            assert!(!dispatcher.verify_hmac(&event, &key), "accepted {bad:?}");
        }
        assert!(dispatcher.verify_hmac(&good, &key));
    }

    #[test]
    fn jcs_canonical_sorts_keys() {
        let key: Arc<[u8]> = Arc::from(b"key".as_slice());
        let (dispatcher, _rx) = AuditDispatcher::new("node-1", Uuid::new_v4().to_string(), key, 1);
        let event = dispatcher.finalize_event(make_payload(&dispatcher));
        let canonical = jcs_canonical(event.payload());
        // Verify it's valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        if let serde_json::Value::Object(map) = &parsed {
            let keys: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
            let mut sorted = keys.clone();
            sorted.sort();
            assert_eq!(
                keys, sorted,
                "top-level keys must be lexicographically sorted"
            );
        } else {
            panic!("expected a JSON object");
        }
    }

    #[tokio::test]
    async fn dispatch_critical_succeeds_while_receiver_alive() {
        let key: Arc<[u8]> = Arc::from(b"key".as_slice());
        let (dispatcher, _rx) = AuditDispatcher::new("node-1", Uuid::new_v4().to_string(), key, 1);
        let event = dispatcher.finalize_event(make_payload(&dispatcher));
        dispatcher.dispatch_critical(event).await.unwrap();
    }

    #[tokio::test]
    async fn dispatch_critical_fails_when_receiver_dropped() {
        let key: Arc<[u8]> = Arc::from(b"key".as_slice());
        let (dispatcher, rx) = AuditDispatcher::new("node-1", Uuid::new_v4().to_string(), key, 1);
        drop(rx.critical);
        let event = dispatcher.finalize_event(make_payload(&dispatcher));
        assert!(dispatcher.dispatch_critical(event).await.is_err());
    }

    #[test]
    fn verify_hmac_rejects_the_wrong_key() {
        let key: Arc<[u8]> = Arc::from(b"key".as_slice());
        let (dispatcher, _rx) =
            AuditDispatcher::new("node-1", Uuid::new_v4().to_string(), Arc::clone(&key), 1);
        let event = dispatcher.finalize_event(make_payload(&dispatcher));
        assert!(dispatcher.verify_hmac(&event, &key));
        let wrong: Vec<u8> = key.iter().map(|b| !b).collect();
        assert!(!dispatcher.verify_hmac(&event, &wrong));
    }

    #[test]
    fn refresh_hmac_key_stamps_the_new_version_and_old_events_still_verify() {
        let old_key: Arc<[u8]> = Arc::from(b"old-key".as_slice());
        let new_key: Arc<[u8]> = Arc::from(b"new-key".as_slice());
        let (dispatcher, _rx) = AuditDispatcher::new(
            "node-1",
            Uuid::new_v4().to_string(),
            Arc::clone(&old_key),
            1,
        );
        let before = dispatcher.finalize_event(make_payload(&dispatcher));

        dispatcher.refresh_hmac_key(Arc::clone(&new_key), 2);
        let after = dispatcher.finalize_event(make_payload(&dispatcher));

        assert_eq!(dispatcher.hmac_key_version(), 2);
        assert_eq!(before.payload().hmac_key_version(), 1);
        assert_eq!(after.payload().hmac_key_version(), 2);
        // Each event verifies under the key of the version it names, and not
        // under the other one.
        assert!(dispatcher.verify_hmac(&before, &old_key));
        assert!(dispatcher.verify_hmac(&after, &new_key));
        assert!(!dispatcher.verify_hmac(&before, &new_key));
        assert!(!dispatcher.verify_hmac(&after, &old_key));
    }

    #[test]
    fn sequence_numbers_continue_across_a_key_rotation() {
        let key: Arc<[u8]> = Arc::from(b"k1".as_slice());
        let (dispatcher, _rx) = AuditDispatcher::new("node-1", Uuid::new_v4().to_string(), key, 1);
        let first = dispatcher.finalize_event(make_payload(&dispatcher));
        dispatcher.refresh_hmac_key(Arc::from(b"k2".as_slice()), 2);
        let second = dispatcher.finalize_event(make_payload(&dispatcher));
        assert_eq!(second.seq(), first.seq() + 1);
    }
}
