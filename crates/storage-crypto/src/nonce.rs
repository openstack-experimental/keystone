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
//! # Durable nonce counter for Raft log encryption
//!
//! Log entry nonces follow the scheme (ADR §2.2, F1):
//! ```text
//! [8-byte NodeId BE] ++ [4-byte monotonic counter BE]
//! ```
//!
//! The counter must be unique for every log encryption under the same Log
//! DEK and must survive crashes without reuse.  This is achieved via
//! **forward reservation**:
//!
//! 1. On startup, a reservation block of [`RESERVE_BLOCK`] is pre-committed to
//!    durable storage.  The in-memory counter starts at the PREVIOUS
//!    reservation point, so the new reservation covers the next range.
//! 2. Each call to [`NonceManager::next_nonce`] returns the current counter and
//!    advances it.  When the in-memory counter reaches the end of the current
//!    reserved block, a new block is committed.
//! 3. After each reservation write, the value is read back and compared; a
//!    mismatch causes [`CryptoError::NonceReadbackMismatch`].
//! 4. A High-Water Mark (`hwm`) records the largest reservation ever written.
//!    On startup, if the persisted counter is strictly less than the HWM,
//!    [`CryptoError::NonceCounterRollback`] is returned and the node must not
//!    start.
//!
//! ## Per-epoch counters
//!
//! The counter space is scoped to a DEK epoch (`_meta:nonce:<node_id>:ctr:
//! <epoch>`): a new Log DEK starts its own counter, so a DEK rotation frees
//! the nonce space. [`NonceManager::switch_epoch`] moves to the counter of
//! another epoch. A counter is never reset, so an epoch that becomes current
//! again (for example after a restore) continues where it stopped.
//!
//! Nodes that ran before per-epoch counters used a single per-node counter
//! (`_meta:nonce_ctr:<node_id>`) for every epoch. On first start the epoch
//! that is current at that moment is recorded as the legacy bound; every
//! epoch up to that bound starts no lower than the legacy counter, since any
//! of them may have used it.
//!
//! ## Rotation threshold
//!
//! When the counter approaches `2^31` ([`ROTATION_THRESHOLD`]), a `WARN` is
//! emitted at 10% remaining (at most once per [`WARN_INTERVAL`];
//! [`NonceManager::rotation_due`] turns true, which the storage layer uses to
//! trigger an automatic DEK rotation) and [`CryptoError::NonceExhausted`] is
//! returned when the threshold is reached. The counter is exposed through
//! [`NonceManager::counter`] and [`NonceManager::remaining`] for monitoring.

use std::time::{Duration, Instant};

use tracing::{error, warn};

use crate::error::CryptoError;

/// Nonces per reservation block.  Absorbs crashes without consuming the
/// entire counter space.
const RESERVE_BLOCK: u32 = 1024;

/// Maximum counter value before DEK rotation is mandatory (2^31).
pub const ROTATION_THRESHOLD: u32 = 1u32 << 31;

/// Warn (and request a DEK rotation) when this many counter values remain
/// before the threshold.
pub const WARN_REMAINING: u32 = ROTATION_THRESHOLD / 10;

/// Minimum interval between two "approaching rotation threshold" warnings.
///
/// Once inside the warning window every log append would otherwise emit a
/// `WARN`, i.e. potentially thousands of lines per second.
const WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Persistence back-end used by [`NonceManager`].
///
/// Implemented by the storage crate against the Fjall meta keyspace.  The
/// interface is kept small and synchronous to keep the nonce manager testable
/// without a real database.
pub trait NoncePersistence: Send + Sync {
    /// Flush any pending writes to durable storage.
    fn flush(&self) -> Result<(), CryptoError>;

    /// Read a `u64` value stored under `key`, or `None` if absent.
    fn read_u64(&self, key: &str) -> Result<Option<u64>, CryptoError>;

    /// Atomically write a `u64` value under `key`.
    fn write_u64(&self, key: &str, value: u64) -> Result<(), CryptoError>;
}

/// Durable, crash-safe nonce manager for log encryption.
pub struct NonceManager {
    /// End of the currently reserved block (exclusive).
    block_end: u32,
    /// Next counter value to issue.
    counter: u32,
    /// DEK epoch the counter belongs to.
    epoch: u32,
    /// When the last "approaching rotation threshold" warning was emitted.
    last_warn: Option<Instant>,
    node_id: u64,
    storage: Box<dyn NoncePersistence>,
}

impl NonceManager {
    /// Next counter value to issue for the current epoch.
    pub fn counter(&self) -> u32 {
        self.counter
    }

    /// DEK epoch the counter currently belongs to.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Initialize the nonce manager for a given `node_id` and DEK `epoch`.
    ///
    /// Reads persisted state, validates against the HWM, then immediately
    /// reserves the next block.
    pub fn new(
        node_id: u64,
        epoch: u32,
        storage: Box<dyn NoncePersistence>,
    ) -> Result<Self, CryptoError> {
        let start = load_counter(storage.as_ref(), node_id, epoch)?;
        let mut mgr = Self {
            node_id,
            epoch,
            counter: start,
            block_end: start,
            last_warn: None,
            storage,
        };

        // Reserve the first block immediately.
        mgr.reserve_block()?;

        Ok(mgr)
    }

    /// Return the next 12-byte nonce and advance the counter.
    ///
    /// Layout: `[node_id_u64_BE; 8] ++ [counter_u32_BE; 4]`.
    pub fn next_nonce(&mut self) -> Result<[u8; 12], CryptoError> {
        if self.counter >= ROTATION_THRESHOLD {
            return Err(CryptoError::NonceExhausted);
        }
        let remaining = ROTATION_THRESHOLD - self.counter;
        if remaining <= WARN_REMAINING
            && self
                .last_warn
                .is_none_or(|last| last.elapsed() >= WARN_INTERVAL)
        {
            self.last_warn = Some(Instant::now());
            warn!(
                node_id = self.node_id,
                epoch = self.epoch,
                counter = self.counter,
                remaining,
                threshold = ROTATION_THRESHOLD,
                "nonce counter approaching rotation threshold — DEK rotation required soon"
            );
        }

        let current = self.counter;
        self.counter = self.counter.saturating_add(1);

        // Replenish reservation when we exhaust the current block.
        if self.counter >= self.block_end {
            self.reserve_block()?;
        }

        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.node_id.to_be_bytes());
        nonce[8..].copy_from_slice(&current.to_be_bytes());
        Ok(nonce)
    }

    /// Counter values left before [`CryptoError::NonceExhausted`] is
    /// returned and a DEK rotation becomes mandatory.
    pub fn remaining(&self) -> u32 {
        ROTATION_THRESHOLD.saturating_sub(self.counter)
    }

    /// Reserve the next block by persisting the new block-end and updating HWM.
    fn reserve_block(&mut self) -> Result<(), CryptoError> {
        let new_end = self
            .counter
            .checked_add(RESERVE_BLOCK)
            .ok_or(CryptoError::NonceExhausted)?;

        let ctr_key = nonce_ctr_key(self.node_id, self.epoch);
        let hwm_key = nonce_hwm_key(self.node_id, self.epoch);

        self.storage.write_u64(&ctr_key, new_end as u64)?;
        self.storage.flush()?;

        // Read-back verification (ADR §2.2).
        let readback = self.storage.read_u64(&ctr_key)?;
        if readback != Some(new_end as u64) {
            error!(
                node_id = self.node_id,
                epoch = self.epoch,
                expected = new_end,
                got = ?readback,
                "nonce counter read-back mismatch — storage error"
            );
            return Err(CryptoError::NonceReadbackMismatch);
        }

        // Update HWM (only ever increases).
        let current_hwm = self.storage.read_u64(&hwm_key)?.unwrap_or(0) as u32;
        if new_end > current_hwm {
            self.storage.write_u64(&hwm_key, new_end as u64)?;
            self.storage.flush()?;
        }

        self.block_end = new_end;
        Ok(())
    }

    /// Whether the counter of the current epoch has entered the last 10%
    /// before [`ROTATION_THRESHOLD`], i.e. the DEK must be rotated.
    pub fn rotation_due(&self) -> bool {
        self.counter >= ROTATION_THRESHOLD - WARN_REMAINING
    }

    /// Continue with the counter of `epoch`. A no-op when it is already the
    /// current one.
    pub fn switch_epoch(&mut self, epoch: u32) -> Result<(), CryptoError> {
        if epoch == self.epoch {
            return Ok(());
        }
        let start = load_counter(self.storage.as_ref(), self.node_id, epoch)?;
        self.epoch = epoch;
        self.counter = start;
        self.block_end = start;
        self.reserve_block()
    }
}

/// Read the persisted counter (the end of the last reserved block) for
/// `node_id` in DEK `epoch` without reserving anything, for status reporting.
///
/// The value is at most [`RESERVE_BLOCK`] ahead of the last nonce issued.
pub fn persisted_counter(
    storage: &dyn NoncePersistence,
    node_id: u64,
    epoch: u32,
) -> Result<u64, CryptoError> {
    Ok(storage
        .read_u64(&nonce_ctr_key(node_id, epoch))?
        .unwrap_or(0))
}

/// Recover the first counter value that may be issued for `epoch`.
fn load_counter(
    storage: &dyn NoncePersistence,
    node_id: u64,
    epoch: u32,
) -> Result<u32, CryptoError> {
    let ctr = storage.read_u64(&nonce_ctr_key(node_id, epoch))?;
    let hwm = storage.read_u64(&nonce_hwm_key(node_id, epoch))?;
    match (ctr, hwm) {
        (None, None) => legacy_floor(storage, node_id, epoch),
        (ctr, hwm) => {
            let ctr = ctr.unwrap_or(0) as u32;
            let hwm = hwm.unwrap_or(0) as u32;
            // Detect counter rollback: recovered start must not be strictly
            // behind HWM.
            if ctr < hwm {
                return Err(CryptoError::NonceCounterRollback {
                    current: ctr as u64,
                    hwm: hwm as u64,
                });
            }
            Ok(ctr)
        }
    }
}

/// Lowest counter value an epoch without its own counter may start at: the
/// pre-per-epoch counter for every epoch up to the legacy bound, zero above
/// it. The bound is recorded the first time it is needed.
fn legacy_floor(
    storage: &dyn NoncePersistence,
    node_id: u64,
    epoch: u32,
) -> Result<u32, CryptoError> {
    let ctr_key = legacy_nonce_ctr_key(node_id);
    let hwm_key = legacy_nonce_hwm_key(node_id);
    let (Some(ctr), hwm) = (storage.read_u64(&ctr_key)?, storage.read_u64(&hwm_key)?) else {
        return Ok(0);
    };
    let hwm = hwm.unwrap_or(0);
    if ctr < hwm {
        return Err(CryptoError::NonceCounterRollback { current: ctr, hwm });
    }

    let bound_key = legacy_epoch_key(node_id);
    let bound = match storage.read_u64(&bound_key)? {
        Some(bound) => bound,
        None => {
            storage.write_u64(&bound_key, epoch as u64)?;
            storage.flush()?;
            epoch as u64
        }
    };
    if epoch as u64 <= bound {
        u32::try_from(ctr).map_err(|_| CryptoError::NonceExhausted)
    } else {
        Ok(0)
    }
}

/// Prefix of every node-local nonce entry of `node_id` in the meta keyspace.
pub fn nonce_meta_prefix(node_id: u64) -> String {
    format!("_meta:nonce:{node_id}:")
}

fn nonce_ctr_key(node_id: u64, epoch: u32) -> String {
    format!("{}ctr:{epoch}", nonce_meta_prefix(node_id))
}

fn nonce_hwm_key(node_id: u64, epoch: u32) -> String {
    format!("{}hwm:{epoch}", nonce_meta_prefix(node_id))
}

fn legacy_epoch_key(node_id: u64) -> String {
    format!("{}legacy_epoch", nonce_meta_prefix(node_id))
}

fn legacy_nonce_ctr_key(node_id: u64) -> String {
    format!("_meta:nonce_ctr:{node_id}")
}

fn legacy_nonce_hwm_key(node_id: u64) -> String {
    format!("_meta:nonce_hwm:{node_id}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// In-memory persistence back-end for tests.
    #[derive(Clone, Default)]
    struct MemNonce(Arc<Mutex<HashMap<String, u64>>>);

    impl NoncePersistence for MemNonce {
        fn read_u64(&self, key: &str) -> Result<Option<u64>, CryptoError> {
            Ok(self.0.lock().expect("lock").get(key).copied())
        }

        fn write_u64(&self, key: &str, value: u64) -> Result<(), CryptoError> {
            self.0.lock().expect("lock").insert(key.to_string(), value);
            Ok(())
        }

        fn flush(&self) -> Result<(), CryptoError> {
            Ok(())
        }
    }

    fn make_mgr(node_id: u64) -> NonceManager {
        NonceManager::new(node_id, 1, Box::new(MemNonce::default())).expect("init")
    }

    #[test]
    fn test_nonces_unique_and_sequential() {
        let mut mgr = make_mgr(1);
        let n1 = mgr.next_nonce().expect("n1");
        let n2 = mgr.next_nonce().expect("n2");
        assert_ne!(n1, n2);
        // Counter part (bytes 8..12) increments by 1.
        let c1 = u32::from_be_bytes(n1[8..].try_into().expect("4b"));
        let c2 = u32::from_be_bytes(n2[8..].try_into().expect("4b"));
        assert_eq!(c2, c1 + 1);
    }

    #[test]
    fn test_node_id_in_nonce() {
        let mut mgr = make_mgr(0xDEADBEEF_CAFEBABE);
        let n = mgr.next_nonce().expect("nonce");
        let stored_id = u64::from_be_bytes(n[..8].try_into().expect("8b"));
        assert_eq!(stored_id, 0xDEADBEEF_CAFEBABE);
    }

    #[test]
    fn test_reservation_replenishment() {
        let mut mgr = make_mgr(42);
        // Exhaust the first block.
        for _ in 0..RESERVE_BLOCK {
            mgr.next_nonce().expect("nonce");
        }
        // Must succeed (new block reserved).
        mgr.next_nonce().expect("after block boundary");
    }

    #[test]
    fn test_nonce_exhausted_at_rotation_threshold() {
        let mut mgr = make_mgr(7);
        // Drive the counter directly to the rotation threshold rather than
        // issuing 2^31 nonces.
        mgr.counter = ROTATION_THRESHOLD;
        mgr.block_end = ROTATION_THRESHOLD;
        assert!(matches!(mgr.next_nonce(), Err(CryptoError::NonceExhausted)));
    }

    #[test]
    fn test_counter_and_remaining() {
        let mut mgr = make_mgr(3);
        let start = mgr.counter();
        assert_eq!(mgr.remaining(), ROTATION_THRESHOLD - start);
        mgr.next_nonce().expect("nonce");
        assert_eq!(mgr.counter(), start + 1);
        assert_eq!(mgr.remaining(), ROTATION_THRESHOLD - start - 1);

        mgr.counter = ROTATION_THRESHOLD;
        assert_eq!(mgr.remaining(), 0);
    }

    #[test]
    fn test_threshold_warning_is_rate_limited() {
        let mut mgr = make_mgr(5);
        // Outside the warning window: no warning recorded.
        mgr.next_nonce().expect("nonce");
        assert!(mgr.last_warn.is_none());

        // Inside the warning window: the first call warns...
        mgr.counter = ROTATION_THRESHOLD - WARN_REMAINING;
        mgr.block_end = mgr.counter + RESERVE_BLOCK;
        mgr.next_nonce().expect("nonce");
        let first = mgr.last_warn.expect("warning emitted");

        // ...and subsequent calls within WARN_INTERVAL stay silent.
        for _ in 0..10 {
            mgr.next_nonce().expect("nonce");
        }
        assert_eq!(mgr.last_warn, Some(first));
    }

    #[test]
    fn test_rollback_detection() {
        let store = MemNonce::default();
        // Simulate a previous session that reached counter 2048 (hwm = 2048).
        store.write_u64("_meta:nonce:1:ctr:1", 2048).expect("write");
        store
            .write_u64("_meta:nonce:1:hwm:1", 2048)
            .expect("write hwm");

        // Normal restart: ctr == hwm (not strictly less) → OK.
        let mut mgr = NonceManager::new(1, 1, Box::new(store.clone())).expect("ok");
        mgr.next_nonce().expect("nonce after normal restart");

        // Simulate rollback: someone set ctr back to 512 < hwm 2048.
        store.write_u64("_meta:nonce:1:ctr:1", 512).expect("write");
        // hwm still 2048 or higher after mgr above wrote new reservation.
        let result = NonceManager::new(1, 1, Box::new(store));
        assert!(matches!(
            result,
            Err(CryptoError::NonceCounterRollback { .. })
        ));
    }

    fn counter_of(nonce: &[u8; 12]) -> u32 {
        u32::from_be_bytes(nonce[8..].try_into().expect("4b"))
    }

    #[test]
    fn test_new_epoch_starts_its_own_counter() {
        let store = MemNonce::default();
        let mut mgr = NonceManager::new(1, 1, Box::new(store.clone())).expect("init");
        for _ in 0..10 {
            mgr.next_nonce().expect("nonce");
        }
        mgr.switch_epoch(2).expect("switch");
        assert_eq!(2, mgr.epoch());
        assert_eq!(0, counter_of(&mgr.next_nonce().expect("nonce")));
    }

    #[test]
    fn test_epoch_counter_resumes_after_switch_back() {
        let store = MemNonce::default();
        let mut mgr = NonceManager::new(1, 1, Box::new(store.clone())).expect("init");
        let last = (0..10)
            .map(|_| counter_of(&mgr.next_nonce().expect("nonce")))
            .last()
            .expect("last");
        mgr.switch_epoch(2).expect("switch");
        mgr.next_nonce().expect("nonce");
        mgr.switch_epoch(1).expect("switch back");
        // Never below what epoch 1 already issued.
        assert!(counter_of(&mgr.next_nonce().expect("nonce")) > last);

        // Same after a restart.
        let mut mgr = NonceManager::new(1, 1, Box::new(store)).expect("restart");
        assert!(counter_of(&mgr.next_nonce().expect("nonce")) > last);
    }

    #[test]
    fn test_legacy_counter_floors_epochs_up_to_bound() {
        let store = MemNonce::default();
        // A node that ran with the single per-node counter.
        store.write_u64("_meta:nonce_ctr:1", 5000).expect("write");
        store.write_u64("_meta:nonce_hwm:1", 5000).expect("write");

        // First start after the upgrade with epoch 3 current.
        let mut mgr = NonceManager::new(1, 3, Box::new(store.clone())).expect("init");
        assert_eq!(5000, counter_of(&mgr.next_nonce().expect("nonce")));
        assert_eq!(
            Some(3),
            store.read_u64("_meta:nonce:1:legacy_epoch").expect("read")
        );

        // An older epoch (e.g. restored) may have used the legacy counter.
        mgr.switch_epoch(2).expect("switch");
        assert_eq!(5000, counter_of(&mgr.next_nonce().expect("nonce")));

        // A newer epoch never did.
        mgr.switch_epoch(4).expect("switch");
        assert_eq!(0, counter_of(&mgr.next_nonce().expect("nonce")));
    }

    #[test]
    fn test_legacy_counter_rollback_detected() {
        let store = MemNonce::default();
        store.write_u64("_meta:nonce_ctr:1", 512).expect("write");
        store.write_u64("_meta:nonce_hwm:1", 2048).expect("write");
        assert!(matches!(
            NonceManager::new(1, 1, Box::new(store)),
            Err(CryptoError::NonceCounterRollback { .. })
        ));
    }

    #[test]
    fn test_rotation_due_near_threshold() {
        let mut mgr = make_mgr(7);
        assert!(!mgr.rotation_due());
        mgr.counter = ROTATION_THRESHOLD - WARN_REMAINING;
        assert!(mgr.rotation_due());
    }

    #[test]
    fn test_persisted_counter_reports_reservation() {
        let store = MemNonce::default();
        assert_eq!(persisted_counter(&store, 7, 1).expect("read"), 0);
        let mut mgr = NonceManager::new(7, 1, Box::new(store.clone())).expect("init");
        mgr.next_nonce().expect("nonce");
        assert_eq!(
            persisted_counter(&store, 7, 1).expect("read"),
            u64::from(RESERVE_BLOCK)
        );
        // Other nodes' and epochs' counters are separate.
        assert_eq!(persisted_counter(&store, 8, 1).expect("read"), 0);
        assert_eq!(persisted_counter(&store, 7, 2).expect("read"), 0);
    }
}
