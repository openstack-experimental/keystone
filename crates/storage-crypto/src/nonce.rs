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
//! The counter must be unique for every log encryption and must survive
//! crashes without reuse.  This is achieved via **forward reservation**:
//!
//! 1. On startup, a reservation block of [`RESERVE_BLOCK`] is pre-committed
//!    to durable storage.  The in-memory counter starts at the PREVIOUS
//!    reservation point, so the new reservation covers the next range.
//! 2. Each call to [`NonceManager::next_nonce`] returns the current counter
//!    and advances it.  When the in-memory counter reaches the end of the
//!    current reserved block, a new block is committed.
//! 3. After each reservation write, the value is read back and compared; a
//!    mismatch causes [`CryptoError::NonceReadbackMismatch`].
//! 4. A High-Water Mark (`nonce_hwm`) records the largest reservation ever
//!    written.  On startup, if the persisted counter is strictly less than
//!    the HWM, [`CryptoError::NonceCounterRollback`] is returned and the
//!    node must not start.
//!
//! ## Rotation threshold
//!
//! When the counter approaches `2^31` (`ROTATION_THRESHOLD`), a `WARN` is
//! emitted at 10% remaining and [`CryptoError::NonceExhausted`] is returned
//! when the threshold is reached.  The operator must trigger a DEK rotation
//! (Phase 5) before that point.

use tracing::{error, warn};

use crate::error::CryptoError;

/// Nonces per reservation block.  Absorbs crashes without consuming the
/// entire counter space.
const RESERVE_BLOCK: u32 = 1024;

/// Maximum counter value before DEK rotation is mandatory (2^31).
const ROTATION_THRESHOLD: u32 = 1u32 << 31;

/// Warn when this many counter values remain before the threshold.
const WARN_REMAINING: u32 = ROTATION_THRESHOLD / 10;

/// Persistence back-end used by [`NonceManager`].
///
/// Implemented by the storage crate against the Fjall meta keyspace.  The
/// interface is kept small and synchronous to keep the nonce manager testable
/// without a real database.
pub trait NoncePersistence: Send + Sync {
    /// Read a `u64` value stored under `key`, or `None` if absent.
    fn read_u64(&self, key: &str) -> Result<Option<u64>, CryptoError>;

    /// Atomically write a `u64` value under `key`.
    fn write_u64(&self, key: &str, value: u64) -> Result<(), CryptoError>;

    /// Flush any pending writes to durable storage.
    fn flush(&self) -> Result<(), CryptoError>;
}

/// Durable, crash-safe nonce manager for log encryption.
pub struct NonceManager {
    node_id: u64,
    /// Next counter value to issue.
    counter: u32,
    /// End of the currently reserved block (exclusive).
    block_end: u32,
    storage: Box<dyn NoncePersistence>,
}

impl NonceManager {
    /// Initialise the nonce manager for a given `node_id`.
    ///
    /// Reads persisted state, validates against the HWM, then immediately
    /// reserves the next block.
    pub fn new(
        node_id: u64,
        storage: Box<dyn NoncePersistence>,
    ) -> Result<Self, CryptoError> {
        let ctr_key = nonce_ctr_key(node_id);
        let hwm_key = nonce_hwm_key(node_id);

        let persisted_ctr = storage.read_u64(&ctr_key)?.unwrap_or(0) as u32;
        let hwm = storage.read_u64(&hwm_key)?.unwrap_or(0) as u32;

        // Detect counter rollback: recovered start must not be strictly behind HWM.
        if persisted_ctr < hwm {
            return Err(CryptoError::NonceCounterRollback {
                current: persisted_ctr as u64,
                hwm: hwm as u64,
            });
        }

        let mut mgr = Self {
            node_id,
            counter: persisted_ctr,
            block_end: persisted_ctr,
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
        if remaining <= WARN_REMAINING {
            warn!(
                node_id = self.node_id,
                counter = self.counter,
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

    /// Reserve the next block by persisting the new block-end and updating HWM.
    fn reserve_block(&mut self) -> Result<(), CryptoError> {
        let new_end = self
            .counter
            .checked_add(RESERVE_BLOCK)
            .ok_or(CryptoError::NonceExhausted)?;

        let ctr_key = nonce_ctr_key(self.node_id);
        let hwm_key = nonce_hwm_key(self.node_id);

        self.storage.write_u64(&ctr_key, new_end as u64)?;
        self.storage.flush()?;

        // Read-back verification (ADR §2.2).
        let readback = self.storage.read_u64(&ctr_key)?;
        if readback != Some(new_end as u64) {
            error!(
                node_id = self.node_id,
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
}

fn nonce_ctr_key(node_id: u64) -> String {
    format!("_meta:nonce_ctr:{node_id}")
}

fn nonce_hwm_key(node_id: u64) -> String {
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
        NonceManager::new(node_id, Box::new(MemNonce::default())).expect("init")
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
    fn test_rollback_detection() {
        let store = MemNonce::default();
        // Simulate a previous session that reached counter 2048 (hwm = 2048).
        store.write_u64("_meta:nonce_ctr:1", 2048).expect("write");
        store.write_u64("_meta:nonce_hwm:1", 2048).expect("write hwm");

        // Normal restart: ctr == hwm (not strictly less) → OK.
        let mut mgr = NonceManager::new(1, Box::new(store.clone())).expect("ok");
        mgr.next_nonce().expect("nonce after normal restart");

        // Simulate rollback: someone set ctr back to 512 < hwm 2048.
        store.write_u64("_meta:nonce_ctr:1", 512).expect("write");
        // hwm still 2048 or higher after mgr above wrote new reservation.
        let result = NonceManager::new(1, Box::new(store));
        assert!(matches!(result, Err(CryptoError::NonceCounterRollback { .. })));
    }
}
