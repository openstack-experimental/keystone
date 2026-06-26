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
//! # Fjall DB based `openraft` log store implementation.
use std::collections::{BTreeMap, HashSet};
use std::fmt::Debug;
use std::io;
use std::marker::PhantomData;
use std::ops::{Bound, RangeBounds};
use std::sync::{Arc, Mutex, RwLock};

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use openraft::alias::{EntryOf, LogIdOf, VoteOf};
use openraft::entry::RaftEntry;
use openraft::storage::{IOFlushed, LogState, RaftLogStorage};
use openraft::vote::RaftLeaderId;
use openraft::{OptionalSend, RaftLogReader, RaftTypeConfig};
use openstack_keystone_storage_crypto::{
    CryptoError, DekEpoch, NonceManager, log_decrypt, log_encrypt,
};

use crate::StoreError;
use crate::types::FjallNoncePersistence;

const KEY_VOTE: &[u8] = b"vote";
const KEY_PURGED: &[u8] = b"purged";

/// Log entry on-disk layout (all fields big-endian):
/// `[dek_version_u32; 4] ++ [term_u64; 8] ++ log_encrypt([nonce_12 ++
/// ciphertext ++ tag_16])`.
const DEK_VERSION_PREFIX_LEN: usize = 4;
/// On-disk prefix length for a log entry: 8 bytes for term (BE u64).
/// Full layout: [term_u64_BE (8)] ++ log_encrypt output [nonce_12 ++ ciphertext
/// ++ tag_16].
const TERM_PREFIX_LEN: usize = 8;
/// Minimum stored size: dek_version(4) + term(8) + nonce(12) + tag(16) = 40.
const LOG_ENTRY_MIN_LEN: usize = DEK_VERSION_PREFIX_LEN + TERM_PREFIX_LEN + 12 + 16;

#[derive(Clone)]
pub struct FjallLogStore<C>
where
    C: RaftTypeConfig,
{
    pub db: Arc<Database>,
    pub logs: Keyspace,
    pub meta: Keyspace,
    /// Current active DEK epoch (shared with FjallStateMachine for live
    /// rotation).
    dek: Arc<RwLock<Arc<DekEpoch>>>,
    /// Retired DEK epochs keyed by version — kept for decrypting old log
    /// entries until those entries are compacted into a snapshot.
    old_deks: Arc<Mutex<BTreeMap<u32, Arc<DekEpoch>>>>,
    /// Revoked DEK versions — immediately rejected on decrypt (ADR §6.2).
    revoked_deks: Arc<Mutex<HashSet<u32>>>,
    nonce_mgr: Arc<Mutex<NonceManager>>,
    _p: PhantomData<C>,
}

impl<C> FjallLogStore<C>
where
    C: RaftTypeConfig,
{
    #[allow(clippy::result_large_err)]
    /// Create a new `FjallLogStore`.
    ///
    /// # Parameters
    /// - `db`: Database instance.
    /// - `node_id`: Raft node ID used as the high 8 bytes of each log nonce.
    /// - `dek`: Shared current DEK epoch (also held by `FjallStateMachine`).
    /// - `old_deks`: Shared map of retired DEK epochs for reading old entries.
    ///
    /// # Returns
    /// A `Result` containing the `FjallLogStore`, or a `StoreError`.
    pub fn new(
        db: Arc<Database>,
        node_id: u64,
        dek: Arc<RwLock<Arc<DekEpoch>>>,
        old_deks: Arc<Mutex<BTreeMap<u32, Arc<DekEpoch>>>>,
        revoked_deks: Arc<Mutex<HashSet<u32>>>,
    ) -> Result<Self, StoreError> {
        let logs = db.keyspace("logs", KeyspaceCreateOptions::default)?;
        let meta = db.keyspace("meta", KeyspaceCreateOptions::default)?;

        let persistence = FjallNoncePersistence {
            keyspace: meta.clone(),
            db: db.clone(),
        };
        let nonce_mgr = NonceManager::new(node_id, Box::new(persistence))?;

        Ok(Self {
            db,
            logs,
            meta,
            dek,
            old_deks,
            revoked_deks,
            nonce_mgr: Arc::new(Mutex::new(nonce_mgr)),
            _p: Default::default(),
        })
    }

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(skip(self, value))]
    /// Set metadata for the log store.
    fn set_meta<T: serde::Serialize>(&self, key: &[u8], value: &T) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(value)?;
        self.meta.insert(key, bytes)?;
        self.db.persist(PersistMode::SyncAll)?;
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(skip(self))]
    /// Get metadata for the log store.
    fn get_meta<T: serde::de::DeserializeOwned>(
        &self,
        key: &[u8],
    ) -> Result<Option<T>, StoreError> {
        let raw = self.meta.get(key)?;
        match raw {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Encrypt a serialized Raft entry for storage.
    ///
    /// Layout: `[dek_version_u32_BE; 4] ++ [term_u64_BE; 8] ++ [nonce_12] ++
    /// [ciphertext] ++ [tag_16]`.
    fn encrypt_entry(
        &self,
        term: u64,
        index: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        let nonce = self
            .nonce_mgr
            .lock()
            .map_err(|_| StoreError::Other(eyre::eyre!("nonce manager lock poisoned")))?
            .next_nonce()?;
        let (dek_version, encrypted) = {
            let guard = self
                .dek
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let version = guard.version;
            let enc = log_encrypt(guard.log_dek(), plaintext, term, index, &nonce)?;
            (version, enc)
        };
        let mut out =
            Vec::with_capacity(DEK_VERSION_PREFIX_LEN + TERM_PREFIX_LEN + encrypted.len());
        out.extend_from_slice(&dek_version.to_be_bytes());
        out.extend_from_slice(&term.to_be_bytes());
        out.extend_from_slice(&encrypted);
        Ok(out)
    }

    /// Decrypt a stored log entry, selecting the correct DEK epoch by version.
    fn decrypt_entry(&self, index: u64, stored: &[u8]) -> Result<Vec<u8>, StoreError> {
        if stored.len() < LOG_ENTRY_MIN_LEN {
            return Err(StoreError::Other(eyre::eyre!(
                "stored log entry too short: {} bytes",
                stored.len()
            )));
        }
        let dek_version = u32::from_be_bytes(
            stored[..DEK_VERSION_PREFIX_LEN]
                .try_into()
                .map_err(|_| StoreError::Other(eyre::eyre!("could not read dek version")))?,
        );
        let rest = &stored[DEK_VERSION_PREFIX_LEN..];
        let term = u64::from_be_bytes(
            rest[..TERM_PREFIX_LEN]
                .try_into()
                .map_err(|_| StoreError::Other(eyre::eyre!("could not read term prefix")))?,
        );
        let payload = &rest[TERM_PREFIX_LEN..];

        // Use active DEK if versions match, otherwise look up retired DEK map.
        let current_version = self.dek.read().unwrap_or_else(|p| p.into_inner()).version;
        if dek_version == current_version {
            let guard = self.dek.read().unwrap_or_else(|p| p.into_inner());
            let plaintext = log_decrypt(guard.log_dek(), payload, term, index)?;
            Ok(plaintext.to_vec())
        } else {
            // Check if this DEK version has been revoked (emergency rotation).
            {
                let revoked = self.revoked_deks.lock().unwrap_or_else(|p| p.into_inner());
                if revoked.contains(&dek_version) {
                    return Err(CryptoError::RevokedDek {
                        version: dek_version,
                    }
                    .into());
                }
            }
            let old_map = self.old_deks.lock().unwrap_or_else(|p| p.into_inner());
            let old = old_map.get(&dek_version).ok_or_else(|| {
                StoreError::Other(eyre::eyre!(
                    "no DEK epoch for version {dek_version} — log entry unreadable"
                ))
            })?;
            let plaintext = log_decrypt(old.log_dek(), payload, term, index)?;
            Ok(plaintext.to_vec())
        }
    }

    /// Register a retired DEK epoch so old log entries can still be decrypted.
    pub fn register_old_dek(&self, epoch: Arc<DekEpoch>) {
        self.old_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(epoch.version, epoch);
    }

    /// Remove a retired DEK epoch once all log entries for that version are
    /// compacted into a snapshot.
    pub fn evict_old_dek(&self, version: u32) {
        self.old_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&version);
    }
}

impl<C> RaftLogReader<C> for FjallLogStore<C>
where
    C: RaftTypeConfig,
    <C::LeaderId as RaftLeaderId>::Committed: Clone + Into<u64>,
{
    #[tracing::instrument(skip(self))]
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<C::Entry>, io::Error> {
        let mut entries = Vec::new();

        let start = match range.start_bound() {
            Bound::Included(i) => Bound::Included(i.to_be_bytes().to_vec()),
            Bound::Excluded(i) => Bound::Excluded(i.to_be_bytes().to_vec()),
            Bound::Unbounded => Bound::Unbounded,
        };
        let end = match range.end_bound() {
            Bound::Included(i) => Bound::Included(i.to_be_bytes().to_vec()),
            Bound::Excluded(i) => Bound::Excluded(i.to_be_bytes().to_vec()),
            Bound::Unbounded => Bound::Unbounded,
        };

        for res in self.logs.range((start, end)) {
            let (key_slice, val_slice) = res
                .into_inner()
                .map_err(|e| io::Error::other(e.to_string()))?;

            let index = u64::from_be_bytes(
                key_slice
                    .as_ref()
                    .try_into()
                    .map_err(|_| io::Error::other("log key has unexpected length"))?,
            );

            let plaintext = self
                .decrypt_entry(index, val_slice.as_ref())
                .map_err(|e| io::Error::other(e.to_string()))?;

            entries.push(serde_json::from_slice::<C::Entry>(&plaintext)?);
        }
        Ok(entries)
    }

    async fn read_vote(&mut self) -> Result<Option<VoteOf<C>>, io::Error> {
        self.get_meta::<VoteOf<C>>(KEY_VOTE)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

impl<C> RaftLogStorage<C> for FjallLogStore<C>
where
    C: RaftTypeConfig,
    <C::LeaderId as RaftLeaderId>::Committed: Clone + Into<u64>,
{
    type LogReader = Self;

    #[tracing::instrument(skip(self))]
    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    #[tracing::instrument(skip(self))]
    async fn get_log_state(&mut self) -> Result<LogState<C>, io::Error> {
        let last_log_id = self
            .logs
            .last_key_value()
            .map(|guard| -> Result<LogIdOf<C>, io::Error> {
                let (key_slice, val_slice) = guard
                    .into_inner()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let index = u64::from_be_bytes(
                    key_slice
                        .as_ref()
                        .try_into()
                        .map_err(|_| io::Error::other("log key has unexpected length"))?,
                );
                let plaintext = self
                    .decrypt_entry(index, val_slice.as_ref())
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let entry: C::Entry = serde_json::from_slice(&plaintext)?;
                Ok(entry.log_id())
            })
            .transpose()?;

        let last_purged_log_id = self
            .get_meta(KEY_PURGED)
            .map_err(|e| io::Error::other(e.to_string()))?;
        tracing::debug!("the state is {:?}, {:?}", last_log_id, last_purged_log_id);

        Ok(LogState {
            last_log_id: last_log_id.or(last_purged_log_id.clone()),
            last_purged_log_id,
        })
    }

    #[tracing::instrument(skip(self))]
    async fn save_vote(&mut self, vote: &VoteOf<C>) -> Result<(), io::Error> {
        self.set_meta(KEY_VOTE, vote)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(())
    }

    #[tracing::instrument(skip(self, entries, callback))]
    async fn append<I>(&mut self, entries: I, callback: IOFlushed<C>) -> Result<(), io::Error>
    where
        I: IntoIterator<Item = EntryOf<C>> + Send,
    {
        for entry in entries {
            let log_id = entry.log_id();
            let term: u64 = log_id.committed_leader_id().clone().into();
            let index = log_id.index();
            tracing::debug!("appending log entry term={} index={}", term, index);

            let plaintext =
                serde_json::to_vec(&entry).map_err(|e| io::Error::other(e.to_string()))?;
            let stored = self
                .encrypt_entry(term, index, &plaintext)
                .map_err(|e| io::Error::other(e.to_string()))?;

            self.logs
                .insert(index.to_be_bytes(), stored)
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        self.db
            .persist(PersistMode::SyncAll)
            .map_err(|e| io::Error::other(e.to_string()))?;
        callback.io_completed(Ok(()));
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn truncate_after(&mut self, last_log_id: Option<LogIdOf<C>>) -> Result<(), io::Error> {
        tracing::debug!("truncate_after: ({:?}, +oo)", last_log_id);

        let start_index = match last_log_id {
            Some(log_id) => log_id.index() + 1,
            None => 0,
        };

        for entry in self.logs.range(start_index.to_be_bytes()..) {
            if let Ok(key) = entry.key() {
                self.logs
                    .remove(key)
                    .map_err(|e| io::Error::other(e.to_string()))?;
            }
        }

        self.db
            .persist(PersistMode::SyncAll)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn purge(&mut self, log_id: LogIdOf<C>) -> Result<(), io::Error> {
        tracing::debug!("delete_log: [0, {:?}]", log_id);
        self.set_meta(KEY_PURGED, &log_id)
            .map_err(|e| io::Error::other(e.to_string()))?;

        let end = log_id.index().to_be_bytes();
        for entry in self.logs.range(..=end) {
            if let Ok(key) = entry.key() {
                self.logs
                    .remove(key)
                    .map_err(|e| io::Error::other(e.to_string()))?;
            }
        }

        self.db
            .persist(PersistMode::SyncAll)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(())
    }
}
