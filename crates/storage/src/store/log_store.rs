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
            // Check `old_deks` *first*: an emergency-revoked epoch stays
            // there, still fully readable, for as long as its re-encryption
            // sweep is in progress (ADR 0016-v2 §6.2 step 4) -- only once
            // the sweep confirms completion is it removed. Checking
            // `revoked_deks` first would treat every entry under a
            // still-being-migrated epoch as unreadable, crashing Raft log
            // replication/replay for the entire sweep window instead of
            // just after the key is genuinely gone (GitHub #1299).
            let old_map = self.old_deks.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(old) = old_map.get(&dek_version) {
                let plaintext = log_decrypt(old.log_dek(), payload, term, index)?;
                return Ok(plaintext.to_vec());
            }
            drop(old_map);

            // Not in `old_deks`: either this epoch was never known here, or
            // it *was* revoked and its key has since been discarded because
            // the re-encryption sweep confirmed nothing still needs it.
            let revoked = self.revoked_deks.lock().unwrap_or_else(|p| p.into_inner());
            if revoked.contains(&dek_version) {
                return Err(CryptoError::RevokedDek {
                    version: dek_version,
                }
                .into());
            }
            drop(revoked);

            Err(StoreError::Other(eyre::eyre!(
                "no DEK epoch for version {dek_version} — log entry unreadable"
            )))
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

        // Collect keys first and remove them all in one `Batch` commit
        // (GitHub #1297 item 1): removing entries one at a time left a
        // crash mid-loop with a partially truncated suffix, and silently
        // skipping a key read error (the old `if let Ok(key) = ...`) could
        // leave a stale entry behind unnoticed.
        let keys: Vec<_> = self
            .logs
            .range(start_index.to_be_bytes()..)
            .map(|entry| entry.key().map_err(|e| io::Error::other(e.to_string())))
            .collect::<Result<_, _>>()?;

        let mut batch = self.db.batch();
        for key in keys {
            batch.remove(&self.logs, key);
        }
        batch
            .commit()
            .map_err(|e| io::Error::other(e.to_string()))?;

        self.db
            .persist(PersistMode::SyncAll)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn purge(&mut self, log_id: LogIdOf<C>) -> Result<(), io::Error> {
        tracing::debug!("delete_log: [0, {:?}]", log_id);

        // `KEY_PURGED` and every removed entry commit in one `Batch`
        // (GitHub #1297 item 1): the old code wrote `KEY_PURGED` first,
        // then removed entries one by one, so a crash mid-way left
        // `last_purged_log_id` ahead of entries that still physically
        // existed on disk.
        let purged_bytes =
            serde_json::to_vec(&log_id).map_err(|e| io::Error::other(e.to_string()))?;
        let end = log_id.index().to_be_bytes();
        let keys: Vec<_> = self
            .logs
            .range(..=end)
            .map(|entry| entry.key().map_err(|e| io::Error::other(e.to_string())))
            .collect::<Result<_, _>>()?;

        let mut batch = self.db.batch();
        batch.insert(&self.meta, KEY_PURGED, purged_bytes);
        for key in keys {
            batch.remove(&self.logs, key);
        }
        batch
            .commit()
            .map_err(|e| io::Error::other(e.to_string()))?;

        self.db
            .persist(PersistMode::SyncAll)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use openstack_keystone_storage_crypto::LockedKey;

    use super::*;

    fn make_store() -> (FjallLogStore<crate::TypeConfig>, tempfile::TempDir) {
        let td = tempfile::TempDir::new().expect("tempdir");
        let db = Arc::new(Database::builder(td.path()).open().expect("open db"));
        let current =
            Arc::new(DekEpoch::from_raw(LockedKey::from_raw([0x30u8; 32]), 2).expect("epoch"));
        let store = FjallLogStore::new(
            db,
            1,
            Arc::new(RwLock::new(current)),
            Arc::new(Mutex::new(BTreeMap::new())),
            Arc::new(Mutex::new(HashSet::new())),
        )
        .expect("construct log store");
        (store, td)
    }

    /// An entry tagged with an old `dek_version` still present in
    /// `old_deks` must decrypt via that epoch even if the same version is
    /// *also* listed in `revoked_deks` -- an emergency-revoked epoch stays
    /// fully readable there for as long as its re-encryption sweep is in
    /// progress (ADR 0016-v2 §6.2 step 4). Checking `revoked_deks` first
    /// would crash Raft log replication/replay for the entire sweep
    /// window instead of only after the key is genuinely gone (GitHub
    /// #1299).
    #[test]
    fn decrypt_entry_prefers_old_deks_over_revoked_marker() {
        let (store, _td) = make_store();

        let old_epoch =
            Arc::new(DekEpoch::from_raw(LockedKey::from_raw([0x31u8; 32]), 1).expect("old epoch"));
        store
            .old_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(1, old_epoch.clone());
        // Also mark version 1 revoked -- exactly the state during an
        // in-progress emergency-rotation sweep.
        store
            .revoked_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(1);

        // Build a fake stored entry encrypted under the old epoch directly
        // (bypassing `encrypt_entry`, which always uses the *current*
        // epoch).
        let ciphertext =
            log_encrypt(old_epoch.log_dek(), b"payload", 7, 5, &[0u8; 12]).expect("encrypt");
        let mut stored = 1u32.to_be_bytes().to_vec();
        stored.extend_from_slice(&7u64.to_be_bytes());
        stored.extend_from_slice(&ciphertext);

        let plaintext = store
            .decrypt_entry(5, &stored)
            .expect("must decrypt via old_deks, not error out as revoked");
        assert_eq!(plaintext, b"payload");
    }

    /// Once an epoch is gone from `old_deks` (its sweep confirmed complete
    /// and the key finalized/discarded), an entry still tagged with it
    /// must fail with a clean `RevokedDek` error rather than a generic
    /// "unknown epoch" one -- distinguishing a legitimate security
    /// containment outcome from actual corruption.
    #[test]
    fn decrypt_entry_returns_revoked_error_once_key_is_gone() {
        let (store, _td) = make_store();
        store
            .revoked_deks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(1);

        let mut stored = 1u32.to_be_bytes().to_vec();
        stored.extend_from_slice(&7u64.to_be_bytes());
        stored.extend_from_slice(&[0u8; 28]); // nonce(12) + tag(16); never reached.

        let err = store
            .decrypt_entry(5, &stored)
            .expect_err("must fail once the key is truly gone");
        assert!(
            matches!(
                err,
                StoreError::Crypto {
                    source: CryptoError::RevokedDek { version: 1 }
                }
            ),
            "expected a clean RevokedDek error, got: {err:?}"
        );
    }

    /// Dumps every log index currently stored, sorted ascending.
    fn indices(store: &FjallLogStore<crate::TypeConfig>) -> Vec<u64> {
        let mut out: Vec<u64> = store
            .logs
            .iter()
            .filter_map(|item| item.into_inner().ok())
            .map(|(k, _)| u64::from_be_bytes(k.as_ref().try_into().expect("8-byte key")))
            .collect();
        out.sort_unstable();
        out
    }

    /// Regression test for GitHub #1297 item 1: `purge` used to write
    /// `KEY_PURGED` first and then remove entries one by one, so a crash
    /// mid-way could leave `last_purged_log_id` ahead of entries that
    /// still physically existed. Both must now land in one `Batch` commit.
    #[tokio::test]
    async fn purge_removes_entries_up_to_and_including_the_log_id() {
        let (mut store, _td) = make_store();
        for i in 1u64..=5 {
            store
                .logs
                .insert(i.to_be_bytes(), vec![0u8; LOG_ENTRY_MIN_LEN])
                .expect("seed log entry");
        }

        let log_id = crate::types::LogId::new(1u64, 3u64);
        store.purge(log_id).await.expect("purge");

        assert_eq!(
            indices(&store),
            vec![4, 5],
            "entries up to and including the purge index must be gone"
        );
        let purged: crate::types::LogId = store
            .get_meta(KEY_PURGED)
            .expect("get meta")
            .expect("purged marker recorded in the same batch as the removals");
        assert_eq!(purged, log_id);
    }

    /// Regression test for GitHub #1297 item 1: `truncate_after` removed
    /// entries one at a time and silently skipped any whose key read
    /// failed; it must now remove the whole suffix in one `Batch` commit.
    #[tokio::test]
    async fn truncate_after_removes_the_correct_suffix() {
        let (mut store, _td) = make_store();
        for i in 1u64..=5 {
            store
                .logs
                .insert(i.to_be_bytes(), vec![0u8; LOG_ENTRY_MIN_LEN])
                .expect("seed log entry");
        }

        let log_id = crate::types::LogId::new(1u64, 2u64);
        store
            .truncate_after(Some(log_id))
            .await
            .expect("truncate_after");

        assert_eq!(
            indices(&store),
            vec![1, 2],
            "only entries up to and including last_log_id must survive"
        );
    }

    /// `truncate_after(None)` must remove every entry (starts at index 0).
    #[tokio::test]
    async fn truncate_after_none_removes_every_entry() {
        let (mut store, _td) = make_store();
        for i in 1u64..=3 {
            store
                .logs
                .insert(i.to_be_bytes(), vec![0u8; LOG_ENTRY_MIN_LEN])
                .expect("seed log entry");
        }

        store.truncate_after(None).await.expect("truncate_after");

        assert!(indices(&store).is_empty());
    }
}
