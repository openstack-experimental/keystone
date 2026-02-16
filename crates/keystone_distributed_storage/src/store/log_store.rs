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
use std::fmt::Debug;
use std::io;
use std::marker::PhantomData;
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use openraft::alias::{EntryOf, LogIdOf, VoteOf};
use openraft::entry::RaftEntry;
use openraft::storage::{IOFlushed, LogState, RaftLogStorage};
use openraft::{OptionalSend, RaftLogReader, RaftTypeConfig};

use crate::StoreError;

const KEY_VOTE: &[u8] = b"vote";
const KEY_PURGED: &[u8] = b"purged";

#[derive(Clone)]
pub struct FjallLogStore<C>
where
    C: RaftTypeConfig,
{
    pub db: Arc<Database>,
    pub logs: Keyspace,
    pub meta: Keyspace,
    _p: PhantomData<C>,
}

impl<C> FjallLogStore<C>
where
    C: RaftTypeConfig,
{
    #[allow(clippy::result_large_err)]
    pub fn new(db: Arc<Database>) -> Result<Self, StoreError> {
        let logs = db.keyspace("logs", KeyspaceCreateOptions::default)?;
        let meta = db.keyspace("meta", KeyspaceCreateOptions::default)?;

        Ok(Self {
            db,
            logs,
            meta,
            _p: Default::default(),
        })
    }

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(skip(self, value))]
    fn set_meta<T: serde::Serialize>(&self, key: &[u8], value: &T) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(value)?;
        self.meta.insert(key, bytes)?;
        self.db.persist(PersistMode::SyncAll)?;
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    #[tracing::instrument(skip(self))]
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
}

impl<C> RaftLogReader<C> for FjallLogStore<C>
where
    C: RaftTypeConfig,
{
    #[tracing::instrument(skip(self))]
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<C::Entry>, io::Error> {
        let mut entries = Vec::new();

        // Convert u64 bounds to Big-Endian Vec<u8>
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
            let v = res.value().map_err(|e| io::Error::other(e.to_string()))?;
            entries.push(serde_json::from_slice::<C::Entry>(&v)?);
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
            .map(|x| x.value())
            .transpose()
            .map_err(|e| io::Error::other(e.to_string()))?
            .map(|x| serde_json::from_slice::<EntryOf<C>>(&x))
            .transpose()
            .map_err(|e| io::Error::other(e.to_string()))?
            .map(|x| x.log_id());

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
            let key = entry.log_id().index.to_be_bytes();
            tracing::debug!("appending {:?}, {:?}", entry.log_id().index, entry);
            let val = serde_json::to_vec(&entry).map_err(|e| io::Error::other(e.to_string()))?;
            self.logs
                .insert(key, val)
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

        // Fjall doesn't have a native "delete_range" yet, so we iterate and remove
        // Alternatively, use a WriteBatch for atomicity
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
        // Write the last-purged log id before purging the logs.
        // The logs at and before last-purged log id will be ignored by openraft.
        // Therefore, there is no need to do it in a transaction.
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
