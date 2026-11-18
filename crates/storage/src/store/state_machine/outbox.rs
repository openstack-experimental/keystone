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

//! Feed outbox (ADR 0045 section 3, M4).
//!
//! [`MutationInner::Emit`] appends an event to `meta` under
//! `_meta:outbox:<log index u64 BE><position u16 BE>` in the same batch as the
//! mutation it describes. The log index is the same on every voter, so any
//! voter can serve the feed and a cursor survives a leader change. The value
//! is `dek_version u32 BE` followed by the event encrypted under that epoch
//! with the outbox key as associated data.

use openstack_keystone_storage_api::FeedOp;

use super::*;

/// Fjall meta key prefix of outbox events.
pub(crate) const OUTBOX_PREFIX: &str = "_meta:outbox:";

/// Fjall meta key of the feed epoch: the log index of the first `Emit`, or of
/// the last restore. A consumer cursor is only valid within one epoch, because
/// a restore restarts the Raft indexes the cursors count in.
pub(crate) const META_FEED_EPOCH: &[u8] = b"_meta:feed:epoch";

/// Fjall meta key of the feed floor: the oldest log index still in the outbox.
pub(crate) const META_FEED_FLOOR: &[u8] = b"_meta:feed:floor";

/// Partition name under which outbox events are encrypted and quarantined.
const OUTBOX_PARTITION: &[u8] = b"outbox";

/// Position of an event in the feed: the Raft log index of the entry that
/// carried it and its place inside that entry.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct FeedCursor {
    /// Raft log index.
    pub index: u64,
    /// Position among the entry's events.
    pub position: u16,
}

/// One feed event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutboxEvent {
    /// Feed kind.
    pub kind: String,
    /// Owning domain, if any.
    pub domain_id: Option<String>,
    /// Key of the changed record.
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    /// What happened to it.
    pub op: FeedOp,
    /// Plaintext value of a `Set`.
    pub value: Option<serde_bytes::ByteBuf>,
}

pub(super) fn outbox_key(cursor: FeedCursor) -> Vec<u8> {
    let mut key = OUTBOX_PREFIX.as_bytes().to_vec();
    key.extend_from_slice(&cursor.index.to_be_bytes());
    key.extend_from_slice(&cursor.position.to_be_bytes());
    key
}

fn cursor_from_key(key: &[u8]) -> Option<FeedCursor> {
    let rest = key.strip_prefix(OUTBOX_PREFIX.as_bytes())?;
    let (index, position) = rest.split_at_checked(8)?;
    Some(FeedCursor {
        index: u64::from_be_bytes(index.try_into().ok()?),
        position: u16::from_be_bytes(position.try_into().ok()?),
    })
}

impl FjallStateMachine {
    /// Kinds that `Emit` may write; empty disables the feed.
    pub fn set_feed_kinds(&self, kinds: impl IntoIterator<Item = String>) {
        *self.feed_kinds.write().unwrap_or_else(|p| p.into_inner()) = kinds.into_iter().collect();
    }

    pub(super) fn feed_kind_enabled(&self, kind: &str) -> bool {
        self.feed_kinds
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .contains(kind)
    }

    /// Stages `event` at `cursor`. Returns `QUARANTINED` as an error like any
    /// encrypted write.
    pub(super) fn stage_outbox_event(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        cursor: FeedCursor,
        event: &OutboxEvent,
    ) -> Result<(), StoreError> {
        let key = outbox_key(cursor);
        let plain = rmp_serde::to_vec(event)?;
        let (encrypted, dek_version) =
            self.encrypt_and_store(&self.meta, &key, OUTBOX_PARTITION, 1, &plain)?;
        let mut stored = dek_version.to_be_bytes().to_vec();
        stored.extend_from_slice(&encrypted);
        batch.insert(&self.meta, key, stored);
        Ok(())
    }

    fn meta_u64(&self, key: &[u8]) -> Result<Option<u64>, StoreError> {
        Ok(self
            .meta
            .get(key)?
            .and_then(|v| v.as_ref().try_into().ok().map(u64::from_be_bytes)))
    }

    /// The feed epoch, if any event was ever emitted.
    pub fn feed_epoch(&self) -> Result<Option<u64>, StoreError> {
        self.meta_u64(META_FEED_EPOCH)
    }

    /// The oldest log index a cursor can still resume from (0 if nothing was
    /// pruned).
    pub fn feed_floor(&self) -> Result<u64, StoreError> {
        Ok(self.meta_u64(META_FEED_FLOOR)?.unwrap_or(0))
    }

    /// Stages the epoch for the first event of a feed.
    pub(super) fn stage_feed_epoch(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        index: u64,
    ) -> Result<(), StoreError> {
        if self.feed_epoch()?.is_none() {
            batch.insert(&self.meta, META_FEED_EPOCH, index.to_be_bytes());
        }
        Ok(())
    }

    /// Stages the removal of every outbox event up to and including
    /// `upto_index` and raises the floor past it.
    pub(super) fn stage_outbox_prune(
        &self,
        batch: &mut fjall::OwnedWriteBatch,
        upto_index: u64,
    ) -> Result<(), StoreError> {
        for item in self.meta.prefix(OUTBOX_PREFIX.as_bytes()) {
            let key = item.key()?;
            match cursor_from_key(&key) {
                Some(c) if c.index <= upto_index => batch.remove(&self.meta, key),
                _ => break,
            }
        }
        let floor = self.feed_floor()?.max(upto_index.saturating_add(1));
        batch.insert(&self.meta, META_FEED_FLOOR, floor.to_be_bytes());
        Ok(())
    }

    /// Starts a new feed after a restore replaced `meta`: drops the restored
    /// outbox and begins a new epoch at the restore's log index, so cursors
    /// of the old epoch are refused. A restore into an uninitialized node
    /// passes a random `index`, since no log index is unique across clusters.
    pub(crate) fn reset_feed(&self, index: u64) -> Result<(), StoreError> {
        let mut batch = self.db.batch();
        for item in self.meta.prefix(OUTBOX_PREFIX.as_bytes()) {
            batch.remove(&self.meta, item.key()?);
        }
        batch.remove(&self.meta, META_FEED_FLOOR);
        if self.feed_epoch()?.is_some() {
            batch.insert(&self.meta, META_FEED_EPOCH, index.to_be_bytes());
        }
        batch.commit()?;
        Ok(())
    }

    /// Up to `limit` events after `after` (all if `None`), oldest first.
    pub fn outbox_events_after(
        &self,
        after: Option<FeedCursor>,
        limit: usize,
    ) -> Result<Vec<(FeedCursor, OutboxEvent)>, StoreError> {
        let start = match after {
            Some(c) => outbox_key(c),
            None => OUTBOX_PREFIX.as_bytes().to_vec(),
        };
        let mut out = Vec::new();
        for item in self.meta.range(start..) {
            if out.len() >= limit {
                break;
            }
            let (key, value) = item.into_inner()?;
            let Some(cursor) = cursor_from_key(&key) else {
                break;
            };
            if after == Some(cursor) {
                continue;
            }
            let (version, body) = value
                .split_at_checked(4)
                .ok_or_else(|| StoreError::Other(eyre::eyre!("short outbox entry")))?;
            let version = u32::from_be_bytes(
                version
                    .try_into()
                    .map_err(|_| StoreError::Other(eyre::eyre!("short outbox entry")))?,
            );
            let plain = self.decrypt_state(body, 1, OUTBOX_PARTITION, &key, Some(version))?;
            out.push((cursor, rmp_serde::from_slice(&plain)?));
        }
        Ok(out)
    }
}
