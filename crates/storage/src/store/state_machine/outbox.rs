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
