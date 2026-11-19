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

//! Feed consumer (ADR 0045 section 3, R6).
//!
//! Subscribes to another authority's feed and applies the events to local
//! storage through a [`FeedSink`], which turns each event into mutations of the
//! consumer's own drivers' keyspaces. The cursor is stored with the data, in
//! the same transaction as the mutations of the events it covers, so an event
//! is applied once even if the process dies between two events, and a replay
//! is skipped.

use std::sync::Arc;
use std::time::Duration;

use openstack_keystone_storage_api::{Metadata, Mutation, StorageApi, StoreError};
use serde::{Deserialize, Serialize};

use crate::network::RaftTlsClient;
use crate::pb::raft::SubscribeRequest;
use crate::pb::raft::feed_message::Message;
use crate::pb::raft::feed_service_client::FeedServiceClient;

/// Keyspace holding one cursor record per source.
pub const FEED_CURSOR_KEYSPACE: &str = "feed_cursor";

fn other(msg: String) -> StoreError {
    StoreError::Other(msg.into())
}

const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// One feed event, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedEventData {
    /// Raft log index at the source.
    pub index: u64,
    /// Position among the events of that log entry.
    pub position: u16,
    /// Feed kind.
    pub kind: String,
    /// Owning domain, if any.
    pub domain_id: Option<String>,
    /// Key of the changed record at the source.
    pub key: Vec<u8>,
    /// Whether the record was removed.
    pub removed: bool,
    /// Plaintext value of a set.
    pub value: Option<Vec<u8>>,
}

/// Applies events to local storage.
#[async_trait::async_trait]
pub trait FeedSink: Send + Sync {
    /// The mutations that make `event` visible locally.
    ///
    /// They must be idempotent: a `Remove` of a missing record is a no-op in
    /// storage, and a `Set` replaces. The consumer adds its cursor update to
    /// the same transaction.
    fn mutations(&self, event: &FeedEventData) -> Result<Vec<Mutation>, StoreError>;

    /// Called when the source says the cursor cannot be resumed, before the
    /// consumer subscribes afresh. A sink that mirrors a kind clears or
    /// reloads it here.
    async fn reseed(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

/// Stored position of a consumer in a source's feed.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CursorRecord {
    /// Feed epoch of the source.
    pub epoch: u64,
    /// Log index of the last applied event.
    pub index: u64,
    /// Its position.
    pub position: u16,
}

/// How [`FeedConsumer::run_once`] ended.
#[derive(Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// The source closed the stream.
    Ended,
    /// The cursor could not be resumed; the sink was reseeded and the stored
    /// cursor cleared.
    Reset,
}

/// A subscription to one source's feed.
pub struct FeedConsumer {
    domains: Vec<String>,
    kinds: Vec<String>,
    name: String,
    sink: Arc<dyn FeedSink>,
    source_addr: String,
    storage: Arc<dyn StorageApi>,
    tls: RaftTlsClient,
}

impl FeedConsumer {
    /// `name` identifies the source in the cursor keyspace; `source_addr` is
    /// the `host:port` of any voter of the source authority.
    pub fn new(
        name: impl Into<String>,
        source_addr: impl Into<String>,
        tls: RaftTlsClient,
        storage: Arc<dyn StorageApi>,
        sink: Arc<dyn FeedSink>,
        kinds: Vec<String>,
        domains: Vec<String>,
    ) -> Self {
        Self {
            domains,
            kinds,
            name: name.into(),
            sink,
            source_addr: source_addr.into(),
            storage,
            tls,
        }
    }

    /// The stored cursor and its record revision.
    pub async fn load_cursor(&self) -> Result<Option<(CursorRecord, u64)>, StoreError> {
        let Some(env) = self
            .storage
            .get_by_key(self.name.as_bytes(), Some(FEED_CURSOR_KEYSPACE))
            .await?
        else {
            return Ok(None);
        };
        let record = rmp_serde::from_slice(&env.data)
            .map_err(|e| other(format!("decoding the feed cursor: {e}")))?;
        Ok(Some((record, env.metadata.revision)))
    }

    /// Applies `events` of `epoch`: skips what the cursor already covers and
    /// writes the rest together with the new cursor.
    pub async fn apply(&self, epoch: u64, events: Vec<FeedEventData>) -> Result<(), StoreError> {
        let stored = self.load_cursor().await?;
        let covered = stored
            .filter(|(c, _)| c.epoch == epoch)
            .map(|(c, _)| (c.index, c.position));
        let mut mutations = Vec::new();
        let mut last = None;
        for event in &events {
            let at = (event.index, event.position);
            if covered.is_some_and(|c| at <= c) {
                continue;
            }
            mutations.extend(self.sink.mutations(event)?);
            last = Some(at);
        }
        let Some((index, position)) = last else {
            return Ok(());
        };
        let record = rmp_serde::to_vec(&CursorRecord {
            epoch,
            index,
            position,
        })
        .map_err(|e| other(format!("encoding the feed cursor: {e}")))?;
        mutations.push(Mutation::Set {
            expected_revision: stored.map(|(_, rev)| rev),
            key: self.name.as_bytes().to_vec(),
            keyspace: FEED_CURSOR_KEYSPACE.to_owned(),
            metadata: Metadata::new(),
            value: record,
        });
        self.storage.transaction(mutations).await?;
        Ok(())
    }

    /// Connects, resumes from the stored cursor and applies events until the
    /// stream ends or the source resets the cursor.
    pub async fn run_once(&self) -> Result<RunOutcome, StoreError> {
        let cursor = self.load_cursor().await?.map(|(c, _)| c);
        let channel = self.tls.connect(&self.source_addr).await?;
        let mut client = FeedServiceClient::new(channel);
        let mut stream = client
            .subscribe(SubscribeRequest {
                epoch: cursor.map_or(0, |c| c.epoch),
                has_cursor: cursor.is_some(),
                cursor_index: cursor.map_or(0, |c| c.index),
                cursor_position: cursor.map_or(0, |c| u32::from(c.position)),
                kinds: self.kinds.clone(),
                domains: self.domains.clone(),
            })
            .await
            .map_err(|e| other(format!("subscribing to the feed: {e}")))?
            .into_inner();
        loop {
            let message = stream
                .message()
                .await
                .map_err(|e| other(format!("feed stream: {e}")))?;
            match message.and_then(|m| m.message) {
                None => return Ok(RunOutcome::Ended),
                Some(Message::Head(_)) => {}
                Some(Message::Events(batch)) => {
                    let events = batch
                        .events
                        .into_iter()
                        .map(|e| {
                            Ok(FeedEventData {
                                index: e.index,
                                position: u16::try_from(e.position)
                                    .map_err(|_| other("event position out of range".to_owned()))?,
                                kind: e.kind,
                                domain_id: e.has_domain.then_some(e.domain_id),
                                key: e.key,
                                removed: e.removed,
                                value: e.has_value.then_some(e.value),
                            })
                        })
                        .collect::<Result<Vec<_>, StoreError>>()?;
                    self.apply(batch.epoch, events).await?;
                }
                Some(Message::Reset(reset)) => {
                    tracing::warn!(
                        source = %self.name,
                        reason = %reset.reason,
                        "feed cursor reset; reseeding"
                    );
                    self.sink.reseed().await?;
                    if let Some((_, revision)) = self.load_cursor().await? {
                        self.storage
                            .transaction(vec![Mutation::Remove {
                                key: self.name.as_bytes().to_vec(),
                                keyspace: FEED_CURSOR_KEYSPACE.to_owned(),
                                expected_revision: Some(revision),
                            }])
                            .await?;
                    }
                    return Ok(RunOutcome::Reset);
                }
            }
        }
    }

    /// Keeps the subscription running, with backoff after errors, until
    /// `stop` completes.
    pub async fn run(&self, stop: impl std::future::Future<Output = ()>) {
        tokio::pin!(stop);
        let mut backoff = BACKOFF_MIN;
        loop {
            let outcome = tokio::select! {
                () = &mut stop => return,
                r = self.run_once() => r,
            };
            match outcome {
                Ok(RunOutcome::Reset) => backoff = BACKOFF_MIN,
                Ok(RunOutcome::Ended) => {}
                Err(e) => {
                    tracing::warn!(source = %self.name, error = %e, "feed subscription failed");
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                }
            }
            tokio::select! {
                () = &mut stop => return,
                () = tokio::time::sleep(backoff) => {}
            }
        }
    }
}
