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

//! Inter-authority change feed (ADR 0045 section 3, M4).
//!
//! Streams the events of the replicated outbox after a cursor. The caller
//! needs the `feed-consumer` role and an entry in `feed_subscribers`; its
//! request is intersected with that entry. Any voter serves, and a node that
//! lost its leader for longer than the staleness bound ends the stream.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use openraft::async_runtime::WatchReceiver;
use tonic::{Request, Response, Status};

use crate::grpc::authz::{PeerAuthz, PeerRole};
use crate::leader_contact::LeaderContact;
use crate::pb;
use crate::store::state_machine::{FeedCursor, OutboxEvent};
use crate::types::{Raft, StateMachineStore};

/// Events read from the outbox per batch.
const BATCH: usize = 256;

/// How often an idle stream looks for new events.
const POLL: Duration = Duration::from_millis(200);

/// What a subscriber identity may receive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriberEntry {
    /// Kinds allowed.
    pub kinds: BTreeSet<String>,
    /// Domains allowed; `None` allows every domain.
    pub domains: Option<BTreeSet<String>>,
}

/// Parses `feed_subscribers` entries into a map keyed by identity.
pub fn parse_subscribers(
    specs: &[String],
) -> Result<HashMap<String, SubscriberEntry>, eyre::Report> {
    let mut out = HashMap::new();
    for spec in specs {
        let (identity, rest) = spec.rsplit_once('=').ok_or_else(|| {
            eyre::eyre!("feed subscriber `{spec}` is not <id>=<kinds>[@<domains>]")
        })?;
        let (kinds, domains) = match rest.split_once('@') {
            Some((k, d)) => (k, Some(d)),
            None => (rest, None),
        };
        let set = |s: &str| -> BTreeSet<String> {
            s.split('+')
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect()
        };
        let kinds = set(kinds);
        if identity.is_empty() || kinds.is_empty() {
            return Err(eyre::eyre!(
                "feed subscriber `{spec}` needs an identity and at least one kind"
            ));
        }
        out.insert(
            identity.to_owned(),
            SubscriberEntry {
                kinds,
                domains: domains.map(set),
            },
        );
    }
    Ok(out)
}

/// The kinds and domains a request may use: its own, narrowed to the entry.
/// An empty request takes the entry whole.
fn effective(
    entry: &SubscriberEntry,
    kinds: &[String],
    domains: &[String],
) -> (BTreeSet<String>, Option<BTreeSet<String>>) {
    let kinds = if kinds.is_empty() {
        entry.kinds.clone()
    } else {
        kinds
            .iter()
            .filter(|k| entry.kinds.contains(*k))
            .cloned()
            .collect()
    };
    let domains = match (&entry.domains, domains.is_empty()) {
        (None, true) => None,
        (None, false) => Some(domains.iter().cloned().collect()),
        (Some(allowed), true) => Some(allowed.clone()),
        (Some(allowed), false) => Some(
            domains
                .iter()
                .filter(|d| allowed.contains(*d))
                .cloned()
                .collect(),
        ),
    };
    (kinds, domains)
}

fn wanted(
    event: &OutboxEvent,
    kinds: &BTreeSet<String>,
    domains: &Option<BTreeSet<String>>,
) -> bool {
    kinds.contains(&event.kind)
        && match (&event.domain_id, domains) {
            // An event with no domain is global; the kind filter governs it.
            (None, _) | (_, None) => true,
            (Some(d), Some(allowed)) => allowed.contains(d),
        }
}

fn to_pb(cursor: FeedCursor, event: OutboxEvent) -> pb::raft::FeedEvent {
    pb::raft::FeedEvent {
        index: cursor.index,
        position: u32::from(cursor.position),
        kind: event.kind,
        has_domain: event.domain_id.is_some(),
        domain_id: event.domain_id.unwrap_or_default(),
        key: event.key,
        removed: event.op == openstack_keystone_storage_api::FeedOp::Remove,
        has_value: event.value.is_some(),
        value: event.value.map(|v| v.into_vec()).unwrap_or_default(),
    }
}

/// The feed gRPC service.
pub struct FeedServiceImpl {
    authz: Arc<PeerAuthz>,
    heartbeat: Duration,
    leader_contact: Arc<LeaderContact>,
    max_staleness: Option<Duration>,
    node_id: u64,
    raft: Raft,
    sm: Arc<StateMachineStore>,
    subscribers: Arc<HashMap<String, SubscriberEntry>>,
}

impl FeedServiceImpl {
    /// Creates the service.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        raft: Raft,
        node_id: u64,
        sm: Arc<StateMachineStore>,
        authz: Arc<PeerAuthz>,
        leader_contact: Arc<LeaderContact>,
        subscribers: HashMap<String, SubscriberEntry>,
        heartbeat: Duration,
        max_staleness: Option<Duration>,
    ) -> Self {
        Self {
            authz,
            heartbeat,
            leader_contact,
            max_staleness,
            node_id,
            raft,
            sm,
            subscribers: Arc::new(subscribers),
        }
    }
}

type FeedStream =
    std::pin::Pin<Box<dyn Stream<Item = Result<pb::raft::FeedMessage, Status>> + Send>>;

#[tonic::async_trait]
impl pb::raft::feed_service_server::FeedService for FeedServiceImpl {
    type SubscribeStream = FeedStream;

    async fn subscribe(
        &self,
        request: Request<pb::raft::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let (identity, _) = self.authz.require(&request, &[PeerRole::FeedConsumer])?;
        let entry = self
            .subscribers
            .get(&identity)
            .ok_or_else(|| Status::permission_denied("this identity has no feed subscription"))?;
        let req = request.into_inner();
        let (kinds, domains) = effective(entry, &req.kinds, &req.domains);
        let mut cursor = req.has_cursor.then_some(FeedCursor {
            index: req.cursor_index,
            position: u16::try_from(req.cursor_position)
                .map_err(|_| Status::invalid_argument("cursor_position is out of range"))?,
        });
        let requested_epoch = req.epoch;
        let req_has_cursor = req.has_cursor;

        let sm = self.sm.clone();
        let raft = self.raft.clone();
        let heartbeat = self.heartbeat;
        let max_staleness = self.max_staleness;
        let leader_contact = self.leader_contact.clone();
        let node_id = self.node_id;
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<pb::raft::FeedMessage, Status>>(4);

        tokio::spawn(async move {
            use pb::raft::feed_message::Message;
            let send = |m: Message| {
                let tx = tx.clone();
                async move {
                    tx.send(Ok(pb::raft::FeedMessage { message: Some(m) }))
                        .await
                        .is_ok()
                }
            };
            let fail = |s: Status| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(Err(s)).await;
                }
            };
            let mut last_head = std::time::Instant::now() - heartbeat;
            let mut stream_epoch: Option<u64> = None;
            loop {
                let epoch = match sm.feed_epoch() {
                    Ok(e) => e.unwrap_or(0),
                    Err(e) => return fail(Status::internal(e.to_string())).await,
                };
                let floor = match sm.feed_floor() {
                    Ok(f) => f,
                    Err(e) => return fail(Status::internal(e.to_string())).await,
                };
                // The epoch a stream runs in is the one the consumer's cursor
                // belongs to, or the current one for a fresh subscription.
                let expected = *stream_epoch.get_or_insert(if req_has_cursor {
                    requested_epoch
                } else {
                    epoch
                });
                // A fresh subscription that began before the first event adopts
                // the epoch that event creates.
                if !req_has_cursor && expected == 0 {
                    stream_epoch = Some(epoch);
                }
                let expected = stream_epoch.unwrap_or(expected);
                let epoch_changed = epoch != 0 && expected != epoch;
                let below_floor = cursor.is_some_and(|c| c.index < floor);
                if epoch_changed || below_floor {
                    let reason = if epoch_changed {
                        "the feed epoch changed"
                    } else {
                        "the cursor is older than the oldest retained event"
                    };
                    let _ = send(Message::Reset(pb::raft::FeedReset {
                        epoch,
                        floor,
                        reason: reason.to_owned(),
                    }))
                    .await;
                    return;
                }
                let age = if raft.metrics().borrow_watched().current_leader == Some(node_id) {
                    Some(Duration::ZERO)
                } else {
                    leader_contact.age()
                };
                if let (Some(limit), Some(age)) = (max_staleness, age)
                    && age > limit
                {
                    return fail(Status::unavailable(
                        "this voter has lost contact with the leader for longer than the \
                         staleness bound",
                    ))
                    .await;
                }
                let batch = match sm.outbox_events_after(cursor, BATCH) {
                    Ok(b) => b,
                    Err(e) => return fail(Status::internal(e.to_string())).await,
                };
                if let Some((last, _)) = batch.last() {
                    let last = *last;
                    let events: Vec<_> = batch
                        .into_iter()
                        .filter(|(_, e)| wanted(e, &kinds, &domains))
                        .map(|(c, e)| to_pb(c, e))
                        .collect();
                    cursor = Some(last);
                    if !events.is_empty()
                        && !send(Message::Events(pb::raft::FeedEvents { epoch, events })).await
                    {
                        return;
                    }
                    continue;
                }
                if last_head.elapsed() >= heartbeat {
                    last_head = std::time::Instant::now();
                    let applied = raft
                        .metrics()
                        .borrow_watched()
                        .last_applied
                        .map(|l| l.index)
                        .unwrap_or(0);
                    let head = pb::raft::FeedHead {
                        epoch,
                        applied_index: applied,
                        leader_contact_age_ms: age.map_or(u64::MAX, |a| {
                            u64::try_from(a.as_millis()).unwrap_or(u64::MAX)
                        }),
                    };
                    if !send(Message::Head(head)).await {
                        return;
                    }
                }
                tokio::time::sleep(POLL).await;
            }
        });

        let stream = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        Ok(Response::new(Box::pin(stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kinds: &[&str], domains: Option<&[&str]>) -> SubscriberEntry {
        SubscriberEntry {
            kinds: kinds.iter().map(|s| s.to_string()).collect(),
            domains: domains.map(|d| d.iter().map(|s| s.to_string()).collect()),
        }
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_subscribers_reads_kinds_and_domains() {
        let m = parse_subscribers(&strings(&[
            "spiffe://a/b=registry+revocation@d1+d2",
            "spiffe://a/c=registry",
        ]))
        .unwrap();
        assert_eq!(
            m["spiffe://a/b"],
            entry(&["registry", "revocation"], Some(&["d1", "d2"]))
        );
        assert_eq!(m["spiffe://a/c"], entry(&["registry"], None));
        assert!(parse_subscribers(&strings(&["nokinds"])).is_err());
        assert!(parse_subscribers(&strings(&["id="])).is_err());
    }

    #[test]
    fn a_request_is_narrowed_never_widened() {
        let e = entry(&["registry"], Some(&["d1"]));
        let (k, d) = effective(
            &e,
            &strings(&["registry", "revocation"]),
            &strings(&["d1", "d2"]),
        );
        assert_eq!(k, ["registry".to_string()].into());
        assert_eq!(d, Some(["d1".to_string()].into()));
        let (k, d) = effective(&e, &[], &[]);
        assert_eq!(k, e.kinds);
        assert_eq!(d, e.domains);
        // An unrestricted entry takes the request's domains as given.
        let open = entry(&["registry"], None);
        assert_eq!(effective(&open, &[], &[]).1, None);
        assert_eq!(
            effective(&open, &[], &strings(&["x"])).1,
            Some(["x".to_string()].into())
        );
    }

    #[test]
    fn events_without_a_domain_follow_the_kind_filter() {
        let ev = |domain: Option<&str>| OutboxEvent {
            kind: "registry".into(),
            domain_id: domain.map(str::to_owned),
            key: vec![],
            op: openstack_keystone_storage_api::FeedOp::Set,
            value: None,
        };
        let kinds: BTreeSet<String> = ["registry".to_string()].into();
        let domains = Some(["d1".to_string()].into());
        assert!(wanted(&ev(Some("d1")), &kinds, &domains));
        assert!(!wanted(&ev(Some("d2")), &kinds, &domains));
        assert!(wanted(&ev(None), &kinds, &domains));
        assert!(!wanted(&ev(None), &BTreeSet::new(), &domains));
    }
}
