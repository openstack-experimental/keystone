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
//! # CADF audit framework for OpenStack services
//!
//! A reusable, [pycadf]-like implementation of the DMTF Cloud Auditing Data
//! Federation (CADF) event model together with the machinery to emit,
//! persist and ship those events reliably. It is the audit layer of Keystone
//! (ADR 0023) and is designed to be embedded by any OpenStack service written
//! in Rust. Nothing in this crate depends on Keystone's domain types.
//!
//! [pycadf]: https://docs.openstack.org/pycadf/latest/
//!
//! ## Pipeline
//!
//! ```text
//! request handler ──► AuditDispatcher ──► spool writer ──► spool segments ──► sink
//!   (CadfEvent)        sign + queue         (one task)      (sealed, verified)  (stdout, syslog)
//! ```
//!
//! 1. **Events** ([`types`]): [`CadfEvent`] is a CADF record built from
//!    [`Initiator`], [`Target`], [`Observer`] and related types. Field values
//!    are sanitized so that untrusted input cannot forge or break records.
//! 2. **Signing and dispatch** ([`dispatcher`]): [`AuditDispatcher`] signs
//!    every event with HMAC-SHA256 and queues it on one of two QoS channels.
//!    The *critical* channel applies back-pressure so the event is never lost;
//!    the *perimeter* channel drops (and counts) events under overload so audit
//!    cannot take the service down.
//! 3. **Keys** ([`keyring`], [`kdf`]): a persisted, versioned [`HmacKeyring`]
//!    holds the key-encryption key. The signing key of each node is derived
//!    from it with HKDF, so a compromised node cannot forge records attributed
//!    to another node, and rotation only adds versions so old records stay
//!    verifiable.
//! 4. **Spool** ([`spool`]): a single writer appends signed events to a
//!    per-node spool file guarded by an exclusive lock, seals it on restart and
//!    verifies sealed segments at rest, giving at-least-once delivery.
//! 5. **Sinks** ([`sink`], `syslog`): sealed segments are shipped to an
//!    [`AuditSink`] ([`StdoutSink`], or an RFC 5424 syslog sink over TCP/TLS
//!    with the `syslog` feature) and removed once acknowledged.
//! 6. **Metrics** ([`metrics`]): Prometheus text-format counters for the
//!    dispatcher, spool and shipper.
//!
//! ## Embedding the framework in a service
//!
//! A service names itself with a [`ServiceIdentity`], which drives everything
//! that would otherwise hard-code a service name: the HKDF label of the
//! signing key, the metric prefix, the default syslog APP-NAME and the default
//! spool directory. The identity must stay stable, because changing it changes
//! the derived keys.
//!
//! ```
//! use cadf::ServiceIdentity;
//!
//! const AUDIT_SERVICE: ServiceIdentity = ServiceIdentity::new("myservice");
//! assert_eq!(
//!     AUDIT_SERVICE.metric_name("events_total"),
//!     "myservice_audit_events_total"
//! );
//! ```
//!
//! The service reads its `[audit]` section into an [`AuditConfig`] (it
//! deserializes with serde and is meant to be embedded in the service's own
//! configuration) and, with the `runtime` feature, starts the whole pipeline
//! with one call:
//!
//! ```ignore
//! let (dispatcher, writer) =
//!     cadf::runtime::init(&AUDIT_SERVICE, &config.audit, Vec::new(), &shutdown).await?;
//! // ... emit events through `dispatcher` ...
//! shutdown.cancel();
//! if let Some(writer) = writer {
//!     writer.await?; // drains queued events and releases the spool lock
//! }
//! ```
//!
//! With `[audit] enabled = false` a disabled dispatcher is returned and
//! nothing is written to disk.
//!
//! ## Submitting an audit event
//!
//! Once the service holds an `Arc<AuditDispatcher>`, recording an event is
//! three steps: build a [`CadfEventPayload`], sign it with the dispatcher and
//! hand the signed [`CadfEvent`] to one of the two channels. An event cannot
//! be dispatched unsigned, because [`CadfEvent`] is only produced by
//! [`CadfEventPayload::sign`].
//!
//! ```
//! use std::sync::Arc;
//!
//! use cadf::{
//!     AuditDispatcher, CadfEventPayload, Initiator, Observer, Outcome, OutcomeReason, Target,
//! };
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), cadf::AuditChannelDead> {
//! # let key: Arc<[u8]> = Arc::from(b"doc-example-key-0123456789abcdef".as_slice());
//! # let (dispatcher, mut receivers) =
//! #     AuditDispatcher::new("node-1", "boot-1".to_string(), key, 1);
//! let node_id = dispatcher.node_id().to_string();
//!
//! let payload = CadfEventPayload::new(
//!     // Unique record id; prefixing the node id keeps it unique across nodes.
//!     format!("{node_id}:{}", uuid::Uuid::new_v4()),
//!     // Record schema version, kept in the signed `integrity` attachment.
//!     "1.1".to_string(),
//!     // Request id shared by every record of one request, so they can be
//!     // joined later.
//!     "req-0123456789abcdef".to_string(),
//!     // RFC 3339 time of the event.
//!     "2026-06-16T00:00:00+00:00".to_string(),
//!     // Lowercase verb, or `/`-separated name: `create`, `oauth2/refresh`.
//!     "delete".to_string(),
//!     Outcome::Failure,
//!     // Fixed vocabulary word, never error text; `None` when there is none.
//!     Some(OutcomeReason::literal("Forbidden")),
//!     // Who acted: opaque ids only, never a user name.
//!     Initiator::new(
//!         "user-id".to_string(),
//!         Some("project-id".to_string()),
//!         Some("domain-id".to_string()),
//!         None,
//!     )
//!     .with_address(Some("203.0.113.9".to_string())),
//!     // What was acted on: its id and a `typeURI`.
//!     Target::new("resource-id", "data/security/myservice/resource"),
//!     // The node that recorded the event.
//!     Observer::new(node_id.clone(), format!("service/security/myservice/{node_id}")),
//! );
//!
//! // Signing fills in `seq`, `boot_session_id` and `hmac_key_version`.
//! let event = payload.sign(&dispatcher);
//!
//! // Best effort: never blocks, drops (and counts) the event if the queue is full.
//! dispatcher.dispatch(event);
//! # let sent = receivers.perimeter.try_recv().expect("queued");
//! # assert_eq!(sent.payload().outcome(), Outcome::Failure);
//! # assert_eq!(sent.payload().correlation_id(), "req-0123456789abcdef");
//! # assert!(!sent.signature().is_empty());
//!
//! // Fail closed: waits for room and errors only if the writer is gone.
//! # let payload = CadfEventPayload::new(
//! #     "node-1:2".to_string(), "1.1".to_string(), "req-1".to_string(),
//! #     "2026-06-16T00:00:00+00:00".to_string(), "delete".to_string(), Outcome::Pending,
//! #     None, Initiator::system("doc"), Target::new("t", "x"), Observer::new("node-1", "o"),
//! # );
//! dispatcher.dispatch_critical(payload.sign(&dispatcher)).await?;
//! # assert!(receivers.critical.try_recv().is_ok());
//! # Ok(())
//! # }
//! ```
//!
//! ### Sample record
//!
//! The event above is written to the spool, and shipped to the sink, as one
//! JSON line in the DSP0262 layout (shown wrapped here). The correlation id
//! is a `tags` entry, and the fields DSP0262 has no place for travel in the
//! `integrity` attachment; the signature covers everything else in the line.
//!
//! ```json
//! {
//!   "typeURI": "http://schemas.dmtf.org/cloud/audit/1.0/event",
//!   "eventType": "activity",
//!   "id": "node-1:550e8400-e29b-41d4-a716-446655440000",
//!   "eventTime": "2026-06-16T00:00:00+00:00",
//!   "action": "delete",
//!   "outcome": "failure",
//!   "reason": {"reasonType": "keystone", "reasonCode": "Forbidden"},
//!   "initiator": {
//!     "typeURI": "service/security/account/user",
//!     "id": "user-id",
//!     "project_id": "project-id",
//!     "domain_id": "domain-id",
//!     "host": {"address": "203.0.113.9"}
//!   },
//!   "target": {"id": "resource-id", "typeURI": "data/security/myservice/resource"},
//!   "observer": {"id": "service/security/myservice/node-1", "typeURI": "service/security/keystone"},
//!   "tags": ["correlation_id:req-0123456789abcdef"],
//!   "attachments": [{
//!     "name": "integrity",
//!     "contentType": "application/json",
//!     "content": {
//!       "seq": 42,
//!       "boot_session_id": "boot-1",
//!       "hmac_key_version": 1,
//!       "version": "1.1",
//!       "domain": "domain-id",
//!       "observer_node_id": "node-1"
//!     }
//!   }],
//!   "signature": "<hex HMAC-SHA256>"
//! }
//! ```
//!
//! Events built with [`CadfEventPayload::with_oauth2_context`] carry an
//! additional `oauth2` attachment (`{"client_id", "grant_type"}`) after the
//! `integrity` one; it is signed like the rest of the record, so readers
//! must find attachments by `name`, not by position.
//!
//! ### Choosing a channel
//!
//! - [`AuditDispatcher::dispatch`] is for high-volume records where losing one
//!   under overload is better than slowing the service, such as a record for
//!   every request. It never fails and never waits; drops show up in
//!   [`AuditDispatcher::dropped_count`] and the drop metric.
//! - [`AuditDispatcher::dispatch_critical`] is for records that must exist
//!   before the action takes effect, such as a state change. Await it and abort
//!   the action on `Err(AuditChannelDead)`. The usual shape is a
//!   [`Outcome::Pending`] record before the action and a [`Outcome::Success`]
//!   or [`Outcome::Failure`] record after it; a `pending` record with no
//!   terminal record means the process died in between.
//!
//! With `[audit] enabled = false` both calls are successful no-ops, so callers
//! need no check of their own.
//!
//! ### What goes in a record
//!
//! - Every free-text field is reduced to a safe character set when the payload
//!   is built, so untrusted input cannot forge or break a record. That is a
//!   floor, not a license: pass identifiers, not user-supplied text.
//! - [`Outcome`] is the closed DSP0262 set. Put the cause in an
//!   [`OutcomeReason`], which only accepts a `'static` literal, a sanitized
//!   error variant name or counters, never an error message.
//! - Use [`Initiator::system`] for work the service does on its own behalf, and
//!   [`Initiator::with_address`] / [`Initiator::with_host_id`] for the client
//!   address and a pre-authentication identity such as an access key id.
//!
//! ## Cargo features
//!
//! - `runtime`: the `runtime` module, the service bootstrap (key load, spool
//!   lock/seal/verify, writer, shipper, key reload).
//! - `syslog`: RFC 5424 syslog sink over TCP, optionally wrapped in TLS.
//! - `testing`: helpers for the tests of embedding crates.
//!
//! ## Where the rest of the architecture lives
//!
//! ADR 0023 describes three phases: this crate is phase 1 (event types,
//! signing, dispatch, spool and delivery). Perimeter auditing (ingress and
//! completion middleware) and provider auditing (context-aware hooks) are
//! service-specific and live in Keystone's `crates/core` and `crates/keystone`.

#![deny(clippy::unwrap_used)]

pub mod config;
pub mod dispatcher;
mod hex;
pub mod identity;
pub mod kdf;
pub mod keyring;
pub mod metrics;
#[cfg(feature = "runtime")]
pub mod runtime;
pub mod sanitize;
pub mod sink;
pub mod spool;
#[cfg(feature = "syslog")]
pub mod syslog;
pub mod types;

pub use config::{AuditConfig, AuditSinkConfig, UNKNOWN_NODE_ID};
pub use dispatcher::{
    AuditChannelDead, AuditChannelReceivers, AuditDispatcher, DEFAULT_CRITICAL_CHANNEL_CAPACITY,
    DEFAULT_PERIMETER_CHANNEL_CAPACITY,
};
pub use identity::ServiceIdentity;
pub use kdf::derive_audit_hmac_key;
pub use keyring::{HmacKeyring, KeyringError, NodeKeyStore};
pub use sink::{
    AuditSink, ShipperConfig, SinkError, StdoutSink, run_raw_segment_shipper, run_segment_shipper,
};
pub use spool::{HmacKeyStore, SpoolConfig, SpoolError};
#[cfg(feature = "syslog")]
pub use syslog::{SyslogSink, SyslogSinkConfig};
pub use types::{
    CadfEvent, CadfEventPayload, Host, Initiator, Observer, Outcome, OutcomeReason, Target,
};
