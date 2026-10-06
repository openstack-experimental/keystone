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
//! 2. **Signing and dispatch** ([`dispatcher`]): [`AuditDispatcher`] signs every
//!    event with HMAC-SHA256 and queues it on one of two QoS channels. The
//!    *critical* channel applies back-pressure so the event is never lost; the
//!    *perimeter* channel drops (and counts) events under overload so audit
//!    cannot take the service down.
//! 3. **Keys** ([`keyring`], [`kdf`]): a persisted, versioned
//!    [`HmacKeyring`] holds the key-encryption key. The signing key of each
//!    node is derived from it with HKDF, so a compromised node cannot forge
//!    records attributed to another node, and rotation only adds versions so
//!    old records stay verifiable.
//! 4. **Spool** ([`spool`]): a single writer appends signed events to a
//!    per-node spool file guarded by an exclusive lock, seals it on restart
//!    and verifies sealed segments at rest, giving at-least-once delivery.
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
//! assert_eq!(AUDIT_SERVICE.metric_name("events_total"), "myservice_audit_events_total");
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
pub use types::{CadfEvent, CadfEventPayload, Host, Initiator, Observer, OutcomeReason, Target};
