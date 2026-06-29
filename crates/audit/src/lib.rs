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
//! # OpenStack Keystone — CADF Audit Framework
//!
//! Implements the three-phase CADF auditing architecture described in ADR 0023:
//!
//! - **Phase 1** (this crate): CADF event types, HMAC-SHA256 signing,
//!   dual-channel QoS dispatch, and spool-based at-least-once delivery.
//! - **Phase 2**: Perimeter auditing (ingress + completion middleware) — in
//!   `crates/core` and `crates/keystone`.
//! - **Phase 3**: Provider auditing via context-aware `AuditHook` — in
//!   `crates/core`.

#![deny(clippy::unwrap_used)]

pub mod dispatcher;
pub mod kdf;
pub mod metrics;
pub mod sanitize;
pub mod spool;
pub mod types;

pub use dispatcher::{AuditChannelDead, AuditChannelReceivers, AuditDispatcher};
pub use kdf::derive_audit_hmac_key;
pub use spool::{HmacKeyStore, SpoolError};
pub use types::{CadfEvent, CadfEventPayload, Initiator, Observer, Target};
