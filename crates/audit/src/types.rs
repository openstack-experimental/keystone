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
//! CADF event type hierarchy.
//!
//! `CadfEvent` wraps a private `CadfEventPayload` together with a `signature`
//! via `serde(flatten)`. This design ensures unsigned events cannot be
//! serialized: the only construction path goes through
//! `CadfEventPayload::sign()`, which calls `AuditDispatcher::finalize_event`.

use serde::{Deserialize, Serialize};

/// All fields of a CADF event before signing.
///
/// Private by design — callers obtain a `CadfEvent` only via
/// `CadfEventPayload::sign()`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CadfEventPayload {
    pub(crate) id: String,
    pub(crate) seq: u64,
    pub(crate) boot_session_id: String,
    pub(crate) hmac_key_version: u64,
    pub(crate) version: String,
    pub(crate) domain: String,
    pub(crate) correlation_id: String,
    pub(crate) event_time: String,
    pub(crate) action: String,
    pub(crate) outcome: String,
    pub(crate) outcome_reason: Option<String>,
    pub(crate) initiator: Initiator,
    pub(crate) target: Target,
    pub(crate) observer: Observer,
}

impl CadfEventPayload {
    /// Construct a new unsigned payload. The `seq`, `boot_session_id`, and
    /// `hmac_key_version` fields are placeholders; `AuditDispatcher::finalize_event`
    /// fills them in when signing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        version: String,
        domain: String,
        correlation_id: String,
        event_time: String,
        action: String,
        outcome: String,
        outcome_reason: Option<String>,
        initiator: Initiator,
        target: Target,
        observer: Observer,
    ) -> Self {
        Self {
            id,
            seq: 0,
            boot_session_id: String::new(),
            hmac_key_version: 0,
            version,
            domain,
            correlation_id,
            event_time,
            action,
            outcome,
            outcome_reason,
            initiator,
            target,
            observer,
        }
    }

    /// Sign this payload via the dispatcher, producing a `CadfEvent`.
    ///
    /// The dispatcher fills `seq`, `boot_session_id`, and `hmac_key_version`,
    /// then computes the HMAC-SHA256 over the JCS-canonical form (RFC 8785).
    pub fn sign(self, dispatcher: &crate::dispatcher::AuditDispatcher) -> CadfEvent {
        dispatcher.finalize_event(self)
    }

    // ---- read-only getters used by the spool and HMAC verification paths ----

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn boot_session_id(&self) -> &str {
        &self.boot_session_id
    }
    pub fn hmac_key_version(&self) -> u64 {
        self.hmac_key_version
    }
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }
    pub fn action(&self) -> &str {
        &self.action
    }
    pub fn outcome(&self) -> &str {
        &self.outcome
    }
    pub fn observer(&self) -> &Observer {
        &self.observer
    }
}

/// A fully signed CADF event. The `signature` field holds the hex-encoded
/// HMAC-SHA256 over the JCS-canonical serialization of the payload.
///
/// External SIEMs MUST verify by:
/// 1. Parse received JSON.
/// 2. Remove the `signature` key.
/// 3. Serialize the remainder in JCS canonical form (RFC 8785).
/// 4. Compute HMAC-SHA256 with the key identified by `hmac_key_version`.
///
/// Cross-language test vectors live in `tests/audit/hmac_vectors.jsonl`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CadfEvent {
    #[serde(flatten)]
    pub(crate) event: CadfEventPayload,
    // pub(crate): external callers must use the `signature()` getter; direct
    // mutation is intentionally prevented outside this crate.
    pub(crate) signature: String,
}

impl CadfEvent {
    pub fn payload(&self) -> &CadfEventPayload {
        &self.event
    }
    pub fn signature(&self) -> &str {
        &self.signature
    }
    pub fn correlation_id(&self) -> &str {
        &self.event.correlation_id
    }
    pub fn id(&self) -> &str {
        &self.event.id
    }
    pub fn seq(&self) -> u64 {
        self.event.seq
    }
    pub fn boot_session_id(&self) -> &str {
        &self.event.boot_session_id
    }
}

/// Audit initiator — only opaque identifiers, never PII.
///
/// Human-readable fields (usernames, emails, project names) are excluded by
/// design. The `host` field carries pre-auth signals; sanitization rules are
/// enforced at construction time (see `sanitize::sanitize_initiator_host`).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Initiator {
    id: String,
    project_id: Option<String>,
    domain_id: Option<String>,
    /// Pre-auth signal (EC2 access key, federation idp_id). No PII.
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
}

impl Initiator {
    pub fn new(
        id: String,
        project_id: Option<String>,
        domain_id: Option<String>,
        host: Option<String>,
    ) -> Self {
        Self {
            id,
            project_id,
            domain_id,
            host,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn project_id(&self) -> Option<&str> {
        self.project_id.as_deref()
    }
    pub fn domain_id(&self) -> Option<&str> {
        self.domain_id.as_deref()
    }
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }
}

/// Audit target — the resource being acted upon.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Target {
    pub id: String,
    pub type_uri: String,
}

/// Audit observer — the node that recorded the event.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Observer {
    pub node_id: String,
    pub id: String,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::dispatcher::AuditDispatcher;

    fn make_dispatcher(
        node: &str,
        key: Arc<[u8]>,
    ) -> (
        Arc<AuditDispatcher>,
        crate::dispatcher::AuditChannelReceivers,
    ) {
        AuditDispatcher::new(node, "boot-1".to_string(), key, 1)
    }

    fn make_payload(dispatcher: &AuditDispatcher) -> CadfEventPayload {
        CadfEventPayload::new(
            format!(
                "{}:aabbccdd-0000-0000-0000-000000000000",
                dispatcher.node_id()
            ),
            "1.0".to_string(),
            "default".to_string(),
            "req-corr".to_string(),
            "2026-06-16T00:00:00+00:00".to_string(),
            "delete".to_string(),
            "success".to_string(),
            None,
            Initiator::new("unknown".to_string(), None, None, None),
            Target {
                id: "some-user-id".to_string(),
                type_uri: "data/security/identity/user".to_string(),
            },
            Observer {
                node_id: dispatcher.node_id().to_string(),
                id: format!("service/security/keystone/{}", dispatcher.node_id()),
            },
        )
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let key: Arc<[u8]> = Arc::from(b"test-key-32-bytes-0123456789abcd".as_slice());
        let (dispatcher, _rx) = make_dispatcher("test-node", Arc::clone(&key));

        let mut event = make_payload(&dispatcher).sign(&dispatcher);
        assert!(
            dispatcher.verify_hmac(&event, &key),
            "fresh event must verify"
        );

        event.signature =
            "deadbeef00000000000000000000000000000000000000000000000000000000".to_string();
        assert!(
            !dispatcher.verify_hmac(&event, &key),
            "tampered signature must fail"
        );
    }
}
