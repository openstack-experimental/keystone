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
    /// `hmac_key_version` fields are placeholders;
    /// `AuditDispatcher::finalize_event` fills them in when signing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        version: String,
        domain: String,
        correlation_id: String,
        event_time: String,
        action: String,
        outcome: String,
        outcome_reason: Option<OutcomeReason>,
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
            outcome_reason: outcome_reason.map(OutcomeReason::into_string),
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
    pub fn initiator(&self) -> &Initiator {
        &self.initiator
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

/// CADF `Resource.host` sub-object (DSP0262 §9.3.3, "Host Data Type").
///
/// Per the CADF spec, `host` on a `Resource` (and therefore on `Initiator`,
/// which is a `Resource`) is itself a structured type, not a bare string.
/// The spec defines four attributes: `id`, `address`, `agent`, `platform`.
/// Only `id` and `address` are populated here; `agent`/`platform` are valid
/// CADF attributes we don't currently capture and are omitted rather than
/// modeled speculatively.
///
/// - `id`: pre-auth identity signal (EC2 access key, federation idp_id).
///   Content arrives before authentication and is fully attacker-controlled;
///   sanitized at construction (see `sanitize::sanitize_initiator_host`).
/// - `address`: the client network address the request was received from.
///   Sanitized via `sanitize::sanitize_initiator_address` (parses as a
///   well-formed `IpAddr`; anything else is dropped, never stored raw).
///
/// # Serialization note
///
/// Both fields are **omitted entirely** (not set to `null`) when absent,
/// via `#[serde(skip_serializing_if = "Option::is_none")]`. See
/// [`Initiator`]'s serialization note for the same rule at the `host` level.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Host {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
}

impl Host {
    /// Construct a `Host` carrying only a pre-auth identity signal (`id`).
    pub fn from_id(id: String) -> Self {
        Self {
            id: Some(id),
            address: None,
        }
    }

    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }
}

/// The `outcome_reason` of an audit record: a closed vocabulary, never free
/// text.
///
/// ADR 0023 ("Outcome Isolation") limits the reason to a sanitized variant
/// name. Making that a type means a caller cannot put an ID, a plugin-supplied
/// sentence or `Debug` output of a request into the record: the only
/// constructors take a `'static` literal, a variant name that is reduced to
/// `[A-Za-z0-9_-]` (at most 64 characters), or a list of `name=count` pairs
/// whose names are reduced the same way. Identifiers belong in the `target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeReason(std::borrow::Cow<'static, str>);

impl OutcomeReason {
    /// Longest accepted variant name.
    const MAX_VARIANT_LEN: usize = 64;

    /// A fixed, compile-time reason such as `"RouteDenied"`.
    #[must_use]
    pub const fn literal(reason: &'static str) -> Self {
        Self(std::borrow::Cow::Borrowed(reason))
    }

    /// A reason derived from an error variant name. Anything outside
    /// `[A-Za-z0-9_-]` is dropped and the result is capped, so even a name
    /// built from error data cannot smuggle free text into the record. An
    /// empty result becomes `"unknown"`.
    #[must_use]
    pub fn variant(name: &str) -> Self {
        let cleaned: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
            .take(Self::MAX_VARIANT_LEN)
            .collect();
        if cleaned.is_empty() {
            Self::literal("unknown")
        } else {
            Self(std::borrow::Cow::Owned(cleaned))
        }
    }

    /// A summary of counters such as `session=3,errors=1`. The values are
    /// numbers and each name is reduced like a [`variant`](Self::variant)
    /// name.
    #[must_use]
    pub fn counts(pairs: &[(&str, u64)]) -> Self {
        let rendered = pairs
            .iter()
            .map(|(name, value)| format!("{}={value}", Self::variant(name).as_str()))
            .collect::<Vec<_>>()
            .join(",");
        Self(std::borrow::Cow::Owned(rendered))
    }

    /// The reason as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn into_string(self) -> String {
        self.0.into_owned()
    }
}

/// Audit initiator — only opaque identifiers, never PII.
///
/// Human-readable fields (usernames, emails, project names) are excluded by
/// design. The `host` field is a [`Host`] sub-object carrying pre-auth
/// signals and the client network address; sanitization rules are enforced
/// at construction time, never on raw input (see `sanitize` module).
///
/// # Serialization note
///
/// `project_id` and `domain_id` serialize as JSON `null` when absent.
/// `host` is **omitted entirely** (not set to `null`) when absent, indicated
/// by `#[serde(skip_serializing_if = "Option::is_none")]`.  SIEMs that
/// re-serialize the received JSON to verify the HMAC signature MUST NOT
/// insert a `"host": null` key for events that do not carry a `host` field;
/// they must re-serialize the JSON object as received (minus the `signature`
/// key) without adding absent keys.  See ADR-0023 §"HMAC Signing" for the
/// full SIEM verification procedure.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Initiator {
    id: String,
    project_id: Option<String>,
    domain_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<Host>,
}

impl Initiator {
    pub fn new(
        id: String,
        project_id: Option<String>,
        domain_id: Option<String>,
        host: Option<Host>,
    ) -> Self {
        Self {
            id,
            project_id,
            domain_id,
            host,
        }
    }

    /// An initiator for work the service does on its own behalf (janitors,
    /// maintenance, startup tasks), identified as `system:<component>`.
    ///
    /// `component` is a compile-time name such as `"api_key_janitor"`; the
    /// `system:` prefix keeps these apart from user and service UUIDs, which
    /// is why the ID is not run through the UUID sanitizer.
    #[must_use]
    pub fn system(component: &'static str) -> Self {
        Self::new(format!("system:{component}"), None, None, None)
    }

    /// Attach a pre-auth identity signal (EC2 access key, federation IdP) to
    /// `host.id`, already sanitized with
    /// [`crate::sanitize::sanitize_initiator_host`]. `None` leaves the
    /// initiator unchanged. Preserves any `host.address` already set.
    #[must_use]
    pub fn with_host_id(mut self, host_id: Option<String>) -> Self {
        let Some(host_id) = host_id else {
            return self;
        };
        match &mut self.host {
            Some(host) => host.id = Some(host_id),
            None => self.host = Some(Host::from_id(host_id)),
        }
        self
    }

    /// Attach a client IP address to `host.address`, sanitized via
    /// [`crate::sanitize::sanitize_initiator_address`]. Preserves any
    /// pre-auth `host.id` signal already set.
    #[must_use]
    pub fn with_address(mut self, address: Option<String>) -> Self {
        let Some(address) = address.and_then(|a| crate::sanitize::sanitize_initiator_address(&a))
        else {
            return self;
        };
        match &mut self.host {
            Some(host) => host.address = Some(address),
            None => {
                self.host = Some(Host {
                    id: None,
                    address: Some(address),
                })
            }
        }
        self
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
    pub fn host(&self) -> Option<&Host> {
        self.host.as_ref()
    }
    /// Convenience passthrough for `host.address`.
    pub fn address(&self) -> Option<&str> {
        self.host.as_ref().and_then(Host::address)
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

    #[test]
    fn with_address_creates_host_when_none_set() {
        let initiator = Initiator::new("uid".to_string(), None, None, None)
            .with_address(Some("203.0.113.42".to_string()));
        assert_eq!(initiator.address(), Some("203.0.113.42"));
        assert_eq!(initiator.host().and_then(Host::id), None);
    }

    #[test]
    fn with_address_preserves_existing_host_id() {
        let initiator = Initiator::new(
            "uid".to_string(),
            None,
            None,
            Some(Host::from_id("idp-1".to_string())),
        )
        .with_address(Some("203.0.113.42".to_string()));
        assert_eq!(initiator.host().and_then(Host::id), Some("idp-1"));
        assert_eq!(initiator.address(), Some("203.0.113.42"));
    }

    #[test]
    fn with_address_invalid_ip_leaves_host_untouched() {
        let initiator = Initiator::new("uid".to_string(), None, None, None)
            .with_address(Some("not-an-ip".to_string()));
        assert!(initiator.host().is_none());
        assert_eq!(initiator.address(), None);
    }

    #[test]
    fn host_serializes_nested_under_initiator() {
        let initiator = Initiator::new("uid".to_string(), None, None, None)
            .with_address(Some("203.0.113.42".to_string()));
        let json = serde_json::to_value(&initiator).unwrap();
        assert_eq!(json["host"]["address"], "203.0.113.42");
        assert!(json["host"].get("id").is_none());
        assert!(json.get("address").is_none(), "no top-level address field");
    }

    #[test]
    fn host_omitted_entirely_when_absent() {
        let initiator = Initiator::new("uid".to_string(), None, None, None);
        let json = serde_json::to_value(&initiator).unwrap();
        assert!(json.get("host").is_none());
    }

    #[test]
    fn outcome_reason_variant_drops_everything_but_identifier_characters() {
        assert_eq!(OutcomeReason::variant("NotFound").as_str(), "NotFound");
        // An ID, a sentence and Debug output cannot pass through.
        assert_eq!(
            OutcomeReason::variant("user 4f1c-a9 not found: {\"x\": [1]}").as_str(),
            "user4f1c-a9notfoundx1"
        );
        assert_eq!(OutcomeReason::variant("!!! ???").as_str(), "unknown");
        assert_eq!(OutcomeReason::variant("").as_str(), "unknown");
        assert_eq!(OutcomeReason::variant(&"a".repeat(500)).as_str().len(), 64);
    }

    #[test]
    fn outcome_reason_counts_renders_name_value_pairs() {
        assert_eq!(
            OutcomeReason::counts(&[("session", 3), ("errors", 1)]).as_str(),
            "session=3,errors=1"
        );
    }

    #[test]
    fn system_initiator_is_prefixed_and_has_no_scope() {
        let i = Initiator::system("api_key_janitor");
        assert_eq!(i.id(), "system:api_key_janitor");
        assert_eq!(i.project_id(), None);
        assert!(i.host().is_none());
    }

    #[test]
    fn with_host_id_and_with_address_compose_in_either_order() {
        let a = Initiator::new("unknown".into(), None, None, None)
            .with_host_id(Some("AKIAABCDEFGHIJKLMNOP".into()))
            .with_address(Some("203.0.113.9".into()));
        let b = Initiator::new("unknown".into(), None, None, None)
            .with_address(Some("203.0.113.9".into()))
            .with_host_id(Some("AKIAABCDEFGHIJKLMNOP".into()));
        for i in [a, b] {
            let host = i.host().expect("host");
            assert_eq!(host.id(), Some("AKIAABCDEFGHIJKLMNOP"));
            assert_eq!(host.address(), Some("203.0.113.9"));
        }
        // `None` leaves the initiator untouched.
        let none = Initiator::new("unknown".into(), None, None, None).with_host_id(None);
        assert!(none.host().is_none());
    }
}
