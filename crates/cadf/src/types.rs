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
#[derive(Clone, Debug)]
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
    /// The record was read from a line written in the pre-DSP0262 layout. Such
    /// a record keeps its original form so that its signature still verifies.
    pub(crate) legacy: bool,
}

/// DSP0262 `typeURI` of an event record.
const EVENT_TYPE_URI: &str = "http://schemas.dmtf.org/cloud/audit/1.0/event";
/// `typeURI` given to every initiator.
const INITIATOR_TYPE_URI: &str = "service/security/account/user";
/// `typeURI` given to the observer.
const OBSERVER_TYPE_URI: &str = "service/security/keystone";
/// Tag prefix carrying the correlation id.
const CORRELATION_TAG: &str = "correlation_id:";
/// Name of the attachment carrying the fields DSP0262 has no place for.
const INTEGRITY_ATTACHMENT: &str = "integrity";

/// Error for a record that is neither a DSP0262 record nor a legacy one.
#[derive(Debug, thiserror::Error)]
#[error("malformed audit record: {0}")]
pub(crate) struct WireError(String);

fn wire_err(what: &str) -> WireError {
    WireError(what.to_string())
}

impl CadfEventPayload {
    /// The pre-DSP0262 layout, used only to verify legacy records.
    fn legacy_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(LegacyPayload {
            id: &self.id,
            seq: self.seq,
            boot_session_id: &self.boot_session_id,
            hmac_key_version: self.hmac_key_version,
            version: &self.version,
            domain: &self.domain,
            correlation_id: &self.correlation_id,
            event_time: &self.event_time,
            action: &self.action,
            outcome: &self.outcome,
            outcome_reason: &self.outcome_reason,
            initiator: &self.initiator,
            target: &self.target,
            observer: &self.observer,
        })
    }

    /// The record as it is signed and written: DSP0262 names, the correlation
    /// id in `tags` and the integrity fields in an `attachments` entry.
    pub(crate) fn to_wire_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        use serde_json::{Value, json};
        if self.legacy {
            return self.legacy_value();
        }
        let mut initiator = serde_json::to_value(&self.initiator)?;
        if let Value::Object(map) = &mut initiator {
            map.insert("typeURI".into(), json!(INITIATOR_TYPE_URI));
        }
        let mut event = json!({
            "typeURI": EVENT_TYPE_URI,
            "eventType": "activity",
            "id": self.id,
            "eventTime": self.event_time,
            "action": self.action,
            "outcome": self.outcome,
            "initiator": initiator,
            "target": {"id": self.target.id, "typeURI": self.target.type_uri},
            "observer": {"id": self.observer.id, "typeURI": OBSERVER_TYPE_URI},
            "tags": [format!("{CORRELATION_TAG}{}", self.correlation_id)],
            "attachments": [{
                "name": INTEGRITY_ATTACHMENT,
                "contentType": "application/json",
                "content": {
                    "seq": self.seq,
                    "boot_session_id": self.boot_session_id,
                    "hmac_key_version": self.hmac_key_version,
                    "version": self.version,
                    "domain": self.domain,
                    "observer_node_id": self.observer.node_id,
                },
            }],
        });
        if let (Some(reason), Value::Object(map)) = (&self.outcome_reason, &mut event) {
            map.insert(
                "reason".into(),
                json!({"reasonType": "keystone", "reasonCode": reason}),
            );
        }
        Ok(event)
    }

    /// Parse a record in either layout.
    pub(crate) fn from_wire_value(value: serde_json::Value) -> Result<Self, WireError> {
        if value.get("eventTime").is_none() {
            let legacy: LegacyOwnedPayload =
                serde_json::from_value(value).map_err(|e| WireError(e.to_string()))?;
            return Ok(Self {
                id: legacy.id,
                seq: legacy.seq,
                boot_session_id: legacy.boot_session_id,
                hmac_key_version: legacy.hmac_key_version,
                version: legacy.version,
                domain: legacy.domain,
                correlation_id: legacy.correlation_id,
                event_time: legacy.event_time,
                action: legacy.action,
                outcome: legacy.outcome,
                outcome_reason: legacy.outcome_reason,
                initiator: legacy.initiator,
                target: legacy.target,
                observer: legacy.observer,
                legacy: true,
            });
        }
        let text = |v: &serde_json::Value, key: &str| -> Result<String, WireError> {
            v.get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| wire_err(&format!("missing `{key}`")))
        };
        let correlation_id = value
            .get("tags")
            .and_then(serde_json::Value::as_array)
            .and_then(|tags| {
                tags.iter()
                    .filter_map(serde_json::Value::as_str)
                    .find_map(|t| t.strip_prefix(CORRELATION_TAG))
            })
            .ok_or_else(|| wire_err("missing correlation id tag"))?
            .to_string();
        let integrity = value
            .get("attachments")
            .and_then(serde_json::Value::as_array)
            .and_then(|a| {
                a.iter().find(|a| {
                    a.get("name").and_then(serde_json::Value::as_str) == Some(INTEGRITY_ATTACHMENT)
                })
            })
            .and_then(|a| a.get("content"))
            .ok_or_else(|| wire_err("missing integrity attachment"))?;
        let number = |key: &str| -> Result<u64, WireError> {
            integrity
                .get(key)
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| wire_err(&format!("missing integrity `{key}`")))
        };
        let initiator: Initiator = serde_json::from_value(
            value
                .get("initiator")
                .cloned()
                .ok_or_else(|| wire_err("missing `initiator`"))?,
        )
        .map_err(|e| WireError(e.to_string()))?;
        let target = value
            .get("target")
            .ok_or_else(|| wire_err("missing `target`"))?;
        let observer = value
            .get("observer")
            .ok_or_else(|| wire_err("missing `observer`"))?;
        Ok(Self {
            id: text(&value, "id")?,
            seq: number("seq")?,
            boot_session_id: text(integrity, "boot_session_id")?,
            hmac_key_version: number("hmac_key_version")?,
            version: text(integrity, "version")?,
            domain: text(integrity, "domain")?,
            correlation_id,
            event_time: text(&value, "eventTime")?,
            action: text(&value, "action")?,
            outcome: text(&value, "outcome")?,
            outcome_reason: value
                .get("reason")
                .and_then(|r| r.get("reasonCode"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            initiator,
            target: Target {
                id: text(target, "id")?,
                type_uri: text(target, "typeURI")?,
            },
            observer: Observer {
                node_id: text(integrity, "observer_node_id")?,
                id: text(observer, "id")?,
            },
            legacy: false,
        })
    }
}

impl Serialize for CadfEventPayload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_wire_value()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CadfEventPayload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        Self::from_wire_value(value).map_err(serde::de::Error::custom)
    }
}

/// Borrowed pre-DSP0262 layout.
#[derive(Serialize)]
struct LegacyPayload<'a> {
    id: &'a str,
    seq: u64,
    boot_session_id: &'a str,
    hmac_key_version: u64,
    version: &'a str,
    domain: &'a str,
    correlation_id: &'a str,
    event_time: &'a str,
    action: &'a str,
    outcome: &'a str,
    outcome_reason: &'a Option<String>,
    initiator: &'a Initiator,
    target: &'a Target,
    observer: &'a Observer,
}

/// Owned pre-DSP0262 layout.
#[derive(Deserialize)]
struct LegacyOwnedPayload {
    id: String,
    seq: u64,
    boot_session_id: String,
    hmac_key_version: u64,
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
}

impl CadfEventPayload {
    /// Construct a new unsigned payload. The `seq`, `boot_session_id`, and
    /// `hmac_key_version` fields are placeholders;
    /// `AuditDispatcher::finalize_event` fills them in when signing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        version: String,
        correlation_id: String,
        event_time: String,
        action: String,
        outcome: String,
        outcome_reason: Option<OutcomeReason>,
        initiator: Initiator,
        target: Target,
        observer: Observer,
    ) -> Self {
        // The record's `domain` is the initiator's domain (`"unknown"` when
        // there is none, e.g. a system actor), never a constant.
        let domain = initiator.domain_id().unwrap_or("unknown").to_string();
        Self {
            id,
            seq: 0,
            boot_session_id: String::new(),
            hmac_key_version: 0,
            version,
            domain,
            correlation_id,
            event_time,
            action: sanitize_action(&action),
            outcome,
            outcome_reason: outcome_reason.map(OutcomeReason::into_string),
            initiator,
            target,
            observer,
            legacy: false,
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
    pub fn target(&self) -> &Target {
        &self.target
    }
    pub fn observer(&self) -> &Observer {
        &self.observer
    }
}

/// Reduce an action name to the CADF action vocabulary every emitter shares:
/// lowercase `[a-z0-9_-]` words separated by `/` (`.` is treated as a
/// separator), at most 64 characters, `"unknown"` when nothing is left.
///
/// Applied by [`CadfEventPayload::new`], so a custom action cannot bypass the
/// naming style of the standard verbs or smuggle free text into a signed
/// record.
#[must_use]
pub fn sanitize_action(action: &str) -> String {
    let cleaned: String = action
        .chars()
        .map(|c| {
            if c == '.' {
                '/'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/'))
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
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
#[derive(Clone, Debug)]
pub struct CadfEvent {
    pub(crate) event: CadfEventPayload,
    // pub(crate): external callers must use the `signature()` getter; direct
    // mutation is intentionally prevented outside this crate.
    pub(crate) signature: String,
}

impl Serialize for CadfEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = self
            .event
            .to_wire_value()
            .map_err(serde::ser::Error::custom)?;
        if let Some(map) = value.as_object_mut() {
            map.insert("signature".into(), self.signature.clone().into());
        }
        value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CadfEvent {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut value = serde_json::Value::deserialize(deserializer)?;
        let signature = value
            .as_object_mut()
            .and_then(|map| map.remove("signature"))
            .and_then(|s| s.as_str().map(str::to_string))
            .ok_or_else(|| serde::de::Error::custom("missing `signature`"))?;
        Ok(Self {
            event: CadfEventPayload::from_wire_value(value).map_err(serde::de::Error::custom)?,
            signature,
        })
    }
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
    fn wire_form_uses_dsp0262_names_and_round_trips() {
        let key: Arc<[u8]> = Arc::from(b"test-key-32-bytes-0123456789abcd".as_slice());
        let (dispatcher, _rx) = make_dispatcher("test-node", Arc::clone(&key));
        let event = make_payload(&dispatcher).sign(&dispatcher);

        let json = serde_json::to_value(&event).unwrap();
        for legacy in ["event_time", "correlation_id", "outcome_reason", "seq"] {
            assert!(json.get(legacy).is_none(), "{legacy} must not be top-level");
        }
        assert_eq!(json["tags"][0], "correlation_id:req-corr");
        assert_eq!(json["attachments"][0]["content"]["seq"], event.seq());
        assert_eq!(json["target"]["typeURI"], "data/security/identity/user");

        let parsed: CadfEvent = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(parsed.correlation_id(), "req-corr");
        assert_eq!(parsed.seq(), event.seq());
        assert!(dispatcher.verify_hmac(&parsed, &key));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), json);
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

    #[test]
    fn domain_is_the_initiators_domain() {
        let (dispatcher, _rx) = make_dispatcher("test-node", Arc::from(b"k".as_slice()));
        let with_domain = |domain: Option<&str>| {
            CadfEventPayload::new(
                "test-node:1".to_string(),
                "1.1".to_string(),
                "req".to_string(),
                "2026-06-16T00:00:00+00:00".to_string(),
                "delete".to_string(),
                "success".to_string(),
                None,
                Initiator::new("u".to_string(), None, domain.map(str::to_string), None),
                Target {
                    id: "t".to_string(),
                    type_uri: "x".to_string(),
                },
                Observer {
                    node_id: "test-node".to_string(),
                    id: "o".to_string(),
                },
            )
            .sign(&dispatcher)
        };
        assert_eq!(with_domain(Some("d1")).payload().domain, "d1");
        assert_eq!(with_domain(None).payload().domain, "unknown");
    }

    #[test]
    fn actions_share_one_naming_style() {
        assert_eq!(sanitize_action("create"), "create");
        assert_eq!(
            sanitize_action("OAUTH2_KEY_ROTATION"),
            "oauth2_key_rotation"
        );
        assert_eq!(
            sanitize_action("wasm_plugin.mapping"),
            "wasm_plugin/mapping"
        );
        assert_eq!(sanitize_action("a b;\n\"c\""), "abc");
        assert_eq!(sanitize_action("  "), "unknown");
        assert_eq!(sanitize_action(&"x".repeat(100)).len(), 64);
    }
}
