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

use crate::sanitize::sanitize_audit_value;

/// All fields of a CADF event before signing.
///
/// Private by design — callers obtain a `CadfEvent` only via
/// `CadfEventPayload::sign()`.
#[derive(Clone, Debug)]
pub struct CadfEventPayload {
    /// The CADF action, reduced to the action vocabulary by
    /// [`sanitize_action`].
    pub(crate) action: String,
    /// The boot/session id of the node that signed the record; filled in at
    /// signing.
    pub(crate) boot_session_id: String,
    /// The request correlation id, also carried as a `tags` entry.
    pub(crate) correlation_id: String,
    /// The initiator's domain id, or `"unknown"` for a system actor.
    pub(crate) domain: String,
    /// When the event happened, RFC 3339.
    pub(crate) event_time: String,
    /// Version of the HMAC key the `signature` was computed with; filled in
    /// at signing.
    pub(crate) hmac_key_version: u64,
    /// The event's UUID.
    pub(crate) id: String,
    /// Who acted.
    pub(crate) initiator: Initiator,
    /// Which node recorded the event.
    pub(crate) observer: Observer,
    /// `"success"` or `"error"`.
    pub(crate) outcome: Outcome,
    /// Structured reason for a `failure` outcome, if any.
    pub(crate) outcome_reason: Option<String>,
    /// OAuth2 `client_id` and `grant_type` of an OP request, if any.
    pub(crate) oauth2: Option<(String, String)>,
    /// Per-boot sequence number; filled in at signing.
    pub(crate) seq: u64,
    /// The resource the action was on.
    pub(crate) target: Target,
    /// The CADF version of the record.
    pub(crate) version: String,
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
/// Name of the optional attachment carrying the OAuth2 client and grant type.
const OAUTH2_ATTACHMENT: &str = "oauth2";

/// DSP0262 `outcome` of an event: a closed vocabulary, so no other value can
/// reach a signed record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The action completed.
    Success,
    /// The action was rejected or failed; see the outcome reason.
    Failure,
    /// The action was started and its result is not yet known.
    Pending,
    /// The result could not be determined.
    Unknown,
}

impl Outcome {
    /// The DSP0262 wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Pending => "pending",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Outcome {
    /// Parse a wire value; anything outside the vocabulary is rejected.
    fn from_wire(s: &str) -> Result<Self, WireError> {
        match s {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            "pending" => Ok(Self::Pending),
            "unknown" => Ok(Self::Unknown),
            _ => Err(wire_err("unsupported `outcome`")),
        }
    }
}

/// Error for a record that is not a valid DSP0262 record.
#[derive(Debug, thiserror::Error)]
#[error("malformed audit record: {0}")]
pub(crate) struct WireError(
    /// What the record is missing or malformed.
    String,
);

fn wire_err(what: &str) -> WireError {
    WireError(what.to_string())
}

impl CadfEventPayload {
    /// Parse a DSP0262 record.
    pub(crate) fn from_wire_value(value: serde_json::Value) -> Result<Self, WireError> {
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
        // Optional: absent is fine, but a present attachment must be
        // well-formed, so a damaged record is rejected rather than losing
        // the attachment on re-serialization.
        let oauth2 = match value
            .get("attachments")
            .and_then(serde_json::Value::as_array)
            .and_then(|a| {
                a.iter().find(|a| {
                    a.get("name").and_then(serde_json::Value::as_str) == Some(OAUTH2_ATTACHMENT)
                })
            }) {
            None => None,
            Some(attachment) => {
                let content = attachment.get("content");
                let field = |key: &str| {
                    content
                        .and_then(|c| c.get(key))
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                };
                match (field("client_id"), field("grant_type")) {
                    (Some(client_id), Some(grant_type)) => Some((client_id, grant_type)),
                    _ => return Err(wire_err("malformed `oauth2` attachment")),
                }
            }
        };
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
            action: text(&value, "action")?,
            boot_session_id: text(integrity, "boot_session_id")?,
            correlation_id,
            domain: text(integrity, "domain")?,
            event_time: text(&value, "eventTime")?,
            hmac_key_version: number("hmac_key_version")?,
            id: text(&value, "id")?,
            initiator,
            observer: Observer {
                id: text(observer, "id")?,
                node_id: text(integrity, "observer_node_id")?,
            },
            outcome: Outcome::from_wire(&text(&value, "outcome")?)?,
            outcome_reason: value
                .get("reason")
                .and_then(|r| r.get("reasonCode"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            oauth2,
            seq: number("seq")?,
            // In-crate struct literals on purpose: wire values are kept
            // verbatim so a record round-trips byte-exact — its signature
            // was computed over exactly these values. New events are reduced
            // by `Target::new` / `Observer::new`.
            target: Target {
                id: text(target, "id")?,
                type_uri: text(target, "typeURI")?,
            },
            version: text(integrity, "version")?,
        })
    }

    /// The record as it is signed and written: DSP0262 names, the correlation
    /// id in `tags` and the integrity fields in an `attachments` entry.
    pub(crate) fn to_wire_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        use serde_json::{Value, json};
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
            "outcome": self.outcome.as_str(),
            "initiator": initiator,
            "target": {"id": self.target.id(), "typeURI": self.target.type_uri()},
            "observer": {"id": self.observer.id(), "typeURI": OBSERVER_TYPE_URI},
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
                    "observer_node_id": self.observer.node_id(),
                },
            }],
        });
        if let (Some((client_id, grant_type)), Some(attachments)) = (
            &self.oauth2,
            event.get_mut("attachments").and_then(Value::as_array_mut),
        ) {
            attachments.push(json!({
                "name": OAUTH2_ATTACHMENT,
                "contentType": "application/json",
                "content": {"client_id": client_id, "grant_type": grant_type},
            }));
        }
        if let (Some(reason), Value::Object(map)) = (&self.outcome_reason, &mut event) {
            map.insert(
                "reason".into(),
                json!({"reasonType": "keystone", "reasonCode": reason}),
            );
        }
        Ok(event)
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

impl CadfEventPayload {
    pub fn action(&self) -> &str {
        &self.action
    }
    pub fn boot_session_id(&self) -> &str {
        &self.boot_session_id
    }
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }
    pub fn hmac_key_version(&self) -> u64 {
        self.hmac_key_version
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn initiator(&self) -> &Initiator {
        &self.initiator
    }

    /// Construct a new unsigned payload. The `seq`, `boot_session_id`, and
    /// `hmac_key_version` fields are placeholders;
    /// `AuditDispatcher::finalize_event` fills them in when signing.
    ///
    /// Arguments: a unique record `id`, the record schema `version`, the
    /// request's `correlation_id`, the RFC 3339 `event_time`, the `action`,
    /// its [`Outcome`] and optional [`OutcomeReason`], then the
    /// [`Initiator`], [`Target`] and [`Observer`]. Pass the result to
    /// [`CadfEventPayload::sign`] and then to the dispatcher; see the crate
    /// documentation for a complete example.
    ///
    /// The free-text fields (`id`, `version`, `correlation_id`,
    /// `event_time`) are reduced to the audit-safe character set
    /// (see [`crate::sanitize::sanitize_audit_value`]); `action` is reduced
    /// to the action vocabulary by [`sanitize_action`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        version: String,
        correlation_id: String,
        event_time: String,
        action: String,
        outcome: Outcome,
        outcome_reason: Option<OutcomeReason>,
        initiator: Initiator,
        target: Target,
        observer: Observer,
    ) -> Self {
        // The record's `domain` is the initiator's domain (`"unknown"` when
        // there is none, e.g. a system actor), never a constant.
        let domain = initiator.domain_id().unwrap_or("unknown").to_string();
        Self {
            action: sanitize_action(&action),
            boot_session_id: String::new(),
            correlation_id: sanitize_audit_value(&correlation_id),
            domain,
            event_time: sanitize_audit_value(&event_time),
            hmac_key_version: 0,
            id: sanitize_audit_value(&id),
            initiator,
            observer,
            outcome,
            outcome_reason: outcome_reason.map(OutcomeReason::into_string),
            oauth2: None,
            seq: 0,
            target,
            version: sanitize_audit_value(&version),
        }
    }

    /// Attach the OAuth2 `client_id` and `grant_type` the event is about.
    ///
    /// Both are reduced to the audit-safe character set so request-supplied
    /// text cannot reach the signed record.
    #[must_use]
    pub fn with_oauth2_context(mut self, client_id: &str, grant_type: &str) -> Self {
        self.oauth2 = Some((
            sanitize_audit_value(client_id),
            sanitize_audit_value(grant_type),
        ));
        self
    }

    /// The OAuth2 `(client_id, grant_type)` attached to the event, if any.
    pub fn oauth2_context(&self) -> Option<(&str, &str)> {
        self.oauth2.as_ref().map(|(c, g)| (c.as_str(), g.as_str()))
    }

    pub fn observer(&self) -> &Observer {
        &self.observer
    }
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Sign this payload via the dispatcher, producing a `CadfEvent`. The
    /// result is then submitted with `AuditDispatcher::dispatch` or
    /// `AuditDispatcher::dispatch_critical`.
    ///
    /// The dispatcher fills `seq`, `boot_session_id`, and `hmac_key_version`,
    /// then computes the HMAC-SHA256 over the JCS-canonical form (RFC 8785).
    pub fn sign(self, dispatcher: &crate::dispatcher::AuditDispatcher) -> CadfEvent {
        dispatcher.finalize_event(self)
    }

    pub fn target(&self) -> &Target {
        &self.target
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
    /// The signed record body.
    pub(crate) event: CadfEventPayload,
    /// The hex-encoded HMAC-SHA256 of the record's JCS-canonical form.
    /// `pub(crate)`: external callers must use the `signature()` getter;
    /// direct mutation is intentionally prevented outside this crate.
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
    pub fn boot_session_id(&self) -> &str {
        &self.event.boot_session_id
    }
    pub fn correlation_id(&self) -> &str {
        &self.event.correlation_id
    }
    pub fn id(&self) -> &str {
        &self.event.id
    }
    pub fn payload(&self) -> &CadfEventPayload {
        &self.event
    }
    pub fn seq(&self) -> u64 {
        self.event.seq
    }
    pub fn signature(&self) -> &str {
        &self.signature
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
    /// The client network address the request was received from; omitted
    /// when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    /// A pre-auth identity signal (EC2 access key, federation idp_id);
    /// omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

impl Host {
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    /// Construct a `Host` carrying only a pre-auth identity signal (`id`).
    pub fn from_id(id: String) -> Self {
        Self {
            address: None,
            id: Some(id),
        }
    }
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
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
pub struct OutcomeReason(
    /// The sanitized reason; borrowed when built from a `'static` literal.
    std::borrow::Cow<'static, str>,
);

impl OutcomeReason {
    /// Longest accepted variant name.
    const MAX_VARIANT_LEN: usize = 64;

    /// The reason as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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

    fn into_string(self) -> String {
        self.0.into_owned()
    }

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
    /// The initiator's domain id, opaque; JSON `null` when absent.
    domain_id: Option<String>,
    /// Pre-auth identity signals and the client address; omitted when
    /// absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<Host>,
    /// The initiator's opaque id; never a username or other PII.
    id: String,
    /// The initiator's project id, opaque; JSON `null` when absent.
    project_id: Option<String>,
}

impl Initiator {
    /// Convenience passthrough for `host.address`.
    pub fn address(&self) -> Option<&str> {
        self.host.as_ref().and_then(Host::address)
    }
    pub fn domain_id(&self) -> Option<&str> {
        self.domain_id.as_deref()
    }
    pub fn host(&self) -> Option<&Host> {
        self.host.as_ref()
    }
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn new(
        id: String,
        project_id: Option<String>,
        domain_id: Option<String>,
        host: Option<Host>,
    ) -> Self {
        Self {
            domain_id,
            host,
            id,
            project_id,
        }
    }
    pub fn project_id(&self) -> Option<&str> {
        self.project_id.as_deref()
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
                    address: Some(address),
                    id: None,
                })
            }
        }
        self
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
}

/// Audit target — the resource being acted upon.
///
/// Both fields are reduced to the audit-safe character set at construction
/// time (see [`crate::sanitize::sanitize_audit_value`]), so free text —
/// newlines, control characters, unbounded values — cannot reach a signed
/// record.
///
/// Records read back from a spool keep their values verbatim (see
/// `CadfEventPayload::from_wire_value`), because a signature was computed
/// over exactly those values. It is deliberately not `Deserialize`.
#[derive(Serialize, Clone, Debug)]
pub struct Target {
    /// The sanitized resource id.
    id: String,
    /// The sanitized resource type URI.
    type_uri: String,
}

impl Target {
    /// The sanitized resource id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Build a target, reducing both values to the audit-safe character set.
    #[must_use]
    pub fn new(id: impl Into<String>, type_uri: impl Into<String>) -> Self {
        Self {
            id: sanitize_audit_value(&id.into()),
            type_uri: sanitize_audit_value(&type_uri.into()),
        }
    }

    /// The sanitized resource type URI.
    #[must_use]
    pub fn type_uri(&self) -> &str {
        &self.type_uri
    }
}

/// Audit observer — the node that recorded the event.
///
/// Both fields are reduced to the audit-safe character set at construction
/// time (see [`crate::sanitize::sanitize_audit_value`]).
///
/// Not `Deserialize`: wire values are kept verbatim by
/// `CadfEventPayload::from_wire_value` (see [`Target`]).
#[derive(Serialize, Clone, Debug)]
pub struct Observer {
    /// The sanitized observer identity, e.g.
    /// `service/security/keystone/<node>`.
    id: String,
    /// The sanitized node id of the node that recorded the event.
    node_id: String,
}

impl Observer {
    /// The sanitized observer id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Build an observer, reducing both values to the audit-safe character
    /// set.
    #[must_use]
    pub fn new(node_id: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            id: sanitize_audit_value(&id.into()),
            node_id: sanitize_audit_value(&node_id.into()),
        }
    }

    /// The sanitized node id.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
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
            Outcome::Success,
            None,
            Initiator::new("unknown".to_string(), None, None, None),
            Target::new("some-user-id", "data/security/identity/user"),
            Observer::new(
                dispatcher.node_id(),
                format!("service/security/keystone/{}", dispatcher.node_id()),
            ),
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
    fn oauth2_context_is_signed_and_round_trips() {
        let key: Arc<[u8]> = Arc::from(b"test-key-32-bytes-0123456789abcd".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-a", key.clone());
        let event = make_payload(&dispatcher)
            .with_oauth2_context("client-1", "device_code")
            .sign(&dispatcher);
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["attachments"][1]["name"], "oauth2");
        assert_eq!(json["attachments"][1]["content"]["client_id"], "client-1");
        assert_eq!(
            json["attachments"][1]["content"]["grant_type"],
            "device_code"
        );
        let parsed: CadfEvent = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            parsed.payload().oauth2_context(),
            Some(("client-1", "device_code"))
        );
        assert!(dispatcher.verify_hmac(&parsed, &key));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), json);
    }

    #[test]
    fn tampered_oauth2_context_fails_verification() {
        let key: Arc<[u8]> = Arc::from(b"test-key-32-bytes-0123456789abcd".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-a", key.clone());
        let event = make_payload(&dispatcher)
            .with_oauth2_context("client-1", "device_code")
            .sign(&dispatcher);
        let mut json = serde_json::to_value(&event).unwrap();
        json["attachments"][1]["content"]["client_id"] = serde_json::json!("client-2");
        let tampered: CadfEvent = serde_json::from_value(json).unwrap();
        assert!(!dispatcher.verify_hmac(&tampered, &key));
    }

    #[test]
    fn malformed_oauth2_attachment_is_rejected() {
        let key: Arc<[u8]> = Arc::from(b"test-key-32-bytes-0123456789abcd".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-a", key);
        let event = make_payload(&dispatcher)
            .with_oauth2_context("client-1", "device_code")
            .sign(&dispatcher);
        let mut json = serde_json::to_value(&event).unwrap();
        json["attachments"][1]["content"]["grant_type"] = serde_json::json!(7);
        assert!(serde_json::from_value::<CadfEvent>(json).is_err());
    }

    #[test]
    fn oauth2_context_is_sanitized() {
        let key: Arc<[u8]> = Arc::from(b"test-key-32-bytes-0123456789abcd".as_slice());
        let (dispatcher, _rx) = make_dispatcher("node-a", key);
        let payload = make_payload(&dispatcher).with_oauth2_context("cli\nent <1>", "device_code");
        let (client_id, _) = payload.oauth2_context().unwrap();
        assert!(!client_id.contains(['\n', '<', '>', ' ']));
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
                Outcome::Success,
                None,
                Initiator::new("u".to_string(), None, domain.map(str::to_string), None),
                Target::new("t", "x"),
                Observer::new("test-node", "o"),
            )
            .sign(&dispatcher)
        };
        assert_eq!(with_domain(Some("d1")).payload().domain, "d1");
        assert_eq!(with_domain(None).payload().domain, "unknown");
    }

    #[test]
    fn target_and_observer_new_reduce_to_the_audit_charset() {
        let t = Target::new("id\nwith\tinjection\x00", "type uri");
        assert_eq!(t.id(), "idwithinjection");
        assert_eq!(t.type_uri(), "typeuri");
        // Legitimate values pass through unchanged.
        let t = Target::new(
            "550e8400-e29b-41d4-a716-446655440000",
            "data/security/identity/user",
        );
        assert_eq!(t.id(), "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(t.type_uri(), "data/security/identity/user");
        // Empty becomes "unknown"; values are capped.
        let t = Target::new("", "a".repeat(300));
        assert_eq!(t.id(), "unknown");
        assert_eq!(t.type_uri().len(), 255);

        let o = Observer::new("node 1\n", "service/security/keystone/node 1");
        assert_eq!(o.node_id(), "node1");
        assert_eq!(o.id(), "service/security/keystone/node1");
    }

    #[test]
    fn payload_new_reduces_free_text_fields() {
        let payload = CadfEventPayload::new(
            "test-node:\n1\r".to_string(),
            "1.0\n".to_string(),
            "req\tcorr".to_string(),
            "2026-06-16T00:00:00+00:00\n".to_string(),
            "delete".to_string(),
            Outcome::Success,
            None,
            Initiator::new("unknown".to_string(), None, None, None),
            Target::new("t", "x"),
            Observer::new("n", "o"),
        );
        assert_eq!(payload.id(), "test-node:1");
        assert_eq!(payload.version, "1.0");
        assert_eq!(payload.correlation_id(), "reqcorr");
        assert_eq!(payload.event_time, "2026-06-16T00:00:00+00:00");
        // Legit values pass through untouched.
        let payload = CadfEventPayload::new(
            "node-1:550e8400-e29b-41d4-a716-446655440000".to_string(),
            "1.1".to_string(),
            "req-00000000000000000000000000000002".to_string(),
            "2026-06-16T00:00:00+00:00".to_string(),
            "oauth2/refresh_family_revoked".to_string(),
            Outcome::Success,
            None,
            Initiator::new("unknown".to_string(), None, None, None),
            Target::new("t", "x"),
            Observer::new("n", "o"),
        );
        assert_eq!(payload.id(), "node-1:550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(payload.version, "1.1");
        assert_eq!(
            payload.correlation_id(),
            "req-00000000000000000000000000000002"
        );
        assert_eq!(payload.event_time, "2026-06-16T00:00:00+00:00");
        assert_eq!(payload.outcome(), Outcome::Success);
    }

    #[test]
    fn outcome_round_trips_and_rejects_values_outside_dsp0262() {
        for outcome in [
            Outcome::Success,
            Outcome::Failure,
            Outcome::Pending,
            Outcome::Unknown,
        ] {
            assert_eq!(Outcome::from_wire(outcome.as_str()).ok(), Some(outcome));
            assert_eq!(outcome.to_string(), outcome.as_str());
        }
        for bad in ["error", "attempt", "Success", ""] {
            assert!(Outcome::from_wire(bad).is_err(), "{bad:?} must be rejected");
        }
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
