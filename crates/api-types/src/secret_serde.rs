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
//! Serialization helpers for [`secrecy::SecretString`] fields.
//!
//! `SecretString` deliberately does not implement `Serialize`. These helpers
//! let DTOs that must remain serializable (e.g. for policy/audit payloads that
//! embed the request or resource) do so **without ever exposing the secret** —
//! a present secret is rendered as a fixed `"[REDACTED]"` marker so field
//! presence is preserved while the value never leaks.
//!
//! This is intentionally different from the "expose once" helper used for
//! secrets that are part of an API contract (e.g. a one-time API-key token):
//! those live next to their own DTO and call `expose_secret()` on purpose.

use secrecy::SecretString;
use serde::Serializer;

// NOTE: length/non-empty validation for wrapped secrets is deliberately NOT done
// with validator's field-level `custom` here: validator 0.20 unconditionally
// calls `ValidationError::add_param(&field)`, which requires the field to be
// `Serialize` — and `SecretString` intentionally is not. Password non-emptiness
// is instead enforced centrally in
// `openstack_keystone_config::SecurityComplianceProvider::validate_password`,
// which runs on the wrapped value at the service layer for every write path.

/// Redact an `Option<SecretString>` on serialize.
pub(crate) fn serialize_secret_redacted<S>(
    secret: &Option<SecretString>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match secret {
        Some(_) => serializer.serialize_str("[REDACTED]"),
        None => serializer.serialize_none(),
    }
}

/// Redact a required `SecretString` on serialize.
pub(crate) fn serialize_secret_redacted_required<S>(
    _secret: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str("[REDACTED]")
}

/// Redact the nested `Option<Option<SecretString>>` used by update DTOs, where
/// the outer `Option` is "present-in-request" and the inner is "set-or-clear".
pub(crate) fn serialize_secret_redacted_nested<S>(
    secret: &Option<Option<SecretString>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match secret {
        Some(Some(_)) => serializer.serialize_str("[REDACTED]"),
        _ => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use serde::Serialize;

    use super::*;

    const SECRET: &str = "super-secret-value";

    #[derive(Serialize)]
    struct OptHolder {
        #[serde(serialize_with = "serialize_secret_redacted")]
        secret: Option<SecretString>,
    }

    #[derive(Serialize)]
    struct RequiredHolder {
        #[serde(serialize_with = "serialize_secret_redacted_required")]
        secret: SecretString,
    }

    #[derive(Serialize)]
    struct NestedHolder {
        #[serde(serialize_with = "serialize_secret_redacted_nested")]
        secret: Option<Option<SecretString>>,
    }

    #[test]
    fn opt_secret_is_redacted_when_present() {
        let json = serde_json::to_string(&OptHolder {
            secret: Some(SecretString::from(SECRET)),
        })
        .unwrap();
        assert!(!json.contains(SECRET), "secret leaked: {json}");
        assert!(json.contains("[REDACTED]"), "not redacted: {json}");
    }

    #[test]
    fn opt_secret_is_null_when_absent() {
        let json = serde_json::to_string(&OptHolder { secret: None }).unwrap();
        assert_eq!(json, r#"{"secret":null}"#);
    }

    #[test]
    fn required_secret_is_redacted() {
        let json = serde_json::to_string(&RequiredHolder {
            secret: SecretString::from(SECRET),
        })
        .unwrap();
        assert!(!json.contains(SECRET), "secret leaked: {json}");
        assert!(json.contains("[REDACTED]"), "not redacted: {json}");
    }

    #[test]
    fn nested_secret_is_redacted_only_when_set() {
        // Present + set -> redacted.
        let set = serde_json::to_string(&NestedHolder {
            secret: Some(Some(SecretString::from(SECRET))),
        })
        .unwrap();
        assert!(!set.contains(SECRET), "secret leaked: {set}");
        assert!(set.contains("[REDACTED]"), "not redacted: {set}");

        // Explicit clear and absent both serialize to null (no value to leak).
        assert_eq!(
            serde_json::to_string(&NestedHolder { secret: Some(None) }).unwrap(),
            r#"{"secret":null}"#
        );
        assert_eq!(
            serde_json::to_string(&NestedHolder { secret: None }).unwrap(),
            r#"{"secret":null}"#
        );
    }

    #[test]
    fn debug_of_secret_does_not_leak() {
        // secrecy's own Debug guarantee, pinned here as the core requirement.
        let secret = SecretString::from(SECRET);
        assert!(!format!("{secret:?}").contains(SECRET));
    }
}
