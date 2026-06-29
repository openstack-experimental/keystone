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
//! Sanitization helpers for audit field values.
//!
//! All functions in this module are `pub(crate)` — consumers of the audit
//! crate construct typed values via the public builder API; raw sanitization
//! is an implementation detail.

/// Kind of pre-auth identity signal carried in `Initiator.host`.
pub enum HostKind {
    /// EC2 `access` key from an EC2-credential auth request.
    Ec2AccessKey,
    /// Federation `idp_id` that is a valid UUID.
    FederationIdpUuid,
    /// Federation `idp_id` that is not a UUID (free-form name).
    FederationIdpNonUuid,
    /// Any other pre-auth signal.
    Other,
}

/// Sanitize a resource / principal UUID for use in audit records.
///
/// Strips everything except hex digits and hyphens, caps at 64 characters,
/// then applies a strict UUID-format check (len 36, 4 hyphens at positions
/// 8/13/18/23, 32 hex digits). Returns `"unknown"` for anything that fails.
pub fn sanitize_audit_id(id: &str) -> String {
    if id.trim().is_empty() {
        return "unknown".to_string();
    }
    let cleaned: String = id
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == '-')
        .take(64)
        .collect();
    if cleaned.is_empty() {
        return "unknown".to_string();
    }
    if cleaned.len() == 36
        && cleaned.chars().filter(|c| *c == '-').count() == 4
        && cleaned.chars().filter(|c| c.is_ascii_hexdigit()).count() == 32
        && cleaned.get(8..9) == Some("-")
        && cleaned.get(13..14) == Some("-")
        && cleaned.get(18..19) == Some("-")
        && cleaned.get(23..24) == Some("-")
    {
        cleaned
    } else {
        "unknown".to_string()
    }
}

/// Sanitize a pre-auth identity signal for use as `Initiator.host`.
///
/// Returns `None` if the value is empty after filtering (field should be
/// omitted rather than emitted as an empty string).
pub fn sanitize_initiator_host(raw: &str, kind: HostKind) -> Option<String> {
    match kind {
        HostKind::Ec2AccessKey => {
            // Must match /^AKIA[A-Z0-9]{16}$/ exactly.
            if raw.len() == 20
                && raw.starts_with("AKIA")
                && raw[4..]
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            {
                Some(raw.to_string())
            } else {
                None
            }
        }
        HostKind::FederationIdpUuid => {
            let s = sanitize_audit_id(raw);
            if s == "unknown" { None } else { Some(s) }
        }
        HostKind::FederationIdpNonUuid => {
            let s: String = raw
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '.' | '_' | '-'))
                .take(64)
                .collect();
            if s.is_empty() { None } else { Some(s) }
        }
        HostKind::Other => {
            let s: String = raw
                .chars()
                .filter(|c| (*c as u32) >= 0x20 && (*c as u32) <= 0x7E)
                .take(128)
                .collect();
            if s.is_empty() { None } else { Some(s) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_uuid_passes() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(sanitize_audit_id(id), id);
    }

    #[test]
    fn uppercase_uuid_passes() {
        let id = "550E8400-E29B-41D4-A716-446655440000";
        assert_eq!(sanitize_audit_id(id), id);
    }

    #[test]
    fn non_uuid_hex_string_returns_unknown() {
        assert_eq!(sanitize_audit_id("deadbeef"), "unknown");
    }

    #[test]
    fn empty_returns_unknown() {
        assert_eq!(sanitize_audit_id(""), "unknown");
        assert_eq!(sanitize_audit_id("   "), "unknown");
    }

    #[test]
    fn injection_chars_stripped_then_returns_unknown() {
        // After stripping non-hex/hyphen the result is not a valid UUID.
        assert_eq!(sanitize_audit_id("'; DROP TABLE users; --"), "unknown");
    }

    #[test]
    fn too_long_not_uuid_returns_unknown() {
        let long = "a".repeat(100);
        assert_eq!(sanitize_audit_id(&long), "unknown");
    }

    #[test]
    fn hyphen_only_returns_unknown() {
        assert_eq!(sanitize_audit_id("----"), "unknown");
    }

    #[test]
    fn uuid_with_wrong_hyphen_positions_returns_unknown() {
        // Hyphens at wrong positions.
        assert_eq!(
            sanitize_audit_id("550e840-0e29b-41d4a-716446-655440000a"),
            "unknown"
        );
    }

    // ---- sanitize_initiator_host ----

    #[test]
    fn ec2_valid_key() {
        let key = "AKIAIOSFODNN7EXAMPLE";
        assert_eq!(
            sanitize_initiator_host(key, HostKind::Ec2AccessKey),
            Some(key.to_string())
        );
    }

    #[test]
    fn ec2_invalid_key_rejected() {
        assert_eq!(
            sanitize_initiator_host("not-an-ec2-key", HostKind::Ec2AccessKey),
            None
        );
        assert_eq!(
            sanitize_initiator_host("AKIA123", HostKind::Ec2AccessKey),
            None
        );
    }

    #[test]
    fn federation_idp_uuid_valid() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            sanitize_initiator_host(uuid, HostKind::FederationIdpUuid),
            Some(uuid.to_string())
        );
    }

    #[test]
    fn federation_idp_uuid_invalid_returns_none() {
        assert_eq!(
            sanitize_initiator_host("not-a-uuid", HostKind::FederationIdpUuid),
            None
        );
    }

    #[test]
    fn federation_idp_non_uuid_filters_special_chars() {
        assert_eq!(
            sanitize_initiator_host("my-idp_v2.0<script>", HostKind::FederationIdpNonUuid),
            Some("my-idp_v2.0script".to_string())
        );
    }

    #[test]
    fn other_filters_non_printable_ascii() {
        let raw = "normal\x00\x01value";
        assert_eq!(
            sanitize_initiator_host(raw, HostKind::Other),
            Some("normalvalue".to_string())
        );
    }

    #[test]
    fn other_caps_at_128() {
        let raw = "a".repeat(200);
        let result = sanitize_initiator_host(&raw, HostKind::Other).unwrap_or_default();
        assert_eq!(result.len(), 128);
    }

    #[test]
    fn empty_raw_returns_none_for_all_kinds() {
        assert_eq!(sanitize_initiator_host("", HostKind::Ec2AccessKey), None);
        assert_eq!(
            sanitize_initiator_host("", HostKind::FederationIdpUuid),
            None
        );
        assert_eq!(
            sanitize_initiator_host("", HostKind::FederationIdpNonUuid),
            None
        );
        assert_eq!(sanitize_initiator_host("", HostKind::Other), None);
    }
}
