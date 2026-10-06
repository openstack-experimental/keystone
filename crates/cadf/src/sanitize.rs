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
/// then accepts either of the two UUID renderings Keystone actually produces:
/// canonical hyphenated (len 36, hyphens at positions 8/13/18/23, 32 hex
/// digits) or simple/no-hyphen (`Uuid::simple()`, exactly 32 hex digits, no
/// hyphens) — which is the format `Uuid::new_v4().simple()` produces and is
/// used for every resource ID minted across the codebase (projects, users,
/// roles, tokens, etc.). Returns `"unknown"` for anything that fails both
/// shapes.
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
    let is_canonical_uuid = cleaned.len() == 36
        && cleaned.chars().filter(|c| *c == '-').count() == 4
        && cleaned.chars().filter(|c| c.is_ascii_hexdigit()).count() == 32
        && cleaned.get(8..9) == Some("-")
        && cleaned.get(13..14) == Some("-")
        && cleaned.get(18..19) == Some("-")
        && cleaned.get(23..24) == Some("-");
    let is_simple_uuid = cleaned.len() == 32 && cleaned.chars().all(|c| c.is_ascii_hexdigit());
    if is_canonical_uuid || is_simple_uuid {
        cleaned
    } else {
        "unknown".to_string()
    }
}

/// Reduce a free-form audit value to the audit-safe character set.
///
/// Keeps `[A-Za-z0-9._:+/-]` (at most 255 characters) and drops everything
/// else, so newlines, control characters and other free text can never reach
/// a signed record. An empty result becomes `"unknown"`.
///
/// This is the floor guarantee: the typed constructors
/// (`Target::new`, `Observer::new`, `CadfEventPayload::new`) apply it, so
/// every value that reaches the wire through them is reduced. Emitters that
/// want a stricter convention (UUID-or-`"unknown"` for resource ids) apply
/// [`sanitize_audit_id`] on top, before constructing the typed value.
#[must_use]
pub fn sanitize_audit_value(value: &str) -> String {
    const MAX_LEN: usize = 255;
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '+' | '/' | '-'))
        .take(MAX_LEN)
        .collect();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
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

/// Sanitize a client IP address for use as `Initiator.address`.
///
/// Parses via [`std::net::IpAddr`] and re-renders through `Display` so the
/// stored value is guaranteed to be a well-formed IPv4/IPv6 address (no
/// port, no scope id oddities, no injected characters) rather than whatever
/// a proxy header happened to contain. Returns `None` for anything that
/// doesn't parse as an IP.
pub fn sanitize_initiator_address(raw: &str) -> Option<String> {
    raw.trim()
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
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
    fn simple_uuid_no_hyphens_passes() {
        // Uuid::new_v4().simple() format used for every resource ID minted
        // across the codebase (projects, users, roles, tokens, etc.).
        let id = "550e8400e29b41d4a716446655440000";
        assert_eq!(sanitize_audit_id(id), id);
    }

    #[test]
    fn simple_uuid_uppercase_passes() {
        let id = "550E8400E29B41D4A716446655440000";
        assert_eq!(sanitize_audit_id(id), id);
    }

    #[test]
    fn thirty_two_hex_chars_but_not_uuid_shape_still_passes() {
        // Any 32-char pure-hex string is accepted as "simple UUID" shaped;
        // this is intentional since Keystone doesn't validate UUID version
        // bits elsewhere either.
        let id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(sanitize_audit_id(id), id);
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

    // ---- sanitize_audit_value ----

    #[test]
    fn value_keeps_the_audit_charset() {
        assert_eq!(sanitize_audit_value("abcXYZ0123._:+/-"), "abcXYZ0123._:+/-");
        // RFC3339 timestamps and type URIs pass through untouched.
        assert_eq!(
            sanitize_audit_value("2026-06-16T00:00:00+00:00"),
            "2026-06-16T00:00:00+00:00"
        );
        assert_eq!(
            sanitize_audit_value("service/security/keystone/node-1"),
            "service/security/keystone/node-1"
        );
    }

    #[test]
    fn value_drops_everything_else() {
        assert_eq!(sanitize_audit_value("a\nb\tc\x00d\u{0430}e"), "abcde");
    }

    #[test]
    fn value_empty_becomes_unknown() {
        assert_eq!(sanitize_audit_value(""), "unknown");
        assert_eq!(sanitize_audit_value("\n\t "), "unknown");
    }

    #[test]
    fn value_caps_at_255() {
        assert_eq!(sanitize_audit_value(&"a".repeat(300)).len(), 255);
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

    // ---- sanitize_initiator_address ----

    #[test]
    fn valid_ipv4_passes() {
        assert_eq!(
            sanitize_initiator_address("203.0.113.42"),
            Some("203.0.113.42".to_string())
        );
    }

    #[test]
    fn valid_ipv6_passes() {
        assert_eq!(
            sanitize_initiator_address("2001:db8::1"),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn address_with_port_rejected() {
        assert_eq!(sanitize_initiator_address("203.0.113.42:8080"), None);
    }

    #[test]
    fn garbage_address_rejected() {
        assert_eq!(sanitize_initiator_address("'; DROP TABLE x; --"), None);
        assert_eq!(sanitize_initiator_address(""), None);
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

    #[test]
    fn non_ascii_audit_id_is_unknown() {
        assert_eq!(
            sanitize_audit_id("550e8400-e29b-41d4-a716-44665544000\u{0430}"),
            "unknown"
        );
        assert_eq!(sanitize_audit_id("\u{1F600}"), "unknown");
    }

    #[test]
    fn other_host_kind_drops_non_printable_and_non_ascii() {
        let host = sanitize_initiator_host("a\u{0430}b\n\tc\u{7f}d", HostKind::Other).unwrap();
        assert_eq!(host, "abcd");
        assert_eq!(
            sanitize_initiator_host("\u{0430}\u{0431}", HostKind::Other),
            None
        );
        assert_eq!(
            sanitize_initiator_host(&"x".repeat(300), HostKind::Other)
                .unwrap()
                .len(),
            128
        );
    }

    #[test]
    fn initiator_address_normalizes_ipv6_and_rejects_oddities() {
        assert_eq!(
            sanitize_initiator_address("2001:DB8:0:0:0:0:0:1").as_deref(),
            Some("2001:db8::1")
        );
        // IPv4-mapped IPv6 stays a well-formed IPv6 literal.
        assert_eq!(
            sanitize_initiator_address("::ffff:192.0.2.1").as_deref(),
            Some("::ffff:192.0.2.1")
        );
        // A zone id is not accepted: the stored value is a bare address.
        assert_eq!(sanitize_initiator_address("fe80::1%eth0"), None);
        assert_eq!(sanitize_initiator_address("203.0.113.9:443"), None);
        assert_eq!(sanitize_initiator_address("203.0.113.9\nX"), None);
    }
}
