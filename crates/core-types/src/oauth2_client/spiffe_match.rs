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
//! # SPIFFE ID patterns of delegatable service clients (ADR 0036 §3.1)
//!
//! A pattern is a SPIFFE ID whose final path segment may be the single
//! wildcard `*`, matching exactly one non-empty segment. Matching works on
//! split path segments, never on string prefixes, so
//! `spiffe://td/ns/nova/*` does not match `spiffe://td/ns/nova-evil/x` or
//! `spiffe://td/ns/nova/x/y`.

const SCHEME: &str = "spiffe://";

/// Split a SPIFFE ID into its trust domain and path segments.
fn split(id: &str) -> Option<(&str, Vec<&str>)> {
    let rest = id.strip_prefix(SCHEME)?;
    let (trust_domain, path) = rest.split_once('/')?;
    if trust_domain.is_empty() {
        return None;
    }
    Some((trust_domain, path.split('/').collect()))
}

/// Validate a pattern at registration time (ADR 0036 §3.1).
///
/// The pattern must be a well-formed SPIFFE ID with a non-empty path and no
/// empty segments, `*` may appear only as the whole final segment, and the
/// trust domain must be one of `allowed_trust_domains` (the deployment's
/// own SPIFFE trust domains).
pub fn validate_spiffe_id_pattern(
    pattern: &str,
    allowed_trust_domains: &[String],
) -> Result<(), String> {
    let (trust_domain, segments) =
        split(pattern).ok_or_else(|| format!("`{pattern}` is not a SPIFFE ID with a path"))?;
    if !allowed_trust_domains.iter().any(|td| td == trust_domain) {
        return Err(format!(
            "trust domain `{trust_domain}` of `{pattern}` is not a trust domain of this deployment"
        ));
    }
    if pattern.contains(['?', '#']) {
        return Err(format!("`{pattern}` must not have a query or fragment"));
    }
    let last = segments.len() - 1;
    for (idx, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            return Err(format!("`{pattern}` has an empty path segment"));
        }
        if segment.contains('*') && (idx != last || *segment != "*") {
            return Err(format!(
                "`{pattern}`: `*` is only allowed as the whole final path segment"
            ));
        }
    }
    if segments == ["*"] {
        return Err(format!("`{pattern}` would match a whole trust domain"));
    }
    Ok(())
}

/// Whether the presented SPIFFE ID matches a registered pattern.
///
/// The trust domain must be equal, the segment counts equal, and every
/// segment equal except a final `*`, which matches one non-empty segment.
pub fn spiffe_id_matches(pattern: &str, presented: &str) -> bool {
    let (Some((p_td, p_segments)), Some((td, segments))) = (split(pattern), split(presented))
    else {
        return false;
    };
    if p_td != td || p_segments.len() != segments.len() {
        return false;
    }
    let last = p_segments.len() - 1;
    p_segments
        .iter()
        .zip(segments.iter())
        .enumerate()
        .all(|(idx, (p, s))| {
            !s.is_empty() && (p == s || (idx == last && *p == "*" && !s.contains('*')))
        })
}

/// Whether the presented SPIFFE ID matches any of the patterns.
pub fn spiffe_id_matches_any(patterns: &[String], presented: &str) -> bool {
    patterns.iter().any(|p| spiffe_id_matches(p, presented))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tds() -> Vec<String> {
        vec!["cloud.example".into()]
    }

    #[test]
    fn test_validate_accepts_exact_and_final_wildcard() {
        assert!(validate_spiffe_id_pattern("spiffe://cloud.example/ns/nova/sa/c", &tds()).is_ok());
        assert!(validate_spiffe_id_pattern("spiffe://cloud.example/ns/nova/sa/*", &tds()).is_ok());
    }

    #[test]
    fn test_validate_rejects() {
        for bad in [
            "https://cloud.example/x",
            "spiffe://cloud.example",
            "spiffe://cloud.example/",
            "spiffe:///x",
            "spiffe://cloud.example/*",
            "spiffe://cloud.example/ns/*/sa",
            "spiffe://cloud.example/ns/nova-*",
            "spiffe://cloud.example/ns//x",
            "spiffe://cloud.example/ns/x/",
            "spiffe://cloud.example/ns/x?y",
            "spiffe://other.example/ns/x",
        ] {
            assert!(validate_spiffe_id_pattern(bad, &tds()).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_matches_segments() {
        let p = "spiffe://cloud.example/ns/nova/sa/*";
        assert!(spiffe_id_matches(
            p,
            "spiffe://cloud.example/ns/nova/sa/compute"
        ));
        assert!(!spiffe_id_matches(p, "spiffe://cloud.example/ns/nova/sa"));
        assert!(!spiffe_id_matches(
            p,
            "spiffe://cloud.example/ns/nova/sa/a/b"
        ));
        assert!(!spiffe_id_matches(
            p,
            "spiffe://cloud.example/ns/nova-evil/sa/x"
        ));
        assert!(!spiffe_id_matches(p, "spiffe://cloud.example/ns/nova/sa/"));
        assert!(!spiffe_id_matches(
            p,
            "spiffe://evil.example/ns/nova/sa/compute"
        ));
        assert!(!spiffe_id_matches(
            p,
            "spiffe://cloud.example.evil/ns/nova/sa/compute"
        ));
    }

    #[test]
    fn test_matches_exact() {
        let p = "spiffe://cloud.example/ns/nova/sa/compute";
        assert!(spiffe_id_matches(p, p));
        assert!(!spiffe_id_matches(
            p,
            "spiffe://cloud.example/ns/nova/sa/computex"
        ));
        assert!(spiffe_id_matches_any(&[p.to_string()], p));
        assert!(!spiffe_id_matches_any(&[], p));
    }
}
