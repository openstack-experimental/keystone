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
//! # Thin SPIFFE ID representation
//!
//! Decouples the core crate from the `spiffe` crate. Listeners in the server
//! crate parse the full `spiffe::SpiffeId` from TLS peer certificates and
//! convert it into this type before inserting it into request extensions.

use std::fmt;

/// A parsed SPIFFE ID carrying the full URI and its trust domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    /// Full SPIFFE URI, e.g. `spiffe://example.org/workload`.
    pub id: String,
    /// Trust domain extracted from the URI, e.g. `example.org`.
    pub trust_domain: String,
}

impl SpiffeId {
    /// Parse a SPIFFE URI of the form `spiffe://<trust-domain>[/path]`.
    ///
    /// Returns `None` if the URI does not start with `spiffe://` or the trust
    /// domain segment is empty.
    pub fn new(uri: &str) -> Option<Self> {
        let without_scheme = uri.strip_prefix("spiffe://")?;
        let trust_domain = without_scheme
            .split('/')
            .next()
            .filter(|s| !s.is_empty())?
            .to_string();
        Some(Self {
            id: uri.to_string(),
            trust_domain,
        })
    }

    /// Returns the full SPIFFE URI.
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// Returns the trust domain of this SPIFFE ID.
    pub fn trust_domain_name(&self) -> &str {
        &self.trust_domain
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id)
    }
}

/// Path-derived claims extracted from a SPIFFE SVID's path segments, when
/// the path matches one of the known keystone-rs identity patterns (SPIRE
/// integration plan, Phase 3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpiffePathClaims {
    /// Hostname from `spiffe://{trust_domain}/service/nova-compute/host/{hostname}`.
    pub host: Option<String>,
    /// Project id from `spiffe://{trust_domain}/project/{project_id}/instance/{instance_id}`.
    pub project_id: Option<String>,
    /// Instance id from `spiffe://{trust_domain}/project/{project_id}/instance/{instance_id}`.
    pub instance_id: Option<String>,
}

/// Outcome of matching a SPIFFE ID's path against the known
/// keystone-rs identity patterns (SPIRE integration plan, Phase 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpiffePathMatch {
    /// The path does not resemble any known pattern (e.g. a plain service
    /// identity like `.../service/nova-api`). This is not an error -- the
    /// SVID simply carries no derivable path claims beyond `spiffe.id`/
    /// `spiffe.trust_domain`.
    Unrecognized,
    /// The path matches a known pattern and was parsed successfully.
    Matched(SpiffePathClaims),
    /// The path starts down a known pattern's literal prefix but deviates
    /// from its exact expected shape (empty segment, trailing slash, extra
    /// segments, undecodable percent-encoding). Callers MUST treat this as
    /// an authentication failure, never as an empty/absent claim.
    Malformed,
}

impl SpiffeId {
    /// Strictly parse this SVID's path against the known keystone-rs
    /// identity patterns (SPIRE integration plan, Phase 3):
    ///
    /// * `spiffe://{trust_domain}/service/nova-compute/host/{hostname}`
    /// * `spiffe://{trust_domain}/project/{project_id}/instance/{instance_id}`
    ///
    /// Matching is prefix-anchored on the literal `service/nova-compute/host`
    /// or `project`/`instance` segments, not a substring search or
    /// unanchored regex, and every path segment is percent-decoded before
    /// validation. See [`SpiffePathMatch`] for the three-way outcome: a
    /// path that does not start with either known literal prefix is
    /// [`SpiffePathMatch::Unrecognized`] (not an error), while a path that
    /// starts down one of those prefixes but deviates from its exact shape
    /// is [`SpiffePathMatch::Malformed`] and must be rejected by the
    /// caller.
    pub fn path_claims(&self) -> SpiffePathMatch {
        let Some(path) = self.id.strip_prefix("spiffe://").and_then(|rest| {
            // Strip the trust domain segment already captured in `self.trust_domain`.
            rest.strip_prefix(&self.trust_domain)
        }) else {
            return SpiffePathMatch::Unrecognized;
        };
        if path.is_empty() {
            return SpiffePathMatch::Unrecognized;
        }
        let Some(path) = path.strip_prefix('/') else {
            return SpiffePathMatch::Unrecognized;
        };

        // Keep empty segments (e.g. a trailing `/`) so a truncated path is
        // treated as malformed rather than silently dropped.
        let raw_segments: Vec<&str> = path.split('/').collect();
        let mut segments = Vec::with_capacity(raw_segments.len());
        for raw in raw_segments {
            match percent_encoding::percent_decode_str(raw).decode_utf8() {
                Ok(decoded) => segments.push(decoded.into_owned()),
                Err(_) => return SpiffePathMatch::Malformed,
            }
        }
        let segments: Vec<&str> = segments.iter().map(String::as_str).collect();

        match segments.as_slice() {
            ["service", "nova-compute", "host", host] if !host.is_empty() => {
                SpiffePathMatch::Matched(SpiffePathClaims {
                    host: Some((*host).to_string()),
                    ..Default::default()
                })
            }
            ["service", "nova-compute", "host", ..] => SpiffePathMatch::Malformed,
            ["project", project_id, "instance", instance_id]
                if !project_id.is_empty() && !instance_id.is_empty() =>
            {
                SpiffePathMatch::Matched(SpiffePathClaims {
                    project_id: Some((*project_id).to_string()),
                    instance_id: Some((*instance_id).to_string()),
                    ..Default::default()
                })
            }
            ["project", ..] => SpiffePathMatch::Malformed,
            _ => SpiffePathMatch::Unrecognized,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_claims_matches_nova_compute_host() {
        let svid = SpiffeId::new("spiffe://cloud.trust.domain/service/nova-compute/host/compute-1")
            .unwrap();
        assert_eq!(
            svid.path_claims(),
            SpiffePathMatch::Matched(SpiffePathClaims {
                host: Some("compute-1".to_string()),
                ..Default::default()
            })
        );
    }

    #[test]
    fn path_claims_matches_project_instance() {
        let svid = SpiffeId::new("spiffe://cloud.trust.domain/project/p1/instance/i1").unwrap();
        assert_eq!(
            svid.path_claims(),
            SpiffePathMatch::Matched(SpiffePathClaims {
                project_id: Some("p1".to_string()),
                instance_id: Some("i1".to_string()),
                ..Default::default()
            })
        );
    }

    #[test]
    fn path_claims_percent_decodes_segments() {
        // "compute 1" percent-encoded.
        let svid =
            SpiffeId::new("spiffe://cloud.trust.domain/service/nova-compute/host/compute%201")
                .unwrap();
        assert_eq!(
            svid.path_claims(),
            SpiffePathMatch::Matched(SpiffePathClaims {
                host: Some("compute 1".to_string()),
                ..Default::default()
            })
        );
    }

    #[test]
    fn path_claims_unrecognized_plain_service() {
        let svid = SpiffeId::new("spiffe://cloud.trust.domain/service/nova-api").unwrap();
        assert_eq!(svid.path_claims(), SpiffePathMatch::Unrecognized);
    }

    #[test]
    fn path_claims_unrecognized_empty_path() {
        let svid = SpiffeId::new("spiffe://cloud.trust.domain").unwrap();
        assert_eq!(svid.path_claims(), SpiffePathMatch::Unrecognized);
    }

    #[test]
    fn path_claims_unrecognized_partial_keyword_overlap() {
        // Starts with "service" but not the "nova-compute"/"host" prefix --
        // must not be confused with the nova-compute pattern.
        let svid = SpiffeId::new("spiffe://cloud.trust.domain/service/neutron").unwrap();
        assert_eq!(svid.path_claims(), SpiffePathMatch::Unrecognized);
    }

    #[test]
    fn path_claims_case_sensitive_literals() {
        let svid = SpiffeId::new("spiffe://cloud.trust.domain/Service/nova-compute/host/compute-1")
            .unwrap();
        assert_eq!(svid.path_claims(), SpiffePathMatch::Unrecognized);
    }

    #[test]
    fn path_claims_rejects_nova_compute_host_trailing_slash() {
        let svid = SpiffeId::new("spiffe://cloud.trust.domain/service/nova-compute/host/").unwrap();
        assert_eq!(svid.path_claims(), SpiffePathMatch::Malformed);
    }

    #[test]
    fn path_claims_rejects_nova_compute_host_extra_segment() {
        let svid =
            SpiffeId::new("spiffe://cloud.trust.domain/service/nova-compute/host/compute-1/extra")
                .unwrap();
        assert_eq!(svid.path_claims(), SpiffePathMatch::Malformed);
    }

    #[test]
    fn path_claims_rejects_nova_compute_host_missing_hostname() {
        let svid = SpiffeId::new("spiffe://cloud.trust.domain/service/nova-compute/host").unwrap();
        assert_eq!(svid.path_claims(), SpiffePathMatch::Malformed);
    }

    #[test]
    fn path_claims_rejects_project_missing_instance() {
        let svid = SpiffeId::new("spiffe://cloud.trust.domain/project/p1").unwrap();
        assert_eq!(svid.path_claims(), SpiffePathMatch::Malformed);
    }

    #[test]
    fn path_claims_rejects_project_empty_instance_id() {
        let svid = SpiffeId::new("spiffe://cloud.trust.domain/project/p1/instance/").unwrap();
        assert_eq!(svid.path_claims(), SpiffePathMatch::Malformed);
    }

    #[test]
    fn path_claims_rejects_project_extra_segment() {
        let svid =
            SpiffeId::new("spiffe://cloud.trust.domain/project/p1/instance/i1/extra").unwrap();
        assert_eq!(svid.path_claims(), SpiffePathMatch::Malformed);
    }
}
