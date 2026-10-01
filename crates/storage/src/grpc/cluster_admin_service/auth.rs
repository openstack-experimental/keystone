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

//! Peer authentication, operator authorization and rate limits.

use super::*;

// ---------------------------------------------------------------------------
// Security constants (ADR 0016-v2 §1 and §4.1)
// ---------------------------------------------------------------------------

/// Maximum `RotateDek` invocations per operator per hour.
pub(super) const ROTATE_DEK_PER_HOUR: NonZeroU32 = {
    match NonZeroU32::new(2) {
        Some(v) => v,
        None => panic!("rate limit constant must be non-zero"),
    }
};

/// Maximum `ClearQuarantine` invocations per operator per hour.
pub(super) const CLEAR_QUARANTINE_PER_HOUR: NonZeroU32 = {
    match NonZeroU32::new(10) {
        Some(v) => v,
        None => panic!("rate limit constant must be non-zero"),
    }
};

pub(super) type IdentityLimiter = DefaultKeyedRateLimiter<String>;

/// Extract the peer TLS identity from the request: prefers SPIFFE URI SAN,
/// falls back to CN, or returns `"unknown"` if no peer cert is present.
pub(super) fn extract_peer_identity<T>(request: &tonic::Request<T>) -> String {
    let der_bytes: Option<Vec<u8>> = request
        .peer_certs()
        .and_then(|certs| certs.first().map(|c| c.as_ref().to_vec()));

    der_bytes
        .as_deref()
        .and_then(|der| x509_parser::parse_x509_certificate(der).ok())
        .and_then(|(_, cert)| {
            cert.subject_alternative_name()
                .ok()
                .flatten()
                .and_then(|san| {
                    san.value.general_names.iter().find_map(|n| {
                        if let x509_parser::extensions::GeneralName::URI(uri) = n {
                            Some((*uri).to_owned())
                        } else {
                            None
                        }
                    })
                })
                .or_else(|| {
                    cert.subject()
                        .iter_common_name()
                        .next()
                        .and_then(|a| a.as_str().ok())
                        .map(str::to_owned)
                })
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Validates a SPIFFE URI against the
/// `spiffe://<trust-domain><spiffe_path_prefix><role>` pattern and configured
/// trust domains. Returns the `<role>` segment.
///
/// Errors with `PERMISSION_DENIED` if the URI is malformed, the trust domain is
/// not in the configured list, or the path does not match.
pub(super) fn parse_spiffe_storage_id(
    id: &str,
    trust_domains: &[String],
    prefix: &str,
) -> Result<String, Status> {
    let rest = id
        .strip_prefix("spiffe://")
        .ok_or_else(|| Status::permission_denied("peer identity is not a SPIFFE URI"))?;

    let slash = rest
        .find('/')
        .ok_or_else(|| Status::permission_denied("SPIFFE ID is missing a path component"))?;
    let (domain, path) = rest.split_at(slash);

    if !trust_domains.iter().any(|d| d == domain) {
        return Err(Status::permission_denied(format!(
            "SPIFFE trust domain '{domain}' is not in the configured trust domain list"
        )));
    }

    // `path` starts with '/', strip the configured prefix to get the role.
    let role = path
        .strip_prefix(prefix)
        .filter(|r| !r.is_empty() && !r.contains('/'))
        .ok_or_else(|| {
            Status::permission_denied(format!(
                "SPIFFE ID '{id}' does not match the required pattern \
                 spiffe://<trust-domain>{prefix}<role>"
            ))
        })?;

    Ok(role.to_owned())
}

// ---------------------------------------------------------------------------
// RBAC — operator role enforcement
// ---------------------------------------------------------------------------

/// Verifies the peer identity and, in SPIFFE mode, asserts the role matches
/// the configured operator role (ADR 0016-v2 §1).
///
/// In TLS-fallback mode emits a security warning and allows the request
/// through; network isolation is the compensating control per ADR 0016-v2 §4.2.
pub(super) fn require_operator<T>(
    request: &tonic::Request<T>,
    trust_domains: Option<&[String]>,
    spiffe_path_prefix: &str,
    operator_role: &str,
) -> Result<String, Status> {
    let identity = extract_peer_identity(request);

    match trust_domains {
        Some(domains) => {
            if !identity.starts_with("spiffe://") {
                return Err(Status::permission_denied(
                    "SPIFFE mode is active; peer must present a SPIFFE URI SAN",
                ));
            }
            check_svid_ttl(request)?;
            let role = parse_spiffe_storage_id(&identity, domains, spiffe_path_prefix)?;
            if role != operator_role {
                return Err(Status::permission_denied(format!(
                    "role '{role}' is not authorized for this operation; \
                     required: '{operator_role}'"
                )));
            }
        }
        None => {
            tracing::warn!(
                identity,
                "RBAC role check skipped in TLS-fallback mode; \
                 upgrade to SPIFFE mTLS to enforce operator role-based access \
                 control (ADR 0016-v2 §4.2)"
            );
        }
    }

    Ok(identity)
}

/// Validates the peer's SPIFFE identity for internal Raft operations.
///
/// When `allowed_peer_svids` is non-empty, the identity must match one of the
/// allow-listed SVIDs. Otherwise falls back to trust-domain-only validation.
///
/// In TLS-fallback mode (`trust_domains = None`) the check is skipped entirely.
pub(super) fn check_peer_trust_domain<T>(
    request: &tonic::Request<T>,
    trust_domains: Option<&[String]>,
    allowed_peer_svids: &[String],
) -> Result<String, Status> {
    let identity = extract_peer_identity(request);

    if trust_domains.is_some() && !identity.starts_with("spiffe://") {
        return Err(Status::permission_denied(
            "SPIFFE mode is active; peer must present a SPIFFE URI SAN",
        ));
    }

    // In SPIFFE mode, enforce the 5-minute force-renewal window (ADR 0016-v2 §4.1).
    if trust_domains.is_some() {
        check_svid_ttl(request)?;
    }

    if allowed_peer_svids.is_empty() {
        // Fallback: trust-domain-only check. Skipped entirely in TLS-fallback
        // mode (`trust_domains = None`), so this branch is a no-op there.
        if let Some(domains) = trust_domains {
            parse_spiffe_trust_domain(&identity, domains)?;
        }
    } else {
        // Allow-list check. In TLS-fallback mode this code is unreachable
        // because `allowed_peer_svids` is always empty when `trust_domains`
        // is `None` (set in `app.rs`).
        if !allowed_peer_svids.contains(&identity) {
            return Err(Status::permission_denied(format!(
                "SPIFFE ID '{identity}' is not in the allowed peer SVID list"
            )));
        }
    }

    Ok(identity)
}

/// Extract and validate only the SPIFFE trust domain from the peer identity,
/// returning it on success. Unlike `parse_spiffe_storage_id`, this does not
/// require a specific path prefix or role.
pub(super) fn parse_spiffe_trust_domain(id: &str, trust_domains: &[String]) -> Result<(), Status> {
    let rest = id
        .strip_prefix("spiffe://")
        .ok_or_else(|| Status::permission_denied("peer identity is not a SPIFFE URI"))?;

    let slash = rest
        .find('/')
        .ok_or_else(|| Status::permission_denied("SPIFFE ID is missing a path component"))?;
    let (domain, _path) = rest.split_at(slash);

    if !trust_domains.iter().any(|d| d == domain) {
        return Err(Status::permission_denied(format!(
            "SPIFFE trust domain '{domain}' is not in the configured trust domain list"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// SVID TTL enforcement (ADR 0016-v2 §4.1 — force-renewal window)
// ---------------------------------------------------------------------------

/// Extracts the peer certificate from `request` and enforces the SVID
/// force-renewal window (ADR 0016-v2 §4.1). Only called in SPIFFE mode.
///
/// Redundant with the `SpiffeIdInterceptor` that already runs this check for
/// every request reaching this service (`raft_grpc::validate_spiffe_id`) —
/// kept as defense-in-depth on the RBAC-sensitive admin surface rather than
/// relying solely on the interceptor layer.
pub(super) fn check_svid_ttl<T>(request: &tonic::Request<T>) -> Result<(), Status> {
    let der = request
        .peer_certs()
        .and_then(|certs| certs.first().map(|c| c.as_ref().to_vec()))
        .ok_or_else(|| Status::permission_denied("no peer certificate presented"))?;
    check_svid_ttl_der(&der, now_unix_secs())
}
