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

pub(super) use crate::grpc::authz::{PeerAuthz, PeerRole};

// ---------------------------------------------------------------------------
// RBAC — role enforcement
// ---------------------------------------------------------------------------

/// Requires the operator role (ADR 0016-v2 §1). Returns the peer identity
/// (for audit / rate-limit keys only; the role comes from the URI SAN).
pub(super) fn require_operator<T>(
    request: &tonic::Request<T>,
    authz: &PeerAuthz,
) -> Result<String, Status> {
    require_peer(request, authz, &[PeerRole::Operator])
}

/// Requires one of `allowed` roles. In SPIFFE mode (and only there; keyed
/// on the configured [`PeerAuthz`] mode, never on the identity string)
/// also enforces the SVID force-renewal window (ADR 0016-v2 §4.1).
/// Returns the peer identity.
pub(super) fn require_peer<T>(
    request: &tonic::Request<T>,
    authz: &PeerAuthz,
    allowed: &[PeerRole],
) -> Result<String, Status> {
    let (identity, _) = authz.require(request, allowed)?;
    if authz.is_spiffe() {
        check_svid_ttl(request)?;
    }
    Ok(identity)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::authz::{PeerAuthz, PeerRole};

    fn authz() -> PeerAuthz {
        PeerAuthz::spiffe(
            vec!["example.org".into()],
            "/keystone/storage/".into(),
            "storage-operator".into(),
            vec![],
        )
    }

    #[test]
    fn require_operator_without_cert_denied() {
        let req = tonic::Request::new(());
        let err = require_operator(&req, &authz()).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn require_peer_without_cert_denied() {
        let req = tonic::Request::new(());
        for allowed in [
            &[PeerRole::Node][..],
            &[PeerRole::Operator][..],
            &[PeerRole::Node, PeerRole::Operator][..],
            &[][..],
        ] {
            let err = require_peer(&req, &authz(), allowed).unwrap_err();
            assert_eq!(err.code(), tonic::Code::PermissionDenied);
        }
    }

    #[test]
    fn role_resolution_matrix() {
        let authz = authz();
        let node = authz
            .role_of_identity("spiffe://example.org/keystone/storage/node")
            .unwrap();
        let op = authz
            .role_of_identity("spiffe://example.org/keystone/storage/storage-operator")
            .unwrap();
        assert_eq!(node, PeerRole::Node);
        assert_eq!(op, PeerRole::Operator);
        // Node is not an operator; operator is not a node.
        let id = "spiffe://example.org/keystone/storage/node";
        assert!(
            authz
                .authorize(Some(id), id, &[PeerRole::Operator])
                .is_err()
        );
        let id = "spiffe://example.org/keystone/storage/storage-operator";
        assert!(authz.authorize(Some(id), id, &[PeerRole::Node]).is_err());
        assert!(
            authz
                .authorize(Some(id), id, &[PeerRole::Node, PeerRole::Operator])
                .is_ok()
        );
    }

    /// A CN-shaped identity without a URI SAN must never yield a role.
    #[test]
    fn cn_only_identity_never_authorizes() {
        let authz = authz();
        let cn = "spiffe://example.org/keystone/storage/storage-operator";
        let err = authz
            .authorize(None, cn, &[PeerRole::Operator])
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }
}
