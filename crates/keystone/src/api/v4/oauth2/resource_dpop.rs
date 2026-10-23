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
//! Resource-side handling of DPoP-bound access tokens (RFC 9449 §7, ADR 0043
//! §4) for the Keystone endpoints that take an access token as their
//! credential.
//!
//! The binding rule itself is [`enforce_token_binding`]; this module reads
//! the credential from the request and verifies the `DPoP` proof against it.
//! Resource servers do not use server nonces in this version, so a proof
//! needs none.

use axum::http::{HeaderMap, header};
use url::Url;

use openstack_keystone_core::oauth2_client::dpop::{
    DpopProofContext, DpopProofError, SUPPORTED_ALGORITHMS, verify_dpop_proof,
};
use openstack_keystone_core_types::oauth2_client::Confirmation;

use super::dpop_http::{charge_key, proof_header, replay_retry_after};
use crate::keystone::ServiceState;

/// Authorization scheme an access token was presented with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scheme {
    /// RFC 6750 `Bearer`.
    Bearer,
    /// RFC 9449 `DPoP`.
    Dpop,
}

/// Extract the access token and its scheme from the `Authorization` header.
/// Any other scheme, or an empty token, is no credential.
pub(super) fn presented_credential(headers: &HeaderMap) -> Option<(Scheme, &str)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let scheme = if scheme.eq_ignore_ascii_case("Bearer") {
        Scheme::Bearer
    } else if scheme.eq_ignore_ascii_case("DPoP") {
        Scheme::Dpop
    } else {
        return None;
    };
    Some(scheme).zip(Some(token.trim()).filter(|t| !t.is_empty()))
}

/// The `algs` challenge parameter: the proof algorithms the server accepts.
pub(super) fn challenge_algs() -> String {
    SUPPORTED_ALGORITHMS.join(" ")
}

/// Why a proof presented with an access token was refused.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ProofRefusal {
    /// The proof is missing, malformed, stale, replayed or for another
    /// request or token.
    Invalid(String),
    /// Throttled; retry after the given number of seconds.
    RateLimited(u64),
}

/// Verify the `DPoP` proof of a request that presents `token` and return the
/// thumbprint of the proof key.
///
/// `uri` is the external URL of the endpoint (`htu`), `method` its HTTP
/// method (`htm`). The caller has rate limited the source already, which
/// bounds the signature checks; this adds the per-key throttle (ADR 0022) on
/// the verified key thumbprint, in its own pool apart from `/token`. `bound_jkt` is the `cnf` of the token.
pub(super) fn verify_resource_proof(
    state: &ServiceState,
    headers: &HeaderMap,
    method: &str,
    uri: &Url,
    token: &str,
    bound_jkt: &Confirmation,
) -> Result<String, ProofRefusal> {
    let proof = proof_header(headers)
        .map_err(|e| ProofRefusal::Invalid(e.description().into()))?
        .ok_or_else(|| ProofRefusal::Invalid("a DPoP proof is required".into()))?;

    let now = chrono::Utc::now().timestamp();
    let verified = verify_dpop_proof(
        proof,
        &DpopProofContext {
            access_token: Some(token),
            accepted_nonces: None,
            max_skew_secs: state.dpop.proof_lifetime_secs,
            method,
            now,
            uri,
        },
    )
    .map_err(|e: DpopProofError| ProofRefusal::Invalid(e.to_string()))?;
    // Only the key the token is bound to may use the replay cache: a proof
    // from any other key is refused before it takes an entry, so a holder of
    // a valid token cannot fill the cache with fresh keys.
    if !bound_jkt.matches(&verified.jkt) {
        return Err(ProofRefusal::Invalid(
            "the DPoP proof key does not match the token".into(),
        ));
    }
    // Throttled on the verified thumbprint: an unverified one is attacker
    // chosen, so a flood of forged proofs naming a victim's key could drain
    // the victim's bucket. A pool apart from `/token`, so reading with a
    // token cannot starve issuing or refreshing one.
    charge_key(&state.dpop.resource_throttle, &verified.jkt).map_err(ProofRefusal::RateLimited)?;
    state
        .dpop
        .replay
        .check_and_insert(&verified, now)
        .map_err(
            |e| match replay_retry_after(&e, state.dpop.proof_lifetime_secs) {
                Some(retry_after) => ProofRefusal::RateLimited(retry_after),
                None => ProofRefusal::Invalid(e.to_string()),
            },
        )?;
    Ok(verified.jkt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(authorization: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(authorization).unwrap(),
        );
        headers
    }

    #[test]
    fn test_presented_credential_schemes() {
        assert_eq!(
            presented_credential(&headers("Bearer abc")),
            Some((Scheme::Bearer, "abc"))
        );
        assert_eq!(
            presented_credential(&headers("bearer abc")),
            Some((Scheme::Bearer, "abc"))
        );
        assert_eq!(
            presented_credential(&headers("DPoP abc")),
            Some((Scheme::Dpop, "abc"))
        );
        assert_eq!(
            presented_credential(&headers("dpop  abc ")),
            Some((Scheme::Dpop, "abc"))
        );
    }

    #[test]
    fn test_presented_credential_rejects_other_input() {
        assert!(presented_credential(&headers("Basic abc")).is_none());
        assert!(presented_credential(&headers("DPoP ")).is_none());
        assert!(presented_credential(&headers("DPoP")).is_none());
        assert!(presented_credential(&HeaderMap::new()).is_none());
    }

    #[test]
    fn test_challenge_algs() {
        assert_eq!(challenge_algs(), "ES256 RS256");
    }
}
