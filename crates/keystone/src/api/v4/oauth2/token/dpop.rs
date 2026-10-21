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
//! DPoP proof handling shared by the `/token` grants (RFC 9449, ADR 0043 §3).

use std::net::SocketAddr;

use axum::http::HeaderMap;
use governor::clock::Clock as _;
use url::Url;

use openstack_keystone_config::DpopMode;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_client::dpop::{
    DpopProofContext, DpopProofError, peek_proof_jkt, verify_dpop_proof,
};
use openstack_keystone_core::oauth2_client::dpop_replay::DpopReplayError;
use openstack_keystone_core_types::oauth2_client::{Confirmation, OAuth2ClientResource};

use super::Oauth2TokenError;
use crate::api::v4::oauth2::well_known::base_url;
use crate::keystone::ServiceState;

/// Name of the proof header.
const DPOP_HEADER: &str = "dpop";

/// Validate the `DPoP` proof of a token request and return the thumbprint of
/// the key the issued token must be bound to.
///
/// Called after the client has been authenticated: the effective mode depends
/// on the client, and an unauthenticated caller never makes the server check
/// a signature. The mode is the strictest of the global, domain and client
/// levels (ADR 0043 §1):
///
/// * `disabled`: the header is ignored and `None` is returned.
/// * `optional`: a proof binds the token, no proof leaves it unbound.
/// * `required`: a request without a proof is rejected.
///
/// A proof is checked for exactly-one-header, the pre-verification rate
/// limit (source and unverified key thumbprint), the server nonce, the
/// signature and bindings, and replay, in that order.
pub(super) async fn bind_token_request(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
    client: &OAuth2ClientResource,
) -> Result<Option<Confirmation>, Oauth2TokenError> {
    let exec = ExecutionContext::internal(state);
    let mode = state
        .provider
        .get_oauth2_client_provider()
        .effective_dpop_mode(&exec, domain_id, client.dpop_bound_access_tokens)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "DPoP mode lookup failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;
    if mode == DpopMode::Disabled {
        return Ok(None);
    }

    let mut proofs = headers.get_all(DPOP_HEADER).iter();
    let Some(proof) = proofs.next() else {
        return match mode {
            DpopMode::Required => Err(Oauth2TokenError::invalid_dpop_proof(
                "a DPoP proof is required",
            )),
            _ => Ok(None),
        };
    };
    if proofs.next().is_some() {
        return Err(Oauth2TokenError::invalid_dpop_proof(
            "exactly one DPoP header is allowed",
        ));
    }
    let proof = proof
        .to_str()
        .map_err(|_| Oauth2TokenError::invalid_dpop_proof("the DPoP header is not valid text"))?;

    let Some(nonces) = state.dpop.nonces.as_ref() else {
        tracing::error!(
            "DPoP is enabled for domain {domain_id} but [mapping] cluster_salt is not set"
        );
        return Err(Oauth2TokenError::server_error_unavailable(
            "DPoP is not configured on this server",
        ));
    };

    // Pre-verification rate limit (ADR 0022): the thumbprint is attacker
    // chosen until the signature is checked, so it is only a throttle key.
    // It has a pool of its own, apart from the `client_id` keys. The source
    // goes through the shared per-IP limiter, which knows the trusted
    // proxies and so does not lump every client behind a load balancer into
    // one bucket.
    let unverified_jkt =
        peek_proof_jkt(proof).map_err(|e| Oauth2TokenError::invalid_dpop_proof(e.to_string()))?;
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(headers, peer_addr.map(|a| a.ip()))
    {
        return Err(Oauth2TokenError::too_many_requests(
            retry_after.as_secs().max(1),
        ));
    }
    if let Err(not_until) = state.dpop.throttle.check_key(&unverified_jkt) {
        let retry_after = not_until
            .wait_time_from(state.dpop.throttle.clock().now())
            .as_secs()
            .max(1);
        return Err(Oauth2TokenError::too_many_requests(retry_after));
    }

    let uri = Url::parse(&format!(
        "{}/v4/oauth2/{domain_id}/token",
        base_url(state, headers).await
    ))
    .map_err(|e| {
        tracing::warn!(error = %e, "token endpoint URL is not valid");
        Oauth2TokenError::internal("token issuance failed")
    })?;
    let now = chrono::Utc::now().timestamp();
    let accepted = nonces.accepted(now);
    let ctx = DpopProofContext {
        access_token: None,
        accepted_nonces: Some(&accepted),
        max_skew_secs: state.dpop.proof_lifetime_secs,
        method: "POST",
        now,
        uri: &uri,
    };
    let verified = verify_dpop_proof(proof, &ctx).map_err(|e| match e {
        DpopProofError::NonceRequired => Oauth2TokenError::use_dpop_nonce(nonces.issue(now)),
        e => Oauth2TokenError::invalid_dpop_proof(e.to_string()),
    })?;
    state
        .dpop
        .replay
        .check_and_insert(&verified, now)
        .map_err(|e| replay_error(e, state.dpop.proof_lifetime_secs))?;

    Ok(Some(Confirmation { jkt: verified.jkt }))
}

/// Map a replay cache refusal to the error response.
///
/// A replay is the client's fault. A full cache or an exhausted per-key
/// share is not: it clears once the entries age out, which takes at most one
/// proof lifetime, so the caller is told to retry after that instead of
/// being sent a final-looking `invalid_dpop_proof`.
fn replay_error(error: DpopReplayError, proof_lifetime_secs: u64) -> Oauth2TokenError {
    match error {
        DpopReplayError::Replayed => Oauth2TokenError::invalid_dpop_proof(error.to_string()),
        DpopReplayError::CacheFull | DpopReplayError::KeyQuotaExceeded => {
            Oauth2TokenError::too_many_requests(proof_lifetime_secs.max(1))
        }
    }
}

/// The `token_type` of a token response: `DPoP` for a token bound to a key,
/// `Bearer` otherwise (RFC 9449 §5).
pub(super) fn token_type(confirmation: Option<&Confirmation>) -> &'static str {
    if confirmation.is_some() {
        "DPoP"
    } else {
        "Bearer"
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;

    fn confirmation(jkt: &str) -> Option<Confirmation> {
        Some(Confirmation { jkt: jkt.into() })
    }

    #[test]
    fn test_replay_is_a_bad_proof_but_exhaustion_is_a_retry() {
        let replayed = replay_error(DpopReplayError::Replayed, 60);
        assert_eq!(replayed.status(), StatusCode::BAD_REQUEST);
        for exhausted in [
            DpopReplayError::CacheFull,
            DpopReplayError::KeyQuotaExceeded,
        ] {
            let error = replay_error(exhausted, 60);
            assert_eq!(error.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    #[test]
    fn test_token_type() {
        assert_eq!(token_type(None), "Bearer");
        assert_eq!(token_type(confirmation("k1").as_ref()), "DPoP");
    }
}
