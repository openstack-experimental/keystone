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
use url::Url;

use openstack_keystone_config::DpopMode;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_client::dpop::{
    DpopProofContext, DpopProofError, verify_dpop_proof,
};
use openstack_keystone_core_types::oauth2_client::{Confirmation, OAuth2ClientResource};

use super::Oauth2TokenError;
use crate::api::v4::oauth2::dpop_http::{charge_key, proof_header, replay_retry_after};
use crate::api::v4::oauth2::well_known::base_url;
use crate::keystone::ServiceState;

/// Whether the caller has charged the per-IP limiter for this request.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SourceLimit {
    /// Not yet charged: [`bind_token_request`] does it before it verifies a
    /// proof.
    Pending,
    /// Already charged by the grant handler: charging again would count the
    /// request twice.
    Charged,
}

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
/// `min_mode` raises the mode for requests that carry their own binding, such
/// as a refresh token of a bound family: such a request needs a proof even
/// when DPoP has since been switched off.
///
/// A proof is checked for exactly-one-header, the pre-verification source
/// rate limit, the server nonce, the signature and bindings, the per-key
/// throttle on the verified thumbprint, and replay, in that order.
pub(super) async fn bind_token_request(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
    client: &OAuth2ClientResource,
    min_mode: DpopMode,
    source_limit: SourceLimit,
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
        })?
        .max(min_mode);
    if mode == DpopMode::Disabled {
        return Ok(None);
    }

    let proof =
        proof_header(headers).map_err(|e| Oauth2TokenError::invalid_dpop_proof(e.description()))?;
    let Some(proof) = proof else {
        return match mode {
            DpopMode::Required => Err(Oauth2TokenError::invalid_dpop_proof(
                "a DPoP proof is required",
            )),
            _ => Ok(None),
        };
    };

    let Some(nonces) = state.dpop.nonces.as_ref() else {
        tracing::error!(
            "DPoP is enabled for domain {domain_id} but [mapping] cluster_salt is not set"
        );
        return Err(Oauth2TokenError::server_error_unavailable(
            "DPoP is not configured on this server",
        ));
    };

    // Pre-verification rate limit (ADR 0022): the source goes through the
    // shared per-IP limiter, which knows the trusted proxies and so does not
    // lump every client behind a load balancer into one bucket. The key
    // thumbprint is not used here: until the signature is checked it is
    // attacker chosen, and a flood naming a victim's key would drain the
    // victim's bucket.
    if source_limit == SourceLimit::Pending
        && let Err(retry_after) = state
            .rate_limiters
            .check_ip(headers, peer_addr.map(|a| a.ip()))
    {
        return Err(Oauth2TokenError::too_many_requests(
            retry_after.as_secs().max(1),
        ));
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
    // Per-key throttle on the verified thumbprint, a pool of its own apart
    // from the `client_id` keys.
    charge_key(&state.dpop.throttle, &verified.jkt).map_err(Oauth2TokenError::too_many_requests)?;
    state
        .dpop
        .replay
        .check_and_insert(&verified, now)
        .map_err(
            |e| match replay_retry_after(&e, state.dpop.proof_lifetime_secs) {
                Some(retry_after) => Oauth2TokenError::too_many_requests(retry_after),
                None => Oauth2TokenError::invalid_dpop_proof(e.to_string()),
            },
        )?;

    Ok(Some(Confirmation { jkt: verified.jkt }))
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

/// Reconcile the key an authorization code was bound to at `/authorize`
/// (`dpop_jkt`) with the key of the proof presented at `/token` (RFC 9449
/// §10, ADR 0043 §3.4).
///
/// A bound code needs a proof from that key; an unbound code takes the key of
/// the proof, if any.
pub(super) fn reconcile_code_binding(
    code_jkt: Option<&str>,
    confirmation: Option<Confirmation>,
) -> Result<Option<Confirmation>, Oauth2TokenError> {
    match (code_jkt, confirmation) {
        (None, confirmation) => Ok(confirmation),
        (Some(jkt), Some(confirmation)) if confirmation.matches(jkt) => Ok(Some(confirmation)),
        (Some(_), Some(_)) => Err(Oauth2TokenError::invalid_dpop_proof(
            "the DPoP proof key does not match the dpop_jkt of the authorization request",
        )),
        (Some(_), None) => Err(Oauth2TokenError::invalid_dpop_proof(
            "the authorization code is bound to a DPoP key; a proof is required",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn confirmation(jkt: &str) -> Option<Confirmation> {
        Some(Confirmation { jkt: jkt.into() })
    }

    #[test]
    fn test_token_type() {
        assert_eq!(token_type(None), "Bearer");
        assert_eq!(token_type(confirmation("k1").as_ref()), "DPoP");
    }

    #[test]
    fn test_unbound_code_takes_the_proof_key() {
        assert_eq!(
            reconcile_code_binding(None, confirmation("k1")).unwrap(),
            confirmation("k1")
        );
        assert_eq!(reconcile_code_binding(None, None).unwrap(), None);
    }

    #[test]
    fn test_bound_code_needs_the_same_key() {
        assert_eq!(
            reconcile_code_binding(Some("k1"), confirmation("k1")).unwrap(),
            confirmation("k1")
        );
        for other in [confirmation("k2"), None] {
            let err = reconcile_code_binding(Some("k1"), other).unwrap_err();
            assert_eq!(err.error_code(), "invalid_dpop_proof");
        }
    }
}
