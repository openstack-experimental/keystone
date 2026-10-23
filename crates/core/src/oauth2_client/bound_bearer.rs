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
//! Authenticating a request that carries both an SVID and a delegated JWT
//! (ADR 0036 §8.1).
//!
//! A delegatable service keeps using mutual TLS after it received a service
//! grant or on-behalf-of token, so its requests carry two proofs: the SVID
//! says which service calls, the token says for whom. Keystone accepts the
//! token as a credential only together with an SVID that authenticates the
//! very client the token names in `act`. A token alone is never accepted:
//! it is an unbound bearer credential.
//!
//! Both proofs are re-evaluated against live state on every request, through
//! the same code as redemption and exchange, so a revoked grant, a lost role
//! or a revoked root token stops working at once.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;
use tracing::debug;

use openstack_keystone_core_types::oauth2_client::{
    DelegationContext, OpenStackAccessTokenClaims, OpenStackScope,
};

use crate::auth::{ExecutionContext, ValidatedSecurityContext};
use crate::common::SpiffeId;
use crate::keystone::ServiceState;
use crate::oauth2_client::on_behalf_of::{
    OnBehalfOfRequest, OnBehalfOfSubject, exchange_on_behalf_of,
};
use crate::oauth2_client::verify::{
    TokenPresentation, enforce_token_binding, verify_openstack_access_token,
};
use crate::service_grant::redeem::redeem_loaded_service_grant;

/// The OpenStack service type of Keystone, accepted in a narrowed `aud`.
const IDENTITY_SERVICE_TYPE: &str = "identity";

/// Why a delegated bearer was not accepted. The caller answers `401` for
/// every one of them; the reason is for the log only.
#[derive(Debug, Error)]
pub enum BoundBearerError {
    /// No `public_endpoint` is configured, so no issuer can be trusted.
    #[error("no public endpoint is configured")]
    NoIssuer,
    /// The token is malformed, expired, revoked or signed by another party.
    #[error("the bearer token is not valid: {0}")]
    InvalidToken(String),
    /// The token is not a service grant or on-behalf-of token, or carries no
    /// actor.
    #[error("the bearer token carries no exchangeable delegation")]
    NotDelegated,
    /// The SVID does not authenticate the client the token names, or the
    /// delegation behind the token is no longer usable.
    #[error("the SVID does not match the token's actor or the delegation is gone: {0}")]
    NotBound(String),
    /// A storage or provider failure.
    #[error("{0}")]
    Provider(String),
}

/// Authenticate `token` presented together with `svid` on the internal
/// interface.
///
/// The domain whose key signed the token is taken from the `iss` claim, but
/// only after the claim equals `{public_endpoint}/v4/oauth2/{domain}`; the
/// signature is then checked against that domain's own keys and issuer.
///
/// # Errors
/// [`BoundBearerError`] for every refusal.
pub async fn authenticate_bound_bearer(
    state: &ServiceState,
    svid: &SpiffeId,
    token: &str,
) -> Result<ValidatedSecurityContext, BoundBearerError> {
    let (public_endpoint, signing_algorithm) = {
        let config = state.config_manager.config.read().await;
        (
            config.default.public_endpoint.clone(),
            crate::oauth2_key::signing_algorithm(config.oauth2.signing_algorithm),
        )
    };
    let public_endpoint = public_endpoint
        .map(|e| e.to_string())
        .ok_or(BoundBearerError::NoIssuer)?;
    let prefix = format!("{}/v4/oauth2/", public_endpoint.trim_end_matches('/'));

    let domain_id = peek_issuer(token)
        .and_then(|iss| iss.strip_prefix(&prefix).map(str::to_string))
        .filter(|d| !d.is_empty() && !d.contains('/'))
        .ok_or_else(|| BoundBearerError::InvalidToken("unknown issuer".into()))?;
    let issuer = format!("{prefix}{domain_id}");

    let keys = state.provider.get_oauth2_key_provider();
    let jwks = keys
        .jwks(state, &domain_id)
        .await
        .map_err(|e| BoundBearerError::InvalidToken(e.to_string()))?;
    let revoked_jtis = keys
        .revoked_jtis(state, &domain_id)
        .await
        .map_err(|e| BoundBearerError::Provider(e.to_string()))?;
    let claims = verify_openstack_access_token(
        token,
        &jwks,
        signing_algorithm,
        std::slice::from_ref(&issuer),
        Some(IDENTITY_SERVICE_TYPE),
        &revoked_jtis,
    )
    .map_err(|e| BoundBearerError::InvalidToken(e.to_string()))?;

    // This path authenticates by the SVID and cannot check a DPoP proof, so a
    // token bound to a key is refused instead of being used as a bearer
    // credential (ADR 0043 §4).
    enforce_token_binding(claims.cnf.as_ref(), TokenPresentation::Bearer, false)
        .map_err(|e| BoundBearerError::InvalidToken(e.to_string()))?;

    // The token must name an actor, and the SVID must authenticate exactly
    // that client (checked again, against the client's `spiffe_ids`, by the
    // paths below).
    let client_id = claims
        .act
        .as_ref()
        .map(|act| act.client_id.clone())
        .filter(|id| *id == claims.client_id)
        .ok_or(BoundBearerError::NotDelegated)?;
    debug!(client_id, %svid, "authenticating a delegated bearer bound to an SVID");

    match &claims.delegation_context {
        DelegationContext::ServiceGrant { grant_id, .. } => {
            bound_grant(state, svid, &domain_id, &client_id, grant_id, &claims).await
        }
        DelegationContext::OnBehalfOf { .. } => {
            let exchanged = exchange_on_behalf_of(
                state,
                &OnBehalfOfRequest {
                    domain_id: &domain_id,
                    issuer: &issuer,
                    signing_algorithm,
                    svid,
                    client_id: &client_id,
                    subject: OnBehalfOfSubject::Hop(token),
                },
            )
            .await
            .map_err(|e| BoundBearerError::NotBound(e.to_string()))?;
            Ok(exchanged.vsc)
        }
        _ => Err(BoundBearerError::NotDelegated),
    }
}

/// Re-redeem the grant behind a service grant token, with the roles the
/// token carried, so the request is bounded exactly like the token was.
async fn bound_grant(
    state: &ServiceState,
    svid: &SpiffeId,
    domain_id: &str,
    client_id: &str,
    grant_id: &str,
    claims: &OpenStackAccessTokenClaims,
) -> Result<ValidatedSecurityContext, BoundBearerError> {
    let OpenStackScope::Project {
        project_id, roles, ..
    } = &claims.openstack_context.scope
    else {
        return Err(BoundBearerError::NotDelegated);
    };
    let grant = state
        .provider
        .get_service_grant_provider()
        .get_service_grant(&ExecutionContext::internal(state), domain_id, grant_id)
        .await
        .map_err(|e| BoundBearerError::Provider(e.to_string()))?
        .ok_or_else(|| BoundBearerError::NotBound("unknown grant".into()))?;
    if grant.target.project_id() != project_id {
        return Err(BoundBearerError::NotBound("project mismatch".into()));
    }
    // The token's roles include implied ones, so only the grant's own role
    // ids the token carried are kept.
    let narrowed: Vec<String> = grant
        .role_ids
        .iter()
        .filter(|id| roles.iter().any(|r| &r.id == *id))
        .cloned()
        .collect();
    if narrowed.is_empty() {
        return Err(BoundBearerError::NotBound(
            "no delegated role in the token".into(),
        ));
    }
    let roles = (narrowed.len() != grant.role_ids.len()).then_some(narrowed);
    let redeemed = redeem_loaded_service_grant(state, svid, Some(client_id), grant, roles, false)
        .await
        .map_err(|e| BoundBearerError::NotBound(e.to_string()))?;
    Ok(redeemed.vsc)
}

/// The `iss` of a compact JWS, read without verifying anything: it only
/// selects which domain's keys the signature is then checked against.
fn peek_issuer(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("iss")?.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jws(payload: &str) -> String {
        format!("h.{}.s", URL_SAFE_NO_PAD.encode(payload))
    }

    #[test]
    fn test_peek_issuer() {
        assert_eq!(
            peek_issuer(&jws(r#"{"iss":"https://ks/v4/oauth2/d1"}"#)).as_deref(),
            Some("https://ks/v4/oauth2/d1")
        );
        for bad in [
            "nodots".to_string(),
            "a.!!!.c".to_string(),
            jws("not json"),
            jws(r#"{"sub":"x"}"#),
            jws(r#"{"iss":1}"#),
        ] {
            assert_eq!(peek_issuer(&bad), None);
        }
    }
}
