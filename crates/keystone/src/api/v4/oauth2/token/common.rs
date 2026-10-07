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
//! Helpers shared by every grant handler.

use axum::http::{HeaderMap, header};
use base64::{
    Engine as _, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_client::crypto;
use openstack_keystone_core_types::oauth2_client::{GrantType, OAuth2ClientResource};
use openstack_keystone_key_repository::asymmetric::{jwt_algorithm, to_encoding_key};

use crate::keystone::ServiceState;

use super::{Oauth2TokenError, TokenForm};

/// Extract `client_id`/`client_secret` via HTTP Basic (`client_secret_basic`,
/// RFC 6749 §2.3.1), falling back to the form body if no `Authorization`
/// header is present. Basic auth takes precedence when both are given, per
/// RFC 6749 §2.3.1's recommendation against accepting credentials in the
/// body when Basic is available.
pub(super) fn client_credentials_from_request(
    headers: &HeaderMap,
    form: &TokenForm,
) -> Option<(String, Option<String>)> {
    client_credentials_from_parts(
        headers,
        form.client_id.as_deref(),
        form.client_secret.as_deref(),
    )
}

/// Same as [`client_credentials_from_request`] for endpoints with their own
/// form type (e.g. RFC 7009 revocation): takes the body `client_id` /
/// `client_secret` values directly.
pub(in crate::api::v4::oauth2) fn client_credentials_from_parts(
    headers: &HeaderMap,
    body_client_id: Option<&str>,
    body_client_secret: Option<&str>,
) -> Option<(String, Option<String>)> {
    if let Some(basic) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Basic "))
    {
        let decoded = STANDARD.decode(basic).ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        let (client_id, client_secret) = decoded.split_once(':')?;
        return Some((client_id.to_string(), Some(client_secret.to_string())));
    }
    body_client_id.map(|client_id| {
        (
            client_id.to_string(),
            body_client_secret.map(str::to_string),
        )
    })
}

/// Sign `claims` into a compact JWS using the domain's active OAuth2
/// signing key (shared by every grant that mints a token).
pub(super) async fn sign_jwt<T: Serialize>(
    state: &ServiceState,
    domain_id: &str,
    claims: &T,
) -> Result<String, Oauth2TokenError> {
    let signing_key = state
        .provider
        .get_oauth2_key_provider()
        .active_signing_key(state, domain_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 signing key lookup failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;
    let encoding_key = to_encoding_key(&signing_key).map_err(|e| {
        tracing::warn!(error = %e, "oauth2 signing key conversion failed");
        Oauth2TokenError::internal("token issuance failed")
    })?;
    let mut header = jsonwebtoken::Header::new(jwt_algorithm(signing_key.algorithm));
    header.kid = Some(openstack_keystone_key_repository::asymmetric::derive_kid(
        &signing_key.public_key_der,
    ));
    jsonwebtoken::encode(&header, claims, &encoding_key).map_err(|e| {
        tracing::warn!(error = %e, "oauth2 token signing failed");
        Oauth2TokenError::internal("token issuance failed")
    })
}

/// Map an `id_token` claim construction failure to a token error: never a
/// partial token (ADR 0026 §4, "Claim Safety").
pub(super) fn id_token_error(
    e: openstack_keystone_core::oauth2_client::IdTokenClaimsError,
) -> Oauth2TokenError {
    tracing::error!(error = %e, "oauth2 id_token claims construction failed");
    Oauth2TokenError::internal("token issuance failed")
}

/// OIDC Core §3.2.2.10 `at_hash`: left half of `SHA-256(access_token)`,
/// base64url-encoded. Binds an `id_token` to its co-issued `access_token`.
pub(super) fn compute_at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
}

/// Authenticate a client for the `authorization_code`/`refresh_token`
/// grants, where -- unlike `client_credentials` (RFC 6749 §4.4, confidential
/// only) -- a public client (no `client_secret_hash`) is allowed: PKCE
/// stands in for client authentication on that path (ADR 0026 §1).
/// Confidential clients still must present and verify a correct secret.
/// Every rejection path burns the same Argon2id cost as a real verification
/// (ADR 0026 §7.A enumeration defense), mirroring the `client_credentials`
/// grant's posture.
pub(in crate::api::v4::oauth2) async fn authenticate_client(
    state: &ServiceState,
    oauth2_cfg: &openstack_keystone_config::Oauth2Provider,
    domain_id: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<OAuth2ClientResource, Oauth2TokenError> {
    let exec = ExecutionContext::internal(state);
    let client = state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&exec, client_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 client lookup failed");
            Oauth2TokenError::internal("client lookup failed")
        })?;

    let Some(client) = client.filter(|c| c.domain_id == domain_id) else {
        let _ = crypto::generate_dummy_hash(oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    };
    if !client.enabled || client.deleted_at.is_some() {
        let _ = crypto::generate_dummy_hash(oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    }

    match (client.client_secret_hash.as_deref(), client_secret) {
        (Some(hash), Some(secret)) => {
            let verified = crypto::verify_secret(secret, hash).await.map_err(|e| {
                tracing::warn!(error = %e, "oauth2 client secret argon2 verification errored");
                Oauth2TokenError::internal("client authentication failed")
            })?;
            if !verified {
                return Err(Oauth2TokenError::invalid_client(
                    "client authentication failed",
                ));
            }
        }
        (Some(_hash), None) => {
            // Confidential client must authenticate even on this grant.
            let _ = crypto::generate_dummy_hash(oauth2_cfg).await;
            return Err(Oauth2TokenError::invalid_client(
                "client authentication failed",
            ));
        }
        (None, _) => {
            // Public client: no secret to verify. PKCE (authorization_code)
            // or the caller's own prior possession of the refresh token
            // bearer value (refresh_token) is the proof instead.
        }
    }

    Ok(client)
}

/// Validate a client for the `device_code` grant: registered in
/// `domain_id`, enabled, not deleted, and holding the `device_code`
/// grant type. Unlike [`authenticate_client`], no `client_secret` is
/// required: device-flow clients are overwhelmingly public/native
/// applications (ADR 0026 §7.C), matching `/device_authorization`'s own
/// posture. Shared by `/device_authorization` (grant creation) and the
/// `device_code` token arm (redemption); the token arm must run this
/// *before* `poll_device_code_grant`, which fetch-and-deletes an
/// `Authorized` grant, so a client that is not entitled to redeem cannot
/// burn the grant (the user can retry once the client is fixed).
pub(in crate::api::v4::oauth2) async fn validate_device_code_client(
    state: &ServiceState,
    domain_id: &str,
    client_id: &str,
) -> Result<OAuth2ClientResource, Oauth2TokenError> {
    let exec = ExecutionContext::internal(state);
    let client = state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&exec, client_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 client lookup failed");
            Oauth2TokenError::internal("client lookup failed")
        })?;
    let Some(client) =
        client.filter(|c| c.domain_id == domain_id && c.enabled && c.deleted_at.is_none())
    else {
        return Err(Oauth2TokenError::invalid_client(
            "unknown or disabled client",
        ));
    };
    if !client.grant_types.contains(&GrantType::DeviceCode) {
        return Err(Oauth2TokenError::unauthorized_client(
            "client is not authorized to use the device_code grant",
        ));
    }
    Ok(client)
}

/// Best-effort cleanup when a grant fails *after* its refresh family was
/// minted (e.g. JWT signing error): the bearer is never delivered, so the
/// family must not linger against the per-user/client family caps. Failures
/// here are only logged -- the caller is already returning the original error.
pub(super) async fn discard_refresh_family(state: &ServiceState, family_id: Option<&str>) {
    use openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason;
    let Some(family_id) = family_id else { return };
    if let Err(e) = state
        .provider
        .get_oauth2_session_provider()
        .revoke_refresh_token_family(
            state,
            family_id,
            RefreshTokenRevocationReason::IssuanceFailed,
        )
        .await
    {
        tracing::warn!(error = %e, family_id, "failed to discard undelivered refresh family");
    }
}
