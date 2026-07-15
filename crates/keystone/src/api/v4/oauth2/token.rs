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
//! `POST /v4/oauth2/{domain_id}/token`: `client_credentials` grant (ADR 0026
//! §5, §7.A, §10 Phase 3).
//!
//! Only `grant_type=client_credentials` is implemented -- `authorization_code`
//! and `device_code` are Phase 4. Unauthenticated at the `Auth`-extractor
//! level: the client secret presented in the request body *is* the
//! credential, the same posture as `ApiKeyAuth`
//! (`openstack_keystone_core::api::api_key_auth`). Error responses follow
//! RFC 6749 §5.2 (`{"error", "error_description"}`), not `KeystoneApiError`'s
//! envelope -- this is a token endpoint, not an authenticated Keystone API.

use axum::{
    Form, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{
    Engine as _, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
};
use governor::clock::Clock as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use openstack_keystone_core::oauth2_client::hydrate_client_credentials_context;
use openstack_keystone_core::oauth2_client::{build_access_token_claims, crypto, pkce};
use openstack_keystone_core::oauth2_session::{IssueRefreshTokenRequest, RefreshTokenRedemption};
use openstack_keystone_core_types::oauth2_client::{
    GrantType, IdTokenClaims, OidcAccessTokenClaims,
};
use openstack_keystone_key_repository::asymmetric::{jwt_algorithm, to_encoding_key};

use crate::api::common::PeerAddr;
use crate::audit::{
    CorrelationId, build_initiator_from_vsc, build_initiator_unknown,
    emit_oauth2_refresh_reuse_critical_event, emit_oauth2_session_event,
    emit_perimeter_authenticate_event,
};
use crate::keystone::ServiceState;

use super::well_known::base_url;

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub(super) struct TokenForm {
    #[serde(default)]
    grant_type: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    /// `authorization_code` grant only (RFC 6749 §4.1.3).
    #[serde(default)]
    code: Option<String>,
    /// `authorization_code` grant only -- must exact-match the value
    /// recorded at `/authorize`.
    #[serde(default)]
    redirect_uri: Option<String>,
    /// `authorization_code` grant only: PKCE verifier (RFC 7636 §4.5).
    #[serde(default)]
    code_verifier: Option<String>,
    /// `refresh_token` grant only (RFC 6749 §6).
    #[serde(default)]
    refresh_token: Option<String>,
    /// RFC 8693 Token Exchange grant only: the existing Keystone-native
    /// token (Fernet or JWS) being exchanged.
    #[serde(default)]
    subject_token: Option<String>,
    /// RFC 8693 Token Exchange grant only. Accepted but not branched on:
    /// this repository's `TokenApi::validate_to_context` already decodes
    /// either wire format transparently, so there is nothing for the value
    /// to select between yet.
    #[serde(default)]
    #[allow(dead_code)]
    subject_token_type: Option<String>,
    /// RFC 8693 Token Exchange grant only. Accepted but not branched on:
    /// v1 always returns `urn:ietf:params:oauth:token-type:access_token`,
    /// the only token type this grant mints.
    #[serde(default)]
    #[allow(dead_code)]
    requested_token_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    scope: String,
    /// `authorization_code` grant only.
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    /// Present when the authenticated client also holds `refresh_token` in
    /// `grant_types` (ADR 0026 §2, §9).
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
}

/// RFC 6749 §5.2 token endpoint error response.
#[derive(Debug, Serialize)]
pub(super) struct Oauth2TokenError {
    #[serde(skip)]
    status: StatusCode,
    #[serde(skip)]
    retry_after: Option<u64>,
    error: &'static str,
    error_description: String,
}

impl Oauth2TokenError {
    fn new(status: StatusCode, error: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            retry_after: None,
            error,
            error_description: description.into(),
        }
    }

    fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_client", description)
    }

    fn unauthorized_client(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "unauthorized_client", description)
    }

    fn unsupported_grant_type(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            description,
        )
    }

    fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_scope", description)
    }

    fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", description)
    }

    fn too_many_requests(retry_after: u64) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            retry_after: Some(retry_after),
            // RFC 6749 §5.2 predates 429 and has no dedicated error code for
            // rate limiting; `invalid_request` is the closest defined code
            // (malformed/unacceptable request). The `429` status + `Retry-After`
            // header are the authoritative signal for clients.
            error: "invalid_request",
            error_description: "rate limit exceeded".to_string(),
        }
    }

    fn internal(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_request",
            description,
        )
    }
}

impl IntoResponse for Oauth2TokenError {
    fn into_response(self) -> Response {
        let status = self.status;
        let retry_after = self.retry_after;
        let mut response = (status, Json(self)).into_response();
        if let Some(retry_after) = retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, retry_after.into());
        }
        response
    }
}

/// Extract `client_id`/`client_secret` via HTTP Basic (`client_secret_basic`,
/// RFC 6749 §2.3.1), falling back to the form body if no `Authorization`
/// header is present. Basic auth takes precedence when both are given, per
/// RFC 6749 §2.3.1's recommendation against accepting credentials in the
/// body when Basic is available.
fn client_credentials_from_request(
    headers: &HeaderMap,
    form: &TokenForm,
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
    form.client_id
        .clone()
        .map(|client_id| (client_id, form.client_secret.clone()))
}

/// `client_credentials` machine-to-machine grant (ADR 0026 §5, §7.A).
#[utoipa::path(
    post,
    path = "/{domain_id}/token",
    operation_id = "/oauth2:token",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = OK, description = "Access token issued"),
        (status = BAD_REQUEST, description = "Malformed request, unsupported grant, or invalid scope"),
        (status = UNAUTHORIZED, description = "Invalid client credentials"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::token",
    level = "debug",
    skip(state, form),
    err(Debug)
)]
pub(super) async fn token(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
    Form(form): Form<TokenForm>,
) -> Result<Response, Oauth2TokenError> {
    let Some(grant_type) = form.grant_type.as_deref() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: grant_type",
        ));
    };

    let oauth2_cfg = state.config_manager.config.read().await.oauth2.clone();

    match grant_type {
        "client_credentials" => {}
        "authorization_code" => {
            return handle_authorization_code_grant(
                &state,
                &domain_id,
                &headers,
                &form,
                &oauth2_cfg,
                &correlation_id.0,
            )
            .await;
        }
        "refresh_token" => {
            return handle_refresh_token_grant(
                &state,
                &domain_id,
                &headers,
                peer_addr,
                &form,
                &oauth2_cfg,
                &correlation_id.0,
            )
            .await;
        }
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            return handle_token_exchange_grant(
                &state,
                &domain_id,
                &headers,
                &form,
                &oauth2_cfg,
                &correlation_id.0,
            )
            .await;
        }
        other => {
            return Err(Oauth2TokenError::unsupported_grant_type(format!(
                "grant_type `{other}` is not supported"
            )));
        }
    }

    let Some((client_id, client_secret)) = client_credentials_from_request(&headers, &form) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: client_id",
        ));
    };

    // Step 1 (ADR 0026 §7.A "Pre-Hash Enforcement"): rate limit on the raw,
    // unverified client_id string, before any storage lookup or Argon2id
    // verification.
    if let Err(not_until) = state.oauth2_token_rate_limiter.check_key(&client_id) {
        let retry_after = not_until
            .wait_time_from(state.oauth2_token_rate_limiter.clock().now())
            .as_secs()
            .max(1);
        return Err(Oauth2TokenError::too_many_requests(retry_after));
    }

    let exec = openstack_keystone_core::auth::ExecutionContext::internal(&state);
    let client = state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&exec, &client_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 client lookup failed");
            Oauth2TokenError::internal("client lookup failed")
        })?;

    let Some(client) = client.filter(|c| c.domain_id == domain_id) else {
        // Enumeration defense (ADR 0026 §7.A / mirrors ADR 0021 Invariant
        // 7): burn the same Argon2id cost a real "found but wrong secret"
        // verification would, so a missing client_id can't be distinguished
        // from a wrong secret by response latency alone. This does NOT mask
        // the DB lookup's own variable timing (unknown client_id: fast
        // reject; known client_id: lookup + Argon2id) -- that gap is
        // accepted as defense-in-depth residual, bounded by the pre-hash
        // rate limiter above (keyed on raw client_id, checked before this
        // DB query), mirroring ADR 0021's API key posture.
        let _ = crypto::generate_dummy_hash(&oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    };

    if !client.enabled || client.deleted_at.is_some() {
        let _ = crypto::generate_dummy_hash(&oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    }

    if !client.grant_types.contains(&GrantType::ClientCredentials) {
        let _ = crypto::generate_dummy_hash(&oauth2_cfg).await;
        return Err(Oauth2TokenError::unauthorized_client(
            "client is not authorized to use the client_credentials grant",
        ));
    }

    // RFC 6749 §4.4 requires a confidential client for client_credentials --
    // a public client has no secret to verify at all.
    let Some(secret_hash) = client.client_secret_hash.as_deref() else {
        let _ = crypto::generate_dummy_hash(&oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    };
    let Some(presented_secret) = client_secret else {
        let _ = crypto::generate_dummy_hash(&oauth2_cfg).await;
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    };

    let verified = crypto::verify_secret(&presented_secret, secret_hash)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 client secret argon2 verification errored");
            Oauth2TokenError::internal("client authentication failed")
        })?;
    if !verified {
        emit_perimeter_authenticate_event(
            &state.audit_dispatcher,
            &correlation_id.0,
            build_initiator_unknown(),
            "failure",
            Some("client authentication failed".to_string()),
        );
        return Err(Oauth2TokenError::invalid_client(
            "client authentication failed",
        ));
    }

    // Scope Validation (ADR 0026 §4): requested scope must be a subset of
    // `allowed_scopes`, reject-outright, never silently narrowed. Omitted
    // scope defaults to the client's full `allowed_scopes`.
    let granted_scope: Vec<String> = match &form.scope {
        Some(requested) => {
            let requested: Vec<String> = requested.split_whitespace().map(str::to_string).collect();
            if requested
                .iter()
                .any(|s| !client.allowed_scopes.iter().any(|allowed| allowed == s))
            {
                return Err(Oauth2TokenError::invalid_scope(
                    "requested scope exceeds the client's allowed_scopes",
                ));
            }
            requested
        }
        None => client.allowed_scopes.clone(),
    };

    let (vsc, ruleset_version) = hydrate_client_credentials_context(&state, &client)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 client_credentials mapping ingress failed");
            Oauth2TokenError::invalid_client("client is not authorized for any scope")
        })?;

    let base = base_url(&state, &headers).await;
    let issuer = format!("{base}/v4/oauth2/{}", client.domain_id);
    let now = chrono::Utc::now().timestamp();
    let lifetime_seconds = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;
    let exp = now + lifetime_seconds;
    let jti = uuid::Uuid::new_v4().to_string();

    let claims = build_access_token_claims(&client, &vsc, &issuer, jti, ruleset_version, now, exp)
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 access token claim construction failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;

    let signing_key = state
        .provider
        .get_oauth2_key_provider()
        .active_signing_key(&state, &client.domain_id)
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
    let access_token = jsonwebtoken::encode(&header, &claims, &encoding_key).map_err(|e| {
        tracing::warn!(error = %e, "oauth2 access token signing failed");
        Oauth2TokenError::internal("token issuance failed")
    })?;

    emit_perimeter_authenticate_event(
        &state.audit_dispatcher,
        &correlation_id.0,
        build_initiator_from_vsc(&vsc),
        "success",
        None,
    );

    let response = TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: lifetime_seconds,
        scope: granted_scope.join(" "),
        // `client_credentials` never issues an `id_token` (no RP identity
        // display surface) or a `refresh_token` (the client re-authenticates
        // with its own credentials on every mint instead of rotating one).
        id_token: None,
        refresh_token: None,
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Sign `claims` into a compact JWS using the domain's active OAuth2
/// signing key (shared by every grant that mints a token).
async fn sign_jwt<T: Serialize>(
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

/// OIDC Core §3.2.2.10 `at_hash`: left half of `SHA-256(access_token)`,
/// base64url-encoded. Binds an `id_token` to its co-issued `access_token`.
fn compute_at_hash(access_token: &str) -> String {
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
async fn authenticate_client(
    state: &ServiceState,
    oauth2_cfg: &openstack_keystone_config::Oauth2Provider,
    domain_id: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<openstack_keystone_core_types::oauth2_client::OAuth2ClientResource, Oauth2TokenError> {
    let exec = openstack_keystone_core::auth::ExecutionContext::internal(state);
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

/// `authorization_code` grant (RFC 6749 §4.1.3, ADR 0026 §10 Phase 4).
async fn handle_authorization_code_grant(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    form: &TokenForm,
    oauth2_cfg: &openstack_keystone_config::Oauth2Provider,
    correlation_id: &str,
) -> Result<Response, Oauth2TokenError> {
    let Some((client_id, client_secret)) = client_credentials_from_request(headers, form) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: client_id",
        ));
    };
    let Some(code) = form.code.clone() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: code",
        ));
    };
    let Some(redirect_uri) = form.redirect_uri.clone() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: redirect_uri",
        ));
    };
    let Some(code_verifier) = form.code_verifier.clone() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: code_verifier",
        ));
    };

    // Step 1 (ADR 0026 §7.A): pre-hash rate limit, before any lookup.
    if let Err(not_until) = state.oauth2_token_rate_limiter.check_key(&client_id) {
        let retry_after = not_until
            .wait_time_from(state.oauth2_token_rate_limiter.clock().now())
            .as_secs()
            .max(1);
        return Err(Oauth2TokenError::too_many_requests(retry_after));
    }

    let client = authenticate_client(
        state,
        oauth2_cfg,
        domain_id,
        &client_id,
        client_secret.as_deref(),
    )
    .await?;
    if !client.grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(Oauth2TokenError::unauthorized_client(
            "client is not authorized to use the authorization_code grant",
        ));
    }

    let record = state
        .provider
        .get_oauth2_session_provider()
        .redeem_authorization_code(state, &code)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 authorization code redemption failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;
    let Some(record) = record else {
        return Err(Oauth2TokenError::invalid_grant(
            "authorization code is invalid, expired, or already redeemed",
        ));
    };

    if record.client_id != client_id
        || record.domain_id != domain_id
        || record.redirect_uri != redirect_uri
    {
        return Err(Oauth2TokenError::invalid_grant(
            "authorization code does not match this client_id/redirect_uri",
        ));
    }
    if record.code_challenge_method != "S256"
        || !pkce::verify_code_challenge(&code_verifier, &record.code_challenge)
    {
        return Err(Oauth2TokenError::invalid_grant("PKCE verification failed"));
    }

    if record.scope.iter().any(|s| s == "openstack:api") {
        // Full `OpenStackAccessTokenClaims` issuance on this grant requires
        // resolving a project/domain authorization scope for the token,
        // which the `/authorize` consent step does not yet collect in this
        // phase (its own scope validation already rejects `openstack:api`
        // outright for the same reason -- this is the token-minting side
        // of that same guard, defense in depth against ever silently
        // downgrading a client that explicitly asked for OpenStack
        // authorization data to a bare identity token).
        return Err(Oauth2TokenError::invalid_scope(
            "openstack:api on the authorization_code grant is not yet supported",
        ));
    }

    let base = base_url(state, headers).await;
    let issuer = format!("{base}/v4/oauth2/{domain_id}");
    let now = chrono::Utc::now().timestamp();
    let access_lifetime = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;
    let id_lifetime = i64::from(oauth2_cfg.id_token_lifetime_minutes) * 60;

    let access_claims = OidcAccessTokenClaims {
        iss: issuer.clone(),
        sub: record.user_id.clone(),
        aud: client_id.clone(),
        exp: now + access_lifetime,
        iat: now,
        nbf: now,
        jti: uuid::Uuid::new_v4().to_string(),
        scope: record.scope.join(" "),
        token_use: "access".to_string(),
    };
    let access_token = sign_jwt(state, domain_id, &access_claims).await?;

    let id_claims = IdTokenClaims {
        iss: issuer,
        sub: record.user_id.clone(),
        aud: client_id.clone(),
        exp: now + id_lifetime,
        iat: now,
        nbf: now,
        auth_time: record.auth_time,
        nonce: record.nonce.clone(),
        amr: record.amr.clone(),
        at_hash: Some(compute_at_hash(&access_token)),
        token_use: "id".to_string(),
        extra_claims: Default::default(),
    };
    let id_token = sign_jwt(state, domain_id, &id_claims).await?;

    let refresh_token = if client.grant_types.contains(&GrantType::RefreshToken) {
        let (_, bearer) = state
            .provider
            .get_oauth2_session_provider()
            .issue_refresh_token(
                state,
                IssueRefreshTokenRequest {
                    domain_id: domain_id.to_string(),
                    client_id: client.client_id.clone(),
                    user_id: record.user_id.clone(),
                    scope: record.scope.clone(),
                },
            )
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "oauth2 refresh token issuance failed");
                Oauth2TokenError::internal("token issuance failed")
            })?;
        Some(bearer)
    } else {
        None
    };

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        correlation_id,
        "authenticate",
        build_initiator_unknown(),
        &client.client_id,
        "success",
        None,
    );

    let response = TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: access_lifetime,
        scope: record.scope.join(" "),
        id_token: Some(id_token),
        refresh_token,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// `refresh_token` grant (RFC 6749 §6, ADR 0026 §9 rotation + reuse
/// detection).
async fn handle_refresh_token_grant(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    peer_addr: Option<std::net::SocketAddr>,
    form: &TokenForm,
    oauth2_cfg: &openstack_keystone_config::Oauth2Provider,
    correlation_id: &str,
) -> Result<Response, Oauth2TokenError> {
    let Some((client_id, client_secret)) = client_credentials_from_request(headers, form) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: client_id",
        ));
    };
    let Some(presented_refresh_token) = form.refresh_token.clone() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: refresh_token",
        ));
    };

    // Unlike `client_credentials` (where `client_id` is public per-client),
    // the refresh token bearer value is itself the secret -- rate limiting
    // only by `client_id` lets a holder of one stolen token brute-rotate it
    // at the client's full configured rate. Add the same global per-IP
    // limiter the `/authorize/login` browser path uses (§7.B) as a second,
    // independent dimension of defense.
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(headers, peer_addr.map(|a| a.ip()))
    {
        return Err(Oauth2TokenError::too_many_requests(
            retry_after.as_secs().max(1),
        ));
    }

    if let Err(not_until) = state.oauth2_token_rate_limiter.check_key(&client_id) {
        let retry_after = not_until
            .wait_time_from(state.oauth2_token_rate_limiter.clock().now())
            .as_secs()
            .max(1);
        return Err(Oauth2TokenError::too_many_requests(retry_after));
    }

    let client = authenticate_client(
        state,
        oauth2_cfg,
        domain_id,
        &client_id,
        client_secret.as_deref(),
    )
    .await?;
    if !client.grant_types.contains(&GrantType::RefreshToken) {
        return Err(Oauth2TokenError::unauthorized_client(
            "client is not authorized to use the refresh_token grant",
        ));
    }

    let redemption = state
        .provider
        .get_oauth2_session_provider()
        .redeem_refresh_token(state, &presented_refresh_token)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 refresh token redemption failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;

    let (record, bearer) = match redemption {
        RefreshTokenRedemption::Invalid => {
            return Err(Oauth2TokenError::invalid_grant(
                "refresh_token is invalid, expired, or already used",
            ));
        }
        RefreshTokenRedemption::ReuseDetected { family_id } => {
            emit_oauth2_refresh_reuse_critical_event(
                &state.audit_dispatcher,
                correlation_id,
                build_initiator_unknown(),
                &family_id,
            )
            .await;
            return Err(Oauth2TokenError::invalid_grant(
                "refresh_token has already been used; the session has been revoked",
            ));
        }
        RefreshTokenRedemption::Rotated { record, bearer } => (record, bearer),
    };

    if record.client_id != client_id || record.domain_id != domain_id {
        return Err(Oauth2TokenError::invalid_grant(
            "refresh_token does not belong to this client",
        ));
    }

    let base = base_url(state, headers).await;
    let issuer = format!("{base}/v4/oauth2/{domain_id}");
    let now = chrono::Utc::now().timestamp();
    let access_lifetime = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;

    let access_claims = OidcAccessTokenClaims {
        iss: issuer,
        sub: record.user_id.clone(),
        aud: client_id.clone(),
        exp: now + access_lifetime,
        iat: now,
        nbf: now,
        jti: uuid::Uuid::new_v4().to_string(),
        scope: record.scope.join(" "),
        token_use: "access".to_string(),
    };
    let access_token = sign_jwt(state, domain_id, &access_claims).await?;

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        correlation_id,
        "authenticate",
        build_initiator_unknown(),
        &client_id,
        "success",
        None,
    );

    let response = TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: access_lifetime,
        scope: record.scope.join(" "),
        id_token: None,
        refresh_token: Some(bearer),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// RFC 8693 Token Exchange grant (ADR 0026 §12 "v2 shape", implemented as
/// the follow-up amendment the ADR itself defers this grant's concrete
/// shape to). Trades an existing Keystone-native delegated credential
/// (trust or application credential; EC2 deferred) for a native
/// `OpenStackAccessTokenClaims`. Gating: the exchanging client must hold
/// `token-exchange` in its own `grant_types` -- SystemAdmin-only to enable,
/// mirroring `pre_authorized`'s gating (ADR 0026 §5), enforced at client
/// create/update time, not here.
async fn handle_token_exchange_grant(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    form: &TokenForm,
    oauth2_cfg: &openstack_keystone_config::Oauth2Provider,
    correlation_id: &str,
) -> Result<Response, Oauth2TokenError> {
    let Some((client_id, client_secret)) = client_credentials_from_request(headers, form) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: client_id",
        ));
    };
    let Some(subject_token) = form.subject_token.clone() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: subject_token",
        ));
    };

    // Step 1 (ADR 0026 §7.A): pre-hash rate limit, inherited by every
    // `/token` sub-path, before any lookup or subject_token validation.
    if let Err(not_until) = state.oauth2_token_rate_limiter.check_key(&client_id) {
        let retry_after = not_until
            .wait_time_from(state.oauth2_token_rate_limiter.clock().now())
            .as_secs()
            .max(1);
        return Err(Oauth2TokenError::too_many_requests(retry_after));
    }

    let client = authenticate_client(
        state,
        oauth2_cfg,
        domain_id,
        &client_id,
        client_secret.as_deref(),
    )
    .await?;
    if !client.grant_types.contains(&GrantType::TokenExchange) {
        return Err(Oauth2TokenError::unauthorized_client(
            "client is not authorized to use the token-exchange grant",
        ));
    }

    let (vsc, delegation_context) =
        openstack_keystone_core::oauth2_client::validate_subject_token(state, &subject_token)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "oauth2 token exchange subject_token rejected");
                Oauth2TokenError::invalid_grant(
                    "subject_token is invalid, expired, or carries no exchangeable delegation",
                )
            })?;

    let base = base_url(state, headers).await;
    let issuer = format!("{base}/v4/oauth2/{domain_id}");
    let now = chrono::Utc::now().timestamp();
    let access_lifetime = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;
    let jti = uuid::Uuid::new_v4().to_string();

    let claims = openstack_keystone_core::oauth2_client::build_token_exchange_claims(
        &client,
        &vsc,
        delegation_context,
        &issuer,
        jti,
        now,
        now + access_lifetime,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "oauth2 token exchange claim construction failed");
        Oauth2TokenError::internal("token issuance failed")
    })?;
    let access_token = sign_jwt(state, domain_id, &claims).await?;

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        correlation_id,
        "authenticate",
        build_initiator_from_vsc(&vsc),
        &client_id,
        "success",
        None,
    );

    let response = TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: access_lifetime,
        scope: "openstack:api".to_string(),
        id_token: None,
        refresh_token: None,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use sea_orm::DatabaseConnection;
    use serde_json::Value;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_audit::AuditDispatcher;
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core::keystone::Service;
    use openstack_keystone_core::policy::MockPolicy;
    use openstack_keystone_core_types::auth::AuthenticationResultBuilder;
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalIdentityInfoBuilder,
        PrincipalInfo, ScopeInfo,
    };
    use openstack_keystone_core_types::mapping::auth::MappingContext;
    use openstack_keystone_core_types::mapping::authorization::Authorization;
    use openstack_keystone_core_types::mapping::resolution::DomainResolutionMode;
    use openstack_keystone_core_types::mapping::resolution::IdentitySource;
    use openstack_keystone_core_types::mapping::rule::{
        IdentityBinding, MappingRule, MatchCriteria,
    };
    use openstack_keystone_core_types::mapping::ruleset::MappingRuleSet;
    use openstack_keystone_core_types::oauth2_client as provider_types;
    use openstack_keystone_core_types::role::RoleRef;
    use openstack_keystone_key_repository::asymmetric::{SigningAlgorithm, generate_keypair};

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::mapping::MockMappingProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_key::MockOauth2KeyProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    async fn confidential_client() -> provider_types::OAuth2ClientResource {
        let cfg = openstack_keystone_config::Oauth2Provider {
            argon2_memory_kib: 8,
            argon2_time_cost: 1,
            argon2_parallelism: 1,
            ..Default::default()
        };
        let hash = openstack_keystone_core::oauth2_client::crypto::hash_secret(
            &secrecy::SecretString::from("s3cr3t".to_string()),
            &cfg,
        )
        .await
        .unwrap();
        provider_types::OAuth2ClientResource {
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain-1".into(),
            client_secret_hash: Some(hash),
            redirect_uris: vec![],
            token_endpoint_auth_method: "client_secret_basic".into(),
            grant_types: vec![provider_types::GrantType::ClientCredentials],
            require_pkce: false,
            allowed_scopes: vec!["openstack:api".into()],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    fn matching_ruleset() -> MappingRuleSet {
        MappingRuleSet {
            mapping_id: "m1".to_string(),
            domain_id: Some("domain-1".to_string()),
            source: IdentitySource::OAuth2Client {
                provider_id: "provider-1".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![MappingRule {
                name: "always".to_string(),
                description: None,
                r#match: MatchCriteria::AllOf(vec![]),
                identity: IdentityBinding {
                    identity_mode: None,
                    user_name: "client-1".to_string(),
                    user_id: None,
                    user_domain_id: None,
                    is_system: false,
                },
                authorizations: vec![Authorization::Domain {
                    domain_id: "domain-1".to_string(),
                    roles: vec![RoleRef {
                        id: "role-1".to_string(),
                        name: Some("member".to_string()),
                        domain_id: None,
                    }],
                }],
                groups: vec![],
            }],
            ruleset_version: 7,
        }
    }

    fn successful_auth_result() -> openstack_keystone_core_types::auth::AuthenticationResult {
        AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Mapping(MappingContext {
                mapping_id: "m1".to_string(),
                matched_rule_name: "always".to_string(),
                virtual_user_id: "shadow-1".to_string(),
                is_system: false,
            }))
            .principal(PrincipalInfo {
                identity: IdentityInfo::Principal(
                    PrincipalIdentityInfoBuilder::default()
                        .id("shadow-1")
                        .resolved_user_name("client-1")
                        .issuer("oauth2_client:provider-1")
                        .build()
                        .unwrap(),
                ),
            })
            .authorization(
                AuthzInfoBuilder::default()
                    .scope(ScopeInfo::Domain(
                        openstack_keystone_core_types::resource::Domain {
                            id: "domain-1".to_string(),
                            name: String::new(),
                            description: None,
                            enabled: true,
                            extra: Default::default(),
                        },
                    ))
                    .roles(vec![RoleRef {
                        id: "role-1".to_string(),
                        name: Some("member".to_string()),
                        domain_id: None,
                    }])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    fn ok_key_mock() -> MockOauth2KeyProvider {
        let mut mock = MockOauth2KeyProvider::default();
        mock.expect_active_signing_key()
            .returning(|_, _| Ok(generate_keypair(SigningAlgorithm::Es256).unwrap()));
        mock
    }

    fn request(body: &str) -> Request<Body> {
        Request::builder()
            .uri("/domain-1/token")
            .method("POST")
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn json_body(response: axum::response::Response) -> Value {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn test_missing_grant_type_is_invalid_request() {
        let provider = Provider::mocked_builder();
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request("client_id=client-1&client_secret=s3cr3t"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn test_unsupported_grant_type() {
        let provider = Provider::mocked_builder();
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request("grant_type=password&client_id=client-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn test_unknown_client_id_is_invalid_client() {
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(|_, _| Ok(None));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=unknown&client_secret=x",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["error"], "invalid_client");
    }

    #[tokio::test]
    async fn test_client_without_client_credentials_grant_is_unauthorized_client() {
        let mut client = confidential_client().await;
        client.grant_types = vec![provider_types::GrantType::AuthorizationCode];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=s3cr3t",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "unauthorized_client");
    }

    #[tokio::test]
    async fn test_wrong_secret_is_invalid_client() {
        let client = confidential_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=wrong",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["error"], "invalid_client");
    }

    #[tokio::test]
    async fn test_public_client_cannot_use_client_credentials() {
        let mut client = confidential_client().await;
        client.client_secret_hash = None;
        client.require_pkce = true;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=x",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["error"], "invalid_client");
    }

    #[tokio::test]
    async fn test_scope_outside_allowed_scopes_is_invalid_scope() {
        let client = confidential_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=s3cr3t&scope=not-allowed",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_scope");
    }

    #[tokio::test]
    async fn test_successful_client_credentials_issues_signed_jwt() {
        let client = confidential_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut mapping_mock = MockMappingProvider::default();
        mapping_mock
            .expect_get_ruleset_by_source()
            .returning(|_, _, _| Ok(Some(matching_ruleset())));
        mapping_mock
            .expect_authenticate_by_mapping()
            .returning(|_, _| Ok(successful_auth_result()));

        let mut resource_mock = MockResourceProvider::default();
        resource_mock.expect_get_domain().returning(|_, _| {
            Ok(Some(openstack_keystone_core_types::resource::Domain {
                id: "domain-1".to_string(),
                name: "domain-1".to_string(),
                description: None,
                enabled: true,
                extra: Default::default(),
            }))
        });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_mapping(mapping_mock)
            .mock_resource(resource_mock)
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=client_credentials&client_id=client-1&client_secret=s3cr3t",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["token_type"], "Bearer");
        let access_token = body["access_token"].as_str().unwrap();
        // Three dot-separated JWT segments, no signature validation here
        // (that belongs to the downstream middleware's own test suite).
        assert_eq!(access_token.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_rate_limit_returns_429_before_client_lookup() {
        let config = Config {
            oauth2: openstack_keystone_config::Oauth2Provider {
                token_rate_limit_burst_size: 1,
                token_rate_limit_replenish_per_minute: 1,
                ..Default::default()
            },
            ..Config::default()
        };

        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(|_, _| Ok(None));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let client_addr: SocketAddr = "203.0.113.9:1234".parse().unwrap();
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let mut req1 = request("grant_type=client_credentials&client_id=client-1&client_secret=x");
        req1.extensions_mut().insert(ConnectInfo(client_addr));
        // First request consumes the single burst token and reaches the
        // (mocked) client lookup, which reports "not found".
        assert_eq!(
            api.as_service().oneshot(req1).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let mut req2 = request("grant_type=client_credentials&client_id=client-1&client_secret=x");
        req2.extensions_mut().insert(ConnectInfo(client_addr));
        // Second request for the same client_id, burst exhausted: rejected
        // by the rate limiter before any further client lookup or Argon2id
        // work (ADR 0026 §7.A).
        assert_eq!(
            api.as_service().oneshot(req2).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    use openstack_keystone_core::oauth2_session::RefreshTokenRedemption;
    use openstack_keystone_core_types::oauth2_session::{AuthorizationCode, RefreshToken};

    use crate::oauth2_session::MockOauth2SessionProvider;

    async fn public_authz_code_client() -> provider_types::OAuth2ClientResource {
        provider_types::OAuth2ClientResource {
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain-1".into(),
            client_secret_hash: None,
            redirect_uris: vec!["https://rp.example.com/callback".into()],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec![provider_types::GrantType::AuthorizationCode],
            require_pkce: true,
            allowed_scopes: vec!["openid".into()],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    // RFC 7636 Appendix B worked example.
    const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn sample_authz_code(scope: Vec<String>) -> AuthorizationCode {
        AuthorizationCode {
            code: "code-1".to_string(),
            domain_id: "domain-1".to_string(),
            client_id: "client-1".to_string(),
            user_id: "user-1".to_string(),
            redirect_uri: "https://rp.example.com/callback".to_string(),
            code_challenge: PKCE_CHALLENGE.to_string(),
            code_challenge_method: "S256".to_string(),
            scope,
            nonce: Some("nonce-1".to_string()),
            auth_time: 1000,
            amr: vec!["pwd".to_string()],
            created_at: 1000,
            expires_at: 1060,
        }
    }

    fn authz_code_form(code_verifier: &str) -> String {
        format!(
            "grant_type=authorization_code&client_id=client-1&code=code-1&redirect_uri=https://rp.example.com/callback&code_verifier={code_verifier}"
        )
    }

    #[tokio::test]
    async fn test_authorization_code_missing_code_is_invalid_request() {
        let provider = Provider::mocked_builder();
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request("grant_type=authorization_code&client_id=client-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn test_authorization_code_pkce_mismatch_is_invalid_grant() {
        let client = public_authz_code_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_authorization_code()
            .returning(|_, _| Ok(Some(sample_authz_code(vec!["openid".to_string()]))));

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&authz_code_form("wrong-verifier")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_authorization_code_redemption_miss_is_invalid_grant() {
        let client = public_authz_code_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_authorization_code()
            .returning(|_, _| Ok(None));

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&authz_code_form(PKCE_VERIFIER)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_authorization_code_openstack_api_scope_is_rejected() {
        let client = public_authz_code_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_authorization_code()
            .returning(|_, _| {
                Ok(Some(sample_authz_code(vec![
                    "openid".to_string(),
                    "openstack:api".to_string(),
                ])))
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&authz_code_form(PKCE_VERIFIER)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_scope");
    }

    #[tokio::test]
    async fn test_authorization_code_success_issues_id_and_access_token() {
        let client = public_authz_code_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_authorization_code()
            .returning(|_, _| Ok(Some(sample_authz_code(vec!["openid".to_string()]))));

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&authz_code_form(PKCE_VERIFIER)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["access_token"].as_str().unwrap().split('.').count(), 3);
        assert_eq!(body["id_token"].as_str().unwrap().split('.').count(), 3);
        assert!(body.get("refresh_token").is_none());
    }

    fn refresh_token_form(token: &str) -> String {
        format!("grant_type=refresh_token&client_id=client-1&refresh_token={token}")
    }

    fn sample_refresh_record(spent_at: Option<i64>) -> RefreshToken {
        RefreshToken {
            token_id: "irrelevant".to_string(),
            family_id: "family-1".to_string(),
            parent_token_id: None,
            domain_id: "domain-1".to_string(),
            client_id: "client-1".to_string(),
            user_id: "user-1".to_string(),
            scope: vec!["openid".to_string()],
            issued_at: 1000,
            spent_at,
            expires_at: 1000 + 2_592_000,
        }
    }

    #[tokio::test]
    async fn test_refresh_token_missing_param_is_invalid_request() {
        let provider = Provider::mocked_builder();
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request("grant_type=refresh_token&client_id=client-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn test_refresh_token_reuse_detected_is_invalid_grant() {
        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            provider_types::GrantType::AuthorizationCode,
            provider_types::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_refresh_token()
            .returning(|_, _| {
                Ok(RefreshTokenRedemption::ReuseDetected {
                    family_id: "family-1".to_string(),
                })
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&refresh_token_form("stolen-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_refresh_token_rotation_success() {
        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            provider_types::GrantType::AuthorizationCode,
            provider_types::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_refresh_token()
            .returning(|_, _| {
                Ok(RefreshTokenRedemption::Rotated {
                    record: sample_refresh_record(None),
                    bearer: "new-bearer-token".to_string(),
                })
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(&refresh_token_form("old-bearer-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["access_token"].as_str().unwrap().split('.').count(), 3);
        assert_eq!(body["refresh_token"], "new-bearer-token");
        assert!(body.get("id_token").is_none());
    }

    #[tokio::test]
    async fn test_refresh_token_grant_rate_limited_by_ip_before_lookup() {
        // A stolen refresh token bearer is itself the secret (unlike
        // client_credentials' public client_id) -- the global per-IP
        // limiter must reject brute-rotation attempts from one source IP
        // even before the (mocked, would otherwise always succeed) session
        // lookup runs.
        let config = Config {
            rate_limit_global_ip: openstack_keystone_config::RateLimitSection {
                enabled: true,
                burst_size: 1,
                replenish_rate_per_second: 1,
            },
            ..Config::default()
        };

        let mut client = public_authz_code_client().await;
        client.grant_types = vec![
            provider_types::GrantType::AuthorizationCode,
            provider_types::GrantType::RefreshToken,
        ];
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut session_mock = MockOauth2SessionProvider::default();
        session_mock
            .expect_redeem_refresh_token()
            .returning(|_, _| {
                Ok(RefreshTokenRedemption::Rotated {
                    record: sample_refresh_record(None),
                    bearer: "new-bearer-token".to_string(),
                })
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_oauth2_session(session_mock)
            .mock_oauth2_key(ok_key_mock())
            .build()
            .unwrap();

        let state = Arc::new(
            Service::new(
                ConfigManager::not_watched(config),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(MockPolicy::default()),
                AuditDispatcher::noop(),
                None,
            )
            .await
            .unwrap(),
        );

        let client_addr: SocketAddr = "203.0.113.9:1234".parse().unwrap();
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let mut req1 = request(&refresh_token_form("old-bearer-token"));
        req1.extensions_mut().insert(ConnectInfo(client_addr));
        assert_eq!(
            api.as_service().oneshot(req1).await.unwrap().status(),
            StatusCode::OK
        );

        let mut req2 = request(&refresh_token_form("another-bearer-token"));
        req2.extensions_mut().insert(ConnectInfo(client_addr));
        // Burst exhausted: rejected by the IP limiter regardless of which
        // (still-valid, per the mock) token is presented next.
        assert_eq!(
            api.as_service().oneshot(req2).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    async fn token_exchange_client() -> provider_types::OAuth2ClientResource {
        provider_types::OAuth2ClientResource {
            grant_types: vec![provider_types::GrantType::TokenExchange],
            ..confidential_client().await
        }
    }

    fn trust_delegated_vsc() -> openstack_keystone_core::auth::ValidatedSecurityContext {
        use openstack_keystone_core_types::identity::UserResponseBuilder;
        use openstack_keystone_core_types::resource::{Domain, Project};
        use openstack_keystone_core_types::trust::Trust;

        let user = UserResponseBuilder::default()
            .id("trustee-1")
            .domain_id("domain-1")
            .enabled(true)
            .name("trustee")
            .build()
            .unwrap();
        let authz = AuthzInfoBuilder::default()
            .roles(vec![RoleRef {
                domain_id: None,
                id: "role-1".to_string(),
                name: Some("member".to_string()),
            }])
            .scope(ScopeInfo::Project {
                project: Project {
                    id: "project-1".to_string(),
                    domain_id: "domain-1".to_string(),
                    enabled: true,
                    name: "project".to_string(),
                    ..Default::default()
                },
                project_domain: Domain {
                    id: "domain-1".to_string(),
                    name: "domain".to_string(),
                    enabled: true,
                    ..Default::default()
                },
            })
            .build()
            .unwrap();
        let sc = openstack_keystone_core_types::auth::SecurityContext::test_build()
            .authentication_context(AuthenticationContext::Trust {
                trust: Trust {
                    id: "trust-1".to_string(),
                    impersonation: false,
                    project_id: Some("project-1".to_string()),
                    trustor_user_id: "trustor-1".to_string(),
                    trustee_user_id: "trustee-1".to_string(),
                    ..Default::default()
                },
                token: None,
            })
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    openstack_keystone_core_types::auth::UserIdentityInfoBuilder::default()
                        .user_id("trustee-1")
                        .user(user)
                        .user_domain(Domain {
                            id: "domain-1".to_string(),
                            name: "domain".to_string(),
                            enabled: true,
                            ..Default::default()
                        })
                        .build()
                        .unwrap(),
                ),
            })
            .authorization(authz)
            .build();
        openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
    }

    #[tokio::test]
    async fn test_token_exchange_success_issues_signed_jwt_with_trust_delegation() {
        let client = token_exchange_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut token_mock = crate::token::MockTokenProvider::default();
        token_mock
            .expect_validate_to_context()
            .returning(|_, _, _, _| Ok(trust_delegated_vsc()));

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_token(token_mock)
            .mock_oauth2_key(ok_key_mock());
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=client-1&client_secret=s3cr3t&subject_token=some-existing-token",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["token_type"], "Bearer");
        let access_token = body["access_token"].as_str().unwrap();
        assert_eq!(access_token.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_token_exchange_missing_subject_token_is_invalid_request() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=client-1&client_secret=s3cr3t",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn test_token_exchange_client_without_grant_is_unauthorized() {
        // `confidential_client()` only holds `ClientCredentials`, not
        // `TokenExchange`.
        let client = confidential_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let provider = Provider::mocked_builder().mock_oauth2_client(client_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=client-1&client_secret=s3cr3t&subject_token=x",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "unauthorized_client");
    }

    #[tokio::test]
    async fn test_token_exchange_rejects_non_delegated_subject_token() {
        let client = token_exchange_client().await;
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut token_mock = crate::token::MockTokenProvider::default();
        token_mock
            .expect_validate_to_context()
            .returning(|_, _, _, _| {
                let sc = openstack_keystone_core_types::auth::SecurityContext::test_build()
                    .authentication_context(AuthenticationContext::Password)
                    .principal(PrincipalInfo {
                        identity: IdentityInfo::User(
                            openstack_keystone_core_types::auth::UserIdentityInfoBuilder::default()
                                .user_id("user-1")
                                .build()
                                .unwrap(),
                        ),
                    })
                    .authorization(
                        AuthzInfoBuilder::default()
                            .roles(vec![])
                            .scope(ScopeInfo::Unscoped)
                            .build()
                            .unwrap(),
                    )
                    .build();
                Ok(openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc))
            });

        let provider = Provider::mocked_builder()
            .mock_oauth2_client(client_mock)
            .mock_token(token_mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&client_id=client-1&client_secret=s3cr3t&subject_token=a-password-authenticated-token",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");
    }
}
