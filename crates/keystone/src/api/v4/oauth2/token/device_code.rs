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
//! RFC 8628 `device_code` grant.

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use cadf::Outcome;
use openstack_keystone_core::oauth2_client::{IdTokenParams, TemplateScope, build_id_token_claims};
use openstack_keystone_core::oauth2_session::{DevicePollOutcome, IssueRefreshTokenRequest};
use openstack_keystone_core_types::oauth2_client::{GrantType, OidcAccessTokenClaims};

use crate::audit::{build_initiator_unknown, emit_oauth2_session_event};
use crate::keystone::ServiceState;

use super::common::*;
use super::{Oauth2TokenError, TokenForm, TokenResponse};
use crate::api::v4::oauth2::well_known::base_url;

/// RFC 8628 Device Authorization Grant polling arm (§3.4, §3.5, ADR 0026
/// §7.C). `client_id` is accepted but not authenticated against a
/// `client_secret` -- device flow clients are overwhelmingly public/native
/// applications, matching `/device_authorization`'s own posture. The
/// `client_id` mismatch check happens inside `poll_device_code_grant`
/// (same bug class as the cross-domain Token Exchange forgery this ADR's
/// implementation previously fixed: a grant must only ever be redeemable by
/// the client it was issued to).
pub(super) async fn handle_device_code_grant(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    form: &TokenForm,
    oauth2_cfg: &openstack_keystone_config::Oauth2Provider,
    correlation_id: &str,
) -> Result<Response, Oauth2TokenError> {
    let Some((client_id, _)) = client_credentials_from_request(headers, form) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: client_id",
        ));
    };
    let Some(device_code) = form.device_code.clone() else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: device_code",
        ));
    };

    let outcome = state
        .provider
        .get_oauth2_session_provider()
        .poll_device_code_grant(state, &device_code, &client_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 device code grant poll failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;

    let record = match outcome {
        DevicePollOutcome::InvalidGrant => {
            return Err(Oauth2TokenError::invalid_grant(
                "device_code is invalid or does not belong to this client_id",
            ));
        }
        DevicePollOutcome::Expired => return Err(Oauth2TokenError::expired_token()),
        DevicePollOutcome::SlowDown => return Err(Oauth2TokenError::slow_down()),
        DevicePollOutcome::Pending => return Err(Oauth2TokenError::authorization_pending()),
        DevicePollOutcome::Denied => return Err(Oauth2TokenError::access_denied()),
        DevicePollOutcome::Authorized(record) => record,
    };

    let (Some(user_id), Some(auth_time)) = (record.user_id.clone(), record.auth_time) else {
        tracing::warn!("oauth2 device code grant authorized without user_id/auth_time");
        return Err(Oauth2TokenError::internal("token issuance failed"));
    };

    let exec = openstack_keystone_core::auth::ExecutionContext::internal(state);
    let client = state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&exec, &client_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 client lookup failed");
            Oauth2TokenError::internal("token issuance failed")
        })?;
    let Some(client) = client else {
        return Err(Oauth2TokenError::invalid_client("unknown client"));
    };

    let base = base_url(state, headers).await;
    let issuer = format!("{base}/v4/oauth2/{domain_id}");
    let now = chrono::Utc::now().timestamp();
    let access_lifetime = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;
    let id_lifetime = i64::from(oauth2_cfg.id_token_lifetime_minutes) * 60;

    // Issued before the access token so the token can carry the session id
    // (`sid`) of its refresh family for RFC 7009 revocation.
    let (sid, refresh_token) = if client.grant_types.contains(&GrantType::RefreshToken) {
        let (record_rt, bearer) = state
            .provider
            .get_oauth2_session_provider()
            .issue_refresh_token(
                state,
                IssueRefreshTokenRequest {
                    domain_id: domain_id.to_string(),
                    client_id: client.client_id.clone(),
                    user_id: user_id.clone(),
                    scope: record.scope.clone(),
                },
            )
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "oauth2 refresh token issuance failed");
                Oauth2TokenError::internal("token issuance failed")
            })?;
        (Some(record_rt.family_id), Some(bearer))
    } else {
        (None, None)
    };

    let signed = async {
        let access_claims = OidcAccessTokenClaims {
            iss: issuer.clone(),
            sub: user_id.clone(),
            aud: client_id.clone(),
            exp: now + access_lifetime,
            iat: now,
            nbf: now,
            jti: uuid::Uuid::new_v4().to_string(),
            scope: record.scope.join(" "),
            token_use: "access".to_string(),
            sid: sid.clone(),
        };
        let access_token = sign_jwt(state, domain_id, &access_claims).await?;

        let id_token = if record.scope.iter().any(|s| s == "openid") {
            let id_claims = build_id_token_claims(
                state,
                &client,
                IdTokenParams {
                    issuer,
                    user_id: user_id.clone(),
                    client_id: client_id.clone(),
                    now,
                    lifetime: id_lifetime,
                    auth_time,
                    nonce: record.nonce.clone(),
                    amr: record.amr.clone(),
                    at_hash: Some(compute_at_hash(&access_token)),
                },
                &record.scope,
                &TemplateScope::default(),
            )
            .await
            .map_err(id_token_error)?;
            Some(sign_jwt(state, domain_id, &id_claims).await?)
        } else {
            None
        };
        Ok::<_, Oauth2TokenError>((access_token, id_token))
    }
    .await;
    let (access_token, id_token) = match signed {
        Ok(tokens) => tokens,
        Err(e) => {
            discard_refresh_family(state, sid.as_deref()).await;
            return Err(e);
        }
    };

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        correlation_id,
        "authenticate",
        build_initiator_unknown(),
        &client_id,
        Outcome::Success,
        None,
    );

    let response = TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: access_lifetime,
        scope: record.scope.join(" "),
        id_token,
        refresh_token,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}
