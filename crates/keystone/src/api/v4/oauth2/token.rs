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

mod authorization_code;
mod client_credentials;
mod common;
mod device_code;
mod error;
mod refresh_token;
#[cfg(test)]
pub(super) mod test_fixtures;
mod token_exchange;

use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use serde::{Deserialize, Serialize};

use crate::api::common::PeerAddr;
use crate::audit::CorrelationId;
use crate::keystone::ServiceState;

use authorization_code::handle_authorization_code_grant;
use client_credentials::handle_client_credentials_grant;
pub(super) use common::{authenticate_client, client_credentials_from_parts};
use device_code::handle_device_code_grant;
pub(super) use error::Oauth2TokenError;
use refresh_token::handle_refresh_token_grant;
use token_exchange::handle_token_exchange_grant;

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
    /// RFC 8628 `device_code` grant only (§3.4): the value returned by
    /// `/device_authorization`.
    #[serde(default)]
    device_code: Option<String>,
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

/// Token endpoint: dispatches on `grant_type` (ADR 0026 §5).
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
        "client_credentials" => {
            handle_client_credentials_grant(
                &state,
                &domain_id,
                &headers,
                &form,
                &oauth2_cfg,
                &correlation_id.0,
            )
            .await
        }
        "authorization_code" => {
            handle_authorization_code_grant(
                &state,
                &domain_id,
                &headers,
                &form,
                &oauth2_cfg,
                &correlation_id.0,
            )
            .await
        }
        "refresh_token" => {
            handle_refresh_token_grant(
                &state,
                &domain_id,
                &headers,
                peer_addr,
                &form,
                &oauth2_cfg,
                &correlation_id.0,
            )
            .await
        }
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            handle_token_exchange_grant(
                &state,
                &domain_id,
                &headers,
                &form,
                &oauth2_cfg,
                &correlation_id.0,
            )
            .await
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            handle_device_code_grant(
                &state,
                &domain_id,
                &headers,
                &form,
                &oauth2_cfg,
                &correlation_id.0,
            )
            .await
        }
        other => Err(Oauth2TokenError::unsupported_grant_type(format!(
            "grant_type `{other}` is not supported"
        ))),
    }
}

#[cfg(test)]
mod tests {

    use axum::http::StatusCode;

    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use crate::api::tests::get_mocked_state;
    use crate::api::v4::oauth2::openapi_router;
    use crate::api::v4::oauth2::token::test_fixtures::{json_body, request};

    use crate::provider::Provider;

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
}
