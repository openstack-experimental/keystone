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
pub(super) use common::sign_jwt_typed;
mod device_code;
mod dpop;
mod error;
mod exchange_request;
mod on_behalf_of;
mod refresh_token;
mod service_grant;
#[cfg(test)]
pub(super) mod test_fixtures;
mod token_exchange;

use axum::{
    Extension,
    body::Bytes,
    extract::{FromRequest, Path, Request, State},
    http::{HeaderMap, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use openstack_keystone_config::Interface;
use openstack_keystone_core::common::SpiffeId;

use crate::api::common::PeerAddr;
use crate::audit::CorrelationId;
use crate::keystone::ServiceState;
use openstack_keystone_core::oauth2_metrics::{OAUTH2_METRICS, grant_type_label};

use super::html::no_store;
use super::well_known::ensure_trusted_issuer;

use authorization_code::handle_authorization_code_grant;
use client_credentials::handle_client_credentials_grant;
use common::client_credentials_from_request;
pub(super) use common::{
    authenticate_client, client_credentials_from_parts, validate_device_code_client,
};
use device_code::handle_device_code_grant;
pub(super) use error::Oauth2TokenError;
use on_behalf_of::handle_on_behalf_of_grant;
use refresh_token::handle_refresh_token_grant;
use service_grant::{SERVICE_GRANT_GRANT_TYPE, handle_service_grant_grant};
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
    /// RFC 8693 subject type: access_token, Keystone-native, or native JWT.
    #[serde(default)]
    subject_token_type: Option<String>,
    /// RFC 8693 requested output type; only access_token is supported.
    #[serde(default)]
    requested_token_type: Option<String>,
    /// Actor-token delegation is not implemented; reject even empty values.
    #[serde(default)]
    actor_token: Option<String>,
    #[serde(default)]
    actor_token_type: Option<String>,
    /// Repeated RFC 8693 resources, extracted alongside audience below.
    #[serde(skip)]
    resource: Vec<String>,
    /// RFC 8628 `device_code` grant only (§3.4): the value returned by
    /// `/device_authorization`.
    #[serde(default)]
    device_code: Option<String>,
    /// Service grant redemption only (ADR 0036 §5.1): the grant to redeem.
    #[serde(default)]
    grant_id: Option<String>,
    /// Service grant redemption only: space-separated role ids narrowing
    /// the grant's roles.
    #[serde(default)]
    roles: Option<String>,
    /// RFC 8693 Token Exchange grant only (§2.1): OpenStack service types the
    /// minted token is narrowed to (ADR 0036 §7.1). The parameter may repeat,
    /// which `serde_urlencoded` cannot map onto a field, so [`TokenRequest`]
    /// fills this in from the raw body.
    #[serde(skip)]
    audience: Vec<String>,
}

/// Extractor for the token endpoint body: an
/// `application/x-www-form-urlencoded` [`TokenForm`], plus every repeated
/// `audience` parameter (RFC 8693 §2.1) that `Form` would reject as a
/// duplicate field.
pub(super) struct TokenRequest(TokenForm);

impl<S: Send + Sync> FromRequest<S> for TokenRequest {
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let is_form = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';').next().is_some_and(|m| {
                    m.trim()
                        .eq_ignore_ascii_case("application/x-www-form-urlencoded")
                })
            });
        if !is_form {
            return Err(Oauth2TokenError::invalid_request(
                "content type must be application/x-www-form-urlencoded",
            )
            .into_response());
        }
        let body = Bytes::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let mut form: TokenForm = serde_urlencoded::from_bytes(&body).map_err(|_| {
            Oauth2TokenError::invalid_request("malformed form body").into_response()
        })?;
        let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(&body).map_err(|_| {
            Oauth2TokenError::invalid_request("malformed form body").into_response()
        })?;
        for (key, value) in pairs {
            match key.as_str() {
                "audience" => form.audience.push(value),
                "resource" => form.resource.push(value),
                _ => {}
            }
        }
        Ok(Self(form))
    }
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    /// Required for RFC 8693 exchanges, absent on other grants.
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_token_type: Option<&'static str>,
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
        (status = SERVICE_UNAVAILABLE, description = "`public_endpoint` is not configured"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::token",
    level = "debug",
    skip(state, form, svid),
    err(Debug)
)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn token(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
    interface: Option<Extension<Interface>>,
    svid: Option<Extension<SpiffeId>>,
    TokenRequest(form): TokenRequest,
) -> Result<Response, Oauth2TokenError> {
    let started = std::time::Instant::now();
    if let Err(e) = ensure_trusted_issuer(&state).await {
        record_token_metrics(&domain_id, "", started, Some(&e));
        return Err(e);
    }

    let Some(grant_type) = form.grant_type.as_deref() else {
        let e = Oauth2TokenError::invalid_request("missing required parameter: grant_type");
        record_token_metrics(&domain_id, "", started, Some(&e));
        return Err(e);
    };

    let oauth2_cfg = state.config_manager.config.read().await.oauth2.clone();

    // A service that authenticated with its SVID on the internal interface
    // and presents no secret exchanges on behalf of a user (ADR 0036 §6);
    // every other caller keeps the secret-authenticated exchange of a
    // delegated credential.
    let on_behalf_of_svid = svid.as_ref().filter(|_| {
        grant_type == "urn:ietf:params:oauth:grant-type:token-exchange"
            && interface
                .as_ref()
                .is_some_and(|Extension(i)| *i == Interface::Internal)
            && client_credentials_from_request(&headers, &form)
                .is_none_or(|(_, secret)| secret.is_none())
    });
    let result = if let Some(Extension(svid)) = on_behalf_of_svid {
        handle_on_behalf_of_grant(
            &state,
            &domain_id,
            &headers,
            &form,
            &oauth2_cfg,
            &correlation_id.0,
            svid,
        )
        .await
    } else {
        match grant_type {
            "client_credentials" => {
                handle_client_credentials_grant(
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
            "authorization_code" => {
                handle_authorization_code_grant(
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
                    peer_addr,
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
                    peer_addr,
                    &form,
                    &oauth2_cfg,
                    &correlation_id.0,
                )
                .await
            }
            SERVICE_GRANT_GRANT_TYPE => {
                handle_service_grant_grant(
                    &state,
                    &domain_id,
                    &headers,
                    &form,
                    &oauth2_cfg,
                    &correlation_id.0,
                    interface.map_or(Interface::Public, |Extension(i)| i),
                    svid.as_ref().map(|Extension(s)| s),
                )
                .await
            }
            other => Err(Oauth2TokenError::unsupported_grant_type(format!(
                "grant_type `{other}` is not supported"
            ))),
        }
    };
    record_token_metrics(&domain_id, grant_type, started, result.as_ref().err());
    result.map(no_store)
}

/// Record the `/token` outcome and latency series (and, for the device code
/// grant, the poll outcome).
fn record_token_metrics(
    domain_id: &str,
    grant_type: &str,
    started: std::time::Instant,
    err: Option<&Oauth2TokenError>,
) {
    // `/token` is unauthenticated and `domain_id` is an arbitrary path
    // segment: only a successful grant proves the domain exists, so only
    // then it may become a label value.
    let domain_label = if err.is_none() {
        domain_id
    } else {
        UNKNOWN_DOMAIN_LABEL
    };
    OAUTH2_METRICS.record_token_request(domain_label, grant_type, token_outcome(err));
    OAUTH2_METRICS.record_token_duration(grant_type, started.elapsed().as_secs_f64());
    if grant_type_label(grant_type) == "device_code" {
        OAUTH2_METRICS.record_device_poll(device_poll_outcome(err));
    }
}

/// `domain_id` label value used for `/token` requests that did not succeed.
const UNKNOWN_DOMAIN_LABEL: &str = "unknown";

/// Map a `/token` result to a fixed `outcome` label value.
fn token_outcome(err: Option<&Oauth2TokenError>) -> &'static str {
    match err {
        None => "success",
        Some(e) if e.status() == axum::http::StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        Some(e) => match e.error_code() {
            "invalid_client" => "invalid_client",
            "invalid_grant" => "invalid_grant",
            "invalid_scope" => "invalid_scope",
            _ => "error",
        },
    }
}

/// Map a device code grant result to a fixed device poll `outcome` label
/// value.
fn device_poll_outcome(err: Option<&Oauth2TokenError>) -> &'static str {
    match err.map(Oauth2TokenError::error_code) {
        None => "authorized",
        Some("authorization_pending") => "pending",
        Some("slow_down") => "slow_down",
        Some("access_denied") => "denied",
        Some("expired_token") => "expired",
        Some(_) => "invalid",
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
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["pragma"], "no-cache");
        assert_eq!(json_body(response).await["error"], "invalid_request");
    }

    /// Without `public_endpoint` (and without the dev override) the issuer
    /// cannot be pinned, so `/token` refuses to serve.
    #[tokio::test]
    async fn test_unset_public_endpoint_is_service_unavailable() {
        let state = crate::api::tests::get_mocked_state_with_config(
            Provider::mocked_builder(),
            true,
            None,
            openstack_keystone_config::Config::default(),
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request("grant_type=client_credentials&client_id=client-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(json_body(response).await["error"], "server_error");
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

    #[test]
    fn test_token_outcome() {
        use super::{Oauth2TokenError, token_outcome};

        assert_eq!(token_outcome(None), "success");
        assert_eq!(
            token_outcome(Some(&Oauth2TokenError::too_many_requests(1))),
            "rate_limited"
        );
        assert_eq!(
            token_outcome(Some(&Oauth2TokenError::invalid_client("x"))),
            "invalid_client"
        );
        assert_eq!(
            token_outcome(Some(&Oauth2TokenError::invalid_grant("x"))),
            "invalid_grant"
        );
        assert_eq!(
            token_outcome(Some(&Oauth2TokenError::invalid_scope("x"))),
            "invalid_scope"
        );
        assert_eq!(
            token_outcome(Some(&Oauth2TokenError::invalid_request("x"))),
            "error"
        );
    }

    #[test]
    fn test_device_poll_outcome() {
        use super::{Oauth2TokenError, device_poll_outcome};

        assert_eq!(device_poll_outcome(None), "authorized");
        assert_eq!(
            device_poll_outcome(Some(&Oauth2TokenError::authorization_pending())),
            "pending"
        );
        assert_eq!(
            device_poll_outcome(Some(&Oauth2TokenError::slow_down())),
            "slow_down"
        );
        assert_eq!(
            device_poll_outcome(Some(&Oauth2TokenError::access_denied())),
            "denied"
        );
        assert_eq!(
            device_poll_outcome(Some(&Oauth2TokenError::expired_token())),
            "expired"
        );
        assert_eq!(
            device_poll_outcome(Some(&Oauth2TokenError::invalid_grant("x"))),
            "invalid"
        );
    }
}
