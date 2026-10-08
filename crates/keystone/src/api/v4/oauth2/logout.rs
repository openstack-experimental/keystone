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
//! `GET|POST /v4/oauth2/{domain_id}/logout`: OIDC RP-Initiated Logout 1.0.
//!
//! Ends the browser's SSO session. A request carrying a valid
//! `id_token_hint` logs out at once; without one the user is asked to
//! confirm, so a link on another site cannot sign them out silently.
//!
//! The redirect to `post_logout_redirect_uri` happens only when the URI is
//! registered on the client (`post_logout_redirect_uris`), exact match, and
//! the client is identified by a verified `id_token_hint` or `client_id`. A
//! request that fails any check renders an error page and changes nothing.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use cadf::Outcome;
use serde::{Deserialize, Serialize};

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_client::verify_id_token_hint;
use openstack_keystone_core_types::oauth2_client::{IdTokenClaims, OAuth2ClientResource};
use openstack_keystone_core_types::oauth2_key::Oauth2KeyProviderError;
use openstack_keystone_key_repository::asymmetric::SigningAlgorithm;

use super::authorize::{cookie_secure, redirect_with_params};
use super::html::{error_page, logout_page, too_many_requests};
use super::renderer::LogoutCtx;
use super::sso::{SSO_COOKIE_NAME, clear_cookie};
use crate::api::common::PeerAddr;
use crate::api::v4::oauth2::well_known::base_url;
use crate::audit::{
    CorrelationId, build_initiator_from_user_id, build_initiator_unknown, emit_oauth2_session_event,
};
use crate::keystone::ServiceState;

/// Request parameters, from the query (`GET`) or the form (`POST`).
#[derive(Debug, Default, Clone, Deserialize, Serialize, utoipa::ToSchema, utoipa::IntoParams)]
pub(super) struct LogoutParams {
    /// An `id_token` this provider issued earlier for the user.
    #[serde(default)]
    id_token_hint: Option<String>,
    /// Where to send the browser afterwards; must be registered on the client.
    #[serde(default)]
    post_logout_redirect_uri: Option<String>,
    /// Echoed on the redirect.
    #[serde(default)]
    state: Option<String>,
    /// The client, when no `id_token_hint` is sent.
    #[serde(default)]
    client_id: Option<String>,
}

const BAD_HINT: &str = "invalid id_token_hint";

/// `GET /v4/oauth2/{domain_id}/logout`.
#[utoipa::path(
    get,
    path = "/{domain_id}/logout",
    operation_id = "/oauth2:logout",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
        LogoutParams,
    ),
    responses(
        (status = OK, description = "Confirmation or signed-out page", content_type = "text/html"),
        (status = SEE_OTHER, description = "Redirect to the registered post_logout_redirect_uri"),
        (status = BAD_REQUEST, description = "Invalid id_token_hint, unknown client or unregistered redirect URI"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::logout",
    level = "debug",
    skip(state, params),
    err(Debug)
)]
pub(super) async fn logout(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
    jar: CookieJar,
    Query(params): Query<LogoutParams>,
) -> Result<Response, std::convert::Infallible> {
    Ok(logout_inner(
        &state,
        &headers,
        peer_addr,
        &domain_id,
        &jar,
        params,
        false,
        &correlation_id.0,
    )
    .await)
}

/// `POST /v4/oauth2/{domain_id}/logout`.
#[utoipa::path(
    post,
    path = "/{domain_id}/logout",
    operation_id = "/oauth2:logout_post",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    request_body(content = LogoutParams, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = OK, description = "Signed-out page", content_type = "text/html"),
        (status = SEE_OTHER, description = "Redirect to the registered post_logout_redirect_uri"),
        (status = BAD_REQUEST, description = "Invalid id_token_hint, unknown client or unregistered redirect URI"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::logout_post",
    level = "debug",
    skip(state, params),
    err(Debug)
)]
pub(super) async fn logout_post(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
    jar: CookieJar,
    Form(params): Form<LogoutParams>,
) -> Result<Response, std::convert::Infallible> {
    Ok(logout_inner(
        &state,
        &headers,
        peer_addr,
        &domain_id,
        &jar,
        params,
        true,
        &correlation_id.0,
    )
    .await)
}

/// Verify `id_token_hint` against the domain's keys.
#[allow(clippy::result_large_err)] // `Response` is the early-return error
async fn verify_hint(
    state: &ServiceState,
    headers: &HeaderMap,
    domain_id: &str,
    token: &str,
) -> Result<IdTokenClaims, Response> {
    let bad = || error_page(StatusCode::BAD_REQUEST, BAD_HINT);
    let jwks = match state
        .provider
        .get_oauth2_key_provider()
        .jwks(state, domain_id)
        .await
    {
        Ok(jwks) => jwks,
        Err(Oauth2KeyProviderError::NotFound(_)) => return Err(bad()),
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 logout: jwks lookup failed");
            return Err(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };
    let algorithm = match state
        .config_manager
        .config
        .read()
        .await
        .oauth2
        .signing_algorithm
    {
        openstack_keystone_config::SigningAlgorithm::Es256 => SigningAlgorithm::Es256,
        openstack_keystone_config::SigningAlgorithm::Rs256 => SigningAlgorithm::Rs256,
    };
    let issuer = format!("{}/v4/oauth2/{domain_id}", base_url(state, headers).await);
    verify_id_token_hint(token, &jwks, algorithm, &[issuer]).map_err(|e| {
        tracing::debug!(error = %e, "oauth2 logout: id_token_hint rejected");
        bad()
    })
}

#[allow(clippy::result_large_err)] // `Response` is the early-return error
async fn find_client(
    state: &ServiceState,
    domain_id: &str,
    client_id: &str,
) -> Result<OAuth2ClientResource, Response> {
    let unknown = || error_page(StatusCode::BAD_REQUEST, "unknown client");
    state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&ExecutionContext::internal(state), client_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 logout: client lookup failed");
            error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        })?
        .filter(|c| c.domain_id == domain_id && c.deleted_at.is_none())
        .ok_or_else(unknown)
}

#[allow(clippy::too_many_arguments)]
async fn logout_inner(
    state: &ServiceState,
    headers: &HeaderMap,
    peer_addr: Option<std::net::SocketAddr>,
    domain_id: &str,
    jar: &CookieJar,
    params: LogoutParams,
    confirmed: bool,
    correlation_id: &str,
) -> Response {
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(headers, peer_addr.map(|a| a.ip()))
    {
        return too_many_requests(retry_after.as_secs());
    }
    if !crate::api::common::oauth2_issuer_is_trusted(state).await {
        return error_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "the OAuth2 provider is not configured with a public endpoint",
        );
    }

    let hint = match params
        .id_token_hint
        .as_deref()
        .filter(|token| !token.is_empty())
    {
        Some(token) => match verify_hint(state, headers, domain_id, token).await {
            Ok(claims) => Some(claims),
            Err(response) => return response,
        },
        None => None,
    };

    // The client comes from the verified hint or from `client_id`; when
    // both are present they must agree.
    let client_id = match (
        hint.as_ref().map(|h| h.aud.as_str()),
        params.client_id.as_deref().filter(|c| !c.is_empty()),
    ) {
        (Some(aud), Some(client_id)) if aud != client_id => {
            return error_page(StatusCode::BAD_REQUEST, "client_id does not match the hint");
        }
        (Some(aud), _) => Some(aud.to_string()),
        (None, client_id) => client_id.map(str::to_string),
    };
    let client = match &client_id {
        Some(client_id) => match find_client(state, domain_id, client_id).await {
            Ok(c) => Some(c),
            Err(response) => return response,
        },
        None => None,
    };

    // Never redirect anywhere that is not registered on the client.
    let redirect = match params
        .post_logout_redirect_uri
        .as_deref()
        .filter(|u| !u.is_empty())
    {
        None => None,
        Some(uri) => match &client {
            Some(c) if c.enabled && c.post_logout_redirect_uris.iter().any(|u| u == uri) => {
                Some(uri.to_string())
            }
            _ => {
                return error_page(
                    StatusCode::BAD_REQUEST,
                    "post_logout_redirect_uri is not registered for this client",
                );
            }
        },
    };

    let provider = state.provider.get_oauth2_session_provider();
    let sso_cookie = jar.get(SSO_COOKIE_NAME).map(|c| c.value().to_string());
    let sso = match &sso_cookie {
        Some(id) => match provider.get_sso_session(state, id).await {
            Ok(session) => session.filter(|s| s.domain_id == domain_id),
            Err(e) => {
                tracing::warn!(error = %e, "oauth2 logout: SSO session lookup failed");
                return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
            }
        },
        None => None,
    };

    // A hint for another user must not end this user's session.
    if let (Some(hint), Some(sso)) = (&hint, &sso)
        && hint.sub != sso.user_id
    {
        return error_page(
            StatusCode::BAD_REQUEST,
            "id_token_hint does not match the signed-in user",
        );
    }

    // Without a hint, ask first: the request may come from any page.
    if sso.is_some() && hint.is_none() && !confirmed {
        let fields = [
            ("post_logout_redirect_uri", &params.post_logout_redirect_uri),
            ("state", &params.state),
            ("client_id", &params.client_id),
        ]
        .into_iter()
        .filter_map(|(name, value)| {
            value
                .as_ref()
                .filter(|v| !v.is_empty())
                .map(|v| (name.to_string(), v.clone()))
        })
        .collect();
        return logout_page(&LogoutCtx {
            confirm: true,
            action: format!("/v4/oauth2/{domain_id}/logout"),
            fields,
        });
    }

    if let Some(sso) = &sso
        && let Err(e) = provider.delete_sso_session(state, &sso.sso_id).await
    {
        tracing::warn!(error = %e, "oauth2 logout: SSO session could not be ended");
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        correlation_id,
        "logout",
        sso.as_ref().map_or_else(build_initiator_unknown, |s| {
            build_initiator_from_user_id(&s.user_id, domain_id)
        }),
        client_id.as_deref().unwrap_or_default(),
        Outcome::Success,
        None,
    );

    let response = match redirect {
        Some(uri) => {
            redirect_with_params(&uri, &[("state", params.state.as_deref().unwrap_or(""))])
        }
        None => logout_page(&LogoutCtx {
            confirm: false,
            action: String::new(),
            fields: Vec::new(),
        }),
    };
    let clear = clear_cookie(cookie_secure(state, headers).await);
    (CookieJar::new().add(clear), response).into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::oauth2_client::{GrantType, OAuth2ClientResource};
    use openstack_keystone_core_types::oauth2_session::SsoSession;

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state_with_config;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    fn client() -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain-1".into(),
            client_secret_hash: None,
            redirect_uris: vec!["https://rp.example.com/callback".into()],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec![GrantType::AuthorizationCode],
            require_pkce: true,
            allowed_scopes: vec!["openid".into()],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
            name: "Example App".into(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
            post_logout_redirect_uris: vec!["https://rp.example.com/bye".into()],
        }
    }

    fn sso(domain: &str) -> SsoSession {
        SsoSession {
            sso_id: "sso-1".into(),
            domain_id: domain.into(),
            user_id: "user-1".into(),
            auth_time: 0,
            amr: vec![],
            upstream: None,
            created_at: 0,
            expires_at: i64::MAX,
        }
    }

    async fn router(sessions: MockOauth2SessionProvider) -> axum::Router {
        router_with_keys(sessions, Default::default()).await
    }

    async fn router_with_keys(
        sessions: MockOauth2SessionProvider,
        keys: crate::oauth2_key::MockOauth2KeyProvider,
    ) -> axum::Router {
        let mut clients = MockOauth2ClientProvider::default();
        clients
            .expect_get_by_client_id()
            .returning(|_, id| Ok((id == "client-1").then(client)));
        let mut config = Config::default();
        config.oauth2.allow_host_header_issuer = true;
        let state = get_mocked_state_with_config(
            Provider::mocked_builder()
                .mock_oauth2_session(sessions)
                .mock_oauth2_key(keys)
                .mock_oauth2_client(clients),
            true,
            None,
            config,
        )
        .await;
        let (router, _) = openapi_router().split_for_parts();
        router.with_state(state)
    }

    fn sessions_with_sso(delete_times: usize) -> MockOauth2SessionProvider {
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_get_sso_session()
            .returning(|_, _| Ok(Some(sso("domain-1"))));
        sessions
            .expect_delete_sso_session()
            .times(delete_times)
            .returning(|_, _| Ok(()));
        sessions
    }

    fn get(query: &str, cookie: bool) -> Request<Body> {
        let mut b = Request::builder().uri(format!("/domain-1/logout?{query}"));
        if cookie {
            b = b.header(header::COOKIE, "keystone_oauth2_sso=sso-1");
        }
        b.body(Body::empty()).unwrap()
    }

    fn post(form: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/domain-1/logout")
            .header(header::COOKIE, "keystone_oauth2_sso=sso-1")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form.to_string()))
            .unwrap()
    }

    async fn text(response: axum::response::Response) -> String {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn test_unregistered_redirect_is_rejected_and_nothing_is_ended() {
        let response = router(sessions_with_sso(0))
            .await
            .oneshot(get(
                "client_id=client-1&post_logout_redirect_uri=https://evil.example.com/",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::LOCATION).is_none());
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn test_redirect_without_a_client_is_rejected() {
        let response = router(sessions_with_sso(0))
            .await
            .oneshot(get(
                "post_logout_redirect_uri=https://rp.example.com/bye",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_unknown_client_is_rejected() {
        let response = router(sessions_with_sso(0))
            .await
            .oneshot(get("client_id=nope", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_malformed_hint_is_rejected_and_nothing_is_ended() {
        let mut keys = crate::oauth2_key::MockOauth2KeyProvider::default();
        keys.expect_jwks().returning(|_, _| {
            Err(crate::oauth2_key::Oauth2KeyProviderError::NotFound(
                "domain-1".into(),
            ))
        });
        let response = router_with_keys(sessions_with_sso(0), keys)
            .await
            .oneshot(get("id_token_hint=not-a-jwt", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn test_without_a_hint_the_user_is_asked_to_confirm() {
        let response = router(sessions_with_sso(0))
            .await
            .oneshot(get(
                "client_id=client-1&post_logout_redirect_uri=https://rp.example.com/bye&state=xyz",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let body = text(response).await;
        assert!(body.contains("<form"), "{body}");
        assert!(body.contains("rp.example.com"), "{body}");
    }

    #[tokio::test]
    async fn test_confirmed_logout_ends_the_session_clears_the_cookie_and_redirects() {
        let response = router(sessions_with_sso(1))
            .await
            .oneshot(post(
                "client_id=client-1&post_logout_redirect_uri=https%3A%2F%2Frp.example.com%2Fbye&state=xyz",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        assert!(
            location.starts_with("https://rp.example.com/bye"),
            "{location}"
        );
        assert!(location.contains("state=xyz"));
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(cookie.starts_with("keystone_oauth2_sso="), "{cookie}");
        assert!(cookie.contains("Max-Age=0"), "{cookie}");
    }

    #[tokio::test]
    async fn test_logout_without_a_session_shows_the_signed_out_page() {
        let response = router(MockOauth2SessionProvider::default())
            .await
            .oneshot(get("", false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_session_of_another_domain_is_not_ended_by_confirmation_page() {
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_get_sso_session()
            .returning(|_, _| Ok(Some(sso("domain-2"))));
        sessions.expect_delete_sso_session().never();
        // Not confirmed and no hint, but the session is not this domain's, so
        // there is nothing to confirm.
        let response = router(sessions).await.oneshot(get("", true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
