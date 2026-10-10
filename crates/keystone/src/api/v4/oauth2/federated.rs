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
//! Federated (upstream IdP) sign-in on the OP login page:
//! `POST .../authorize/federated` sends the browser to the upstream IdP and
//! `GET .../authorize/federated/callback` receives it back.
//!
//! The upstream `state` is a random value stored on the pre-auth session; the
//! callback only completes the login when the session cookie's session is
//! waiting on exactly that `state` and IdP, and the pending redirect is
//! consumed on use. A forged or replayed callback, or one arriving in a
//! browser that did not start the flow, therefore cannot sign anyone in.
//! The redirect target always comes from the discovery document of a
//! registered, enabled IdP of the domain -- never from a request parameter.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use cadf::{Outcome, OutcomeReason};
use chrono::Utc;
use serde::Deserialize;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::auth::IdentityInfo;
use openstack_keystone_core_types::federation::IdentityProvider;
use openstack_keystone_core_types::federation::IdentityProviderListParameters;
use openstack_keystone_core_types::oauth2_session::{
    PreAuthSession, UpstreamLogin, UpstreamLoginCompletion,
};

use super::authorize::{
    SESSION_COOKIE_NAME, after_authentication, render_login, verify_csrf_token,
};
use super::html::{client_view, error_page, fetch_client, security_headers, too_many_requests};
use super::renderer::IdpView;
use crate::api::common::PeerAddr;
use crate::audit::{
    CorrelationId, build_initiator_from_user_id, build_initiator_unknown, emit_oauth2_session_event,
};
use crate::federation::api::auth::begin_upstream_auth;
use crate::federation::api::oidc::authenticate_upstream;
use crate::keystone::ServiceState;

/// The error shown on the login page when the upstream sign-in fails. The
/// reason is logged, never shown.
const UPSTREAM_FAILED: &str = "sign-in with the identity provider failed";

/// Longest `amr` list / entry accepted from an upstream ID token.
const MAX_UPSTREAM_AMR: usize = 8;
const MAX_UPSTREAM_AMR_LEN: usize = 32;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub(super) struct FederatedForm {
    csrf_token: String,
    idp_id: String,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(super) struct FederatedCallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// The IdPs of `domain_id` the login page may offer: enabled, usable for
/// OIDC login, and only when the `openid` auth method is enabled.
///
/// Global IdPs (no domain) are not offered: the upstream callback resolves
/// the user inside the IdP's own domain. A listing failure degrades to the
/// password form alone.
pub(super) async fn login_idps(state: &ServiceState, domain_id: &str) -> Vec<IdentityProvider> {
    let openid_enabled = state
        .config_manager
        .config
        .read()
        .await
        .auth
        .methods
        .iter()
        .any(|m| m == "openid");
    if !openid_enabled {
        return Vec::new();
    }
    let params = IdentityProviderListParameters {
        domain_ids: Some(std::collections::HashSet::from([Some(
            domain_id.to_string(),
        )])),
        ..Default::default()
    };
    match state
        .provider
        .get_federation_provider()
        .list_identity_providers(&ExecutionContext::internal(state), &params)
        .await
    {
        Ok(list) => list
            .into_iter()
            .filter(|idp| {
                idp.enabled
                    && idp.domain_id.as_deref() == Some(domain_id)
                    && idp.default_mapping_name.is_some()
                    && idp.oidc_discovery_url.is_some()
            })
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "listing identity providers for the login page failed");
            Vec::new()
        }
    }
}

/// Convert listed IdPs into what the login page shows.
pub(super) fn idp_views(idps: &[IdentityProvider]) -> Vec<IdpView> {
    idps.iter()
        .map(|idp| IdpView {
            id: idp.id.clone(),
            name: idp.name.clone(),
        })
        .collect()
}

/// Where the upstream IdP sends the browser back to.
async fn callback_url(state: &ServiceState, headers: &HeaderMap, domain_id: &str) -> String {
    let base = crate::api::common::public_base_url(state, headers).await;
    format!(
        "{}/v4/oauth2/{domain_id}/authorize/federated/callback",
        base.trim_end_matches('/')
    )
}

/// Remember the redirect on the session and answer with the `303` to the
/// upstream IdP. Errors are the (already user-safe) message to show.
pub(super) async fn redirect_to_upstream(
    state: &ServiceState,
    headers: &HeaderMap,
    domain_id: &str,
    session_id: &str,
    idp: IdentityProvider,
) -> Result<Response, &'static str> {
    let redirect_uri = callback_url(state, headers, domain_id).await;
    let idp_id = idp.id.clone();
    let started = begin_upstream_auth(state, idp, &redirect_uri, None)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, idp_id = %idp_id, "starting the upstream sign-in failed");
            UPSTREAM_FAILED
        })?;
    state
        .provider
        .get_oauth2_session_provider()
        .begin_upstream_login(state, session_id, &idp_id, &started.state)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "oauth2 pre-auth session update failed");
            UPSTREAM_FAILED
        })?;
    Ok(security_headers(
        Redirect::to(&started.auth_url).into_response(),
    ))
}

/// Load the pre-auth session of the cookie. A session only ever belongs to the
/// domain it was started in: a path `domain_id` that differs would pick the
/// IdPs (and so the user) of another domain.
#[allow(clippy::result_large_err)] // `Response` is the early-return error
async fn load_session(
    state: &ServiceState,
    jar: &CookieJar,
    domain_id: &str,
) -> Result<PreAuthSession, Response> {
    let expired = || {
        error_page(
            StatusCode::BAD_REQUEST,
            "session expired; please restart sign-in",
        )
    };
    let Some(session_id) = jar.get(SESSION_COOKIE_NAME).map(|c| c.value().to_string()) else {
        return Err(expired());
    };
    match state
        .provider
        .get_oauth2_session_provider()
        .get_pre_auth_session(state, &session_id)
        .await
    {
        Ok(Some(s)) if s.domain_id == domain_id => Ok(s),
        Ok(Some(_)) | Ok(None) => Err(expired()),
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 pre-auth session lookup failed");
            Err(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ))
        }
    }
}

/// `POST /v4/oauth2/{domain_id}/authorize/federated`.
#[utoipa::path(
    post,
    path = "/{domain_id}/authorize/federated",
    operation_id = "/oauth2:authorize_federated",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = SEE_OTHER, description = "Redirect to the upstream identity provider"),
        (status = OK, description = "Login form re-rendered with an error", content_type = "text/html"),
        (status = BAD_REQUEST, description = "Missing/expired session, invalid CSRF token or unknown identity provider"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::authorize_federated",
    level = "debug",
    skip(state, form),
    err(Debug)
)]
pub(super) async fn authorize_federated(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    jar: CookieJar,
    Form(form): Form<FederatedForm>,
) -> Result<Response, std::convert::Infallible> {
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|a| a.ip()))
    {
        return Ok(too_many_requests(retry_after.as_secs()));
    }
    let session = match load_session(&state, &jar, &domain_id).await {
        Ok(s) => s,
        Err(response) => return Ok(response),
    };
    if !verify_csrf_token(&session, &form.csrf_token) {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "invalid or expired form submission; please restart sign-in",
        ));
    }

    let idps = login_idps(&state, &domain_id).await;
    let Some(idp) = idps.iter().find(|idp| idp.id == form.idp_id).cloned() else {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "unknown identity provider",
        ));
    };

    match redirect_to_upstream(&state, &headers, &domain_id, &session.session_id, idp).await {
        Ok(response) => Ok(response),
        Err(message) => {
            let client_ui = client_view(&state, &session.client_id).await;
            Ok(render_login(
                &domain_id,
                &session,
                &client_ui,
                Some(message),
                idp_views(&idps),
            ))
        }
    }
}

/// Epoch seconds of the upstream login are "now": `auth_time` is when this
/// OP established the session.
///
/// `amr` is the upstream's own list when it sent a short, well-formed one,
/// otherwise `["federated"]`. The values are attested by the IdP, not by
/// this OP: an IdP can claim `mfa`, and the issued tokens will carry it.
fn upstream_amr(claims: &serde_json::Value) -> Vec<String> {
    let upstream: Vec<String> = claims
        .get("amr")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty() && s.len() <= MAX_UPSTREAM_AMR_LEN)
                .take(MAX_UPSTREAM_AMR)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if upstream.is_empty() {
        vec!["federated".to_string()]
    } else {
        upstream
    }
}

/// `GET /v4/oauth2/{domain_id}/authorize/federated/callback`.
#[utoipa::path(
    get,
    path = "/{domain_id}/authorize/federated/callback",
    operation_id = "/oauth2:authorize_federated_callback",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
        FederatedCallbackQuery,
    ),
    responses(
        (status = OK, description = "Consent form, or the login form with an error", content_type = "text/html"),
        (status = SEE_OTHER, description = "Pre-authorized client: redirected straight to the RP with a code"),
        (status = BAD_REQUEST, description = "Missing/expired session or unexpected state"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::authorize_federated_callback",
    level = "debug",
    skip(state, query),
    err(Debug)
)]
pub(super) async fn authorize_federated_callback(
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    correlation_id: CorrelationId,
    jar: CookieJar,
    Query(query): Query<FederatedCallbackQuery>,
) -> Result<Response, std::convert::Infallible> {
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|a| a.ip()))
    {
        return Ok(too_many_requests(retry_after.as_secs()));
    }
    let session = match load_session(&state, &jar, &domain_id).await {
        Ok(s) => s,
        Err(response) => return Ok(response),
    };

    // The callback must answer the redirect this very session sent.
    let invalid = || {
        error_page(
            StatusCode::BAD_REQUEST,
            "invalid or expired sign-in; please restart sign-in",
        )
    };
    let (Some(pending), Some(returned_state)) = (session.pending_upstream.clone(), query.state)
    else {
        return Ok(invalid());
    };
    if !super::html::constant_time_eq(&pending.state, &returned_state) {
        return Ok(invalid());
    }

    let idps = login_idps(&state, &domain_id).await;
    let client_ui = client_view(&state, &session.client_id).await;
    let fail = |session: &PreAuthSession, reason: &'static str| {
        emit_oauth2_session_event(
            &state.audit_dispatcher,
            &correlation_id.0,
            "authenticate",
            build_initiator_unknown(),
            &session.client_id,
            Outcome::Failure,
            Some(OutcomeReason::literal(reason)),
        );
        render_login(
            &domain_id,
            session,
            &client_ui,
            Some(UPSTREAM_FAILED),
            idp_views(&idps),
        )
    };

    let exec = ExecutionContext::internal(&state);
    // Best-effort single use of the auth state. The replay guarantee itself is
    // `complete_upstream_login`, which consumes `pending_upstream` atomically,
    // so two racing callbacks cannot both sign the session in.
    let auth_state = match state
        .provider
        .get_federation_provider()
        .get_auth_state(&exec, &returned_state)
        .await
    {
        Ok(Some(a)) => a,
        Ok(None) => return Ok(fail(&session, "UpstreamStateUnknown")),
        Err(e) => {
            tracing::warn!(error = %e, "upstream auth state lookup failed");
            return Ok(fail(&session, "UpstreamStateUnknown"));
        }
    };
    if let Err(e) = state
        .provider
        .get_federation_provider()
        .delete_auth_state(&exec, &returned_state)
        .await
    {
        tracing::warn!(error = %e, "upstream auth state could not be consumed");
        return Ok(fail(&session, "UpstreamStateUnknown"));
    }
    if auth_state.expires_at < Utc::now() || auth_state.idp_id != pending.idp_id {
        return Ok(fail(&session, "UpstreamStateExpired"));
    }

    // Only a registered, enabled IdP of this domain is ever trusted.
    let Some(idp) = idps.iter().find(|idp| idp.id == pending.idp_id) else {
        return Ok(fail(&session, "UpstreamIdpUnavailable"));
    };

    let (Some(code), None) = (query.code.as_deref(), query.error.as_deref()) else {
        tracing::debug!("upstream IdP returned an error response");
        return Ok(fail(&session, "UpstreamError"));
    };

    let (auth_result, claims) =
        match authenticate_upstream(&state, &exec, &auth_state, idp, code).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, idp_id = %idp.id, "upstream sign-in failed");
                return Ok(fail(&session, "UpstreamAuthenticationFailed"));
            }
        };
    let IdentityInfo::User(user_info) = &auth_result.principal.identity else {
        tracing::warn!(idp_id = %idp.id, "upstream sign-in did not resolve to a user");
        return Ok(fail(&session, "UpstreamAuthenticationFailed"));
    };
    let user_id = user_info.user_id.clone();

    let session = match state
        .provider
        .get_oauth2_session_provider()
        .complete_upstream_login(
            &state,
            &session.session_id,
            UpstreamLoginCompletion {
                upstream_state: returned_state,
                user_id: user_id.clone(),
                auth_time: Utc::now().timestamp(),
                amr: upstream_amr(&claims),
                upstream: UpstreamLogin {
                    idp_id: idp.id.clone(),
                    sid: claims
                        .get("sid")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty() && s.len() <= 256)
                        .map(str::to_string),
                },
            },
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 pre-auth session update failed");
            return Ok(invalid());
        }
    };

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        &correlation_id.0,
        "authenticate",
        build_initiator_from_user_id(&user_id, &session.domain_id),
        &session.client_id,
        Outcome::Success,
        None,
    );

    let client = fetch_client(&state, &session.client_id).await;
    Ok(after_authentication(
        &state,
        &domain_id,
        &session,
        client.as_ref(),
        &correlation_id.0,
    )
    .await)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use httpmock::prelude::*;
    use serde_json::json;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthenticationResultBuilder, AuthzInfoBuilder, PrincipalInfo,
        ScopeInfo, UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::federation::AuthState;
    use openstack_keystone_core_types::oauth2_client as client_types;
    use openstack_keystone_core_types::oauth2_session::PendingUpstream;

    use super::super::authorize::compute_csrf_token;
    use super::super::openapi_router;
    use super::*;
    use crate::api::tests::get_mocked_state_with_config;
    use crate::federation::MockFederationProvider;
    use crate::federation::api::oidc_utils::fixtures::*;
    use crate::mapping::MockMappingProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    fn idp(discovery_url: &str) -> IdentityProvider {
        IdentityProvider {
            id: "idp-1".into(),
            name: "Corp SSO".into(),
            domain_id: Some("domain-1".into()),
            enabled: true,
            oidc_discovery_url: Some(discovery_url.into()),
            oidc_client_id: Some("op-client".into()),
            default_mapping_name: Some("corp-rule".into()),
            ..Default::default()
        }
    }

    fn client() -> client_types::OAuth2ClientResource {
        client_types::OAuth2ClientResource {
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain-1".into(),
            client_secret_hash: None,
            redirect_uris: vec!["https://rp.example.com/callback".into()],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec![client_types::GrantType::AuthorizationCode],
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
        }
    }

    fn session(pending: Option<(&str, &str)>) -> PreAuthSession {
        PreAuthSession {
            session_id: "session-1".into(),
            domain_id: "domain-1".into(),
            client_id: "client-1".into(),
            redirect_uri: "https://rp.example.com/callback".into(),
            scope: vec!["openid".into()],
            state: "xyz".into(),
            code_challenge: "abc".into(),
            code_challenge_method: "S256".into(),
            nonce: None,
            server_side_session_secret: "secret".into(),
            user_id: None,
            auth_time: None,
            consent_granted: None,
            created_at: 0,
            expires_at: 1_000_000_000,
            amr: vec![],
            pending_user_id: None,
            pending_factors: vec![],
            mfa_attempts: 0,
            pending_upstream: pending.map(|(idp_id, state)| PendingUpstream {
                idp_id: idp_id.into(),
                state: state.into(),
            }),
            upstream: None,
        }
    }

    async fn api(
        federation: MockFederationProvider,
        sessions: MockOauth2SessionProvider,
        mapping: MockMappingProvider,
        openid: bool,
    ) -> axum::Router {
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(|_, _| Ok(Some(client())));
        let mut config = Config::default();
        config.oauth2.allow_host_header_issuer = true;
        config.auth.methods = if openid {
            vec!["password".into(), "openid".into()]
        } else {
            vec!["password".into()]
        };
        let state = get_mocked_state_with_config(
            Provider::mocked_builder()
                .mock_federation(federation)
                .mock_oauth2_session(sessions)
                .mock_oauth2_client(client_mock)
                .mock_mapping(mapping),
            true,
            None,
            config,
        )
        .await;
        let (router, _) = openapi_router().split_for_parts();
        router.layer(TraceLayer::new_for_http()).with_state(state)
    }

    fn federation_listing(url: &str) -> MockFederationProvider {
        let idp = idp(url);
        let mut federation = MockFederationProvider::default();
        federation
            .expect_list_identity_providers()
            .returning(move |_, _| Ok(vec![idp.clone()]));
        federation
    }

    fn sessions_returning(s: PreAuthSession) -> MockOauth2SessionProvider {
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(s.clone())));
        sessions
    }

    fn post(uri: &str, body: String) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .method("POST")
            .header(header::COOKIE, "keystone_oauth2_session=session-1")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap()
    }

    fn callback(query: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("/domain-1/authorize/federated/callback?{query}"))
            .method("GET")
            .header(header::COOKIE, "keystone_oauth2_session=session-1")
            .body(Body::empty())
            .unwrap()
    }

    async fn text(response: Response) -> String {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn test_login_page_offers_the_domains_identity_providers() {
        let mut sessions = MockOauth2SessionProvider::default();
        let s = session(None);
        sessions
            .expect_start_pre_auth_session()
            .returning(move |_, _| Ok(s.clone()));
        let router = api(
            federation_listing("https://idp.example.com"),
            sessions,
            MockMappingProvider::default(),
            true,
        )
        .await;
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/domain-1/authorize?response_type=code&client_id=client-1&redirect_uri=https://rp.example.com/callback&scope=openid&state=xyz&code_challenge=abc&code_challenge_method=S256")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = text(response).await;
        assert!(body.contains("Sign in with Corp SSO"), "{body}");
        assert!(
            body.contains("&#x2f;v4&#x2f;oauth2&#x2f;domain-1&#x2f;authorize&#x2f;federated"),
            "{body}"
        );
        assert!(body.contains("value=\"idp-1\""), "{body}");
    }

    #[tokio::test]
    async fn test_login_page_offers_no_provider_without_openid_method() {
        let mut sessions = MockOauth2SessionProvider::default();
        let s = session(None);
        sessions
            .expect_start_pre_auth_session()
            .returning(move |_, _| Ok(s.clone()));
        // No `list_identity_providers` expectation: it must not be called.
        let router = api(
            MockFederationProvider::default(),
            sessions,
            MockMappingProvider::default(),
            false,
        )
        .await;
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/domain-1/authorize?response_type=code&client_id=client-1&redirect_uri=https://rp.example.com/callback&scope=openid&state=xyz&code_challenge=abc&code_challenge_method=S256")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!text(response).await.contains("Sign in with"));
    }

    #[tokio::test]
    async fn test_unknown_idp_hint_is_ignored() {
        let mut sessions = MockOauth2SessionProvider::default();
        let s = session(None);
        sessions
            .expect_start_pre_auth_session()
            .returning(move |_, _| Ok(s.clone()));
        let router = api(
            federation_listing("https://idp.example.com"),
            sessions,
            MockMappingProvider::default(),
            true,
        )
        .await;
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/domain-1/authorize?response_type=code&client_id=client-1&redirect_uri=https://rp.example.com/callback&scope=openid&state=xyz&code_challenge=abc&code_challenge_method=S256&idp_hint=https://evil.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Rendered, not redirected anywhere.
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::LOCATION).is_none());
    }

    #[tokio::test]
    async fn test_idp_hint_sends_the_browser_upstream() {
        let server = MockServer::start();
        let issuer = server.base_url();
        server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
            }));
        });
        let mut sessions = MockOauth2SessionProvider::default();
        let s = session(None);
        sessions
            .expect_start_pre_auth_session()
            .returning(move |_, _| Ok(s.clone()));
        sessions
            .expect_begin_upstream_login()
            .withf(|_, session_id, idp_id, upstream_state| {
                session_id == "session-1" && idp_id == "idp-1" && !upstream_state.is_empty()
            })
            .times(1)
            .returning(|_, _, _, _| Ok(session(None)));
        let mut federation = federation_listing(&issuer);
        federation
            .expect_create_auth_state()
            .withf(|_, auth_state| {
                auth_state.idp_id == "idp-1"
                    && auth_state.redirect_uri
                        == "http://localhost/v4/oauth2/domain-1/authorize/federated/callback"
            })
            .times(1)
            .returning(|_, auth_state| Ok(auth_state));
        let router = api(federation, sessions, MockMappingProvider::default(), true).await;
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/domain-1/authorize?response_type=code&client_id=client-1&redirect_uri=https://rp.example.com/callback&scope=openid&state=xyz&code_challenge=abc&code_challenge_method=S256&idp_hint=idp-1")
                    .header(header::HOST, "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            location.starts_with(&format!("{issuer}/authorize?")),
            "{location}"
        );
        assert!(location.contains("code_challenge_method=S256"));
    }

    #[tokio::test]
    async fn test_federated_post_rejects_unknown_idp_and_bad_csrf() {
        let s = session(None);
        let csrf = compute_csrf_token(&s).unwrap();
        let router = api(
            federation_listing("https://idp.example.com"),
            sessions_returning(s),
            MockMappingProvider::default(),
            true,
        )
        .await;

        let unknown = router
            .clone()
            .oneshot(post(
                "/domain-1/authorize/federated",
                format!("csrf_token={csrf}&idp_id=other-idp"),
            ))
            .await
            .unwrap();
        assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
        assert!(unknown.headers().get(header::LOCATION).is_none());

        let bad_csrf = router
            .oneshot(post(
                "/domain-1/authorize/federated",
                "csrf_token=nope&idp_id=idp-1".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(bad_csrf.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_federated_endpoints_reject_a_session_of_another_domain() {
        // The session belongs to domain-1; the path names another domain, so
        // that domain's IdPs must not be usable for it.
        let s = session(Some(("idp-1", "state-1")));
        let csrf = compute_csrf_token(&s).unwrap();
        let router = api(
            federation_listing("https://idp.example.com"),
            sessions_returning(s),
            MockMappingProvider::default(),
            true,
        )
        .await;
        let post_response = router
            .clone()
            .oneshot(post(
                "/domain-2/authorize/federated",
                format!("csrf_token={csrf}&idp_id=idp-1"),
            ))
            .await
            .unwrap();
        assert_eq!(post_response.status(), StatusCode::BAD_REQUEST);
        assert!(post_response.headers().get(header::LOCATION).is_none());

        let mut req = callback("code=c&state=state-1");
        *req.uri_mut() = "/domain-2/authorize/federated/callback?code=c&state=state-1"
            .parse()
            .unwrap();
        let callback_response = router.oneshot(req).await.unwrap();
        assert_eq!(callback_response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_callback_without_pending_redirect_is_rejected() {
        let router = api(
            federation_listing("https://idp.example.com"),
            sessions_returning(session(None)),
            MockMappingProvider::default(),
            true,
        )
        .await;
        let response = router
            .oneshot(callback("code=c&state=state-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_callback_with_foreign_state_is_rejected() {
        // The session waits on `state-1`; a callback carrying another state
        // (for example one started in the attacker's browser) is refused
        // before the auth state is even looked up.
        let router = api(
            federation_listing("https://idp.example.com"),
            sessions_returning(session(Some(("idp-1", "state-1")))),
            MockMappingProvider::default(),
            true,
        )
        .await;
        let response = router
            .oneshot(callback("code=c&state=attacker-state"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_callback_with_unknown_auth_state_shows_login_error() {
        let mut federation = federation_listing("https://idp.example.com");
        federation
            .expect_get_auth_state()
            .returning(|_, _| Ok(None));
        let router = api(
            federation,
            sessions_returning(session(Some(("idp-1", "state-1")))),
            MockMappingProvider::default(),
            true,
        )
        .await;
        let response = router
            .oneshot(callback("code=c&state=state-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            text(response)
                .await
                .contains("sign-in with the identity provider failed")
        );
    }

    #[tokio::test]
    async fn test_callback_error_from_upstream_consumes_state_and_shows_error() {
        let mut federation = federation_listing("https://idp.example.com");
        federation.expect_get_auth_state().returning(|_, _| {
            Ok(Some(AuthState {
                idp_id: "idp-1".into(),
                state: "state-1".into(),
                expires_at: Utc::now() + chrono::TimeDelta::seconds(60),
                ..Default::default()
            }))
        });
        federation
            .expect_delete_auth_state()
            .times(1)
            .returning(|_, _| Ok(()));
        let router = api(
            federation,
            sessions_returning(session(Some(("idp-1", "state-1")))),
            MockMappingProvider::default(),
            true,
        )
        .await;
        let response = router
            .oneshot(callback("error=access_denied&state=state-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            text(response)
                .await
                .contains("sign-in with the identity provider failed")
        );
    }

    #[tokio::test]
    async fn test_callback_success_signs_in_and_shows_consent() {
        let server = MockServer::start();
        let issuer = server.base_url();
        server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
            }));
        });
        server.mock(|when, then| {
            when.method(GET).path("/jwks");
            then.status(200).json_body(json!({"keys": [{
                "kty": "RSA", "use": "sig", "alg": "RS256", "kid": TEST_KID,
                "n": TEST_JWK_N, "e": TEST_JWK_E,
            }]}));
        });
        let id_token = make_jwt(
            &json!({
                "iss": issuer,
                "aud": "op-client",
                "sub": "upstream-sub",
                "sid": "upstream-sid",
                "nonce": "the-nonce",
                "iat": Utc::now().timestamp(),
                "exp": Utc::now().timestamp() + 600,
            }),
            Some(TEST_KID),
        );
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200)
                .json_body(json!({"id_token": id_token, "token_type": "Bearer"}));
        });

        let mut federation = federation_listing(&issuer);
        federation.expect_get_auth_state().returning(|_, _| {
            Ok(Some(AuthState {
                idp_id: "idp-1".into(),
                nonce: "the-nonce".into(),
                pkce_verifier: "verifier".into(),
                redirect_uri: "http://localhost/cb".into(),
                state: "state-1".into(),
                expires_at: Utc::now() + chrono::TimeDelta::seconds(60),
                ..Default::default()
            }))
        });
        federation
            .expect_delete_auth_state()
            .times(1)
            .returning(|_, _| Ok(()));

        let mut mapping = MockMappingProvider::default();
        mapping.expect_authenticate_by_mapping().returning(|_, _| {
            Ok(AuthenticationResultBuilder::default()
                .context(AuthenticationContext::Password)
                .principal(PrincipalInfo {
                    identity: IdentityInfo::User(
                        UserIdentityInfoBuilder::default()
                            .user_id("shadow-user")
                            .build()
                            .unwrap(),
                    ),
                })
                .authorization(
                    AuthzInfoBuilder::default()
                        .scope(ScopeInfo::Unscoped)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap())
        });

        let mut sessions = sessions_returning(session(Some(("idp-1", "state-1"))));
        sessions
            .expect_complete_upstream_login()
            .withf(|_, session_id, completion| {
                session_id == "session-1"
                    && completion.upstream_state == "state-1"
                    && completion.user_id == "shadow-user"
                    && completion.amr == ["federated"]
                    && completion.upstream
                        == UpstreamLogin {
                            idp_id: "idp-1".into(),
                            sid: Some("upstream-sid".into()),
                        }
            })
            .times(1)
            .returning(|_, _, completion| {
                let mut signed_in = session(None);
                signed_in.user_id = Some(completion.user_id);
                signed_in.auth_time = Some(completion.auth_time);
                signed_in.amr = completion.amr;
                signed_in.upstream = Some(completion.upstream);
                Ok(signed_in)
            });

        let router = api(federation, sessions, mapping, true).await;
        let response = router
            .oneshot(callback("code=c&state=state-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = text(response).await;
        assert!(body.contains("authorize&#x2f;consent"), "{body}");
    }
}
