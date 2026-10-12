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
//
// SPDX-License-Identifier: Apache-2.0
//! Federated (upstream IdP) sign-in on the device verification page:
//! `POST .../device/federated` sends the browser to the upstream IdP and
//! `GET .../device/federated/callback` receives it back.
//!
//! The same rules as the browser flow (`federated.rs`) apply, with the device
//! grant of the `keystone_oauth2_device_code` cookie in the role of the
//! pre-auth session: the upstream `state` is stored on the grant, compared
//! in constant time and consumed on use, and the redirect target always
//! comes from the discovery document of a registered, enabled IdP of the
//! domain. The upstream `amr`, IdP id and `sid` are recorded on the grant
//! and travel to the refresh token family.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use axum_extra::extract::CookieJar;
use cadf::{Outcome, OutcomeReason};
use chrono::Utc;

use openstack_keystone_core_types::oauth2_session::{DeviceCodeGrant, UpstreamLoginCompletion};

use super::device::{
    DEVICE_COOKIE_NAME, after_device_authentication, render_login, verify_csrf_token,
};
use super::federated::{
    FederatedCallbackQuery, FederatedForm, PendingRedirect, UPSTREAM_FAILED, begin_upstream,
    complete_upstream, idp_views, login_idps, upstream_redirect_response,
};
use super::html::{error_page, fetch_client, too_many_requests, view_of};
use crate::api::common::PeerAddr;
use crate::audit::{
    CorrelationId, build_initiator_from_user_id, build_initiator_unknown, emit_oauth2_session_event,
};
use crate::keystone::ServiceState;

/// Path (below the domain) of the device flow's upstream callback.
const CALLBACK_PATH: &str = "device/federated/callback";

/// Load the device grant of the cookie; it only ever belongs to the domain it
/// was started in.
#[allow(clippy::result_large_err)] // `Response` is the early-return error
async fn load_grant(
    state: &ServiceState,
    jar: &CookieJar,
    domain_id: &str,
) -> Result<DeviceCodeGrant, Response> {
    let expired = || error_page(StatusCode::BAD_REQUEST, "code expired; please restart");
    let Some(device_code) = jar.get(DEVICE_COOKIE_NAME).map(|c| c.value().to_string()) else {
        return Err(expired());
    };
    match state
        .provider
        .get_oauth2_session_provider()
        .get_device_code_grant(state, &device_code)
        .await
    {
        Ok(Some(g)) if g.domain_id == domain_id => Ok(g),
        Ok(Some(_)) | Ok(None) => Err(expired()),
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 device code grant lookup failed");
            Err(error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ))
        }
    }
}

/// `POST /v4/oauth2/{domain_id}/device/federated`.
#[utoipa::path(
    post,
    path = "/{domain_id}/device/federated",
    operation_id = "/oauth2:device_federated",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    responses(
        (status = SEE_OTHER, description = "Redirect to the upstream identity provider"),
        (status = OK, description = "Login form re-rendered with an error", content_type = "text/html"),
        (status = BAD_REQUEST, description = "Missing/expired code, invalid CSRF token or unknown identity provider"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::device_federated",
    level = "debug",
    skip(state, form, headers, jar),
    err(Debug)
)]
pub(super) async fn device_federated(
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
    let grant = match load_grant(&state, &jar, &domain_id).await {
        Ok(g) => g,
        Err(response) => return Ok(response),
    };
    if !verify_csrf_token(&grant, form.csrf_token()) {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "invalid or expired form submission; please restart",
        ));
    }

    let idps = login_idps(&state, &domain_id).await;
    let Some(idp) = idps.iter().find(|idp| idp.id == form.idp_id()).cloned() else {
        return Ok(error_page(
            StatusCode::BAD_REQUEST,
            "unknown identity provider",
        ));
    };

    let idp_id = idp.id.clone();
    let started = match begin_upstream(&state, &headers, &domain_id, CALLBACK_PATH, idp).await {
        Ok(started) => started,
        Err(message) => return Ok(login_with_error(&state, &domain_id, &grant, message).await),
    };
    if let Err(e) = state
        .provider
        .get_oauth2_session_provider()
        .begin_device_upstream_login(&state, &grant.device_code, &idp_id, &started.state)
        .await
    {
        tracing::warn!(error = %e, "oauth2 device code grant update failed");
        return Ok(login_with_error(&state, &domain_id, &grant, UPSTREAM_FAILED).await);
    }
    Ok(upstream_redirect_response(&started.auth_url))
}

/// The device login form again, with an error.
async fn login_with_error(
    state: &ServiceState,
    domain_id: &str,
    grant: &DeviceCodeGrant,
    message: &str,
) -> Response {
    let client = view_of(
        fetch_client(state, &grant.client_id).await.as_ref(),
        &grant.client_id,
    );
    render_login(
        domain_id,
        &client,
        grant,
        Some(message),
        idp_views(&login_idps(state, domain_id).await),
    )
}

/// `GET /v4/oauth2/{domain_id}/device/federated/callback`.
#[utoipa::path(
    get,
    path = "/{domain_id}/device/federated/callback",
    operation_id = "/oauth2:device_federated_callback",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
        FederatedCallbackQuery,
    ),
    responses(
        (status = OK, description = "Consent form, the result page, or the login form with an error", content_type = "text/html"),
        (status = BAD_REQUEST, description = "Missing/expired code or unexpected state"),
        (status = TOO_MANY_REQUESTS, description = "Rate limit exceeded"),
    ),
    tag = "oauth2"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::device_federated_callback",
    level = "debug",
    skip(state, query, headers, jar),
    err(Debug)
)]
pub(super) async fn device_federated_callback(
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
    let grant = match load_grant(&state, &jar, &domain_id).await {
        Ok(g) => g,
        Err(response) => return Ok(response),
    };

    // The callback must answer the redirect this very grant sent.
    let invalid = || {
        error_page(
            StatusCode::BAD_REQUEST,
            "invalid or expired sign-in; please restart",
        )
    };
    let (Some(pending), Some(returned_state)) = (
        grant.pending_upstream.clone(),
        query.state().map(str::to_string),
    ) else {
        return Ok(invalid());
    };
    if !super::html::constant_time_eq(&pending.state, &returned_state) {
        return Ok(invalid());
    }

    let idps = login_idps(&state, &domain_id).await;
    let identity = match complete_upstream(
        &state,
        &idps,
        &PendingRedirect {
            idp_id: &pending.idp_id,
            state: &returned_state,
        },
        &query,
    )
    .await
    {
        Ok(identity) => identity,
        Err(reason) => {
            emit_oauth2_session_event(
                &state.audit_dispatcher,
                &correlation_id.0,
                "authenticate",
                build_initiator_unknown(),
                &grant.client_id,
                Outcome::Failure,
                Some(OutcomeReason::literal(reason)),
            );
            return Ok(login_with_error(&state, &domain_id, &grant, UPSTREAM_FAILED).await);
        }
    };
    let user_id = identity.user_id.clone();

    let grant = match state
        .provider
        .get_oauth2_session_provider()
        .complete_device_upstream_login(
            &state,
            &grant.device_code,
            UpstreamLoginCompletion {
                upstream_state: returned_state,
                user_id: identity.user_id,
                auth_time: Utc::now().timestamp(),
                amr: identity.amr,
                upstream: identity.upstream,
            },
        )
        .await
    {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 device code grant update failed");
            return Ok(invalid());
        }
    };

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        &correlation_id.0,
        "authenticate",
        build_initiator_from_user_id(&user_id, &grant.domain_id),
        &grant.client_id,
        Outcome::Success,
        None,
    );

    let client = fetch_client(&state, &grant.client_id).await;
    Ok(after_device_authentication(
        &state,
        &domain_id,
        client.as_ref(),
        &grant,
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
        AuthenticationContext, AuthenticationResultBuilder, AuthzInfoBuilder, IdentityInfo,
        PrincipalInfo, ScopeInfo, UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::federation::{AuthState, IdentityProvider};
    use openstack_keystone_core_types::oauth2_client as client_types;
    use openstack_keystone_core_types::oauth2_session::{
        DeviceGrantStatus, PendingUpstream, UpstreamLogin,
    };

    use super::super::device::compute_csrf_token;
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
            post_logout_redirect_uris: Default::default(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain-1".into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec![client_types::GrantType::DeviceCode],
            require_pkce: false,
            allowed_scopes: vec!["openid".into()],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
            name: "Example CLI".into(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
        }
    }

    fn grant(pending: Option<(&str, &str)>) -> DeviceCodeGrant {
        DeviceCodeGrant {
            device_code: "dc-1".into(),
            user_code: "BCDFGHJK".into(),
            domain_id: "domain-1".into(),
            client_id: "client-1".into(),
            scope: vec!["openid".into()],
            status: DeviceGrantStatus::Pending,
            user_id: None,
            auth_time: None,
            amr: vec![],
            nonce: None,
            server_side_session_secret: "secret".into(),
            last_polled_at: None,
            created_at: 0,
            expires_at: 1_000_000_000,
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
    ) -> axum::Router {
        let mut client_mock = MockOauth2ClientProvider::default();
        client_mock
            .expect_get_by_client_id()
            .returning(|_, _| Ok(Some(client())));
        let mut config = Config::default();
        config.oauth2.allow_host_header_issuer = true;
        config.auth.methods = vec!["password".into(), "openid".into()];
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

    fn sessions_returning(g: DeviceCodeGrant) -> MockOauth2SessionProvider {
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_get_device_code_grant()
            .returning(move |_, _| Ok(Some(g.clone())));
        sessions
    }

    fn post(uri: &str, body: String) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .method("POST")
            .header(header::COOKIE, "keystone_oauth2_device_code=dc-1")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap()
    }

    fn callback(query: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("/domain-1/device/federated/callback?{query}"))
            .header(header::COOKIE, "keystone_oauth2_device_code=dc-1")
            .body(Body::empty())
            .unwrap()
    }

    async fn text(response: Response) -> String {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn test_code_entry_offers_the_domains_identity_providers() {
        let mut sessions = MockOauth2SessionProvider::default();
        let g = grant(None);
        sessions
            .expect_get_device_code_grant_by_user_code()
            .returning(move |_, _| Ok(Some(g.clone())));
        let router = api(
            federation_listing("https://idp.example.com"),
            sessions,
            MockMappingProvider::default(),
        )
        .await;
        let response = router
            .oneshot(post("/domain-1/device", "user_code=BCDFGHJK".into()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = text(response).await;
        assert!(body.contains("Sign in with Corp SSO"), "{body}");
        assert!(
            body.contains("&#x2f;v4&#x2f;oauth2&#x2f;domain-1&#x2f;device&#x2f;federated"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn test_post_sends_the_browser_upstream_and_remembers_the_state() {
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
        let g = grant(None);
        let csrf = compute_csrf_token(&g).unwrap();
        let mut sessions = sessions_returning(g);
        sessions
            .expect_begin_device_upstream_login()
            .withf(|_, device_code, idp_id, upstream_state| {
                device_code == "dc-1" && idp_id == "idp-1" && !upstream_state.is_empty()
            })
            .times(1)
            .returning(|_, _, _, _| Ok(grant(None)));
        let mut federation = federation_listing(&issuer);
        federation
            .expect_create_auth_state()
            .withf(|_, auth_state| {
                auth_state.idp_id == "idp-1"
                    && auth_state.redirect_uri
                        == "http://localhost/v4/oauth2/domain-1/device/federated/callback"
            })
            .times(1)
            .returning(|_, auth_state| Ok(auth_state));
        let router = api(federation, sessions, MockMappingProvider::default()).await;
        let mut request = post(
            "/domain-1/device/federated",
            format!("csrf_token={csrf}&idp_id=idp-1"),
        );
        request
            .headers_mut()
            .insert(header::HOST, "localhost".parse().unwrap());
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        assert!(
            location.starts_with(&format!("{issuer}/authorize?")),
            "{location}"
        );
    }

    #[tokio::test]
    async fn test_post_rejects_unknown_idp_bad_csrf_and_other_domains() {
        let g = grant(None);
        let csrf = compute_csrf_token(&g).unwrap();
        let router = api(
            federation_listing("https://idp.example.com"),
            sessions_returning(g),
            MockMappingProvider::default(),
        )
        .await;
        for (uri, body) in [
            (
                "/domain-1/device/federated",
                format!("csrf_token={csrf}&idp_id=other-idp"),
            ),
            (
                "/domain-1/device/federated",
                "csrf_token=nope&idp_id=idp-1".to_string(),
            ),
            (
                "/domain-2/device/federated",
                format!("csrf_token={csrf}&idp_id=idp-1"),
            ),
        ] {
            let response = router.clone().oneshot(post(uri, body)).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(response.headers().get(header::LOCATION).is_none());
        }
    }

    #[tokio::test]
    async fn test_callback_without_pending_or_with_foreign_state_is_rejected() {
        for g in [grant(None), grant(Some(("idp-1", "state-1")))] {
            let router = api(
                federation_listing("https://idp.example.com"),
                sessions_returning(g),
                MockMappingProvider::default(),
            )
            .await;
            let response = router
                .oneshot(callback("code=c&state=attacker-state"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn test_callback_of_another_domain_is_rejected() {
        let router = api(
            federation_listing("https://idp.example.com"),
            sessions_returning(grant(Some(("idp-1", "state-1")))),
            MockMappingProvider::default(),
        )
        .await;
        let mut request = callback("code=c&state=state-1");
        *request.uri_mut() = "/domain-2/device/federated/callback?code=c&state=state-1"
            .parse()
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_callback_with_unknown_auth_state_shows_login_error() {
        let mut federation = federation_listing("https://idp.example.com");
        federation
            .expect_get_auth_state()
            .returning(|_, _| Ok(None));
        let mut sessions = sessions_returning(grant(Some(("idp-1", "state-1"))));
        sessions.expect_complete_device_upstream_login().never();
        let router = api(federation, sessions, MockMappingProvider::default()).await;
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
    async fn test_callback_success_records_the_upstream_login_and_shows_consent() {
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
                "amr": ["mfa"],
                "nonce": "the-nonce",
                "iat": chrono::Utc::now().timestamp(),
                "exp": chrono::Utc::now().timestamp() + 600,
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
                expires_at: chrono::Utc::now() + chrono::TimeDelta::seconds(60),
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
        let mut sessions = sessions_returning(grant(Some(("idp-1", "state-1"))));
        sessions
            .expect_get_consent()
            .returning(|_, _, _, _| Ok(None));
        sessions
            .expect_complete_device_upstream_login()
            .withf(|_, device_code, completion| {
                device_code == "dc-1"
                    && completion.upstream_state == "state-1"
                    && completion.user_id == "shadow-user"
                    && completion.amr == ["mfa"]
                    && completion.upstream
                        == UpstreamLogin {
                            idp_id: "idp-1".into(),
                            sid: Some("upstream-sid".into()),
                        }
            })
            .times(1)
            .returning(|_, _, completion| {
                let mut signed_in = grant(None);
                signed_in.user_id = Some(completion.user_id);
                signed_in.auth_time = Some(completion.auth_time);
                signed_in.amr = completion.amr;
                signed_in.upstream = Some(completion.upstream);
                Ok(signed_in)
            });
        let router = api(federation, sessions, mapping).await;
        let response = router
            .oneshot(callback("code=c&state=state-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = text(response).await;
        assert!(body.contains("device&#x2f;consent"), "{body}");
    }
}
