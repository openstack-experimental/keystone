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
//! The browser single-sign-on session behind the `keystone_oauth2_sso`
//! cookie: set after a completed login, consulted by `GET /authorize`, ended
//! by logout and by user / domain lifecycle events.

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_session::CreateSsoSessionRequest;
use openstack_keystone_core_types::oauth2_session::{PreAuthSession, SsoSession};

use crate::keystone::ServiceState;

pub(super) const SSO_COOKIE_NAME: &str = "keystone_oauth2_sso";

/// The SSO cookie, living as long as the session record.
fn sso_cookie(sso_id: String, secure: bool, lifetime_minutes: u32) -> Cookie<'static> {
    Cookie::build((SSO_COOKIE_NAME, sso_id))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .path("/")
        .max_age(time::Duration::minutes(i64::from(lifetime_minutes)))
        .build()
}

/// A cookie that makes the browser drop the SSO cookie.
pub(super) fn clear_cookie(secure: bool) -> Cookie<'static> {
    Cookie::build((SSO_COOKIE_NAME, ""))
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .path("/")
        .max_age(time::Duration::ZERO)
        .build()
}

/// The valid SSO session of this browser for `domain_id`, if any.
///
/// Valid means: the record exists and has not expired, it belongs to the
/// domain, and its user still exists, is enabled and still belongs to the
/// domain (the lifecycle hook also ends sessions eagerly; this re-check
/// fails closed if that raced or failed).
pub(super) async fn current(
    state: &ServiceState,
    jar: &CookieJar,
    domain_id: &str,
) -> Option<SsoSession> {
    let sso_id = jar.get(SSO_COOKIE_NAME)?.value().to_string();
    let session = match state
        .provider
        .get_oauth2_session_provider()
        .get_sso_session(state, &sso_id)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return None,
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 SSO session lookup failed");
            return None;
        }
    };
    if session.domain_id != domain_id {
        return None;
    }
    let user = state
        .provider
        .get_identity_provider()
        .get_user(&ExecutionContext::internal(state), &session.user_id)
        .await;
    match user {
        Ok(Some(u)) if u.enabled && u.domain_id == domain_id => Some(session),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 SSO user lookup failed");
            None
        }
    }
}

/// Start the SSO session for a login that just completed (see
/// [`establish`]) and set its cookie on `response`.
pub(super) async fn attach(
    state: &ServiceState,
    headers: &HeaderMap,
    jar: &CookieJar,
    session: &PreAuthSession,
    response: Response,
) -> Response {
    match establish(state, headers, jar, session).await {
        Some(cookie) => (CookieJar::new().add(cookie), response).into_response(),
        None => response,
    }
}

/// Start the SSO session for a login that just completed on `session`,
/// replacing the one the browser presented (if any). Returns the cookie to
/// set; `None` (logged) leaves the user signed in for this authorization
/// only.
pub(super) async fn establish(
    state: &ServiceState,
    headers: &HeaderMap,
    jar: &CookieJar,
    session: &PreAuthSession,
) -> Option<Cookie<'static>> {
    let (Some(user_id), Some(auth_time)) = (session.user_id.clone(), session.auth_time) else {
        return None;
    };
    let provider = state.provider.get_oauth2_session_provider();
    if let Some(previous) = jar.get(SSO_COOKIE_NAME) {
        let _ = provider.delete_sso_session(state, previous.value()).await;
    }
    let lifetime_minutes = state
        .config_manager
        .config
        .read()
        .await
        .oauth2
        .sso_session_lifetime_minutes;
    match provider
        .create_sso_session(
            state,
            CreateSsoSessionRequest {
                domain_id: session.domain_id.clone(),
                user_id,
                auth_time,
                amr: session.amr.clone(),
                upstream: session.upstream.clone(),
            },
        )
        .await
    {
        Ok(sso) => Some(sso_cookie(
            sso.sso_id,
            super::authorize::cookie_secure(state, headers).await,
            lifetime_minutes,
        )),
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 SSO session creation failed");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::oauth2_client as client_types;

    use super::super::openapi_router;
    use super::*;
    use crate::api::tests::get_mocked_state_with_config;
    use crate::identity::MockIdentityProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    const QS: &str = "response_type=code&client_id=client-1&redirect_uri=https://rp.example.com/callback&scope=openid&state=xyz&code_challenge=abc&code_challenge_method=S256";

    fn client(pre_authorized: bool) -> client_types::OAuth2ClientResource {
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
            pre_authorized,
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
            post_logout_redirect_uris: vec![],
        }
    }

    fn pre_auth(user: Option<&str>) -> PreAuthSession {
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
            user_id: user.map(str::to_string),
            auth_time: user.map(|_| 1000),
            consent_granted: None,
            created_at: 0,
            expires_at: 1_000_000_000,
            amr: vec![],
            pending_user_id: None,
            pending_factors: vec![],
            mfa_attempts: 0,
            pending_upstream: None,
            upstream: None,
        }
    }

    fn sso_record(auth_time: i64) -> SsoSession {
        SsoSession {
            sso_id: "sso-1".into(),
            domain_id: "domain-1".into(),
            user_id: "user-1".into(),
            auth_time,
            amr: vec!["pwd".into()],
            upstream: None,
            created_at: auth_time,
            expires_at: i64::MAX,
        }
    }

    fn identity(enabled: bool) -> MockIdentityProvider {
        let mut identity = MockIdentityProvider::default();
        identity.expect_get_user().returning(move |_, id| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id(id)
                    .domain_id("domain-1")
                    .enabled(enabled)
                    .name("alice")
                    .build()
                    .unwrap(),
            ))
        });
        identity
    }

    async fn router(
        sessions: MockOauth2SessionProvider,
        pre_authorized: bool,
        user_enabled: bool,
    ) -> axum::Router {
        let mut clients = MockOauth2ClientProvider::default();
        clients
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client(pre_authorized))));
        let mut config = Config::default();
        config.oauth2.allow_host_header_issuer = true;
        let state = get_mocked_state_with_config(
            Provider::mocked_builder()
                .mock_oauth2_session(sessions)
                .mock_oauth2_client(clients)
                .mock_identity(identity(user_enabled)),
            true,
            None,
            config,
        )
        .await;
        let (router, _) = openapi_router().split_for_parts();
        router.layer(TraceLayer::new_for_http()).with_state(state)
    }

    fn authorize(extra: &str, with_sso_cookie: bool) -> Request<Body> {
        let mut builder = Request::builder().uri(format!("/domain-1/authorize?{QS}{extra}"));
        if with_sso_cookie {
            builder = builder.header(header::COOKIE, "keystone_oauth2_sso=sso-1");
        }
        builder.body(Body::empty()).unwrap()
    }

    fn location(response: &axum::response::Response) -> String {
        response
            .headers()
            .get(header::LOCATION)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default()
    }

    async fn text(response: axum::response::Response) -> String {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    }

    /// Session mock with a live SSO session whose login was `age_secs` ago.
    fn sessions_with_sso(age_secs: i64) -> MockOauth2SessionProvider {
        let mut sessions = MockOauth2SessionProvider::default();
        let auth_time = chrono::Utc::now().timestamp() - age_secs;
        sessions
            .expect_get_sso_session()
            .returning(move |_, _| Ok(Some(sso_record(auth_time))));
        sessions
    }

    /// Session mock where signing in with the SSO session works.
    fn sessions_resuming_sso(age_secs: i64) -> MockOauth2SessionProvider {
        let mut sessions = sessions_with_sso(age_secs);
        sessions
            .expect_start_pre_auth_session()
            .returning(|_, _| Ok(pre_auth(None)));
        sessions
            .expect_mark_authenticated_by_sso()
            .times(1)
            .returning(|_, _, sso| {
                let mut session = pre_auth(Some(&sso.user_id));
                session.auth_time = Some(sso.auth_time);
                session.amr = sso.amr.clone();
                Ok(session)
            });
        sessions
    }

    #[test]
    fn test_parse_prompt() {
        assert_eq!(
            super::super::authorize::parse_prompt(None),
            Ok(Default::default())
        );
        let p = super::super::authorize::parse_prompt(Some("login consent")).unwrap();
        assert!(p.login && !p.none);
        assert!(
            super::super::authorize::parse_prompt(Some("none"))
                .unwrap()
                .none
        );
        assert!(super::super::authorize::parse_prompt(Some("none login")).is_err());
        assert!(super::super::authorize::parse_prompt(Some("bogus")).is_err());
    }

    #[tokio::test]
    async fn test_prompt_none_without_session_is_login_required_and_sets_no_cookie() {
        let mut sessions = MockOauth2SessionProvider::default();
        // No expectations: no SSO lookup (no cookie), no session created.
        sessions.expect_start_pre_auth_session().never();
        let response = router(sessions, false, true)
            .await
            .oneshot(authorize("&prompt=none", false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = location(&response);
        assert!(
            location.starts_with("https://rp.example.com/callback?"),
            "{location}"
        );
        assert!(location.contains("error=login_required"), "{location}");
        assert!(location.contains("state=xyz"));
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn test_prompt_none_with_unknown_sso_cookie_is_login_required() {
        let mut sessions = MockOauth2SessionProvider::default();
        sessions.expect_get_sso_session().returning(|_, _| Ok(None));
        let response = router(sessions, false, true)
            .await
            .oneshot(authorize("&prompt=none", true))
            .await
            .unwrap();
        assert!(location(&response).contains("error=login_required"));
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn test_prompt_none_with_sso_needs_consent_unless_pre_authorized() {
        // The user is signed in but consent would have to be asked.
        let response = router(sessions_with_sso(10), false, true)
            .await
            .oneshot(authorize("&prompt=none", true))
            .await
            .unwrap();
        assert!(location(&response).contains("error=consent_required"));
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn test_prompt_none_with_sso_and_pre_authorized_client_issues_a_code() {
        let mut sessions = sessions_resuming_sso(10);
        sessions
            .expect_complete_pre_auth_session()
            .returning(|_, _| Ok(()));
        sessions
            .expect_issue_authorization_code()
            .withf(|_, req| {
                req.user_id == "user-1" && req.amr == ["pwd"] && req.auth_time < 1_000_000_000_000
            })
            .times(1)
            .returning(|_, _| Ok("the-code".to_string()));
        let response = router(sessions, true, true)
            .await
            .oneshot(authorize("&prompt=none", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = location(&response);
        assert!(location.contains("code=the-code"), "{location}");
        assert!(location.contains("state=xyz"));
    }

    #[tokio::test]
    async fn test_sso_session_skips_the_login_form() {
        let response = router(sessions_resuming_sso(10), false, true)
            .await
            .oneshot(authorize("", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = text(response).await;
        assert!(body.contains("authorize&#x2f;consent"), "{body}");
        assert!(!body.contains("name=\"password\""));
    }

    #[tokio::test]
    async fn test_prompt_login_and_select_account_force_the_login_form() {
        for prompt in ["login", "select_account"] {
            let response = router(sessions_startable(), false, true)
                .await
                .oneshot(authorize(&format!("&prompt={prompt}"), true))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(
                text(response).await.contains("name=\"password\""),
                "{prompt}"
            );
        }
    }

    /// Session mock that serves a fresh login (SSO session exists but must
    /// not be used).
    fn sessions_startable() -> MockOauth2SessionProvider {
        let mut sessions = sessions_with_sso(10);
        sessions
            .expect_start_pre_auth_session()
            .returning(|_, _| Ok(pre_auth(None)));
        sessions.expect_mark_authenticated_by_sso().never();
        sessions
    }

    #[tokio::test]
    async fn test_max_age_zero_forces_reauthentication() {
        let response = router(sessions_startable(), false, true)
            .await
            .oneshot(authorize("&max_age=0", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(text(response).await.contains("name=\"password\""));
    }

    #[tokio::test]
    async fn test_max_age_older_than_the_login_forces_reauthentication() {
        // Logged in 10 s ago, only 5 s allowed.
        let response = router(sessions_startable(), false, true)
            .await
            .oneshot(authorize("&max_age=5", true))
            .await
            .unwrap();
        assert!(text(response).await.contains("name=\"password\""));
    }

    #[tokio::test]
    async fn test_max_age_within_the_login_keeps_the_sso_session() {
        let response = router(sessions_resuming_sso(100), false, true)
            .await
            .oneshot(authorize("&max_age=3600", true))
            .await
            .unwrap();
        assert!(text(response).await.contains("authorize&#x2f;consent"));
    }

    #[tokio::test]
    async fn test_prompt_none_with_expired_max_age_is_login_required() {
        let response = router(sessions_with_sso(100), true, true)
            .await
            .oneshot(authorize("&prompt=none&max_age=30", true))
            .await
            .unwrap();
        assert!(location(&response).contains("error=login_required"));
    }

    #[tokio::test]
    async fn test_invalid_prompt_and_max_age_are_invalid_request_redirects() {
        for extra in [
            "&prompt=bogus",
            "&prompt=none%20login",
            "&max_age=-1",
            "&max_age=abc",
        ] {
            let response = router(MockOauth2SessionProvider::default(), false, true)
                .await
                .oneshot(authorize(extra, false))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER, "{extra}");
            assert!(
                location(&response).contains("error=invalid_request"),
                "{extra}"
            );
        }
    }

    #[tokio::test]
    async fn test_sso_session_of_a_disabled_user_is_ignored() {
        let response = router(sessions_startable(), false, false)
            .await
            .oneshot(authorize("", true))
            .await
            .unwrap();
        assert!(text(response).await.contains("name=\"password\""));
    }

    #[tokio::test]
    async fn test_login_hint_prefills_the_username() {
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_start_pre_auth_session()
            .returning(|_, _| Ok(pre_auth(None)));
        let response = router(sessions, false, true)
            .await
            .oneshot(authorize("&login_hint=alice%22%3E%3Cb", false))
            .await
            .unwrap();
        let body = text(response).await;
        assert!(
            body.contains("value=\"alice&#x22;&#x3e;&lt;b\"") || body.contains("alice&quot;"),
            "{body}"
        );
        assert!(!body.contains("alice\"><b"));
    }

    #[tokio::test]
    async fn test_sso_session_of_another_domain_is_ignored() {
        let mut sessions = MockOauth2SessionProvider::default();
        sessions.expect_get_sso_session().returning(|_, _| {
            let mut other = sso_record(chrono::Utc::now().timestamp());
            other.domain_id = "domain-2".into();
            Ok(Some(other))
        });
        let response = router(sessions, false, true)
            .await
            .oneshot(authorize("&prompt=none", true))
            .await
            .unwrap();
        assert!(location(&response).contains("error=login_required"));
    }

    #[tokio::test]
    async fn test_password_login_starts_an_sso_session_and_sets_its_cookie() {
        use crate::api::v4::oauth2::authorize::compute_csrf_token;
        use openstack_keystone_core_types::auth::*;

        // Signed-in session returned by `mark_authenticated`.
        let mut signed_in = pre_auth(Some("user-1"));
        signed_in.amr = vec!["pwd".into()];
        let csrf = compute_csrf_token(&pre_auth(None)).unwrap();
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_get_pre_auth_session()
            .returning(|_, _| Ok(Some(pre_auth(None))));
        sessions
            .expect_mark_authenticated()
            .returning(move |_, _, _, _, _| Ok(signed_in.clone()));
        // The previous SSO session of this browser is replaced.
        sessions
            .expect_delete_sso_session()
            .withf(|_, id| id == "stale-sso")
            .times(1)
            .returning(|_, _| Ok(()));
        sessions
            .expect_create_sso_session()
            .withf(|_, req| {
                req.user_id == "user-1" && req.domain_id == "domain-1" && req.amr == ["pwd"]
            })
            .times(1)
            .returning(|_, req| {
                Ok(SsoSession {
                    sso_id: "new-sso".into(),
                    domain_id: req.domain_id,
                    user_id: req.user_id,
                    auth_time: req.auth_time,
                    amr: req.amr,
                    upstream: None,
                    created_at: 0,
                    expires_at: i64::MAX,
                })
            });

        let mut clients = MockOauth2ClientProvider::default();
        clients
            .expect_get_by_client_id()
            .returning(|_, _| Ok(Some(client(false))));
        let mut identity = identity(true);
        identity
            .expect_authenticate_by_password()
            .returning(|_, _| {
                Ok(AuthenticationResultBuilder::default()
                    .context(AuthenticationContext::Password)
                    .principal(PrincipalInfo {
                        identity: IdentityInfo::User(
                            UserIdentityInfoBuilder::default()
                                .user_id("user-1")
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
        let mut credential = crate::credential::MockCredentialProvider::default();
        credential
            .expect_list_credentials_for_user()
            .returning(|_, _, _| Ok(Vec::new()));
        let mut config = Config::default();
        config.oauth2.allow_host_header_issuer = true;
        let state = get_mocked_state_with_config(
            Provider::mocked_builder()
                .mock_oauth2_session(sessions)
                .mock_oauth2_client(clients)
                .mock_credential(credential)
                .mock_identity(identity),
            true,
            None,
            config,
        )
        .await;
        let (router, _) = openapi_router().split_for_parts();
        let response = router
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/domain-1/authorize/login")
                    .method("POST")
                    .header(
                        header::COOKIE,
                        "keystone_oauth2_session=session-1; keystone_oauth2_sso=stale-sso",
                    )
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "csrf_token={csrf}&username=alice&password=pw"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .find(|c| c.starts_with("keystone_oauth2_sso="))
            .expect("the SSO cookie must be set");
        assert!(
            cookie.starts_with("keystone_oauth2_sso=new-sso"),
            "{cookie}"
        );
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        assert!(cookie.contains("SameSite=Lax"), "{cookie}");
        assert!(cookie.contains("Max-Age=28800"), "{cookie}");
    }
}
