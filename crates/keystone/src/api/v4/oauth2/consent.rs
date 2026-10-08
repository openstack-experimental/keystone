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
//! Remembered consent for the browser flows: when the user approved a client
//! for a set of scopes and ticked "remember", later authorization requests
//! that ask for no more skip the consent page. `prompt=consent` always asks.

use openstack_keystone_core_types::oauth2_client::OAuth2ClientResource;

use crate::audit::{build_initiator_from_user_id, emit_oauth2_session_event};
use crate::keystone::ServiceState;
use cadf::{Outcome, OutcomeReason};

/// Scopes for which "remember" is ticked by default. Anything else (for
/// example `openstack:api`) has to be remembered deliberately.
const REMEMBER_BY_DEFAULT: [&str; 3] = ["openid", "profile", "email"];

/// Whether the "remember" checkbox is ticked by default for `scopes`.
pub(super) fn remember_default(scopes: &[String]) -> bool {
    scopes
        .iter()
        .all(|s| REMEMBER_BY_DEFAULT.contains(&s.as_str()))
}

/// The "remember" checkbox state for the consent page: `None` when it is not
/// offered (`pre_authorized` clients skip consent anyway), otherwise the
/// default state.
pub(super) fn remember_choice(
    client: Option<&OAuth2ClientResource>,
    scopes: &[String],
) -> Option<bool> {
    client
        .filter(|c| !c.pre_authorized)
        .map(|_| remember_default(scopes))
}

/// Whether a remembered consent of the user covers every requested scope.
/// Any lookup failure counts as "not covered": the user is asked.
pub(super) async fn is_covered(
    state: &ServiceState,
    domain_id: &str,
    user_id: &str,
    client_id: &str,
    scopes: &[String],
) -> bool {
    match state
        .provider
        .get_oauth2_session_provider()
        .get_consent(state, domain_id, user_id, client_id)
        .await
    {
        Ok(Some(consent)) => scopes.iter().all(|s| consent.scopes.contains(s)),
        Ok(None) => false,
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 consent lookup failed");
            false
        }
    }
}

/// Store the consent the user just gave, if they asked to remember it, and
/// audit it. Failure to store is logged and ignored: the flow continues and
/// the user is asked again next time.
pub(super) async fn remember(
    state: &ServiceState,
    client: Option<&OAuth2ClientResource>,
    domain_id: &str,
    user_id: &str,
    scopes: &[String],
    correlation_id: &str,
) {
    // Never for `pre_authorized` clients (they skip consent anyway) or when
    // the client is gone.
    let Some(client) = client.filter(|c| !c.pre_authorized) else {
        return;
    };
    match state
        .provider
        .get_oauth2_session_provider()
        .remember_consent(state, domain_id, user_id, &client.client_id, scopes)
        .await
    {
        Ok(_) => emit_oauth2_session_event(
            &state.audit_dispatcher,
            correlation_id,
            "consent_granted",
            build_initiator_from_user_id(user_id, domain_id),
            &client.client_id,
            Outcome::Success,
            Some(OutcomeReason::literal("Remembered")),
        ),
        Err(e) => {
            tracing::warn!(error = %e, "oauth2 consent could not be remembered");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_remember_default_is_on_only_for_identity_scopes() {
        assert!(remember_default(&scopes(&["openid", "profile", "email"])));
        assert!(remember_default(&scopes(&["openid"])));
        assert!(!remember_default(&scopes(&["openid", "openstack:api"])));
        assert!(!remember_default(&scopes(&["openid", "custom"])));
    }

    #[test]
    fn test_remember_is_not_offered_for_pre_authorized_clients() {
        let mut client = client(false);
        assert_eq!(
            remember_choice(Some(&client), &scopes(&["openid"])),
            Some(true)
        );
        assert_eq!(
            remember_choice(Some(&client), &scopes(&["openstack:api"])),
            Some(false)
        );
        client.pre_authorized = true;
        assert_eq!(remember_choice(Some(&client), &scopes(&["openid"])), None);
        assert_eq!(remember_choice(None, &scopes(&["openid"])), None);
    }

    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::auth::*;
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::oauth2_client::GrantType;
    use openstack_keystone_core_types::oauth2_session::{Consent, PreAuthSession};

    use super::super::authorize::compute_csrf_token;
    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state_with_config;
    use crate::identity::MockIdentityProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    fn client(pre_authorized: bool) -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain-1".into(),
            client_secret_hash: None,
            redirect_uris: vec!["https://rp.example.com/callback".into()],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec![GrantType::AuthorizationCode],
            require_pkce: true,
            allowed_scopes: vec!["openid".into(), "email".into()],
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

    /// A pre-auth session for a user that is signed in.
    fn session(scope: &[&str], force_consent: bool) -> PreAuthSession {
        PreAuthSession {
            session_id: "session-1".into(),
            domain_id: "domain-1".into(),
            client_id: "client-1".into(),
            redirect_uri: "https://rp.example.com/callback".into(),
            scope: scopes(scope),
            state: "xyz".into(),
            code_challenge: "abc".into(),
            code_challenge_method: "S256".into(),
            nonce: None,
            server_side_session_secret: "secret".into(),
            user_id: Some("user-1".into()),
            auth_time: Some(1000),
            consent_granted: None,
            created_at: 0,
            expires_at: 1_000_000_000,
            amr: vec!["pwd".into()],
            pending_user_id: None,
            pending_factors: vec![],
            mfa_attempts: 0,
            pending_upstream: None,
            upstream: None,
            force_consent,
        }
    }

    fn stored(scope: &[&str]) -> Consent {
        Consent {
            domain_id: "domain-1".into(),
            user_id: "user-1".into(),
            client_id: "client-1".into(),
            scopes: scopes(scope),
            authorization_target: None,
            granted_at: 1,
            updated_at: 1,
        }
    }

    async fn router(sessions: MockOauth2SessionProvider) -> axum::Router {
        let mut clients = MockOauth2ClientProvider::default();
        clients
            .expect_get_by_client_id()
            .returning(|_, _| Ok(Some(client(false))));
        let mut identity = MockIdentityProvider::default();
        identity.expect_get_user().returning(|_, id| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id(id)
                    .domain_id("domain-1")
                    .enabled(true)
                    .name("alice")
                    .build()
                    .unwrap(),
            ))
        });
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
        router.with_state(state)
    }

    /// Sessions mock for a login of a user whose pre-auth session is
    /// `session` (the login itself returns it signed in).
    fn sessions_for_login(
        session: PreAuthSession,
        remembered: Option<Consent>,
    ) -> MockOauth2SessionProvider {
        let mut sessions = MockOauth2SessionProvider::default();
        let unauthenticated = PreAuthSession {
            user_id: None,
            auth_time: None,
            ..session.clone()
        };
        sessions
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(unauthenticated.clone())));
        sessions
            .expect_mark_authenticated()
            .returning(move |_, _, _, _, _| Ok(session.clone()));
        sessions
            .expect_get_consent()
            .returning(move |_, _, _, _| Ok(remembered.clone()));
        sessions.expect_get_sso_session().returning(|_, _| Ok(None));
        sessions.expect_create_sso_session().returning(|_, req| {
            Ok(openstack_keystone_core_types::oauth2_session::SsoSession {
                sso_id: "sso-new".into(),
                domain_id: req.domain_id,
                user_id: req.user_id,
                auth_time: req.auth_time,
                amr: req.amr,
                upstream: None,
                created_at: 0,
                expires_at: i64::MAX,
            })
        });
        sessions
    }

    fn login_request(session: &PreAuthSession) -> Request<Body> {
        let csrf = compute_csrf_token(&PreAuthSession {
            user_id: None,
            auth_time: None,
            ..session.clone()
        })
        .unwrap();
        Request::builder()
            .method("POST")
            .uri("/domain-1/authorize/login")
            .header(header::COOKIE, "keystone_oauth2_session=session-1")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "csrf_token={csrf}&username=alice&password=pw"
            )))
            .unwrap()
    }

    async fn text(response: axum::response::Response) -> String {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn test_covering_consent_skips_the_consent_page() {
        let session = session(&["openid", "email"], false);
        let mut sessions = sessions_for_login(
            session.clone(),
            Some(stored(&["openid", "email", "profile"])),
        );
        sessions
            .expect_complete_pre_auth_session()
            .returning(|_, _| Ok(()));
        sessions
            .expect_issue_authorization_code()
            .times(1)
            .returning(|_, _| Ok("the-code".to_string()));
        let response = router(sessions)
            .await
            .oneshot(login_request(&session))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        assert!(location.contains("code=the-code"), "{location}");
    }

    #[tokio::test]
    async fn test_scope_escalation_asks_again() {
        // Only `openid` was remembered; `email` is new.
        let session = session(&["openid", "email"], false);
        let mut sessions = sessions_for_login(session.clone(), Some(stored(&["openid"])));
        sessions.expect_issue_authorization_code().never();
        let response = router(sessions)
            .await
            .oneshot(login_request(&session))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = text(response).await;
        assert!(body.contains("name=\"decision\""), "{body}");
        assert!(body.contains("name=\"remember\""), "{body}");
    }

    #[tokio::test]
    async fn test_prompt_consent_asks_even_when_remembered() {
        let session = session(&["openid"], true);
        let mut sessions = sessions_for_login(session.clone(), Some(stored(&["openid"])));
        sessions.expect_issue_authorization_code().never();
        let response = router(sessions)
            .await
            .oneshot(login_request(&session))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(text(response).await.contains("name=\"decision\""));
    }

    #[tokio::test]
    async fn test_no_stored_consent_shows_the_page_with_remember_ticked_by_default() {
        let session = session(&["openid", "profile"], false);
        let sessions = sessions_for_login(session.clone(), None);
        let response = router(sessions)
            .await
            .oneshot(login_request(&session))
            .await
            .unwrap();
        let body = text(response).await;
        assert!(
            body.contains("name=\"remember\" value=\"1\" checked"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn test_remember_is_unticked_by_default_for_non_identity_scopes() {
        let session = session(&["openid", "custom"], false);
        let sessions = sessions_for_login(session.clone(), None);
        let response = router(sessions)
            .await
            .oneshot(login_request(&session))
            .await
            .unwrap();
        let body = text(response).await;
        assert!(body.contains("name=\"remember\""), "{body}");
        assert!(
            !body.contains("name=\"remember\" value=\"1\" checked"),
            "{body}"
        );
    }

    fn consent_post(session: &PreAuthSession, extra: &str) -> Request<Body> {
        let csrf = compute_csrf_token(session).unwrap();
        Request::builder()
            .method("POST")
            .uri("/domain-1/authorize/consent")
            .header(header::COOKIE, "keystone_oauth2_session=session-1")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "csrf_token={csrf}&decision=allow{extra}"
            )))
            .unwrap()
    }

    fn sessions_for_consent_post(session: PreAuthSession) -> MockOauth2SessionProvider {
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(session.clone())));
        sessions
            .expect_complete_pre_auth_session()
            .returning(|_, _| Ok(()));
        sessions
            .expect_issue_authorization_code()
            .returning(|_, _| Ok("the-code".to_string()));
        sessions
    }

    #[tokio::test]
    async fn test_ticking_remember_stores_the_consent() {
        let session = session(&["openid", "email"], false);
        let mut sessions = sessions_for_consent_post(session.clone());
        sessions
            .expect_remember_consent()
            .withf(|_, domain, user, client, scopes| {
                domain == "domain-1"
                    && user == "user-1"
                    && client == "client-1"
                    && scopes == ["openid", "email"]
            })
            .times(1)
            .returning(|_, _, _, _, _| Ok(stored(&["openid", "email"])));
        let response = router(sessions)
            .await
            .oneshot(consent_post(&session, "&remember=1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(
            response.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .contains("code=the-code")
        );
    }

    #[tokio::test]
    async fn test_unticked_remember_stores_nothing() {
        let session = session(&["openid"], false);
        let mut sessions = sessions_for_consent_post(session.clone());
        sessions.expect_remember_consent().never();
        let response = router(sessions)
            .await
            .oneshot(consent_post(&session, ""))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_denying_never_remembers() {
        let session = session(&["openid"], false);
        let mut sessions = MockOauth2SessionProvider::default();
        let for_get = session.clone();
        sessions
            .expect_get_pre_auth_session()
            .returning(move |_, _| Ok(Some(for_get.clone())));
        sessions
            .expect_complete_pre_auth_session()
            .returning(|_, _| Ok(()));
        sessions.expect_remember_consent().never();
        let csrf = compute_csrf_token(&session).unwrap();
        let response = router(sessions)
            .await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/domain-1/authorize/consent")
                    .header(header::COOKIE, "keystone_oauth2_session=session-1")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "csrf_token={csrf}&decision=deny&remember=1"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .contains("error=access_denied")
        );
    }
}
