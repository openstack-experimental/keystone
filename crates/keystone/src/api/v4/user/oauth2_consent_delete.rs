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
//! User: withdraw the consent for an OAuth2 application.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use cadf::{Outcome, OutcomeReason};
use openstack_keystone_core::auth::ExecutionContext;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::audit::{CorrelationId, build_initiator_from_vsc, emit_oauth2_session_event};
use crate::keystone::ServiceState;

/// Withdraw the consent for an application
///
/// Deletes the remembered consent of the user for the client **and** revokes
/// the user's refresh tokens issued to that client, so the application can no
/// longer renew its access. Access tokens already issued stay valid until
/// they expire.
#[utoipa::path(
    delete,
    path = "/{user_id}/oauth2/consents/{client_id}",
    description = "Withdraw the consent for an OAuth2 application and revoke its refresh tokens",
    params(
        ("user_id" = String, Path, description = "User ID"),
        ("client_id" = String, Path, description = "OAuth2 client ID"),
    ),
    responses(
        (status = NO_CONTENT, description = "Consent withdrawn"),
        (status = 404, description = "User or consent not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1")))),
    ),
    security(("x-auth" = [])),
    tag = "users"
)]
#[tracing::instrument(
    name = "api::v4::user::oauth2_consent_delete",
    level = "debug",
    skip(state, user_auth)
)]
pub(super) async fn oauth2_consent_delete(
    Auth(user_auth): Auth,
    Path((user_id, client_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
    correlation_id: CorrelationId,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/consent/delete",
            &user_auth,
            json!({"user_id": &user_id, "client_id": &client_id}),
            None,
        )
        .await?;

    let user = state
        .provider
        .get_identity_provider()
        .get_user(&ExecutionContext::from_auth(&state, &user_auth), &user_id)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "user".to_string(),
            identifier: user_id.clone(),
        })?;

    let (existed, families) = state
        .provider
        .get_oauth2_session_provider()
        .revoke_consent(&state, &user.domain_id, &user_id, &client_id)
        .await?;
    if !existed && families.is_empty() {
        return Err(KeystoneApiError::NotFound {
            resource: "oauth2_consent".to_string(),
            identifier: client_id,
        });
    }

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        &correlation_id.0,
        "consent_revoked",
        build_initiator_from_vsc(&user_auth),
        &client_id,
        Outcome::Success,
        Some(OutcomeReason::counts(&[(
            "revoked_families",
            families.len() as u64,
        )])),
    );
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::identity::UserResponseBuilder;

    use super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::identity::MockIdentityProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    fn identity() -> MockIdentityProvider {
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
    }

    fn request(auth: bool) -> Request<Body> {
        let builder = Request::builder()
            .method("DELETE")
            .uri("/foo/oauth2/consents/client-1");
        if auth {
            builder.extension(test_fixture_scoped())
        } else {
            builder
        }
        .body(Body::empty())
        .unwrap()
    }

    fn sessions(existed: bool, families: Vec<String>) -> MockOauth2SessionProvider {
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_revoke_consent()
            .withf(|_, domain, user, client| {
                domain == "domain-1" && user == "foo" && client == "client-1"
            })
            .times(1)
            .returning(move |_, _, _, _| Ok((existed, families.clone())));
        sessions
    }

    #[tokio::test]
    async fn test_delete_withdraws_the_consent_and_revokes_the_families() {
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity())
                .mock_oauth2_session(sessions(true, vec!["f1".into()])),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_with_only_live_families_still_succeeds() {
        // The consent was never remembered, but the application holds
        // refresh tokens: they are revoked.
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity())
                .mock_oauth2_session(sessions(false, vec!["f1".into()])),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_of_nothing_is_not_found() {
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity())
                .mock_oauth2_session(sessions(false, vec![])),
            true,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_policy_input_contract() {
        let (state, policy) = get_capturing_state(
            Provider::mocked_builder()
                .mock_identity(identity())
                .mock_oauth2_session(sessions(true, vec![])),
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/oauth2/consent/delete");
        policy_contract::assert_object_keys(&calls[0].target, &["client_id", "user_id"]);
        policy_contract::assert_existing_presence(&calls[0].existing, false);
        policy_contract::assert_no_secrets(&calls[0].target);
    }

    #[tokio::test]
    async fn test_delete_policy_denied_changes_nothing() {
        let mut sessions = MockOauth2SessionProvider::default();
        sessions.expect_revoke_consent().never();
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity())
                .mock_oauth2_session(sessions),
            false,
            None,
        )
        .await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_delete_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api.as_service().oneshot(request(false)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
