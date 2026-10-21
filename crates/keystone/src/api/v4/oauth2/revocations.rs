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
//! Bulk revocation of OAuth2 refresh token families (ADR 0026 §9): every
//! family of one user, of one client, or of a whole domain. Used by
//! operators during incidents (`keystone-manage oauth2 revoke`).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::v4::oauth2_revocation::{
    Oauth2RevocationRequest, Oauth2RevocationResponse,
};
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::oauth2_session::RefreshTokenRevocationReason;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::oauth2_metrics::OAUTH2_METRICS;

/// Longest accepted `reason`.
const MAX_REASON_LEN: usize = 256;

/// Revoke the refresh token families of a user, a client or a domain.
#[utoipa::path(
    post,
    path = "/{domain_id}/revocations",
    operation_id = "/oauth2/revocation:create",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
    ),
    request_body = Oauth2RevocationRequest,
    responses(
        (status = OK, description = "Revocation counts", body = Oauth2RevocationResponse),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_revocation"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::revocations::create",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn create(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<Oauth2RevocationRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let selectors = usize::from(req.user_id.is_some())
        + usize::from(req.client_id.is_some())
        + usize::from(req.all);
    if selectors != 1 {
        return Err(KeystoneApiError::BadRequest(
            "exactly one of user_id, client_id or all must be given".to_string(),
        ));
    }

    if req
        .reason
        .as_ref()
        .is_some_and(|r| r.chars().count() > MAX_REASON_LEN)
    {
        return Err(KeystoneApiError::BadRequest(format!(
            "reason must be at most {MAX_REASON_LEN} characters"
        )));
    }

    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/revocation/create",
            &user_auth,
            serde_json::json!({"revocation": req, "domain_id": domain_id}),
            None,
        )
        .await?;

    let sessions = state.provider.get_oauth2_session_provider();
    let reason = RefreshTokenRevocationReason::Operator;
    let revoked_families = if let Some(user_id) = &req.user_id {
        sessions
            .revoke_refresh_token_families_by_user(&state, Some(&domain_id), user_id, reason)
            .await?
            .len()
    } else if let Some(client_id) = &req.client_id {
        let exec = ExecutionContext::from_auth(&state, &user_auth);
        // The client must belong to the domain named in the URL, so a domain
        // manager cannot revoke the sessions of another domain's client.
        state
            .provider
            .get_oauth2_client_provider()
            .get_by_client_id(&exec, client_id)
            .await?
            .filter(|c| c.domain_id == domain_id)
            .ok_or_else(|| KeystoneApiError::NotFound {
                resource: "oauth2_client".into(),
                identifier: client_id.clone(),
            })?;
        sessions
            .revoke_refresh_token_families_by_client(&state, client_id, reason)
            .await?
    } else {
        sessions
            .revoke_refresh_token_families_by_domain(&state, &domain_id, reason)
            .await?
            .len()
    };

    OAUTH2_METRICS.record_revocations("operator", revoked_families as u64);
    tracing::warn!(
        actor = %user_auth.inner().principal().get_user_id(),
        domain_id,
        user_id = ?req.user_id,
        client_id = ?req.client_id,
        all = req.all,
        reason = ?req.reason,
        revoked_families,
        "oauth2 sessions revoked by operator"
    );

    Ok((
        StatusCode::OK,
        Json(Oauth2RevocationResponse { revoked_families }),
    )
        .into_response())
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

    use openstack_keystone_api_types::v4::oauth2_revocation::{
        Oauth2RevocationRequest, Oauth2RevocationResponse,
    };

    use openstack_keystone_core_types::oauth2_client as provider_types;

    use crate::api::tests::{
        get_capturing_state, get_mocked_state, policy_contract, test_fixture_scoped,
    };
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::oauth2_session::MockOauth2SessionProvider;
    use crate::provider::Provider;

    fn request<V: Clone + Send + Sync + 'static>(
        body: &Oauth2RevocationRequest,
        vsc: Option<V>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/domain_id/revocations")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(vsc) = vsc {
            builder = builder.extension(vsc);
        }
        builder
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    fn sample_client(domain_id: &str) -> provider_types::OAuth2ClientResource {
        provider_types::OAuth2ClientResource {
            post_logout_redirect_uris: Default::default(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            spiffe_ids: vec![],
            delegation: None,
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: domain_id.into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: "client_secret_basic".into(),
            grant_types: vec![],
            require_pkce: true,
            allowed_scopes: vec![],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
            name: String::new(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
            dpop_bound_access_tokens: false,
        }
    }

    #[tokio::test]
    async fn test_revoke_client() {
        let mut clients = MockOauth2ClientProvider::default();
        clients
            .expect_get_by_client_id()
            .returning(|_, _| Ok(Some(sample_client("domain_id"))));
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_revoke_refresh_token_families_by_client()
            .returning(|_, _, _| Ok(3));
        let provider = Provider::mocked_builder()
            .mock_oauth2_client(clients)
            .mock_oauth2_session(sessions);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                &Oauth2RevocationRequest {
                    client_id: Some("client-1".into()),
                    ..Default::default()
                },
                Some(test_fixture_scoped()),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Oauth2RevocationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.revoked_families, 3);
    }

    #[tokio::test]
    async fn test_revoke_client_of_other_domain() {
        let mut clients = MockOauth2ClientProvider::default();
        clients
            .expect_get_by_client_id()
            .returning(|_, _| Ok(Some(sample_client("other_domain"))));
        // No revoke expectation: the mock panics if the session provider is
        // reached.
        let provider = Provider::mocked_builder().mock_oauth2_client(clients);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                &Oauth2RevocationRequest {
                    client_id: Some("client-1".into()),
                    ..Default::default()
                },
                Some(test_fixture_scoped()),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_revoke_domain() {
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_revoke_refresh_token_families_by_domain()
            .withf(|_, domain_id, _| domain_id == "domain_id")
            .returning(|_, _, _| Ok(vec!["f1".into()]));
        let provider = Provider::mocked_builder().mock_oauth2_session(sessions);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                &Oauth2RevocationRequest {
                    all: true,
                    reason: Some("incident 42".into()),
                    ..Default::default()
                },
                Some(test_fixture_scoped()),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Oauth2RevocationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.revoked_families, 1);
    }

    #[tokio::test]
    async fn test_rejects_long_reason() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                &Oauth2RevocationRequest {
                    all: true,
                    reason: Some("x".repeat(257)),
                    ..Default::default()
                },
                Some(test_fixture_scoped()),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_revoke_user() {
        let mut mock = MockOauth2SessionProvider::default();
        mock.expect_revoke_refresh_token_families_by_user()
            .returning(|_, _, _, _| Ok(vec!["f1".into(), "f2".into()]));
        let provider = Provider::mocked_builder().mock_oauth2_session(mock);
        let state = get_mocked_state(provider, true, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                &Oauth2RevocationRequest {
                    user_id: Some("u1".into()),
                    ..Default::default()
                },
                Some(test_fixture_scoped()),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: Oauth2RevocationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.revoked_families, 2);
    }

    #[tokio::test]
    async fn test_requires_exactly_one_selector() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                &Oauth2RevocationRequest::default(),
                Some(test_fixture_scoped()),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_policy_input_contract() {
        let mut sessions = MockOauth2SessionProvider::default();
        sessions
            .expect_revoke_refresh_token_families_by_domain()
            .returning(|_, _, _| Ok(vec![]));
        let provider = Provider::mocked_builder().mock_oauth2_session(sessions);
        let (state, policy) = get_capturing_state(provider).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                &Oauth2RevocationRequest {
                    all: true,
                    ..Default::default()
                },
                Some(test_fixture_scoped()),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/oauth2/revocation/create");
        policy_contract::assert_object_keys(&calls[0].target, &["revocation", "domain_id"]);
        policy_contract::assert_no_secrets(&calls[0].target);
        policy_contract::assert_existing_presence(&calls[0].existing, false);
    }

    #[tokio::test]
    async fn test_policy_denied() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                &Oauth2RevocationRequest {
                    all: true,
                    ..Default::default()
                },
                Some(test_fixture_scoped()),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        let mut api = super::super::openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(request(
                &Oauth2RevocationRequest {
                    all: true,
                    ..Default::default()
                },
                None::<()>,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
