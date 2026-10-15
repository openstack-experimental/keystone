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
//! Service grant: create.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use validator::Validate;

use openstack_keystone_api_types::v4::service_grant::{
    ServiceGrant, ServiceGrantCreateRequest, ServiceGrantResponse,
};
use openstack_keystone_core::auth::ExecutionContext;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Create a service grant delegating the caller's roles on a project to a
/// service.
///
/// The caller is always the grantor, and must not itself be authenticated
/// through a delegation (trust, restricted application credential, service
/// grant).
#[utoipa::path(
    post,
    path = "/",
    operation_id = "/service_grant:create",
    request_body = ServiceGrantCreateRequest,
    responses(
        (status = CREATED, description = "Service grant", body = ServiceGrantResponse),
        (status = BAD_REQUEST, description = "The grantee, project or roles are not usable"),
        (status = FORBIDDEN, description = "The caller may not delegate"),
        (status = TOO_MANY_REQUESTS, description = "The project reached its grant quota"),
    ),
    security(("x-auth" = [])),
    tag="service_grant"
)]
#[tracing::instrument(
    name = "api::v4::service_grant::create",
    level = "debug",
    skip(state, user_auth, req),
    err(Debug)
)]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(req): Json<ServiceGrantCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/service_grant/create",
            &user_auth,
            serde_json::json!({"service_grant": req.service_grant}),
            None,
        )
        .await?;

    let grant = state
        .provider
        .get_service_grant_provider()
        .create_service_grant(
            &ExecutionContext::from_auth(&state, &user_auth),
            req.service_grant.into(),
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(ServiceGrantResponse {
            service_grant: ServiceGrant::from(grant),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_api_types::v4::service_grant::ServiceGrantResponse;
    use openstack_keystone_core_types::service_grant::ServiceGrantProviderError;

    use super::super::openapi_router;
    use super::super::tests::grant;
    use crate::api::tests::{get_capturing_state, get_mocked_state, test_fixture_scoped};
    use crate::provider::Provider;
    use crate::service_grant::MockServiceGrantProvider;

    const BODY: &str =
        r#"{"service_grant": {"grantee_client_id": "heat-client", "project_id": "project_id"}}"#;

    fn post() -> axum::http::request::Builder {
        Request::builder()
            .method(Method::POST)
            .uri("/")
            .header(header::CONTENT_TYPE, "application/json")
    }

    async fn call(
        state: crate::keystone::ServiceState,
        req: Request<Body>,
    ) -> axum::response::Response {
        openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(req)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_create() {
        let mut mock = MockServiceGrantProvider::default();
        mock.expect_create_service_grant()
            .withf(|_, data| {
                data.grantee_client_id == "heat-client"
                    && data.project_id == "project_id"
                    && data.role_ids.is_none()
            })
            .returning(|_, _| Ok(grant("g1")));
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_service_grant(mock)).await;

        let response = call(
            state,
            post()
                .extension(test_fixture_scoped())
                .body(Body::from(BODY))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ServiceGrantResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.service_grant.id, "g1");

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/service_grant/create");
        assert_eq!(calls[0].target["service_grant"]["project_id"], "project_id");
        assert!(calls[0].existing.is_none());
        crate::api::tests::policy_contract::assert_object_keys(
            &calls[0].target,
            &["service_grant"],
        );
        crate::api::tests::policy_contract::assert_no_secrets(&calls[0].target);
        crate::api::tests::policy_contract::assert_existing_presence(&calls[0].existing, false);
    }

    #[tokio::test]
    async fn test_create_policy_denied() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_service_grant(MockServiceGrantProvider::default()),
            false,
            None,
        )
        .await;
        let response = call(
            state,
            post()
                .extension(test_fixture_scoped())
                .body(Body::from(BODY))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_unauthorized() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_service_grant(MockServiceGrantProvider::default()),
            true,
            None,
        )
        .await;
        let response = call(state, post().body(Body::from(BODY)).unwrap()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_invalid_body() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_service_grant(MockServiceGrantProvider::default()),
            true,
            None,
        )
        .await;
        let body = r#"{"service_grant": {"grantee_client_id": "", "project_id": "p"}}"#;
        let response = call(
            state,
            post()
                .extension(test_fixture_scoped())
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_provider_errors() {
        for (err, status) in [
            (
                ServiceGrantProviderError::Validation("not delegatable".into()),
                StatusCode::BAD_REQUEST,
            ),
            (
                ServiceGrantProviderError::Forbidden("delegated".into()),
                StatusCode::FORBIDDEN,
            ),
            (
                ServiceGrantProviderError::QuotaExceeded("full".into()),
                StatusCode::TOO_MANY_REQUESTS,
            ),
        ] {
            let mut mock = MockServiceGrantProvider::default();
            mock.expect_create_service_grant()
                .return_once(move |_, _| Err(err));
            let state = get_mocked_state(
                Provider::mocked_builder().mock_service_grant(mock),
                true,
                None,
            )
            .await;
            let response = call(
                state,
                post()
                    .extension(test_fixture_scoped())
                    .body(Body::from(BODY))
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), status);
        }
    }
}
