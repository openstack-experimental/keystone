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
//! SCIM realm: create.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use openstack_keystone_api_types::v4::scim_realm::{
    ScimRealm, ScimRealmCreateRequest, ScimRealmResponse,
};
use validator::Validate;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Register a new SCIM realm.
#[utoipa::path(
    post,
    path = "/",
    operation_id = "/scim_realm:create",
    request_body = ScimRealmCreateRequest,
    responses(
        (status = CREATED, description = "SCIM realm object", body = ScimRealmResponse),
    ),
    security(("x-auth" = [])),
    tag="scim_realm"
)]
#[tracing::instrument(
    name = "api::v4::scim_realm::create",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(req): Json<ScimRealmCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/scim_realm/create",
            &user_auth,
            serde_json::json!({"scim_realm": req.scim_realm}),
            None,
        )
        .await?;

    let exec = ExecutionContext::from_auth(&state, &user_auth);

    // Every SCIM realm must be linked to a real, existing federation
    // IdentityProvider — SCIM users are always provisioned as `nonlocal_user`
    // shadow identities keyed off this IdP (see ADR 0024 dedup fix), so an
    // unresolvable idp_id must not be allowed to create a realm at all.
    if state
        .provider
        .get_federation_provider()
        .get_identity_provider(&exec, &req.scim_realm.idp_id)
        .await?
        .is_none()
    {
        return Err(KeystoneApiError::NotFound {
            resource: "identity_provider".to_string(),
            identifier: req.scim_realm.idp_id.clone(),
        });
    }

    let res = state
        .provider
        .get_scim_realm_provider()
        .create_realm(&exec, req.into())
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(ScimRealmResponse {
            scim_realm: ScimRealm::from(res),
        }),
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

    use openstack_keystone_api_types::v4::scim_realm::{
        ScimRealmCreate, ScimRealmCreateRequest, ScimRealmResponse,
    };
    use openstack_keystone_core_types::federation::IdentityProviderBuilder;
    use openstack_keystone_core_types::scim as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::federation::MockFederationProvider;
    use crate::provider::Provider;
    use crate::scim_realm::MockScimRealmProvider;

    fn sample_realm_core() -> provider_types::ScimRealmResource {
        provider_types::ScimRealmResource {
            domain_id: "domain_id".into(),
            provider_id: "provider-1".into(),
            idp_id: "idp-1".into(),
            display_name: "Okta - Employees".into(),
            enabled: true,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn sample_create() -> ScimRealmCreateRequest {
        ScimRealmCreateRequest {
            scim_realm: ScimRealmCreate {
                domain_id: "domain_id".into(),
                provider_id: "provider-1".into(),
                idp_id: "idp-1".into(),
                display_name: "Okta - Employees".into(),
            },
        }
    }

    #[tokio::test]
    async fn test_create() {
        let vsc = test_fixture_scoped();
        let mut mock = MockScimRealmProvider::default();
        mock.expect_create_realm()
            .returning(|_, _| Ok(sample_realm_core()));
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_get_identity_provider()
            .returning(|_, id| {
                Ok(Some(
                    IdentityProviderBuilder::default()
                        .id(id)
                        .name("okta")
                        .build()
                        .unwrap(),
                ))
            });
        let provider = Provider::mocked_builder()
            .mock_scim_realm(mock)
            .mock_federation(federation_mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_create();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ScimRealmResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.scim_realm.provider_id, "provider-1");
    }

    #[tokio::test]
    async fn test_create_policy_denied() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_create();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_create();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
