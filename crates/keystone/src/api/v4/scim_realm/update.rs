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
//! SCIM realm: update (including the enable/disable toggle, ADR 0024 §2.B).

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use openstack_keystone_api_types::v4::scim_realm::{
    ScimRealm, ScimRealmResponse, ScimRealmUpdateRequest,
};
use validator::Validate;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Update a SCIM realm (including enable/disable).
#[utoipa::path(
    put,
    path = "/{domain_id}/{provider_id}",
    operation_id = "/scim_realm:update",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
        ("provider_id" = String, Path, description = "Realm provider_id"),
    ),
    request_body = ScimRealmUpdateRequest,
    responses(
        (status = OK, description = "SCIM realm object", body = ScimRealmResponse),
    ),
    security(("x-auth" = [])),
    tag="scim_realm"
)]
#[tracing::instrument(
    name = "api::v4::scim_realm::update",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path((domain_id, provider_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
    Json(req): Json<ScimRealmUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    let exec = ExecutionContext::from_auth(&state, &user_auth);

    let current = state
        .provider
        .get_scim_realm_provider()
        .get_realm(&exec, &domain_id, &provider_id)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "scim_realm".into(),
            identifier: provider_id.clone(),
        })?;

    // If the realm's IdP link is being changed, it must resolve to a real
    // identity provider — see ADR 0024 dedup fix rationale in create.rs.
    if let Some(idp_id) = &req.scim_realm.idp_id
        && state
            .provider
            .get_federation_provider()
            .get_identity_provider(&exec, idp_id)
            .await?
            .is_none()
    {
        return Err(KeystoneApiError::NotFound {
            resource: "identity_provider".to_string(),
            identifier: idp_id.clone(),
        });
    }

    state
        .policy_enforcer
        .enforce(
            "identity/scim_realm/disable",
            &user_auth,
            serde_json::json!({"scim_realm": req.scim_realm}),
            Some(serde_json::json!({"scim_realm": ScimRealm::from(current.clone())})),
        )
        .await?;

    let res = state
        .provider
        .get_scim_realm_provider()
        .update_realm(&exec, &domain_id, &provider_id, req.scim_realm.into())
        .await?;

    Ok((
        StatusCode::OK,
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
        ScimRealmResponse, ScimRealmUpdate, ScimRealmUpdateRequest,
    };
    use openstack_keystone_core_types::scim as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
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

    fn sample_disabled_realm_core() -> provider_types::ScimRealmResource {
        provider_types::ScimRealmResource {
            enabled: false,
            ..sample_realm_core()
        }
    }

    fn sample_update() -> ScimRealmUpdateRequest {
        ScimRealmUpdateRequest {
            scim_realm: ScimRealmUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn test_update_disables_realm() {
        let vsc = test_fixture_scoped();
        let mut mock = MockScimRealmProvider::default();
        mock.expect_get_realm()
            .returning(|_, _, _| Ok(Some(sample_realm_core())));
        mock.expect_update_realm()
            .returning(|_, _, _, _| Ok(sample_disabled_realm_core()));
        let provider = Provider::mocked_builder().mock_scim_realm(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_update();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/domain_id/provider-1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ScimRealmResponse = serde_json::from_slice(&body).unwrap();
        assert!(!res.scim_realm.enabled);
    }

    #[tokio::test]
    async fn test_update_policy_denied() {
        let vsc = test_fixture_scoped();
        let mut mock = MockScimRealmProvider::default();
        mock.expect_get_realm()
            .returning(|_, _, _| Ok(Some(sample_realm_core())));
        let provider = Provider::mocked_builder().mock_scim_realm(mock);

        let state = get_mocked_state(provider, false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_update();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/domain_id/provider-1")
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
    async fn test_update_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_update();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/domain_id/provider-1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
