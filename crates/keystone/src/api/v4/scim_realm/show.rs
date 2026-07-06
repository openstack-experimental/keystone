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
//! SCIM realm: show.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use openstack_keystone_api_types::v4::scim_realm::{ScimRealm, ScimRealmResponse};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// Show a SCIM realm by its `(domain_id, provider_id)` coordinate.
#[utoipa::path(
    get,
    path = "/{domain_id}/{provider_id}",
    operation_id = "/scim_realm:show",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
        ("provider_id" = String, Path, description = "Realm provider_id"),
    ),
    responses(
        (status = OK, description = "SCIM realm object", body = ScimRealmResponse),
    ),
    security(("x-auth" = [])),
    tag="scim_realm"
)]
#[tracing::instrument(
    name = "api::v4::scim_realm::show",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path((domain_id, provider_id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_scim_realm_provider()
        .get_realm(
            &ExecutionContext::from_auth(&state, &user_auth),
            &domain_id,
            &provider_id,
        )
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "scim_realm".into(),
            identifier: provider_id.clone(),
        })?;

    state
        .policy_enforcer
        .enforce(
            "identity/scim_realm/show",
            &user_auth,
            serde_json::json!({"scim_realm": null}),
            Some(serde_json::json!({"scim_realm": ScimRealm::from(current.clone())})),
        )
        .await?;

    Ok((
        StatusCode::OK,
        Json(ScimRealmResponse {
            scim_realm: ScimRealm::from(current),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_api_types::v4::scim_realm::ScimRealmResponse;
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

    #[tokio::test]
    async fn test_show() {
        let vsc = test_fixture_scoped();
        let mut mock = MockScimRealmProvider::default();
        mock.expect_get_realm()
            .returning(|_, _, _| Ok(Some(sample_realm_core())));
        let provider = Provider::mocked_builder().mock_scim_realm(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain_id/provider-1")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ScimRealmResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.scim_realm.provider_id, "provider-1");
    }

    #[tokio::test]
    async fn test_show_not_found() {
        let vsc = test_fixture_scoped();
        let mut mock = MockScimRealmProvider::default();
        mock.expect_get_realm().returning(|_, _, _| Ok(None));
        let provider = Provider::mocked_builder().mock_scim_realm(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain_id/nonexistent")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_show_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain_id/provider-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
