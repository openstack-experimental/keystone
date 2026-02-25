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

//! K8s auth role: update.
use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use mockall_double::double;
use validator::Validate;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::k8s_auth::{
    K8sAuthApi,
    api::types::{K8sAuthRolePathParams, K8sAuthRoleResponse, K8sAuthRoleUpdateRequest},
};
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// Update K8s auth role of an instance.
#[utoipa::path(
    put,
    path = "/instance/{instance_id}/role/{id}",
    operation_id = "/k8s_auth/instance/role:update",
    params(K8sAuthRolePathParams),
    responses(
        (status = OK, description = "role object", body = K8sAuthRoleResponse),
        (status = 404, description = "role not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="k8s_auth_role"
)]
#[tracing::instrument(
    name = "api::v4::k8s_auth::role::update",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn update_nested(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(path_params): Path<K8sAuthRolePathParams>,
    State(state): State<ServiceState>,
    Json(req): Json<K8sAuthRoleUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    let current = state
        .provider
        .get_k8s_auth_provider()
        .get_auth_role(&state, &path_params.id)
        .await?;

    policy
        .enforce(
            "identity/k8s_auth/role/update",
            &user_auth,
            serde_json::to_value(&current)?,
            Some(serde_json::to_value(&req.role)?),
        )
        .await?;

    let res = state
        .provider
        .get_k8s_auth_provider()
        .update_auth_role(&state, &path_params.id, req.into())
        .await?;
    Ok(res.into_response())
}

/// Update K8s auth role.
#[utoipa::path(
    put,
    path = "/role/{id}",
    operation_id = "/k8s_auth/role:update",
    params(
      ("id" = String, Path, description = "The ID of the k8s auth role.")
    ),
    responses(
        (status = OK, description = "role object", body = K8sAuthRoleResponse),
        (status = 404, description = "role not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="k8s_auth_role"
)]
#[tracing::instrument(
    name = "api::v4::k8s_auth::role::update",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn update(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<K8sAuthRoleUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    let current = state
        .provider
        .get_k8s_auth_provider()
        .get_auth_role(&state, &id)
        .await?;

    policy
        .enforce(
            "identity/k8s_auth/role/update",
            &user_auth,
            serde_json::to_value(&current)?,
            Some(serde_json::to_value(&req.role)?),
        )
        .await?;

    let res = state
        .provider
        .get_k8s_auth_provider()
        .update_auth_role(&state, &id, req.into())
        .await?;
    Ok(res.into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt; // for `collect`
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use super::{super::*, *};
    use crate::api::tests::get_mocked_state;
    use crate::k8s_auth::{
        MockK8sAuthProvider, api::types::K8sAuthRoleUpdate, types as provider_types,
    };
    use crate::provider::Provider;

    #[tokio::test]
    #[traced_test]
    async fn test_update() {
        let mut provider = Provider::mocked_builder();
        let mut mock = MockK8sAuthProvider::default();
        mock.expect_get_auth_role()
            .withf(|_, id: &'_ str| id == "1")
            .returning(|_, _| {
                Ok(Some(provider_types::K8sAuthRole {
                    auth_instance_id: "cid".into(),
                    bound_audience: Some("aud".into()),
                    bound_service_account_names: vec!["san".into()],
                    bound_service_account_namespaces: vec!["ns".into()],
                    domain_id: "did".into(),
                    enabled: true,
                    id: "id".into(),
                    name: "name".into(),
                    token_restriction_id: "trid".into(),
                }))
            });

        mock.expect_update_auth_role()
            .withf(|_, id: &'_ str, req: &provider_types::K8sAuthRoleUpdate| {
                id == "1" && req.name == Some("name".to_string())
            })
            .returning(|_, _, _| {
                Ok(provider_types::K8sAuthRole {
                    auth_instance_id: "cid".into(),
                    bound_audience: Some("aud".into()),
                    bound_service_account_names: vec!["san".into()],
                    bound_service_account_namespaces: vec!["ns".into()],
                    domain_id: "did".into(),
                    enabled: true,
                    id: "id".into(),
                    name: "name".into(),
                    token_restriction_id: "trid".into(),
                })
            });

        provider = provider.k8s_auth(mock);
        let state = get_mocked_state(provider, true, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        // Nested style
        let req = K8sAuthRoleUpdateRequest {
            role: K8sAuthRoleUpdate {
                name: Some("name".into()),
                ..Default::default()
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/instance/cid/role/1")
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: K8sAuthRoleResponse = serde_json::from_slice(&body).unwrap();

        // Flat style
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/role/1")
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: K8sAuthRoleResponse = serde_json::from_slice(&body).unwrap();
    }
}
