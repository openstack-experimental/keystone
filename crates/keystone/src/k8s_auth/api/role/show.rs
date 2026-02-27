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

//! K8s auth role: show.
use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use mockall_double::double;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::k8s_auth::{
    K8sAuthApi,
    api::types::{K8sAuthRolePathParams, K8sAuthRoleResponse},
};
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// Get single K8s auth role of a instance.
///
/// Show the k8s auth role by the ID.
#[utoipa::path(
    get,
    path = "/instances/{instance_id}/roles/{id}",
    operation_id = "/k8s_auth/instance/role:show",
    params(K8sAuthRolePathParams),
    responses(
        (status = OK, description = "role object", body = K8sAuthRoleResponse),
        (status = 404, description = "role not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="k8s_auth_role"
)]
#[tracing::instrument(
    name = "api::v4::k8s_auth::role::show",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug),
    err(Debug)
)]
pub(super) async fn show_nested(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(path_params): Path<K8sAuthRolePathParams>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_k8s_auth_provider()
        .get_auth_role(&state, &path_params.id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "k8s_auth role".into(),
                identifier: path_params.id,
            })
        })??;

    policy
        .enforce(
            "identity/k8s_auth/role/show",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;
    Ok(current)
}

/// Get single K8s auth role.
///
/// Show the k8s auth role by the ID.
#[utoipa::path(
    get,
    path = "/roles/{id}",
    operation_id = "/k8s_auth/role:show",
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
    name = "api::v4::k8s_auth::role::show",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_k8s_auth_provider()
        .get_auth_role(&state, &id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "k8s_auth role".into(),
                identifier: id,
            })
        })??;

    policy
        .enforce(
            "identity/k8s_auth/role/show",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;
    Ok(current)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use super::{super::openapi_router, *};
    use crate::api::tests::get_mocked_state;
    use crate::k8s_auth::{MockK8sAuthProvider, api::types::K8sAuthRole, types as provider_types};
    use crate::provider::Provider;

    #[tokio::test]
    #[traced_test]
    async fn test_get() {
        let mut provider = Provider::mocked_builder();
        let mut mock = MockK8sAuthProvider::default();
        mock.expect_get_auth_role()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        mock.expect_get_auth_role()
            .withf(|_, id: &'_ str| id == "bar")
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

        provider = provider.k8s_auth(mock);
        let state = get_mocked_state(provider, true, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        // Nested style
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/instances/cid/roles/foo")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/instances/cid/roles/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: K8sAuthRoleResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            K8sAuthRole {
                auth_instance_id: "cid".into(),
                bound_audience: Some("aud".into()),
                bound_service_account_names: vec!["san".into()],
                bound_service_account_namespaces: vec!["ns".into()],
                domain_id: "did".into(),
                enabled: true,
                id: "id".into(),
                name: "name".into(),
                token_restriction_id: "trid".into(),
            },
            res.role,
        );

        // Flat style
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/roles/foo")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/roles/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: K8sAuthRoleResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            K8sAuthRole {
                auth_instance_id: "cid".into(),
                bound_audience: Some("aud".into()),
                bound_service_account_names: vec!["san".into()],
                bound_service_account_namespaces: vec!["ns".into()],
                domain_id: "did".into(),
                enabled: true,
                id: "id".into(),
                name: "name".into(),
                token_restriction_id: "trid".into(),
            },
            res.role,
        );
    }
}
