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

//! K8s auth role: create.
use axum::{
    Json, debug_handler,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mockall_double::double;
use serde_json::json;
use validator::Validate;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::k8s_auth::{K8sAuthApi, api::types::*};
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// Create K8s auth role.
#[utoipa::path(
    post,
    path = "/instances/{instance_id}/roles",
    operation_id = "/k8s_auth/instance/role:create",
    params(
      ("instance_id" = String, Path, description = "The ID of the k8s auth instance"),
    ),
    responses(
        (status = CREATED, description = "role object", body = K8sAuthRoleResponse),
    ),
    security(("x-auth" = [])),
    tag="k8s_auth_role"
)]
#[tracing::instrument(
    name = "api::v4::k8s_auth::role::create",
    level = "debug",
    skip(state, user_auth, policy)
)]
#[debug_handler]
pub(super) async fn create_nested(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(instance_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<K8sAuthRoleCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    let instance = state
        .provider
        .get_k8s_auth_provider()
        .get_auth_instance(&state, &instance_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "k8s_auth instance".into(),
                identifier: instance_id.clone(),
            })
        })??;

    policy
        .enforce(
            "identity/k8s_auth/role/create",
            &user_auth,
            serde_json::to_value(json!({"role": req.role, "instance": instance}))?,
            None,
        )
        .await?;

    let res = state
        .provider
        .get_k8s_auth_provider()
        .create_auth_role(&state, (req, instance_id, instance.domain_id).into())
        .await?;
    Ok((StatusCode::CREATED, res).into_response())
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

    use super::{super::openapi_router, *};
    use crate::api::tests::get_mocked_state;
    use crate::k8s_auth::{MockK8sAuthProvider, types as provider_types};
    use crate::provider::Provider;

    #[tokio::test]
    #[traced_test]
    async fn test_create() {
        let mut provider = Provider::mocked_builder();
        let mut mock = MockK8sAuthProvider::default();
        mock.expect_get_auth_instance()
            .withf(|_, id: &'_ str| id == "cid")
            .returning(|_, _| {
                Ok(Some(provider_types::K8sAuthInstance {
                    ca_cert: Some("cert".into()),
                    disable_local_ca_jwt: false,
                    domain_id: "did".into(),
                    enabled: true,
                    host: "http://host:post".into(),
                    id: "id".into(),
                    name: Some("name".into()),
                }))
            });
        mock.expect_create_auth_role()
            .withf(|_, req: &provider_types::K8sAuthRoleCreate| req.name == "name")
            .returning(|_, _| {
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

        let req = K8sAuthRoleCreateRequest {
            role: K8sAuthRoleCreate {
                //auth_instance_id: "cid".into(),
                bound_audience: Some("aud".into()),
                bound_service_account_names: vec!["san".into()],
                bound_service_account_namespaces: vec!["ns".into()],
                enabled: true,
                name: "name".into(),
                token_restriction_id: "trid".into(),
            },
        };

        // Nested style
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/instances/cid/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: K8sAuthRoleResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.role.name, req.role.name);
        //assert_eq!(
        //    res.role.auth_instance_id,
        //    req.role.auth_instance_id
        //);
    }
}
