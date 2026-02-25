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

//! K8s auth: update auth instance.
use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use mockall_double::double;
use validator::Validate;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::k8s_auth::{K8sAuthApi, api::types::*};
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// Update single K8s auth instance.
///
/// Updates the existing k8s auth instance.
#[utoipa::path(
    put,
    path = "/{instance_id}",
    operation_id = "/k8s_auth/instance:update",
    params(
      ("instance" = String, Path, description = "The ID of the instance")
    ),
    responses(
        (status = OK, description = "Instance object", body = K8sAuthInstanceResponse),
        (status = 404, description = "Instance not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="k8s_auth_instance"
)]
#[tracing::instrument(
    name = "api::v4::k8s_auth::instance::update",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn update(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(instance_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<K8sAuthInstanceUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    // Fetch the current resource to pass current object into the policy evaluation
    let current = state
        .provider
        .get_k8s_auth_provider()
        .get_auth_instance(&state, &instance_id)
        .await?;

    policy
        .enforce(
            "identity/k8s_auth/instance/update",
            &user_auth,
            serde_json::to_value(&current)?,
            Some(serde_json::to_value(&req.instance)?),
        )
        .await?;

    let res = state
        .provider
        .get_k8s_auth_provider()
        .update_auth_instance(&state, &instance_id, req.into())
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

    use super::{super::openapi_router, *};
    use crate::api::tests::get_mocked_state;
    use crate::k8s_auth::{MockK8sAuthProvider, types as provider_types};
    use crate::provider::Provider;

    #[tokio::test]
    #[traced_test]
    async fn test_update() {
        let mut provider = Provider::mocked_builder();
        let mut mock = MockK8sAuthProvider::default();
        mock.expect_get_auth_instance()
            .withf(|_, id: &'_ str| id == "1")
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
        mock.expect_update_auth_instance()
            .withf(
                |_, id: &'_ str, req: &provider_types::K8sAuthInstanceUpdate| {
                    id == "1" && req.name == Some("name".to_string())
                },
            )
            .returning(|_, _, _| {
                Ok(provider_types::K8sAuthInstance {
                    ca_cert: Some("cert".into()),
                    disable_local_ca_jwt: false,
                    domain_id: "did".into(),
                    enabled: true,
                    host: "http://host:post".into(),
                    id: "id".into(),
                    name: Some("name".into()),
                })
            });

        provider = provider.k8s_auth(mock);
        let state = get_mocked_state(provider, true, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = K8sAuthInstanceUpdateRequest {
            instance: K8sAuthInstanceUpdate {
                ca_cert: Some("cert".into()),
                disable_local_ca_jwt: Some(false),
                enabled: Some(true),
                host: Some("http://host:post".into()),
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
                    .uri("/1")
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: K8sAuthInstanceResponse = serde_json::from_slice(&body).unwrap();
    }
}
