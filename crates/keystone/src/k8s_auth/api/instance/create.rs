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

//! K8s auth instance: create.
use axum::{Json, debug_handler, extract::State, http::StatusCode, response::IntoResponse};
use mockall_double::double;
use validator::Validate;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::k8s_auth::{
    K8sAuthApi,
    api::types::{K8sAuthInstanceCreateRequest, K8sAuthInstanceResponse},
};
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// Create the K8s auth instance.
///
/// Create the K8s auth instance with the specified properties.
#[utoipa::path(
    post,
    path = "/",
    operation_id = "/k8s_auth/auth_instance:create",
    responses(
        (status = CREATED, description = "auth instance object", body = K8sAuthInstanceResponse),
    ),
    security(("x-auth" = [])),
    tag="k8s_auth_instance"
)]
#[tracing::instrument(
    name = "api::v4::k8s_auth::instance::create",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
#[debug_handler]
pub(super) async fn create(
    Auth(user_auth): Auth,
    mut policy: Policy,
    State(state): State<ServiceState>,
    Json(req): Json<K8sAuthInstanceCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;
    policy
        .enforce(
            "identity/k8s_auth/instance/create",
            &user_auth,
            serde_json::to_value(&req.instance)?,
            None,
        )
        .await?;

    let res = state
        .provider
        .get_k8s_auth_provider()
        .create_auth_instance(&state, req.into())
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
    use crate::k8s_auth::{
        MockK8sAuthProvider,
        api::types::{K8sAuthInstanceCreate, K8sAuthInstanceCreateRequest},
        types as provider_types,
    };
    use crate::provider::Provider;

    #[tokio::test]
    #[traced_test]
    async fn test_create() {
        let mut provider = Provider::mocked_builder();
        let mut mock = MockK8sAuthProvider::default();
        mock.expect_create_auth_instance()
            .withf(|_, req: &provider_types::K8sAuthInstanceCreate| {
                req.name == Some("name".to_string())
            })
            .returning(|_, _| {
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

        let req = K8sAuthInstanceCreateRequest {
            instance: K8sAuthInstanceCreate {
                ca_cert: Some("cert".into()),
                disable_local_ca_jwt: None,
                domain_id: "did".into(),
                enabled: true,
                host: "http://host:post".into(),
                name: Some("name".into()),
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: K8sAuthInstanceResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.instance.name, req.instance.name);
        assert_eq!(res.instance.domain_id, req.instance.domain_id);
    }
}
