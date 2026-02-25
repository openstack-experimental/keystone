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

//! K8s auth: show auth instances.
use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use mockall_double::double;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::k8s_auth::{K8sAuthApi, api::types::*};
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// Get single K8s auth instance.
///
/// Shows details of the existing instance.
#[utoipa::path(
    get,
    path = "/{instance_id}",
    operation_id = "/k8s_auth/instance:show",
    params(
      ("instance_id" = String, Path, description = "The ID of the instance")
    ),
    responses(
        (status = OK, description = "K8s auth instance object", body = K8sAuthInstanceResponse),
        (status = 404, description = "Resource not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="k8s_auth_instance"
)]
#[tracing::instrument(
    name = "api::v4::k8s_auth::instance::get",
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
        .get_auth_instance(&state, &id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "k8s_auth instance".into(),
                identifier: id,
            })
        })??;

    policy
        .enforce(
            "identity/k8s_auth/instance/show",
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
    use crate::k8s_auth::{MockK8sAuthProvider, types as provider_types};
    use crate::provider::Provider;

    #[tokio::test]
    #[traced_test]
    async fn test_get() {
        let mut provider = Provider::mocked_builder();
        let mut mock = MockK8sAuthProvider::default();
        mock.expect_get_auth_instance()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        mock.expect_get_auth_instance()
            .withf(|_, id: &'_ str| id == "bar")
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

        provider = provider.k8s_auth(mock);
        let state = get_mocked_state(provider, true, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo")
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
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: K8sAuthInstanceResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            K8sAuthInstance {
                ca_cert: Some("cert".into()),
                disable_local_ca_jwt: false,
                domain_id: "did".into(),
                enabled: true,
                host: "http://host:post".into(),
                id: "id".into(),
                name: Some("name".into()),
            },
            res.instance,
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_get_forbidden() {
        let mut provider = Provider::mocked_builder();
        let mut mock = MockK8sAuthProvider::default();
        mock.expect_get_auth_instance()
            .withf(|_, id: &'_ str| id == "bar")
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
        provider = provider.k8s_auth(mock);
        let state = get_mocked_state(provider, false, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
