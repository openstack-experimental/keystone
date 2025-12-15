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

//! Federation attribute mapping: delete
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use mockall_double::double;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::federation::FederationApi;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// Delete attribute mapping.
#[utoipa::path(
    delete,
    path = "/{id}",
    operation_id = "/federation/mapping:delete",
    params(
      ("id" = String, Path, description = "The ID of the attribute mapping")
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Mapping not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="mappings"
)]
#[tracing::instrument(
    name = "api::mapping_delete",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn remove(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Path(id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_federation_provider()
        .get_mapping(&state, &id)
        .await?;

    policy
        .enforce(
            "identity/mapping_delete",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;
    if current.is_some() {
        state
            .provider
            .get_federation_provider()
            .delete_mapping(&state, &id)
            .await?;
    } else {
        return Err(KeystoneApiError::NotFound {
            resource: "mapping".to_string(),
            identifier: id.clone(),
        });
    }
    Ok((StatusCode::NO_CONTENT).into_response())
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

    use super::super::{openapi_router, tests::get_mocked_state};
    use crate::federation::{MockFederationProvider, types as provider_types};

    #[tokio::test]
    #[traced_test]
    async fn test_delete() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_get_mapping()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));
        federation_mock
            .expect_get_mapping()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(provider_types::Mapping {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                }))
            });
        federation_mock
            .expect_delete_mapping()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| Ok(()));

        let state = get_mocked_state(federation_mock, true);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/foo")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{:?}",
            response.into_body().collect().await.unwrap()
        );

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
