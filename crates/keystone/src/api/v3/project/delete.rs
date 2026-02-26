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
//! # Delete project API
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::resource::ResourceApi;

/// Delete project by ID.
#[utoipa::path(
    delete,
    path = "/{project_id}",
    params(),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Project not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="projects"
)]
#[tracing::instrument(name = "api::v3::project::delete", level = "debug", skip(state))]
pub async fn remove(
    Auth(user_auth): Auth,
    Path(id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_resource_provider()
        .get_project(&state, &id)
        .await?;

    if current.is_some() {
        state
            .provider
            .get_resource_provider()
            .delete_project(&state, &id)
            .await?;
    } else {
        return Err(KeystoneApiError::NotFound {
            resource: "project".to_string(),
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
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use super::super::openapi_router;
    use crate::api::tests::get_mocked_state;
    use crate::provider::Provider;
    use crate::resource::{MockResourceProvider, types as provider_types};

    #[tokio::test]
    #[traced_test]
    async fn test_delete() {
        let mut provider = Provider::mocked_builder();
        let mut mock = MockResourceProvider::default();
        mock.expect_get_project()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));
        mock.expect_get_project()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(provider_types::Project {
                    id: "id".into(),
                    domain_id: "did".into(),
                    ..Default::default()
                }))
            });
        mock.expect_delete_project()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| Ok(()));

        provider = provider.resource(mock);
        let state = get_mocked_state(provider, true, None);

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

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

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
