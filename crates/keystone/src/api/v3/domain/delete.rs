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
//! # Delete domain API
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::resource::ResourceApi;

/// Delete domain by ID.
#[utoipa::path(
    delete,
    path = "/{domain_id}",
    params(),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Domain not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    tag="domains"
)]
#[tracing::instrument(name = "api::v3::domain::delete", level = "debug", skip(state))]
pub(super) async fn remove(
    Auth(user_auth): Auth,
    Path(id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_resource_provider()
        .get_domain(&state, &id)
        .await?;

    state
        .policy_enforcer
        .enforce(
            "identity/resource/domain/delete",
            &user_auth,
            serde_json::Value::Null,
            Some(json!({"domain": current})),
        )
        .await?;

    match current {
        Some(_) => {
            state
                .provider
                .get_resource_provider()
                .delete_domain(&state, &id)
                .await?;
            Ok((StatusCode::NO_CONTENT).into_response())
        }
        _ => Err(KeystoneApiError::NotFound {
            resource: "domain".to_string(),
            identifier: id.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use openstack_keystone_core_types::resource::Domain as ProviderDomain;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, mocked_builder, test_fixture_scoped};

    use crate::resource::MockResourceProvider;

    #[tokio::test]
    #[traced_test]
    async fn test_delete() {
        let mut provider = mocked_builder();
        let mut mock = MockResourceProvider::default();
        mock.expect_get_domain()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));
        mock.expect_get_domain()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(ProviderDomain {
                    id: "id".into(),
                    enabled: true,
                    name: "domain_name".into(),
                    ..Default::default()
                }))
            });
        mock.expect_delete_domain()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| Ok(()));

        provider = provider.mock_resource(mock);
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/foo")
                    .extension(vsc.clone())
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
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_not_found_not_allowed() {
        let mut provider = mocked_builder();
        let mut mock = MockResourceProvider::default();
        mock.expect_get_domain()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        provider = provider.mock_resource(mock);
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(provider, false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/foo")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
