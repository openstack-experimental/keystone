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
//! # Delete domain configuration API

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Delete the whole configuration of a domain.
#[utoipa::path(
    delete,
    path = "/{domain_id}/config",
    responses(
        (status = 204, description = "Deleted"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Domain has no configuration"),
    ),
    tag = "domain_config"
)]
#[tracing::instrument(name = "api::v3::domain_config_delete", level = "debug", skip(state))]
pub(super) async fn remove(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/domain_config/delete",
            &user_auth,
            json!({"domain_id": domain_id}),
            None,
        )
        .await?;

    state
        .provider
        .get_domain_config_provider()
        .delete_domain_config(&state, &domain_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::domain_config::DomainConfigProviderError;

    use super::super::test_support::*;

    fn authed() -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri("/did/config")
            .extension(test_fixture_scoped())
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_allowed() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_delete_domain_config().returning(|_, _| Ok(()));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api.as_service().oneshot(authed()).await.unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_not_found() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_delete_domain_config().returning(|_, _| {
            Err(DomainConfigProviderError::NotFound {
                domain_id: "did".into(),
                group_or_option: "any options".into(),
            })
        });

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api.as_service().oneshot(authed()).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_forbidden() {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(no_backend_calls(), false).await);
        let response = api.as_service().oneshot(authed()).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_unauthorized() {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(no_backend_calls(), true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/did/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
