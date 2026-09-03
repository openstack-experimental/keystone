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
//! # Show domain configuration API

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use super::types::DomainConfigResponse;
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Show the whole configuration of a domain.
#[utoipa::path(
    get,
    path = "/{domain_id}/config",
    responses(
        (status = OK, description = "Stored configuration", body = DomainConfigResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Domain has no configuration"),
    ),
    tag = "domain_config"
)]
#[tracing::instrument(name = "api::v3::domain_config_show", level = "debug", skip(state))]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/domain_config/show",
            &user_auth,
            json!({"domain_id": domain_id}),
            None,
        )
        .await?;

    match state
        .provider
        .get_domain_config_provider()
        .get_domain_config(&state, &domain_id)
        .await?
    {
        Some(config) => Ok((StatusCode::OK, Json(DomainConfigResponse::from(config)))),
        None => Err(KeystoneApiError::NotFound {
            resource: "domain config".to_string(),
            identifier: domain_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::test_support::*;

    fn authed() -> Request<Body> {
        Request::builder()
            .uri("/did/config")
            .extension(test_fixture_scoped())
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_allowed() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_get_domain_config()
            .returning(|_, _| Ok(Some(config(json!({"ldap": {"url": "ldap://stored"}})))));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api.as_service().oneshot(authed()).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(res["config"]["ldap"]["url"], json!("ldap://stored"));
    }

    #[tokio::test]
    async fn test_not_found() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_get_domain_config().returning(|_, _| Ok(None));

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
                    .uri("/did/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
