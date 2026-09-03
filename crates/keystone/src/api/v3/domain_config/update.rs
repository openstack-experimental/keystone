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
//! # Update domain configuration API

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use super::types::{DomainConfigRequest, DomainConfigResponse};
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core_types::domain_config::{DomainConfig, DomainConfigUpdate};

/// Merge changes into the whole configuration of a domain.
///
/// Options absent from the body keep their stored value.
#[utoipa::path(
    patch,
    path = "/{domain_id}/config",
    request_body = DomainConfigRequest,
    responses(
        (status = OK, description = "Resulting configuration", body = DomainConfigResponse),
        (status = 400, description = "Invalid configuration"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Domain has no configuration"),
    ),
    tag = "domain_config"
)]
#[tracing::instrument(name = "api::v3::domain_config_update", level = "debug", skip(state))]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<DomainConfigRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let config = DomainConfig::from_value(req.config)?;
    config.validate()?;

    let policy_config = serde_json::to_value(&config)?;
    state
        .policy_enforcer
        .enforce(
            "identity/domain_config/update",
            &user_auth,
            json!({"domain_id": domain_id, "config": policy_config}),
            None,
        )
        .await?;

    let stored = state
        .provider
        .get_domain_config_provider()
        .update_domain_config(&state, &domain_id, DomainConfigUpdate::from(config))
        .await?;

    Ok((StatusCode::OK, Json(DomainConfigResponse::from(stored))))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use openstack_keystone_core_types::domain_config::DomainConfigProviderError;

    use super::super::test_support::*;

    fn request(body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("PATCH")
            .uri("/did/config")
            .extension(test_fixture_scoped())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn test_allowed() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_update_domain_config()
            .returning(|_, _, _| Ok(config(json!({"ldap": {"url": "ldap://merged"}}))));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api
            .as_service()
            .oneshot(request(json!({"config": {"ldap": {"url": "ldap://in"}}})))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(res["config"]["ldap"]["url"], json!("ldap://merged"));
    }

    #[tokio::test]
    async fn test_not_found() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_update_domain_config().returning(|_, _, _| {
            Err(DomainConfigProviderError::NotFound {
                domain_id: "did".into(),
                group_or_option: "any options".into(),
            })
        });

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api
            .as_service()
            .oneshot(request(json!({"config": {"ldap": {"url": "ldap://in"}}})))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_forbidden() {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(no_backend_calls(), false).await);
        let response = api
            .as_service()
            .oneshot(request(json!({"config": {"ldap": {"url": "ldap://in"}}})))
            .await
            .unwrap();

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
                    .method("PATCH")
                    .uri("/did/config")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"config":{"ldap":{"url":"x"}}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
