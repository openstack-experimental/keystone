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
//! # Group-scoped domain configuration API

use std::str::FromStr;

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
use openstack_keystone_core_types::domain_config::{
    DomainConfig, DomainConfigGroupName, DomainConfigUpdate,
};

/// Show a single configuration group of a domain.
#[utoipa::path(
    get,
    path = "/{domain_id}/config/{group}",
    responses(
        (status = OK, description = "Stored group", body = DomainConfigResponse),
        (status = 403, description = "Forbidden or unsupported group"),
        (status = 404, description = "Group not stored for the domain"),
    ),
    tag = "domain_config"
)]
#[tracing::instrument(
    name = "api::v3::domain_config_group_show",
    level = "debug",
    skip(state)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path((domain_id, group)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let group = DomainConfigGroupName::from_str(&group)?;

    state
        .policy_enforcer
        .enforce(
            "identity/domain_config/show",
            &user_auth,
            json!({"domain_id": domain_id, "group": group.as_str()}),
            None,
        )
        .await?;

    match state
        .provider
        .get_domain_config_provider()
        .get_domain_config_group(&state, &domain_id, group)
        .await?
    {
        Some(stored) => Ok((StatusCode::OK, Json(DomainConfigResponse::from(stored)))),
        None => Err(KeystoneApiError::NotFound {
            resource: format!("domain config group {}", group.as_str()),
            identifier: domain_id,
        }),
    }
}

/// Merge changes into a single configuration group of a domain.
#[utoipa::path(
    patch,
    path = "/{domain_id}/config/{group}",
    request_body = DomainConfigRequest,
    responses(
        (status = OK, description = "Resulting group", body = DomainConfigResponse),
        (status = 400, description = "Invalid configuration"),
        (status = 403, description = "Forbidden or unsupported group"),
        (status = 404, description = "Group not stored for the domain"),
    ),
    tag = "domain_config"
)]
#[tracing::instrument(
    name = "api::v3::domain_config_group_update",
    level = "debug",
    skip(state)
)]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path((domain_id, group)): Path<(String, String)>,
    State(state): State<ServiceState>,
    Json(req): Json<DomainConfigRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let group = DomainConfigGroupName::from_str(&group)?;
    let config = DomainConfig::from_value(req.config)?;
    config.validate()?;

    let policy_config = serde_json::to_value(&config)?;
    state
        .policy_enforcer
        .enforce(
            "identity/domain_config/update",
            &user_auth,
            json!({"domain_id": domain_id, "group": group.as_str(), "config": policy_config}),
            None,
        )
        .await?;

    let stored = state
        .provider
        .get_domain_config_provider()
        .update_domain_config_group(&state, &domain_id, group, DomainConfigUpdate::from(config))
        .await?;

    Ok((StatusCode::OK, Json(DomainConfigResponse::from(stored))))
}

/// Delete a single configuration group of a domain.
#[utoipa::path(
    delete,
    path = "/{domain_id}/config/{group}",
    responses(
        (status = 204, description = "Deleted"),
        (status = 403, description = "Forbidden or unsupported group"),
        (status = 404, description = "Group not stored for the domain"),
    ),
    tag = "domain_config"
)]
#[tracing::instrument(
    name = "api::v3::domain_config_group_delete",
    level = "debug",
    skip(state)
)]
pub(super) async fn remove(
    Auth(user_auth): Auth,
    Path((domain_id, group)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let group = DomainConfigGroupName::from_str(&group)?;

    state
        .policy_enforcer
        .enforce(
            "identity/domain_config/delete",
            &user_auth,
            json!({"domain_id": domain_id, "group": group.as_str()}),
            None,
        )
        .await?;

    state
        .provider
        .get_domain_config_provider()
        .delete_domain_config_group(&state, &domain_id, group)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use openstack_keystone_core_types::domain_config::DomainConfigGroupName;

    use super::super::test_support::*;

    fn ldap_group() -> openstack_keystone_core_types::domain_config::DomainConfigGroup {
        config(json!({"ldap": {"url": "ldap://stored"}}))
            .into_group(DomainConfigGroupName::Ldap)
            .expect("ldap group")
    }

    #[tokio::test]
    async fn test_show_allowed() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_get_domain_config_group()
            .returning(|_, _, _| Ok(Some(ldap_group())));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/did/config/ldap")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(res["config"]["ldap"]["url"], json!("ldap://stored"));
    }

    #[tokio::test]
    async fn test_show_unknown_group_forbidden() {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(no_backend_calls(), true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/did/config/bogus")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_show_forbidden() {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(no_backend_calls(), false).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/did/config/ldap")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_update_allowed() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_update_domain_config_group()
            .returning(|_, _, _, _| Ok(ldap_group()));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/did/config/ldap")
                    .extension(test_fixture_scoped())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"config":{"ldap":{"url":"ldap://in"}}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_update_forbidden() {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(no_backend_calls(), false).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/did/config/ldap")
                    .extension(test_fixture_scoped())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"config":{"ldap":{"url":"ldap://in"}}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_delete_allowed() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_delete_domain_config_group()
            .returning(|_, _, _| Ok(()));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/did/config/ldap")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_unauthorized() {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(no_backend_calls(), true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/did/config/ldap")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
