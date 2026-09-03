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
//! # Option-scoped domain configuration API

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
use openstack_keystone_core_types::domain_config::{DomainConfigGroupName, DomainConfigOption};

/// Show a single configuration option of a domain.
#[utoipa::path(
    get,
    path = "/{domain_id}/config/{group}/{option}",
    responses(
        (status = OK, description = "Stored option", body = DomainConfigResponse),
        (status = 403, description = "Forbidden or unsupported group"),
        (status = 404, description = "Option not stored for the domain"),
    ),
    tag = "domain_config"
)]
#[tracing::instrument(
    name = "api::v3::domain_config_option_show",
    level = "debug",
    skip(state)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path((domain_id, group, option)): Path<(String, String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let group = DomainConfigGroupName::from_str(&group)?;

    state
        .policy_enforcer
        .enforce(
            "identity/domain_config/show",
            &user_auth,
            json!({"domain_id": domain_id, "group": group.as_str(), "option": option}),
            None,
        )
        .await?;

    match state
        .provider
        .get_domain_config_provider()
        .get_domain_config_option(&state, &domain_id, group, &option)
        .await?
    {
        Some(stored) => Ok((StatusCode::OK, Json(DomainConfigResponse::from(stored)))),
        None => Err(KeystoneApiError::NotFound {
            resource: format!("domain config option {}/{option}", group.as_str()),
            identifier: domain_id,
        }),
    }
}

/// Set a single configuration option of a domain.
#[utoipa::path(
    patch,
    path = "/{domain_id}/config/{group}/{option}",
    request_body = DomainConfigRequest,
    responses(
        (status = OK, description = "Stored option", body = DomainConfigResponse),
        (status = 400, description = "Invalid configuration"),
        (status = 403, description = "Forbidden or unsupported group"),
    ),
    tag = "domain_config"
)]
#[tracing::instrument(
    name = "api::v3::domain_config_option_update",
    level = "debug",
    skip(state)
)]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path((domain_id, group, option)): Path<(String, String, String)>,
    State(state): State<ServiceState>,
    Json(req): Json<DomainConfigRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let group = DomainConfigGroupName::from_str(&group)?;

    let value = req
        .config
        .get(group.as_str())
        .and_then(|options| options.get(&option))
        .cloned()
        .ok_or_else(|| {
            KeystoneApiError::BadRequest(format!(
                "the config body must carry {}.{option}",
                group.as_str()
            ))
        })?;

    let to_store = DomainConfigOption::new(group, option.clone(), value);

    // The value may be sensitive (`ldap.password`); never place it in the
    // policy input (security model, invariant 6).
    state
        .policy_enforcer
        .enforce(
            "identity/domain_config/update",
            &user_auth,
            json!({"domain_id": domain_id, "group": group.as_str(), "option": option}),
            None,
        )
        .await?;

    let stored = state
        .provider
        .get_domain_config_provider()
        .update_domain_config_option(&state, &domain_id, to_store)
        .await?;

    Ok((StatusCode::OK, Json(DomainConfigResponse::from(stored))))
}

/// Delete a single configuration option of a domain.
#[utoipa::path(
    delete,
    path = "/{domain_id}/config/{group}/{option}",
    responses(
        (status = 204, description = "Deleted"),
        (status = 403, description = "Forbidden or unsupported group"),
        (status = 404, description = "Option not stored for the domain"),
    ),
    tag = "domain_config"
)]
#[tracing::instrument(
    name = "api::v3::domain_config_option_delete",
    level = "debug",
    skip(state)
)]
pub(super) async fn remove(
    Auth(user_auth): Auth,
    Path((domain_id, group, option)): Path<(String, String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let group = DomainConfigGroupName::from_str(&group)?;

    state
        .policy_enforcer
        .enforce(
            "identity/domain_config/delete",
            &user_auth,
            json!({"domain_id": domain_id, "group": group.as_str(), "option": option}),
            None,
        )
        .await?;

    state
        .provider
        .get_domain_config_provider()
        .delete_domain_config_option(&state, &domain_id, group, &option)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::domain_config::{DomainConfigGroupName, DomainConfigOption};

    use super::super::test_support::*;

    fn ldap_url_option() -> DomainConfigOption {
        DomainConfigOption::new(DomainConfigGroupName::Ldap, "url", "ldap://stored")
    }

    #[tokio::test]
    async fn test_show_allowed() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_get_domain_config_option()
            .returning(|_, _, _, _| Ok(Some(ldap_url_option())));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/did/config/ldap/url")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            res["config"]["ldap"]["url"],
            serde_json::json!("ldap://stored")
        );
    }

    #[tokio::test]
    async fn test_show_not_found() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_get_domain_config_option()
            .returning(|_, _, _, _| Ok(None));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/did/config/ldap/url")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_allowed() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_update_domain_config_option()
            .returning(|_, _, option| Ok(option));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/did/config/ldap/url")
                    .extension(test_fixture_scoped())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"config":{"ldap":{"url":"ldap://in"}}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(res["config"]["ldap"]["url"], serde_json::json!("ldap://in"));
    }

    #[tokio::test]
    async fn test_update_missing_value_bad_request() {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(no_backend_calls(), true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/did/config/ldap/url")
                    .extension(test_fixture_scoped())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"config":{"ldap":{"suffix":"dc=x"}}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
                    .uri("/did/config/ldap/url")
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
        mock.expect_delete_domain_config_option()
            .returning(|_, _, _, _| Ok(()));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/did/config/ldap/url")
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
                    .uri("/did/config/ldap/url")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
