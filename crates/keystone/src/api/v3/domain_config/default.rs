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
//! # Default domain configuration API
//!
//! The global defaults a domain without its own configuration falls back to.
//! Read-only, and served from the running service configuration rather than
//! from storage.

use std::str::FromStr;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::{Value, json};

use super::types::DomainConfigResponse;
use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core_types::domain_config::DomainConfigGroupName;

/// Show every group's defaults.
#[utoipa::path(
    get,
    path = "/config/default",
    responses(
        (status = OK, description = "Default configuration", body = DomainConfigResponse),
        (status = 403, description = "Forbidden"),
    ),
    tag = "domain_config"
)]
#[tracing::instrument(name = "api::v3::domain_config_default", level = "debug", skip(state))]
pub(super) async fn show(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/domain_config/get_default",
            &user_auth,
            Value::Null,
            None,
        )
        .await?;

    let defaults = state
        .provider
        .get_domain_config_provider()
        .get_default_config(&state)
        .await?;

    Ok((StatusCode::OK, Json(DomainConfigResponse::from(defaults))))
}

/// Show one group's defaults.
#[utoipa::path(
    get,
    path = "/config/{group}/default",
    responses(
        (status = OK, description = "Default group", body = DomainConfigResponse),
        (status = 403, description = "Forbidden or unsupported group"),
    ),
    tag = "domain_config"
)]
#[tracing::instrument(
    name = "api::v3::domain_config_default_group",
    level = "debug",
    skip(state)
)]
pub(super) async fn show_group(
    Auth(user_auth): Auth,
    Path(group): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let group = DomainConfigGroupName::from_str(&group)?;

    state
        .policy_enforcer
        .enforce(
            "identity/domain_config/get_default",
            &user_auth,
            json!({"group": group.as_str()}),
            None,
        )
        .await?;

    let defaults = state
        .provider
        .get_domain_config_provider()
        .get_default_group(&state, group)
        .await?;

    Ok((StatusCode::OK, Json(DomainConfigResponse::from(defaults))))
}

/// Show one option's default.
#[utoipa::path(
    get,
    path = "/config/{group}/{option}/default",
    responses(
        (status = OK, description = "Default option", body = DomainConfigResponse),
        (status = 403, description = "Forbidden or unsupported option"),
    ),
    tag = "domain_config"
)]
#[tracing::instrument(
    name = "api::v3::domain_config_default_option",
    level = "debug",
    skip(state)
)]
pub(super) async fn show_option(
    Auth(user_auth): Auth,
    Path((group, option)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let group = DomainConfigGroupName::from_str(&group)?;

    state
        .policy_enforcer
        .enforce(
            "identity/domain_config/get_default",
            &user_auth,
            json!({"group": group.as_str(), "option": option}),
            None,
        )
        .await?;

    let response = match state
        .provider
        .get_domain_config_provider()
        .get_default_option(&state, group, &option)
        .await?
    {
        Some(stored) => DomainConfigResponse::from(stored),
        // python-keystone reports a whitelisted option with no configured
        // default as a `null` value rather than a 404.
        None => DomainConfigResponse {
            config: json!({ group.as_str(): { &option: Value::Null } }),
        },
    };

    Ok((StatusCode::OK, Json(response)))
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::domain_config::{DomainConfigGroupName, DomainConfigOption};

    use super::super::test_support::*;

    #[tokio::test]
    async fn test_default_allowed() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_get_default_config()
            .returning(|_| Ok(config(serde_json::json!({"identity": {"driver": "sql"}}))));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/config/default")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_default_forbidden() {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(no_backend_calls(), false).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/config/default")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_default_unauthorized() {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(no_backend_calls(), true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/config/default")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_default_group_allowed() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_get_default_group().returning(|_, _| {
            Ok(
                config(serde_json::json!({"ldap": {"url": "ldap://default"}}))
                    .into_group(DomainConfigGroupName::Ldap)
                    .expect("ldap group"),
            )
        });

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/config/ldap/default")
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
            serde_json::json!("ldap://default")
        );
    }

    #[tokio::test]
    async fn test_default_option_null_when_unset() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_get_default_option()
            .returning(|_, _, _| Ok(None));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/config/ldap/url/default")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(res["config"]["ldap"]["url"].is_null());
    }

    #[tokio::test]
    async fn test_default_option_value() {
        let mut mock = MockDomainConfigProvider::default();
        mock.expect_get_default_option()
            .returning(|_, group, option| {
                Ok(Some(DomainConfigOption::new(
                    group,
                    option.to_string(),
                    "ldap",
                )))
            });

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state(mock, true).await);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/config/identity/driver/default")
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
            res["config"]["identity"]["driver"],
            serde_json::json!("ldap")
        );
    }
}
