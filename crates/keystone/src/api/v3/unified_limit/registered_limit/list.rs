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
//! # List registered limits API
use axum::{
    Json,
    extract::{OriginalUri, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use openstack_keystone_api_types::PaginationQuery;
use openstack_keystone_core_types::ListPagination;

use super::types::{RegisteredLimit, RegisteredLimitList, RegisteredLimitListParameters};
use crate::api::auth::Auth;
use crate::api::common::{collect_authorized_page, paginate_forward_filtered};
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::policy::PolicyError;

/// List registered limits.
///
/// Two-phase policy check (security model I8): `identity/registered_limit/list`
/// is enforced first against the query filter, then every returned record is
/// individually re-checked against `identity/registered_limit/show`. Non
/// `Forbidden` policy errors are propagated.
#[utoipa::path(
    get,
    path = "/",
    params(RegisteredLimitListParameters, PaginationQuery),
    description = "List registered limits",
    responses(
        (status = OK, description = "List of registered limits", body = RegisteredLimitList),
        (status = 500, description = "Internal error")
    ),
    tag="limits"
)]
#[tracing::instrument(name = "api::v3::registered_limit_list", level = "debug", skip_all)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<RegisteredLimitListParameters>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/registered_limit/list",
            &user_auth,
            json!({"registered_limit": query}),
            None,
        )
        .await?;

    let config = state.config_manager.config.read().await;
    let base_params =
        openstack_keystone_core_types::limit::RegisteredLimitListParameters::from(query);
    let limit = config.resolve_list_limit(&config.limit.list_limit, pagination.limit);

    let provider = state.provider.get_limit_provider();
    let exec_ctx = ExecutionContext::from_auth(&state, &user_auth);
    let exec = &exec_ctx;
    let enforcer = &state.policy_enforcer;
    let auth = &user_auth;

    let page = collect_authorized_page(
        limit,
        pagination.marker.clone(),
        |marker| {
            let mut params = base_params.clone();
            params.pagination = ListPagination {
                limit,
                marker,
                page_reverse: false,
            };
            async move {
                Ok(provider
                    .list_registered_limits(exec, &params)
                    .await?
                    .into_iter()
                    .map(RegisteredLimit::from)
                    .collect())
            }
        },
        |item: RegisteredLimit| async move {
            match enforcer
                .enforce(
                    "identity/registered_limit/show",
                    auth,
                    serde_json::Value::Null,
                    Some(json!({"registered_limit": item})),
                )
                .await
            {
                Ok(_) => Ok(Some(item)),
                Err(PolicyError::Forbidden(_)) => Ok(None),
                Err(err) => Err(err.into()),
            }
        },
    )
    .await?;

    let (registered_limits, links) = paginate_forward_filtered(
        &config,
        &config.limit.list_limit,
        page,
        &pagination,
        &original_url,
    )?;

    Ok((
        StatusCode::OK,
        Json(RegisteredLimitList {
            registered_limits,
            links,
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core::auth::ValidatedSecurityContext;
    use openstack_keystone_core::policy::{PolicyEnforcer, PolicyEvaluationResult};
    use openstack_keystone_core_types::limit as provider_types;

    use super::super::openapi_router;
    use super::*;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, get_state_with_policy, policy_contract,
        test_fixture_scoped,
    };
    use crate::limit::MockLimitProvider;
    use crate::provider::Provider;

    fn stored(id: &str) -> provider_types::RegisteredLimit {
        provider_types::RegisteredLimit {
            default_limit: 10,
            description: None,
            id: id.into(),
            region_id: None,
            resource_name: "cores".into(),
            service_id: "srv".into(),
        }
    }

    async fn get(
        state: crate::keystone::ServiceState,
        uri: &'static str,
        auth: bool,
    ) -> axum::response::Response {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let mut request = Request::builder().uri(uri);
        if auth {
            request = request.extension(test_fixture_scoped());
        }
        api.as_service()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// Denies the per-item `show` check for the listed ids.
    struct SelectivePolicy {
        forbidden: Vec<String>,
    }

    #[async_trait::async_trait]
    impl PolicyEnforcer for SelectivePolicy {
        async fn enforce(
            &self,
            policy_name: &'static str,
            _credentials: &ValidatedSecurityContext,
            _target: serde_json::Value,
            existing: Option<serde_json::Value>,
        ) -> Result<PolicyEvaluationResult, PolicyError> {
            if policy_name == "identity/registered_limit/show" {
                let id = existing
                    .as_ref()
                    .and_then(|e| e["registered_limit"]["id"].as_str())
                    .unwrap_or_default()
                    .to_string();
                if self.forbidden.contains(&id) {
                    return Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()));
                }
            }
            Ok(PolicyEvaluationResult::allowed_admin())
        }

        async fn health_check(&self) -> Result<(), PolicyError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_list() {
        let mut mock = MockLimitProvider::default();
        mock.expect_list_registered_limits()
            .withf(|_, p: &provider_types::RegisteredLimitListParameters| {
                p.service_id.as_deref() == Some("srv") && p.resource_name.is_none()
            })
            .returning(|_, _| Ok(vec![stored("1"), stored("2")]));
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_limit(mock)).await;

        let response = get(state, "/?service_id=srv", true).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RegisteredLimitList = serde_json::from_slice(&body).unwrap();
        assert_eq!(2, res.registered_limits.len());

        // One collection check followed by one `show` check per item.
        let calls = policy.calls();
        assert_eq!(3, calls.len());
        assert_eq!("identity/registered_limit/list", calls[0].policy_name);
        policy_contract::assert_object_keys(&calls[0].target, &["registered_limit"]);
        policy_contract::assert_existing_presence(&calls[0].existing, false);
        for call in &calls[1..] {
            assert_eq!("identity/registered_limit/show", call.policy_name);
            assert!(call.target.is_null());
            policy_contract::assert_existing_presence(&call.existing, true);
        }
    }

    #[tokio::test]
    async fn test_list_omits_items_denied_by_show_policy() {
        let mut mock = MockLimitProvider::default();
        mock.expect_list_registered_limits()
            .returning(|_, _| Ok(vec![stored("1"), stored("2"), stored("3")]));
        let state = get_state_with_policy(
            Provider::mocked_builder().mock_limit(mock),
            Arc::new(SelectivePolicy {
                forbidden: vec!["2".into()],
            }),
        )
        .await;

        let response = get(state, "/", true).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RegisteredLimitList = serde_json::from_slice(&body).unwrap();
        let ids: Vec<_> = res
            .registered_limits
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(vec!["1", "3"], ids);
    }

    #[tokio::test]
    async fn test_list_pagination_link() {
        let mut mock = MockLimitProvider::default();
        mock.expect_list_registered_limits()
            .withf(|_, p: &provider_types::RegisteredLimitListParameters| {
                p.pagination.limit == Some(2)
            })
            .returning(|_, _| Ok(vec![stored("1"), stored("2"), stored("3")]));
        let state = get_mocked_state(Provider::mocked_builder().mock_limit(mock), true, None).await;

        let response = get(state, "/?limit=2", true).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: RegisteredLimitList = serde_json::from_slice(&body).unwrap();
        assert_eq!(2, res.registered_limits.len());
        assert!(res.links.is_some());
    }

    #[tokio::test]
    async fn test_list_forbidden() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        assert_eq!(get(state, "/", true).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        assert_eq!(
            get(state, "/", false).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
