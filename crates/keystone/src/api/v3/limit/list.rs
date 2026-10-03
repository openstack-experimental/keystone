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
//! # List limits API
use axum::{
    Json,
    extract::{OriginalUri, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use openstack_keystone_api_types::PaginationQuery;
use openstack_keystone_core_types::ListPagination;

use super::types::{Limit, LimitList, LimitListParameters};
use crate::api::auth::Auth;
use crate::api::common::{collect_authorized_page, paginate_forward_filtered};
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::policy::PolicyError;

/// List limits.
///
/// Two-phase policy check (security model I8): `identity/limit/list` is
/// enforced first against the query filter, then every returned record is
/// individually re-checked against `identity/limit/show`. That check decides
/// what the caller sees: the system scope and the `admin` role see all
/// limits, a domain scope the limits of the domain and of its projects and a
/// project scope the limits of the project. Non `Forbidden` policy errors are
/// propagated.
#[utoipa::path(
    get,
    path = "/",
    params(LimitListParameters, PaginationQuery),
    description = "List limits",
    responses(
        (status = OK, description = "List of limits", body = LimitList),
        (status = 500, description = "Internal error")
    ),
    tag="limits"
)]
#[tracing::instrument(name = "api::limit_list", level = "debug", skip_all)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<LimitListParameters>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/limit/list",
            &user_auth,
            json!({"limit": query}),
            None,
        )
        .await?;

    let config = state.config_manager.config.read().await;
    let base_params = openstack_keystone_core_types::limit::LimitListParameters::from(query);
    let limit = config.resolve_list_limit(&config.limit.list_limit, pagination.limit);

    let provider = state.provider.get_limit_provider();
    let exec_ctx = ExecutionContext::from_auth(&state, &user_auth);
    let exec = &exec_ctx;
    let enforcer = &state.policy_enforcer;
    let auth = &user_auth;
    let state_ref = &state;

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
                    .list_limits(exec, &params)
                    .await?
                    .into_iter()
                    .map(Limit::from)
                    .collect())
            }
        },
        |item: Limit| async move {
            let existing = super::limit_policy_view(state_ref, exec, &item).await?;
            match enforcer
                .enforce(
                    "identity/limit/show",
                    auth,
                    serde_json::Value::Null,
                    Some(existing),
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

    let (limits, links) = paginate_forward_filtered(
        &config,
        &config.limit.list_limit,
        page,
        &pagination,
        &original_url,
    )?;

    Ok((StatusCode::OK, Json(LimitList { limits, links })).into_response())
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
    use openstack_keystone_core_types::resource::Project;

    use super::super::openapi_router;
    use super::*;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, get_state_with_policy, policy_contract,
        test_fixture_scoped,
    };
    use crate::limit::MockLimitProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    fn stored(id: &str, project_id: &str) -> provider_types::Limit {
        provider_types::Limit {
            description: None,
            domain_id: None,
            id: id.into(),
            project_id: Some(project_id.into()),
            region_id: None,
            resource_limit: 10,
            resource_name: "cores".into(),
            service_id: "srv".into(),
        }
    }

    fn resource_mock() -> MockResourceProvider {
        let mut resource = MockResourceProvider::default();
        resource.expect_get_project().returning(|_, id| {
            Ok(Some(Project {
                id: id.into(),
                domain_id: "d1".into(),
                ..Default::default()
            }))
        });
        resource
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

    /// Denies the per-item `show` check for the limits of the listed
    /// projects.
    struct SelectivePolicy {
        forbidden_projects: Vec<String>,
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
            if policy_name == "identity/limit/show" {
                let project = existing
                    .as_ref()
                    .and_then(|e| e["limit"]["project_id"].as_str())
                    .unwrap_or_default()
                    .to_string();
                if self.forbidden_projects.contains(&project) {
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
        mock.expect_list_limits()
            .withf(|_, p: &provider_types::LimitListParameters| {
                p.project_id.as_deref() == Some("p1") && p.domain_id.is_none()
            })
            .returning(|_, _| Ok(vec![stored("1", "p1"), stored("2", "p1")]));
        let (state, policy) = get_capturing_state(
            Provider::mocked_builder()
                .mock_limit(mock)
                .mock_resource(resource_mock()),
        )
        .await;

        let response = get(state, "/?project_id=p1", true).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: LimitList = serde_json::from_slice(&body).unwrap();
        assert_eq!(2, res.limits.len());

        let calls = policy.calls();
        assert_eq!(3, calls.len());
        assert_eq!("identity/limit/list", calls[0].policy_name);
        policy_contract::assert_object_keys(&calls[0].target, &["limit"]);
        policy_contract::assert_existing_presence(&calls[0].existing, false);
        for call in &calls[1..] {
            assert_eq!("identity/limit/show", call.policy_name);
            assert!(call.target.is_null());
            policy_contract::assert_existing_presence(&call.existing, true);
            assert_eq!(
                "d1",
                call.existing.as_ref().unwrap()["limit"]["project_domain_id"]
            );
        }
    }

    #[tokio::test]
    async fn test_list_omits_items_denied_by_show_policy() {
        let mut mock = MockLimitProvider::default();
        mock.expect_list_limits().returning(|_, _| {
            Ok(vec![
                stored("1", "p1"),
                stored("2", "p2"),
                stored("3", "p1"),
            ])
        });
        let state = get_state_with_policy(
            Provider::mocked_builder()
                .mock_limit(mock)
                .mock_resource(resource_mock()),
            Arc::new(SelectivePolicy {
                forbidden_projects: vec!["p2".into()],
            }),
        )
        .await;

        let response = get(state, "/", true).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: LimitList = serde_json::from_slice(&body).unwrap();
        let ids: Vec<_> = res.limits.iter().map(|l| l.id.as_str()).collect();
        assert_eq!(vec!["1", "3"], ids);
    }

    #[tokio::test]
    async fn test_list_pagination_link() {
        let mut mock = MockLimitProvider::default();
        mock.expect_list_limits()
            .withf(|_, p: &provider_types::LimitListParameters| p.pagination.limit == Some(2))
            .returning(|_, _| {
                Ok(vec![
                    stored("1", "p1"),
                    stored("2", "p1"),
                    stored("3", "p1"),
                ])
            });
        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_limit(mock)
                .mock_resource(resource_mock()),
            true,
            None,
        )
        .await;

        let response = get(state, "/?limit=2", true).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: LimitList = serde_json::from_slice(&body).unwrap();
        assert_eq!(2, res.limits.len());
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
