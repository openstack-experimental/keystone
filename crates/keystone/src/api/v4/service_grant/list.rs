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
//! Service grant: list.

use axum::{
    Json,
    extract::{OriginalUri, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use validator::Validate;

use openstack_keystone_api_types::PaginationQuery;
use openstack_keystone_api_types::v4::service_grant::{
    ServiceGrant, ServiceGrantList, ServiceGrantListParameters,
};
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::policy::PolicyError;
use openstack_keystone_core_types::ListPagination;
use openstack_keystone_core_types::service_grant as provider_types;

use crate::api::auth::Auth;
use crate::api::common::{ResourceIdentifier, collect_authorized_page, paginate_forward_filtered};
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

impl ResourceIdentifier for ServiceGrant {
    fn get_id(&self) -> String {
        self.id.clone()
    }
}

/// List service grants.
///
/// Without `admin`, the caller must filter on itself (`user_id`), or on the
/// project (`project_id`) or domain (`domain_id`) it manages. Every
/// returned grant is re-checked against the show policy.
#[utoipa::path(
    get,
    path = "/",
    operation_id = "/service_grant:list",
    params(ServiceGrantListParameters, PaginationQuery),
    responses(
        (status = OK, description = "Service grants", body = ServiceGrantList),
    ),
    security(("x-auth" = [])),
    tag="service_grant"
)]
#[tracing::instrument(
    name = "api::v4::service_grant::list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<ServiceGrantListParameters>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    query.validate()?;

    state
        .policy_enforcer
        .enforce(
            "identity/service_grant/list",
            &user_auth,
            serde_json::json!({"service_grant": query}),
            None,
        )
        .await?;

    let config = state.config_manager.config.read().await;
    let base_params = provider_types::ServiceGrantListParameters::from(query);
    let limit = config.resolve_list_limit(&config.delegation.list_limit, pagination.limit);

    let provider = state.provider.get_service_grant_provider();
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
                    .list_service_grants(exec, &params)
                    .await?
                    .into_iter()
                    .map(ServiceGrant::from)
                    .collect())
            }
        },
        |item: ServiceGrant| async move {
            match enforcer
                .enforce(
                    "identity/service_grant/show",
                    auth,
                    serde_json::json!({"service_grant": null}),
                    Some(serde_json::json!({"service_grant": item})),
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

    let (service_grants, links) = paginate_forward_filtered(
        &config,
        &config.delegation.list_limit,
        page,
        &pagination,
        &original_url,
    )?;

    Ok((
        StatusCode::OK,
        Json(ServiceGrantList {
            service_grants,
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

    use openstack_keystone_api_types::v4::service_grant::ServiceGrantList;
    use openstack_keystone_core::auth::ValidatedSecurityContext;
    use openstack_keystone_core::policy::{PolicyEnforcer, PolicyError, PolicyEvaluationResult};

    use super::super::openapi_router;
    use super::super::tests::grant;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, get_state_with_policy, test_fixture_scoped,
    };
    use crate::provider::Provider;
    use crate::service_grant::MockServiceGrantProvider;

    fn grants(ids: &'static [&'static str]) -> MockServiceGrantProvider {
        let mut mock = MockServiceGrantProvider::default();
        mock.expect_list_service_grants()
            .returning(move |_, params| {
                Ok(ids
                    .iter()
                    .filter(|id| params.pagination.marker.as_deref().is_none_or(|m| **id > m))
                    .map(|id| grant(id))
                    .collect())
            });
        mock
    }

    async fn call(
        state: crate::keystone::ServiceState,
        req: Request<Body>,
    ) -> axum::response::Response {
        openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(req)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_list() {
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_service_grant(grants(&["a", "b"])))
                .await;
        let response = call(
            state,
            Request::builder()
                .uri("/?user_id=uid")
                .extension(test_fixture_scoped())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ServiceGrantList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.service_grants.len(), 2);

        let calls = policy.calls();
        assert_eq!(calls[0].policy_name, "identity/service_grant/list");
        assert_eq!(calls[0].target["service_grant"]["user_id"], "uid");
        crate::api::tests::policy_contract::assert_object_keys(
            &calls[0].target,
            &["service_grant"],
        );
        crate::api::tests::policy_contract::assert_existing_presence(&calls[0].existing, false);
        for call in &calls {
            crate::api::tests::policy_contract::assert_no_secrets(&call.target);
            if let Some(existing) = &call.existing {
                crate::api::tests::policy_contract::assert_no_secrets(existing);
            }
        }
        for call in calls
            .iter()
            .filter(|c| c.policy_name == "identity/service_grant/show")
        {
            crate::api::tests::policy_contract::assert_existing_presence(&call.existing, true);
            crate::api::tests::policy_contract::assert_object_keys(
                call.existing.as_ref().unwrap(),
                &["service_grant"],
            );
        }
        // One per-item re-check per returned grant.
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.policy_name == "identity/service_grant/show")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn test_list_policy_denied() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_service_grant(MockServiceGrantProvider::default()),
            false,
            None,
        )
        .await;
        let response = call(
            state,
            Request::builder()
                .uri("/")
                .extension(test_fixture_scoped())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_unauthorized() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_service_grant(MockServiceGrantProvider::default()),
            true,
            None,
        )
        .await;
        let response = call(
            state,
            Request::builder().uri("/").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Allows the collection check, forbids `forbidden` items and errors on
    /// `erroring` ones in the per-item re-check.
    struct SelectivePolicy {
        forbidden: &'static str,
        erroring: Option<&'static str>,
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
            if policy_name == "identity/service_grant/show" {
                let id = existing
                    .as_ref()
                    .and_then(|e| e["service_grant"]["id"].as_str())
                    .unwrap_or_default()
                    .to_string();
                if id == self.forbidden {
                    return Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()));
                }
                if Some(id.as_str()) == self.erroring {
                    return Err(PolicyError::IO(std::io::Error::other("opa unreachable")));
                }
            }
            Ok(PolicyEvaluationResult::allowed_admin())
        }

        async fn health_check(&self) -> Result<(), PolicyError> {
            Ok(())
        }
    }

    /// The per-item re-check drops grants the caller may not see.
    #[tokio::test]
    async fn test_list_filters_items_by_show_policy() {
        let state = get_state_with_policy(
            Provider::mocked_builder().mock_service_grant(grants(&["a", "b", "c"])),
            Arc::new(SelectivePolicy {
                forbidden: "b",
                erroring: None,
            }),
        )
        .await;
        let response = call(
            state,
            Request::builder()
                .uri("/?project_id=project_id")
                .extension(test_fixture_scoped())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ServiceGrantList = serde_json::from_slice(&body).unwrap();
        let ids: Vec<_> = res.service_grants.iter().map(|g| g.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "c"]);
    }

    /// A policy failure other than a denial fails the whole request.
    #[tokio::test]
    async fn test_list_propagates_policy_errors() {
        let state = get_state_with_policy(
            Provider::mocked_builder().mock_service_grant(grants(&["a", "b"])),
            Arc::new(SelectivePolicy {
                forbidden: "none",
                erroring: Some("b"),
            }),
        )
        .await;
        let response = call(
            state,
            Request::builder()
                .uri("/?project_id=project_id")
                .extension(test_fixture_scoped())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert!(response.status().is_server_error());
    }
}
