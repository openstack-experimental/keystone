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

use axum::{
    Json,
    extract::{OriginalUri, Query, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::PaginationQuery;
use openstack_keystone_core_types::ListPagination;

use super::types::{Policy, PolicyList, PolicyListParameters};
use crate::api::auth::Auth;
use crate::api::common::{collect_authorized_page, paginate_forward_filtered};
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::policy::PolicyError;

/// List policies.
///
/// Two-phase policy check (security model I8): `identity/policy/list` is
/// enforced first against the query filter, then **every** returned record is
/// individually re-checked against `identity/policy/show` using that record's
/// own identifiers, dropping the ones the caller may not read. A policy error
/// that is not `Forbidden` (OPA unreachable, malformed decision, ...) is
/// propagated rather than silently filtering the item out — failing closed on
/// the request instead of returning a quietly truncated collection.
///
/// Pagination follows this repository's ADR 0029 `limit`/`marker` + `links`
/// model. Python keystone instead truncates to `[DEFAULT] list_limit` and sets
/// a `truncated` flag; that is a deliberate, documented deviation, consistent
/// with every other collection endpoint here.
#[utoipa::path(
    get,
    path = "/",
    params(PolicyListParameters, PaginationQuery),
    description = "List policies",
    responses(
        (status = OK, description = "List of policies", body = PolicyList),
        (status = 500, description = "Internal error")
    ),
    tag="policies"
)]
#[tracing::instrument(
    name = "api::policy_list",
    level = "debug",
    skip_all,
    fields(policy_type = query.r#type.as_deref().unwrap_or("*"))
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<PolicyListParameters>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/policy/list",
            &user_auth,
            super::policy_input(query.to_policy_input()),
            None,
        )
        .await?;

    let config = state.config_manager.config.read().await;
    let base_params =
        openstack_keystone_core_types::policy_store::PolicyListParameters::from(query);
    let limit = config.resolve_list_limit(&config.policy.list_limit, pagination.limit);

    let provider = state.provider.get_policy_store_provider();
    // Bind by reference: `collect_authorized_page` takes `FnMut`, so the
    // per-batch future must capture a `Copy` handle rather than move the
    // context out of the closure.
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
                    .list_policies(exec, &params)
                    .await?
                    .into_iter()
                    .map(Policy::from)
                    .collect())
            }
        },
        |item: Policy| async move {
            match enforcer
                .enforce(
                    "identity/policy/show",
                    auth,
                    serde_json::Value::Null,
                    Some(super::policy_input(item.to_policy_input())),
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

    let (policies, links) = paginate_forward_filtered(
        &config,
        &config.policy.list_limit,
        page,
        &pagination,
        &original_url,
    )?;

    Ok((StatusCode::OK, Json(PolicyList { policies, links })).into_response())
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
    use openstack_keystone_core::policy::{PolicyEnforcer, PolicyError, PolicyEvaluationResult};
    use openstack_keystone_core_types::policy_store::{PolicyBuilder, PolicyListParameters};

    use super::super::openapi_router;
    use crate::api::tests::{
        get_capturing_state, get_mocked_state, get_state_with_policy, policy_contract,
        test_fixture_scoped,
    };
    use crate::api::v3::policy::types::PolicyList;
    use crate::policy_store::MockPolicyStoreProvider;
    use crate::provider::Provider;

    fn stored(id: &str) -> openstack_keystone_core_types::policy_store::Policy {
        PolicyBuilder::default()
            .id(id)
            .r#type("application/json")
            .blob(serde_json::Value::String(format!("blob-{id}")))
            .build()
            .unwrap()
    }

    /// A `PolicyEnforcer` that allows the collection check but decides each
    /// per-item `show` check by policy id, so the I8 re-check can be tested
    /// for both filtering and error propagation.
    struct SelectivePolicy {
        /// Ids whose `show` check is denied with `Forbidden`.
        forbidden: Vec<String>,
        /// Ids whose `show` check fails with a non-`Forbidden` error.
        erroring: Vec<String>,
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
            if policy_name == "identity/policy/show" {
                let id = existing
                    .as_ref()
                    .and_then(|e| e["policy"]["id"].as_str())
                    .unwrap_or_default()
                    .to_string();
                if self.erroring.contains(&id) {
                    return Err(PolicyError::IO(std::io::Error::other("opa unreachable")));
                }
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

    async fn list_with(
        policy: SelectivePolicy,
        stored_ids: &'static [&'static str],
    ) -> axum::response::Response {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_list_policies()
            .returning(|_, _| Ok(stored_ids.iter().map(|id| stored(id)).collect()));

        let vsc = test_fixture_scoped();
        let state = get_state_with_policy(
            Provider::mocked_builder().mock_policy_store(mock),
            Arc::new(policy),
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        api.as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_list() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_list_policies()
            .withf(|_, _: &PolicyListParameters| true)
            .returning(|_, _| Ok(vec![stored("1")]));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_policy_store(mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: PolicyList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.policies.len(), 1);
        assert_eq!(res.policies[0].id, "1");
        assert_eq!(res.policies[0].blob, serde_json::json!("blob-1"));
    }

    /// `?type=` must reach the provider as an exact-match filter.
    #[tokio::test]
    async fn test_list_type_filter_reaches_provider() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_list_policies()
            .withf(|_, qp: &PolicyListParameters| qp.r#type == Some("application/json".into()))
            .returning(|_, _| Ok(Vec::new()));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_policy_store(mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?type=application%2Fjson")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_list_unauth() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_forbidden() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(test_fixture_scoped())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Security model I8: one collection check, then exactly one per-item
    /// `show` check for every candidate, each keyed on that record's own
    /// identifiers under `existing`.
    #[tokio::test]
    async fn test_list_runs_one_show_check_per_item() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_list_policies()
            .returning(|_, _| Ok(vec![stored("1"), stored("2"), stored("3")]));

        let vsc = test_fixture_scoped();
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_policy_store(mock)).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let calls = policy.calls();
        assert_eq!(calls.len(), 4, "1 collection check + 3 per-item checks");

        assert_eq!(calls[0].policy_name, "identity/policy/list");
        policy_contract::assert_object_keys(&calls[0].target, &["policy"]);
        policy_contract::assert_existing_presence(&calls[0].existing, false);
        policy_contract::assert_no_secrets(&calls[0].target);

        for (i, expected_id) in ["1", "2", "3"].iter().enumerate() {
            let call = &calls[i + 1];
            assert_eq!(call.policy_name, "identity/policy/show");
            assert_eq!(call.target, serde_json::Value::Null);
            policy_contract::assert_existing_presence(&call.existing, true);
            let existing = call.existing.as_ref().unwrap();
            policy_contract::assert_object_keys(existing, &["policy"]);
            policy_contract::assert_no_secrets(existing);
            assert_eq!(existing["policy"]["id"], *expected_id);
            assert!(
                !existing.to_string().contains("blob"),
                "per-item input must not carry the document: {existing}"
            );
        }
    }

    /// Items the per-item `show` policy denies are omitted from the
    /// collection (CVE-2019-19687 class).
    #[tokio::test]
    async fn test_list_omits_items_denied_by_show_policy() {
        let response = list_with(
            SelectivePolicy {
                forbidden: vec!["2".into()],
                erroring: Vec::new(),
            },
            &["1", "2", "3"],
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: PolicyList = serde_json::from_slice(&body).unwrap();
        let ids: Vec<&str> = res.policies.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["1", "3"], "denied item must be omitted");
    }

    /// A non-`Forbidden` policy failure must not be mistaken for "deny this
    /// item": it fails the whole request instead of silently truncating.
    #[tokio::test]
    async fn test_list_propagates_non_forbidden_policy_errors() {
        let response = list_with(
            SelectivePolicy {
                forbidden: Vec::new(),
                erroring: vec!["2".into()],
            },
            &["1", "2", "3"],
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_list_pagination_link() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_list_policies()
            .withf(|_, qp: &PolicyListParameters| qp.pagination.limit == Some(1))
            .returning(|_, _| Ok(vec![stored("1"), stored("2")]));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_policy_store(mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?limit=1")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: PolicyList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.policies.len(), 1);
        assert_eq!(res.policies[0].id, "1");
        assert!(res.links.is_some());
    }

    /// The per-item filter must not truncate pagination: with `limit=2` and a
    /// denied row in the first batch, the handler keeps pulling batches until
    /// it has `limit + 1` *visible* items, so a full page and a `next` link
    /// are still produced. Before the fill loop this returned a short page
    /// with no `next`, stranding every remaining visible policy.
    #[tokio::test]
    async fn test_list_refills_page_when_items_are_filtered_out() {
        // Backend pages of 3 (limit + 1).
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_list_policies().returning(|_, params| {
            let after = params.pagination.marker.clone();
            let all = ["1", "2", "3", "4", "5", "6", "7"];
            let start = match after {
                None => 0,
                Some(m) => all.iter().position(|id| *id == m).map_or(0, |i| i + 1),
            };
            Ok(all
                .iter()
                .skip(start)
                .take(3)
                .map(|id| stored(id))
                .collect())
        });

        let vsc = test_fixture_scoped();
        let state = get_state_with_policy(
            Provider::mocked_builder().mock_policy_store(mock),
            Arc::new(SelectivePolicy {
                forbidden: vec!["1".into()],
                erroring: Vec::new(),
            }),
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?limit=2")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: PolicyList = serde_json::from_slice(&body).unwrap();

        let ids: Vec<&str> = res.policies.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["2", "3"],
            "the page must be filled with visible items past the denied row"
        );
        assert!(
            res.links.is_some(),
            "more visible policies remain, so a next link is required"
        );
    }

    /// When denied rows exhaust the `limit * AUTHORIZED_PAGE_SCAN_FACTOR`
    /// examine budget before the page fills, the response is deliberately
    /// short — but it must still carry a `next` link, or the caller would read
    /// the short page as the end of the collection and lose the tail. The
    /// budget is what stops a sparse-visibility caller from forcing a full
    /// table scan.
    #[tokio::test]
    async fn test_list_short_page_still_links_when_scan_budget_exhausted() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_list_policies().returning(|_, params| {
            let after = params.pagination.marker.clone();
            let all = ["1", "2", "3", "4", "5", "6", "7"];
            let start = match after {
                None => 0,
                Some(m) => all.iter().position(|id| *id == m).map_or(0, |i| i + 1),
            };
            Ok(all
                .iter()
                .skip(start)
                .take(3)
                .map(|id| stored(id))
                .collect())
        });

        let vsc = test_fixture_scoped();
        let state = get_state_with_policy(
            Provider::mocked_builder().mock_policy_store(mock),
            Arc::new(SelectivePolicy {
                // limit=2 gives a budget of 4 examined rows; three denials
                // leave room for only one authorized item.
                forbidden: vec!["1".into(), "2".into(), "3".into()],
                erroring: Vec::new(),
            }),
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?limit=2")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: PolicyList = serde_json::from_slice(&body).unwrap();

        let ids: Vec<&str> = res.policies.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["4"], "the budget cut the scan short");
        let links = res
            .links
            .expect("a truncated scan must still advertise a next link");
        assert!(
            links[0].href.contains("marker=4"),
            "keyed on the last authorized item: {}",
            links[0].href
        );
    }

    /// A `next` link must keep the collection's resource filters: dropping
    /// `?type=` would silently widen page 2 from the filtered collection to
    /// the unfiltered one.
    #[tokio::test]
    async fn test_list_pagination_link_preserves_type_filter() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_list_policies()
            .returning(|_, _| Ok(vec![stored("1"), stored("2")]));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_policy_store(mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?type=application%2Fjson&limit=1")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: PolicyList = serde_json::from_slice(&body).unwrap();

        let links = res.links.expect("a next link is produced");
        let next = links
            .iter()
            .find(|l| l.rel == "next")
            .expect("next link present");
        assert!(
            next.href.contains("type=application%2Fjson"),
            "next link must keep the type filter: {}",
            next.href
        );
        assert!(next.href.contains("marker=1"), "next link: {}", next.href);
    }

    #[tokio::test]
    async fn test_list_pagination_no_false_positive_next() {
        let mut mock = MockPolicyStoreProvider::default();
        mock.expect_list_policies()
            .withf(|_, qp: &PolicyListParameters| qp.pagination.limit == Some(1))
            .returning(|_, _| Ok(vec![stored("1")]));

        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_policy_store(mock),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?limit=1")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: PolicyList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.policies.len(), 1);
        assert_eq!(res.links, None);
    }
}
