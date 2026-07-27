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
//! Mapping ruleset: list.

use axum::{
    Json,
    extract::{OriginalUri, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use openstack_keystone_api_types::PaginationQuery;
use openstack_keystone_api_types::v4::mapping::{
    MappingRuleSet, MappingRuleSetList, MappingRuleSetListParameters,
};
use openstack_keystone_core_types::ListPagination;
use openstack_keystone_core_types::mapping::MappingRuleSetListParameters as ProviderMappingRuleSetListParameters;

use crate::api::auth::Auth;
use crate::api::common::{ResourceIdentifier, paginate_bidirectional};
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

impl ResourceIdentifier for MappingRuleSet {
    fn get_id(&self) -> String {
        self.mapping_id.clone()
    }
}

/// List mapping rulesets.
#[utoipa::path(
    get,
    path = "/",
    operation_id = "/mapping_ruleset:list",
    params(MappingRuleSetListParameters, PaginationQuery),
    responses(
        (status = OK, description = "List of rulesets", body = MappingRuleSetList),
    ),
    security(("x-auth" = [])),
    tag="mapping_ruleset"
)]
#[tracing::instrument(
    name = "api::v4::mapping::ruleset::list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<MappingRuleSetListParameters>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let res = state
        .policy_enforcer
        .enforce(
            "identity/mapping/ruleset/list",
            &user_auth,
            json!({"mapping": query}),
            None,
        )
        .await?;

    let config = state.config_manager.config.read().await;
    let mut provider_list_params: ProviderMappingRuleSetListParameters = query.into();

    if provider_list_params.domain_id.is_none()
        && !res.can_see_other_domain_resources.is_some_and(|x| x)
    {
        provider_list_params.domain_id = user_auth.principal().domain_id();
    }
    provider_list_params.pagination = ListPagination {
        limit: config.resolve_list_limit(&config.mapping.list_limit, pagination.limit),
        marker: pagination.marker.clone(),
        page_reverse: pagination.page_reverse,
    };

    let rulesets: Vec<MappingRuleSet> = state
        .provider
        .get_mapping_provider()
        .list_rulesets(
            &ExecutionContext::from_auth(&state, &user_auth),
            &provider_list_params,
        )
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    let (mappings, links) =
        paginate_bidirectional(&config, rulesets, &pagination, original_url.path())?;

    Ok((StatusCode::OK, Json(MappingRuleSetList { mappings, links })).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_api_types::v4::mapping::MappingRuleSetList;
    use openstack_keystone_core_types::mapping as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::mapping::MockMappingProvider;
    use crate::provider::Provider;

    fn sample_ruleset_core() -> provider_types::MappingRuleSet {
        provider_types::MappingRuleSet {
            mapping_id: "test-ruleset".into(),
            domain_id: Some("domain_id".into()),
            source: provider_types::IdentitySource::Federation {
                idp_id: "okta".into(),
            },
            domain_resolution_mode: provider_types::DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![],
            ruleset_version: 1,
        }
    }

    #[tokio::test]
    async fn test_list() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockMappingProvider::default();
        mock.expect_list_rulesets()
            .returning(|_, _| Ok(vec![sample_ruleset_core()]));
        provider = provider.mock_mapping(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

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
        let res: MappingRuleSetList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.mappings.len(), 1);
        assert_eq!(res.mappings[0].mapping_id, "test-ruleset");
    }

    fn ruleset_with_mapping_id(mapping_id: &str) -> provider_types::MappingRuleSet {
        provider_types::MappingRuleSet {
            mapping_id: mapping_id.into(),
            ..sample_ruleset_core()
        }
    }

    /// Backend over-fetched (returned `limit + 1 == 2` rows), not the first
    /// page (`marker` set): both `next` and `previous` links are produced,
    /// and the extra row is trimmed from the response body.
    #[tokio::test]
    async fn test_list_pagination_bidirectional_links() {
        let vsc = test_fixture_scoped();
        let mut mock = MockMappingProvider::default();
        mock.expect_list_rulesets()
            .withf(|_, qp: &provider_types::MappingRuleSetListParameters| {
                qp.pagination.limit == Some(1) && qp.pagination.marker == Some("m".into())
            })
            .returning(|_, _| {
                Ok(vec![
                    ruleset_with_mapping_id("ruleset-1"),
                    ruleset_with_mapping_id("ruleset-2"),
                ])
            });
        let provider = Provider::mocked_builder().mock_mapping(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?limit=1&marker=m")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: MappingRuleSetList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.mappings.len(), 1);
        assert_eq!(res.mappings[0].mapping_id, "ruleset-1");
        let links = res.links.expect("expected next+previous links");
        assert!(links.iter().any(|l| l.rel == "next"));
        assert!(links.iter().any(|l| l.rel == "previous"));
    }

    /// Backend returned exactly `limit` rows (no over-fetched extra row): no
    /// `next` link should be produced.
    #[tokio::test]
    async fn test_list_pagination_no_false_positive_next() {
        let vsc = test_fixture_scoped();
        let mut mock = MockMappingProvider::default();
        mock.expect_list_rulesets()
            .withf(|_, qp: &provider_types::MappingRuleSetListParameters| {
                qp.pagination.limit == Some(1)
            })
            .returning(|_, _| Ok(vec![sample_ruleset_core()]));
        let provider = Provider::mocked_builder().mock_mapping(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

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
        let res: MappingRuleSetList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.mappings.len(), 1);
        assert_eq!(res.links, None);
    }

    #[tokio::test]
    async fn test_list_policy_denied() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_mapping(MockMappingProvider::default()),
            false,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_unauthorized() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_mapping(MockMappingProvider::default()),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
