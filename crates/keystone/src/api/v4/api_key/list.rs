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
//! API Key: list.

use axum::{
    Json,
    extract::{OriginalUri, Query, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::PaginationQuery;
use openstack_keystone_api_types::v4::api_key::{ApiKey, ApiKeyList, ApiKeyListParameters};
use openstack_keystone_core_types::ListPagination;
use openstack_keystone_core_types::api_key::ApiClientResourceListParameters;

use crate::api::auth::Auth;
use crate::api::common::{ResourceIdentifier, paginate_bidirectional};
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

impl ResourceIdentifier for ApiKey {
    fn get_id(&self) -> String {
        self.client_id.clone()
    }
}

/// List API Keys.
///
/// `domain_id` is a mandatory filter (ADR 0021 §5.B): unlike mapping
/// rulesets, API Keys are always domain-owned, so there is no "global" or
/// "all visible domains" listing mode.
#[utoipa::path(
    get,
    path = "/",
    operation_id = "/api_key:list",
    params(ApiKeyListParameters, PaginationQuery),
    responses(
        (status = OK, description = "List of API Keys", body = ApiKeyList),
    ),
    security(("x-auth" = [])),
    tag="api_key"
)]
#[tracing::instrument(
    name = "api::v4::api_key::list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<ApiKeyListParameters>,
    Query(pagination): Query<PaginationQuery>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/api_key/list",
            &user_auth,
            serde_json::json!({"api_key": query}),
            None,
        )
        .await?;

    let config = state.config_manager.config.read().await;
    let mut params: ApiClientResourceListParameters = query.into();
    params.pagination = ListPagination {
        limit: config.resolve_list_limit(&config.api_key.list_limit, pagination.limit),
        marker: pagination.marker.clone(),
        page_reverse: pagination.page_reverse,
    };

    let keys: Vec<ApiKey> = state
        .provider
        .get_api_key_provider()
        .list(&state, &params)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    let (api_keys, links) =
        paginate_bidirectional(&config, keys, &pagination, original_url.path())?;

    Ok((StatusCode::OK, Json(ApiKeyList { api_keys, links })).into_response())
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

    use openstack_keystone_api_types::v4::api_key::ApiKeyList;
    use openstack_keystone_core_types::api_key as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api_key::MockApiKeyProvider;
    use crate::provider::Provider;

    fn sample_resource_core() -> provider_types::ApiClientResource {
        provider_types::ApiClientResource {
            domain_id: "domain_id".into(),
            provider_id: "provider-1".into(),
            client_id: "client-1".into(),
            lookup_hash: "lookup-hash".into(),
            secret_hash: "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA".into(),
            allowed_ips: None,
            description: None,
            enabled: true,
            created_at: 1_000,
            expires_at: 2_000,
            last_used_at: None,
            revoked_at: None,
            revoked_by: None,
        }
    }

    #[tokio::test]
    async fn test_list() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockApiKeyProvider::default();
        mock.expect_list()
            .returning(|_, _| Ok(vec![sample_resource_core()]));
        provider = provider.mock_api_key(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?domain_id=domain_id")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApiKeyList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.api_keys.len(), 1);
        assert_eq!(res.api_keys[0].client_id, "client-1");
    }

    fn resource_with_client_id(client_id: &str) -> provider_types::ApiClientResource {
        provider_types::ApiClientResource {
            client_id: client_id.into(),
            ..sample_resource_core()
        }
    }

    /// Backend over-fetched (returned `limit + 1 == 2` rows), not the first
    /// page (`marker` set): both `next` and `previous` links are produced,
    /// and the extra row is trimmed from the response body.
    #[tokio::test]
    async fn test_list_pagination_bidirectional_links() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockApiKeyProvider::default();
        mock.expect_list()
            .withf(|_, qp: &provider_types::ApiClientResourceListParameters| {
                qp.pagination.limit == Some(1) && qp.pagination.marker == Some("m".into())
            })
            .returning(|_, _| {
                Ok(vec![
                    resource_with_client_id("client-1"),
                    resource_with_client_id("client-2"),
                ])
            });
        provider = provider.mock_api_key(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?domain_id=domain_id&limit=1&marker=m")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApiKeyList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.api_keys.len(), 1);
        assert_eq!(res.api_keys[0].client_id, "client-1");
        let links = res.links.expect("expected next+previous links");
        assert!(links.iter().any(|l| l.rel == "next"));
        assert!(links.iter().any(|l| l.rel == "previous"));
    }

    /// Backend returned exactly `limit` rows (no over-fetched extra row): no
    /// `next` link should be produced.
    #[tokio::test]
    async fn test_list_pagination_no_false_positive_next() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockApiKeyProvider::default();
        mock.expect_list()
            .withf(|_, qp: &provider_types::ApiClientResourceListParameters| {
                qp.pagination.limit == Some(1)
            })
            .returning(|_, _| Ok(vec![sample_resource_core()]));
        provider = provider.mock_api_key(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?domain_id=domain_id&limit=1")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApiKeyList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.api_keys.len(), 1);
        assert_eq!(res.links, None);
    }

    #[tokio::test]
    async fn test_list_policy_denied() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(
            Provider::mocked_builder().mock_api_key(MockApiKeyProvider::default()),
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
                    .uri("/?domain_id=domain_id")
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
            Provider::mocked_builder().mock_api_key(MockApiKeyProvider::default()),
            true,
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
                    .uri("/?domain_id=domain_id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
