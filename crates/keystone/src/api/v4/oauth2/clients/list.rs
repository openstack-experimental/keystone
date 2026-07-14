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
//! OAuth2 client: list.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::v4::oauth2_client::{
    OAuth2Client, OAuth2ClientList, OAuth2ClientListParameters,
};
use openstack_keystone_core_types::oauth2_client::OAuth2ClientResourceListParameters;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// List OAuth2 clients for a domain.
#[utoipa::path(
    get,
    path = "/{domain_id}/clients",
    operation_id = "/oauth2/client:list",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
        OAuth2ClientListParameters,
    ),
    responses(
        (status = OK, description = "List of OAuth2 clients", body = OAuth2ClientList),
    ),
    security(("x-auth" = [])),
    tag = "oauth2_client"
)]
#[tracing::instrument(
    name = "api::v4::oauth2::clients::list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Path(domain_id): Path<String>,
    Query(query): Query<OAuth2ClientListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/oauth2/client/list",
            &user_auth,
            serde_json::json!({"domain_id": domain_id, "oauth2_client": query}),
            None,
        )
        .await?;

    let params = OAuth2ClientResourceListParameters {
        domain_id: domain_id.clone(),
        enabled: query.enabled,
    };
    let clients: Vec<OAuth2Client> = state
        .provider
        .get_oauth2_client_provider()
        .list(&ExecutionContext::from_auth(&state, &user_auth), &params)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    Ok((
        StatusCode::OK,
        Json(OAuth2ClientList {
            oauth2_clients: clients,
            links: None,
        }),
    )
        .into_response())
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

    use openstack_keystone_api_types::v4::oauth2_client::OAuth2ClientList;
    use openstack_keystone_core_types::oauth2_client as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;

    fn sample_resource() -> provider_types::OAuth2ClientResource {
        provider_types::OAuth2ClientResource {
            client_id: "client-1".into(),
            provider_id: "provider-1".into(),
            domain_id: "domain_id".into(),
            client_secret_hash: None,
            redirect_uris: vec!["https://rp.example.com/callback".into()],
            token_endpoint_auth_method: "none".into(),
            grant_types: vec![],
            require_pkce: true,
            allowed_scopes: vec![],
            pre_authorized: false,
            enabled: true,
            claims_template: Default::default(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    #[tokio::test]
    async fn test_list() {
        let vsc = test_fixture_scoped();
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_list()
            .returning(|_, _| Ok(vec![sample_resource()]));
        let provider = Provider::mocked_builder().mock_oauth2_client(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain_id/clients")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: OAuth2ClientList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.oauth2_clients.len(), 1);
    }

    #[tokio::test]
    async fn test_list_policy_denied() {
        let vsc = test_fixture_scoped();
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain_id/clients")
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
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/domain_id/clients")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
