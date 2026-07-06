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
//! SCIM realm: list.

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::v4::scim_realm::{
    ScimRealm, ScimRealmList, ScimRealmListParameters,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use openstack_keystone_core::auth::ExecutionContext;

/// List SCIM realms for a domain.
#[utoipa::path(
    get,
    path = "/",
    operation_id = "/scim_realm:list",
    params(ScimRealmListParameters),
    responses(
        (status = OK, description = "List of SCIM realms", body = ScimRealmList),
    ),
    security(("x-auth" = [])),
    tag="scim_realm"
)]
#[tracing::instrument(
    name = "api::v4::scim_realm::list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    Query(query): Query<ScimRealmListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/scim_realm/list",
            &user_auth,
            serde_json::json!({"scim_realm": query}),
            None,
        )
        .await?;

    let params = query.into();
    let realms: Vec<ScimRealm> = state
        .provider
        .get_scim_realm_provider()
        .list_realms(&ExecutionContext::from_auth(&state, &user_auth), &params)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    Ok((
        StatusCode::OK,
        Json(ScimRealmList {
            scim_realms: realms,
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

    use openstack_keystone_api_types::v4::scim_realm::ScimRealmList;
    use openstack_keystone_core_types::scim as provider_types;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::provider::Provider;
    use crate::scim_realm::MockScimRealmProvider;

    fn sample_realm_core() -> provider_types::ScimRealmResource {
        provider_types::ScimRealmResource {
            domain_id: "domain_id".into(),
            provider_id: "provider-1".into(),
            idp_id: "idp-1".into(),
            display_name: "Okta - Employees".into(),
            enabled: true,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[tokio::test]
    async fn test_list() {
        let vsc = test_fixture_scoped();
        let mut mock = MockScimRealmProvider::default();
        mock.expect_list_realms()
            .returning(|_, _| Ok(vec![sample_realm_core()]));
        let provider = Provider::mocked_builder().mock_scim_realm(mock);

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
        let res: ScimRealmList = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.scim_realms.len(), 1);
        assert_eq!(res.scim_realms[0].provider_id, "provider-1");
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
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

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
