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

//! Identity providers: list IDP
use axum::{
    extract::{Query, State},
    response::IntoResponse,
};
use mockall_double::double;
use serde_json::to_value;
use std::collections::HashSet;
use validator::Validate;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v4::federation::types::*;
use crate::federation::{
    FederationApi, types::IdentityProviderListParameters as ProviderIdentityProviderListParameters,
};
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// List identity providers.
///
/// List identity providers. Without any filters only global identity providers
/// are returned. With the `domain_id` identity providers owned by the specified
/// identity provider are returned.
///
/// It is expected that only global or owned identity providers can be returned,
/// while an admin user is able to list all providers.
#[utoipa::path(
    get,
    path = "/",
    operation_id = "/federation/identity_provider:list",
    params(IdentityProviderListParameters),
    responses(
        (status = OK, description = "List of identity providers", body = IdentityProviderList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="identity_providers"
)]
#[tracing::instrument(
    name = "api::identity_provider_list",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Query(query): Query<IdentityProviderListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    query.validate()?;
    let res = policy
        .enforce(
            "identity/identity_provider_list",
            &user_auth,
            to_value(&query)?,
            None,
        )
        .await?;

    let domain_ids = if query.domain_id.as_ref().is_none() {
        if !res.can_see_other_domain_resources.is_some_and(|x| x) {
            let domain_ids: HashSet<Option<String>> = HashSet::from([
                None,
                // TODO: perhaps we should first look at the domain_scope and than user domain.
                user_auth.user().as_ref().map(|val| val.domain_id.clone()),
            ]);
            Some(domain_ids)
        } else {
            // User can see other domain's resources and query is empty - leave it empty
            None
        }
    } else {
        Some(HashSet::from([query.domain_id.clone()]))
    };
    let mut provider_list_params = ProviderIdentityProviderListParameters::from(query);
    provider_list_params.domain_ids = domain_ids;

    let identity_providers: Vec<IdentityProvider> = state
        .provider
        .get_federation_provider()
        .list_identity_providers(&state, &provider_list_params)
        .await
        .map_err(KeystoneApiError::federation)?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(IdentityProviderList { identity_providers })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`

    use std::collections::HashSet;

    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use super::{
        super::{openapi_router, tests::get_mocked_state},
        *,
    };
    use crate::federation::{MockFederationProvider, types as provider_types};

    #[tokio::test]
    #[traced_test]
    async fn test_list() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_list_identity_providers()
            .withf(|_, _: &provider_types::IdentityProviderListParameters| true)
            .returning(|_, _| {
                Ok(vec![provider_types::IdentityProvider {
                    id: "id".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    enabled: true,
                    default_mapping_name: Some("dummy".into()),
                    ..Default::default()
                }])
            });
        let state = get_mocked_state(federation_mock, true, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: IdentityProviderList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![IdentityProvider {
                id: "id".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                enabled: true,
                oidc_discovery_url: None,
                oidc_client_id: None,
                oidc_response_mode: None,
                oidc_response_types: None,
                jwks_url: None,
                jwt_validation_pubkeys: None,
                bound_issuer: None,
                default_mapping_name: Some("dummy".into()),
                provider_config: None
            }],
            res.identity_providers
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_qp() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_list_identity_providers()
            .withf(|_, qp: &provider_types::IdentityProviderListParameters| {
                provider_types::IdentityProviderListParameters {
                    name: Some("name".into()),
                    domain_ids: Some(HashSet::from([Some("did".into())])),
                    limit: Some(1),
                    marker: Some("marker".into()),
                } == *qp
            })
            .returning(|_, _| {
                Ok(vec![provider_types::IdentityProvider {
                    id: "id".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(federation_mock, true, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?name=name&domain_id=did&limit=1&marker=marker")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: IdentityProviderList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_forbidden() {
        let federation_mock = MockFederationProvider::default();
        let state = get_mocked_state(federation_mock, false, None);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_shared_and_own() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_list_identity_providers()
            .withf(|_, qp: &provider_types::IdentityProviderListParameters| {
                provider_types::IdentityProviderListParameters {
                    name: Some("name".into()),
                    domain_ids: Some(HashSet::from([None, Some("udid".into())])),
                    limit: Some(20),
                    marker: None,
                } == *qp
            })
            .returning(|_, _| {
                Ok(vec![provider_types::IdentityProvider {
                    id: "id".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(federation_mock, true, Some(false));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?name=name")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: IdentityProviderList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_all() {
        // Test listing ALL idps when the user does not specify the domain_id and is
        // allowed to see IDP of other domains (admin)
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_list_identity_providers()
            .withf(|_, qp: &provider_types::IdentityProviderListParameters| {
                provider_types::IdentityProviderListParameters {
                    name: Some("name".into()),
                    domain_ids: None,
                    limit: Some(20),
                    marker: None,
                } == *qp
            })
            .returning(|_, _| {
                Ok(vec![provider_types::IdentityProvider {
                    id: "id".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(federation_mock, true, Some(true));

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?name=name")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: IdentityProviderList = serde_json::from_slice(&body).unwrap();
    }
}
