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

//! Federation attribute mapping: list
use axum::{
    extract::{Query, State},
    response::IntoResponse,
};
use mockall_double::double;
use serde_json::to_value;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::api::v4::federation::types::*;
use crate::federation::FederationApi;
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// List federation mappings.
///
/// List available federation mappings.
///
/// Without `domain_id` specified global mappings are returned.
///
/// It is expected that listing mappings belonging to the other domain is only
/// allowed to the admin user.
#[utoipa::path(
    get,
    path = "/",
    operation_id = "/federation/mapping:list",
    params(MappingListParameters),
    responses(
        (status = OK, description = "List of mappings", body = MappingList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="mappings"
)]
#[tracing::instrument(
    name = "api::mapping_list",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    mut policy: Policy,
    Query(query): Query<MappingListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    policy
        .enforce("identity/mapping_list", &user_auth, to_value(&query)?, None)
        .await?;

    let mappings: Vec<Mapping> = state
        .provider
        .get_federation_provider()
        .list_mappings(&state, &query.try_into()?)
        .await
        .map_err(KeystoneApiError::federation)?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(MappingList { mappings })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`

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
            .expect_list_mappings()
            .withf(|_, _: &provider_types::MappingListParameters| true)
            .returning(|_, _| {
                Ok(vec![provider_types::Mapping {
                    id: "id".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    idp_id: "idp_id".into(),
                    user_id_claim: "sub".into(),
                    user_name_claim: "preferred_username".into(),
                    domain_id_claim: Some("domain_id".into()),
                    ..Default::default()
                }])
            });

        let state = get_mocked_state(federation_mock, true);

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
        let res: MappingList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![Mapping {
                id: "id".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                idp_id: "idp_id".into(),
                r#type: MappingType::default(),
                allowed_redirect_uris: None,
                user_id_claim: "sub".into(),
                user_name_claim: "preferred_username".into(),
                domain_id_claim: Some("domain_id".into()),
                groups_claim: None,
                bound_audiences: None,
                bound_subject: None,
                bound_claims: None,
                oidc_scopes: None,
                token_project_id: None,
                token_restriction_id: None
            }],
            res.mappings
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_qp() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_list_mappings()
            .withf(|_, qp: &provider_types::MappingListParameters| {
                provider_types::MappingListParameters {
                    name: Some("name".into()),
                    domain_id: Some("did".into()),
                    idp_id: Some("idp".into()),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| {
                Ok(vec![provider_types::Mapping {
                    id: "id".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    idp_id: "idp".into(),
                    r#type: MappingType::default().into(),
                    allowed_redirect_uris: None,
                    user_id_claim: "sub".into(),
                    user_name_claim: "preferred_username".into(),
                    domain_id_claim: Some("domain_id".into()),
                    groups_claim: None,
                    bound_audiences: None,
                    bound_subject: None,
                    bound_claims: None,
                    oidc_scopes: None,
                    token_project_id: None,
                    token_restriction_id: None,
                }])
            });

        let state = get_mocked_state(federation_mock, true);

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/?name=name&domain_id=did&idp_id=idp")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: MappingList = serde_json::from_slice(&body).unwrap();
    }
}
