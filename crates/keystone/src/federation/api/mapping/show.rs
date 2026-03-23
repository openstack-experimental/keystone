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

//! Federation attribute mapping: show.
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::federation::{FederationApi, api::types::*};
use crate::keystone::ServiceState;

/// Get single mapping.
///
/// Show the attribute mapping attribute by the ID.
#[utoipa::path(
    get,
    path = "/{id}",
    operation_id = "/federation/mapping:show",
    params(
      ("id" = String, Path, description = "The ID of the attribute mapping.")
    ),
    responses(
        (status = OK, description = "mapping object", body = MappingResponse),
        (status = 404, description = "mapping not found", example = json!(KeystoneApiError::NotFound(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="mappings"
)]
#[tracing::instrument(
    name = "api::mapping_get",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn show(
    Auth(user_auth): Auth,
    Path(id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let current = state
        .provider
        .get_federation_provider()
        .get_mapping(&state, &id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "mapping".into(),
                identifier: id,
            })
        })??;

    state
        .policy_enforcer
        .enforce(
            "identity/mapping_show",
            &user_auth,
            serde_json::to_value(&current)?,
            None,
        )
        .await?;
    Ok((
        StatusCode::OK,
        Json(MappingResponse {
            mapping: Mapping::from(current),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt; // for `collect`
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`
    use tower_http::trace::TraceLayer;
    use tracing_test::traced_test;

    use openstack_keystone_core_types::federation as provider_types;

    use super::{super::openapi_router, *};
    use crate::api::tests::get_mocked_state;
    use crate::federation::MockFederationProvider;
    use crate::provider::Provider;

    #[tokio::test]
    #[traced_test]
    async fn test_get() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_get_mapping()
            .withf(|_, id: &'_ str| id == "foo")
            .returning(|_, _| Ok(None));

        federation_mock
            .expect_get_mapping()
            .withf(|_, id: &'_ str| id == "bar")
            .returning(|_, _| {
                Ok(Some(provider_types::Mapping {
                    id: "bar".into(),
                    name: "name".into(),
                    domain_id: Some("did".into()),
                    idp_id: "idp_id".into(),
                    enabled: true,
                    user_id_claim: "sub".into(),
                    user_name_claim: "preferred_username".into(),
                    domain_id_claim: Some("domain_id".into()),
                    ..Default::default()
                }))
            });

        let state = get_mocked_state(
            Provider::mocked_builder().mock_federation(federation_mock),
            true,
            None,
            None,
        );

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/foo")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/bar")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: MappingResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            Mapping {
                id: "bar".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                idp_id: "idp_id".into(),
                r#type: MappingType::default(),
                enabled: true,
                allowed_redirect_uris: None,
                user_id_claim: "sub".into(),
                user_name_claim: "preferred_username".into(),
                domain_id_claim: Some("domain_id".into()),
                groups_claim: None,
                bound_audiences: None,
                bound_subject: None,
                bound_claims: HashMap::new(),
                oidc_scopes: None,
                token_project_id: None,
                token_restriction_id: None,
            },
            res.mapping,
        );
    }
}
