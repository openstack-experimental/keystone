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
//! # SPIFFE binding: update.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use validator::Validate;

use openstack_keystone_api_types::v4::spiffe::binding::{
    SpiffeBinding, SpiffeBindingResponse, SpiffeBindingUpdateRequest,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::spiffe::SpiffeApi;

/// Update existing SPIFFE binding.
///
/// Updates the existing SPIFFE binding by SVID.
#[utoipa::path(
    put,
    path = "/{svid}",
    operation_id = "/spiffe_binding:update",
    params(
      ("svid" = String, Path, description = "The SVID of the binding to update")
    ),
    responses(
        (status = OK, description = "Binding object", body = SpiffeBindingResponse),
        (status = 404, description = "Binding not found", example = json!(KeystoneApiError::NotFound(String::from("svid"))))
    ),
    security(("x-auth" = [])),
    tag="spiffe_binding"
)]
#[tracing::instrument(
    name = "api::v4::spiffe::binding::update",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn update(
    Auth(user_auth): Auth,
    Path(svid): Path<String>,
    State(state): State<ServiceState>,
    Json(req): Json<SpiffeBindingUpdateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    let current = state
        .provider
        .get_spiffe_provider()
        .get_binding(&state, &svid)
        .await?;

    // Enrich the authorizations so that the policy is capable to do additional checks
    let target_auths =
        super::enrich_authorizations_list(&state, req.binding.authorizations.clone()).await;
    let target = super::EnrichedSpiffeBindingUpdate {
        authorizations: target_auths,
    };
    let existing_binding = current.as_ref().map(serde_json::to_value).transpose()?;

    state
        .policy_enforcer
        .enforce(
            "identity/spiffe/binding/update",
            &user_auth,
            serde_json::json!({"binding": target}),
            existing_binding,
        )
        .await?;

    let res = state
        .provider
        .get_spiffe_provider()
        .update_binding(&state, &svid, req.into())
        .await?;

    Ok((
        StatusCode::OK,
        Json(SpiffeBindingResponse {
            binding: SpiffeBinding::from(res),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_api_types::v4::spiffe::binding::{
        SpiffeAuthorization, SpiffeBindingUpdate, SpiffeBindingUpdateRequest,
    };
    use openstack_keystone_core_types::resource::Project;
    use openstack_keystone_core_types::role::RoleBuilder;
    use openstack_keystone_core_types::spiffe as provider_types;

    use super::{super::openapi_router, *};
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::role::MockRoleProvider;
    use crate::spiffe::MockSpiffeProvider;

    #[tokio::test]
    async fn test_update() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockSpiffeProvider::default();

        mock.expect_get_binding()
            .withf(|_, svid: &'_ str| svid == "spiffe://example.com/foo")
            .returning(|_, _| {
                Ok(Some(provider_types::SpiffeBinding {
                    authorizations: None,
                    domain_id: "did".into(),
                    svid: "spiffe://example.com/foo".into(),
                    is_system: false,
                    user_id: Some("uid".into()),
                }))
            });

        mock.expect_update_binding()
            .withf(
                |_, svid: &'_ str, _: &provider_types::SpiffeBindingUpdate| {
                    svid == "spiffe://example.com/foo"
                },
            )
            .returning(|_, _, _| {
                Ok(provider_types::SpiffeBinding {
                    authorizations: Some(vec![provider_types::SpiffeAuthorization::Project {
                        project_id: "pid".into(),
                        role_ids: Some(vec!["r1".into()]),
                    }]),
                    domain_id: "did".into(),
                    svid: "spiffe://example.com/foo".into(),
                    is_system: false,
                    user_id: Some("uid".into()),
                })
            });

        provider = provider.mock_spiffe(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = SpiffeBindingUpdateRequest {
            binding: SpiffeBindingUpdate {
                authorizations: None,
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/spiffe%3A%2F%2Fexample.com%2Ffoo")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: SpiffeBindingResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.binding.svid, "spiffe://example.com/foo");
    }

    #[tokio::test]
    async fn test_update_with_authorizations_all_resolved() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, pid: &'_ str| pid == "pid")
            .returning(|_, id: &'_ str| {
                Ok(Some(Project {
                    id: id.to_string(),
                    domain_id: "did".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
        provider = provider.mock_resource(resource_mock);

        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, rid: &'_ str| rid == "manager")
            .returning(|_, id: &'_ str| {
                Ok(Some(
                    RoleBuilder::default()
                        .id(id)
                        .name("manager")
                        .build()
                        .unwrap(),
                ))
            });
        provider = provider.mock_role(role_mock);

        let mut mock = MockSpiffeProvider::default();
        mock.expect_get_binding()
            .withf(|_, svid: &'_ str| svid == "spiffe://example.com/foo")
            .returning(|_, _| {
                Ok(Some(provider_types::SpiffeBinding {
                    authorizations: None,
                    domain_id: "did".into(),
                    svid: "spiffe://example.com/foo".into(),
                    is_system: false,
                    user_id: Some("uid".into()),
                }))
            });
        mock.expect_update_binding().returning(|_, _, _| {
            Ok(provider_types::SpiffeBinding {
                authorizations: Some(vec![provider_types::SpiffeAuthorization::Project {
                    project_id: "pid".into(),
                    role_ids: Some(vec!["manager".into()]),
                }]),
                domain_id: "did".into(),
                svid: "spiffe://example.com/foo".into(),
                is_system: false,
                user_id: Some("uid".into()),
            })
        });
        provider = provider.mock_spiffe(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = SpiffeBindingUpdateRequest {
            binding: SpiffeBindingUpdate {
                authorizations: Some(vec![
                    SpiffeAuthorization::Project {
                        project_id: "pid".into(),
                        role_ids: Some(vec!["manager".into()]),
                    },
                    SpiffeAuthorization::System {
                        system_id: "all".into(),
                        role_ids: None,
                    },
                ]),
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/spiffe%3A%2F%2Fexample.com%2Ffoo")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: SpiffeBindingResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.binding.svid, "spiffe://example.com/foo");
    }

    #[tokio::test]
    async fn test_update_authorizations_missing_resources() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project()
            .withf(|_, _: &'_ str| true)
            .returning(|_, _| Ok(None));
        resource_mock
            .expect_get_domain()
            .withf(|_, _: &'_ str| true)
            .returning(|_, _| Ok(None));
        provider = provider.mock_resource(resource_mock);

        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_get_role()
            .withf(|_, _: &'_ str| true)
            .returning(|_, _| Ok(None));
        provider = provider.mock_role(role_mock);

        let mut mock = MockSpiffeProvider::default();
        mock.expect_get_binding()
            .withf(|_, svid: &'_ str| svid == "spiffe://example.com/foo")
            .returning(|_, _| {
                Ok(Some(provider_types::SpiffeBinding {
                    authorizations: None,
                    domain_id: "did".into(),
                    svid: "spiffe://example.com/foo".into(),
                    is_system: false,
                    user_id: Some("uid".into()),
                }))
            });
        mock.expect_update_binding().returning(|_, _, _| {
            Ok(provider_types::SpiffeBinding {
                authorizations: None,
                domain_id: "did".into(),
                svid: "spiffe://example.com/foo".into(),
                is_system: false,
                user_id: Some("uid".into()),
            })
        });
        provider = provider.mock_spiffe(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = SpiffeBindingUpdateRequest {
            binding: SpiffeBindingUpdate {
                authorizations: Some(vec![
                    SpiffeAuthorization::Project {
                        project_id: "nonexistent".into(),
                        role_ids: Some(vec!["missing_role".into()]),
                    },
                    SpiffeAuthorization::Domain {
                        domain_id: "nonexistent".into(),
                        role_ids: None,
                    },
                ]),
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/spiffe%3A%2F%2Fexample.com%2Ffoo")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: SpiffeBindingResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.binding.svid, "spiffe://example.com/foo");
    }
}
