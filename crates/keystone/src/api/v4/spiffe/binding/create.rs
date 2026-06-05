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
//! # SPIFFE binding: create.

use axum::{Json, debug_handler, extract::State, http::StatusCode, response::IntoResponse};
use validator::Validate;

use openstack_keystone_api_types::v4::spiffe::binding::{
    SpiffeBinding, SpiffeBindingCreateRequest, SpiffeBindingResponse,
};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;
use crate::spiffe::SpiffeApi;

/// Create SPIFFE binding.
///
/// Create the SPIFFE binding with the specified properties.
#[utoipa::path(
    post,
    path = "/",
    operation_id = "/spiffe_binding:create",
    responses(
        (status = CREATED, description = "binding object", body = SpiffeBindingResponse),
    ),
    security(("x-auth" = [])),
    tag="spiffe_binding"
)]
#[tracing::instrument(
    name = "api::v4::spiffe::binding::create",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
#[debug_handler]
pub(super) async fn create(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(req): Json<SpiffeBindingCreateRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    // Enrich the authorizations so that the policy is capable to do additional
    // checks
    let auths = super::enrich_authorizations_list(&state, req.binding.authorizations.clone()).await;

    let target = super::EnrichedSpiffeBinding {
        domain_id: &req.binding.domain_id,
        is_system: req.binding.is_system,
        svid: &req.binding.svid,
        user_id: req.binding.user_id.as_deref(),
        authorizations: auths,
    };

    state
        .policy_enforcer
        .enforce(
            "identity/spiffe/binding/create",
            &user_auth,
            serde_json::json!({"binding": target}),
            None,
        )
        .await?;

    let res = state
        .provider
        .get_spiffe_provider()
        .create_binding(&state, req.into())
        .await?;
    Ok((
        StatusCode::CREATED,
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
        SpiffeAuthorization, SpiffeBindingCreate, SpiffeBindingCreateRequest,
    };
    use openstack_keystone_core_types::resource::{Domain, Project};
    use openstack_keystone_core_types::role::RoleBuilder;
    use openstack_keystone_core_types::spiffe as provider_types;

    use super::{super::openapi_router, *};
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::role::MockRoleProvider;
    use crate::spiffe::MockSpiffeProvider;

    #[tokio::test]
    async fn test_create() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut mock = MockSpiffeProvider::default();
        mock.expect_create_binding()
            .withf(|_, req: &provider_types::SpiffeBindingCreate| {
                req.svid == "spiffe://example.com/foo" && req.domain_id == "did" && !req.is_system
            })
            .returning(|_, req| {
                Ok(provider_types::SpiffeBinding {
                    authorizations: req.authorizations,
                    domain_id: req.domain_id.clone(),
                    svid: req.svid.clone(),
                    is_system: req.is_system,
                    user_id: req.user_id.clone(),
                })
            });
        provider = provider.mock_spiffe(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = SpiffeBindingCreateRequest {
            binding: SpiffeBindingCreate {
                domain_id: "did".into(),
                is_system: false,
                svid: "spiffe://example.com/foo".into(),
                user_id: None,
                authorizations: None,
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: SpiffeBindingResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.binding.svid, req.binding.svid);
        assert_eq!(res.binding.domain_id, req.binding.domain_id);
    }

    #[tokio::test]
    async fn test_create_with_authorizations_all_resolved() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_, did: &'_ str| did == "did")
            .returning(|_, id: &'_ str| {
                Ok(Some(Domain {
                    id: id.to_string(),
                    name: "default".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
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
            .withf(|_, rid: &'_ str| rid == "admin")
            .returning(|_, id: &'_ str| {
                Ok(Some(
                    RoleBuilder::default().id(id).name("admin").build().unwrap(),
                ))
            });
        role_mock
            .expect_get_role()
            .withf(|_, rid: &'_ str| rid == "reader")
            .returning(|_, id: &'_ str| {
                Ok(Some(
                    RoleBuilder::default()
                        .id(id)
                        .name("reader")
                        .build()
                        .unwrap(),
                ))
            });
        provider = provider.mock_role(role_mock);

        let mut mock = MockSpiffeProvider::default();
        mock.expect_create_binding().returning(|_, req| {
            Ok(provider_types::SpiffeBinding {
                authorizations: req.authorizations,
                domain_id: req.domain_id.clone(),
                svid: req.svid.clone(),
                is_system: req.is_system,
                user_id: req.user_id.clone(),
            })
        });
        provider = provider.mock_spiffe(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = SpiffeBindingCreateRequest {
            binding: SpiffeBindingCreate {
                domain_id: "did".into(),
                is_system: false,
                svid: "spiffe://example.com/bar".into(),
                user_id: None,
                authorizations: Some(vec![
                    SpiffeAuthorization::Domain {
                        domain_id: "did".into(),
                        role_ids: Some(vec!["admin".into()]),
                    },
                    SpiffeAuthorization::Project {
                        project_id: "pid".into(),
                        role_ids: Some(vec!["reader".into()]),
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
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: SpiffeBindingResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.binding.svid, req.binding.svid);
    }

    #[tokio::test]
    async fn test_create_authorizations_missing_resources() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();

        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_domain()
            .withf(|_, _: &'_ str| true)
            .returning(|_, _| Ok(None));
        resource_mock
            .expect_get_project()
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
        mock.expect_create_binding().returning(|_, req| {
            Ok(provider_types::SpiffeBinding {
                authorizations: req.authorizations,
                domain_id: req.domain_id.clone(),
                svid: req.svid.clone(),
                is_system: req.is_system,
                user_id: req.user_id.clone(),
            })
        });
        provider = provider.mock_spiffe(mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = SpiffeBindingCreateRequest {
            binding: SpiffeBindingCreate {
                domain_id: "did".into(),
                is_system: false,
                svid: "spiffe://example.com/foo".into(),
                user_id: None,
                authorizations: Some(vec![
                    SpiffeAuthorization::Domain {
                        domain_id: "did".into(),
                        role_ids: Some(vec!["missing_role".into()]),
                    },
                    SpiffeAuthorization::Project {
                        project_id: "pid".into(),
                        role_ids: Some(vec!["missing_role".into()]),
                    },
                ]),
            },
        };

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: SpiffeBindingResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.binding.svid, req.binding.svid);
    }
}
