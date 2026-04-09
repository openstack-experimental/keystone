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

//! K8s auth: list auth roles.
use axum::{
    Json,
    extract::{OriginalUri, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::to_value;
use validator::Validate;

use openstack_keystone_api_types::k8s_auth::*;
use openstack_keystone_core::k8s_auth::K8sAuthApi;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core_types::k8s_auth as provider_types;

use crate::api::{KeystoneApiError, auth::Auth};

/// List K8 auth roles.
///
/// List available K8s auth roles belonging to the auth instance.
#[utoipa::path(
    get,
    path = "/instances/{instance_id}/roles",
    operation_id = "/k8s_auth/instance/role:list",
    params(
        K8sAuthRoleListParametersNested,
        ("instance_id" = String, Path, description = "The ID of the k8s auth instance"),
    ),
    responses(
        (status = OK, description = "List of roles", body = K8sAuthRoleList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="k8s_auth_role"
)]
#[tracing::instrument(
    name = "api::v4::k8s_auth::role::list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list_nested(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Path(instance_id): Path<String>,
    Query(query): Query<K8sAuthRoleListParametersNested>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    query.validate()?;

    let res = state
        .policy_enforcer
        .enforce(
            "identity/k8s_auth/role/list",
            &user_auth,
            to_value(&query)?,
            None,
        )
        .await?;

    let params = provider_types::K8sAuthRoleListParameters {
        auth_instance_id: Some(instance_id),
        name: query.name,
        domain_id: if !res.can_see_other_domain_resources.is_some_and(|x| x) {
            user_auth.user().as_ref().map(|val| val.domain_id.clone())
        } else {
            None
        },
    };

    let roles: Vec<K8sAuthRole> = state
        .provider
        .get_k8s_auth_provider()
        .list_auth_roles(&state, &params)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    //let links = build_pagination_links(
    //    &state.config,
    //    mappings.as_slice(),
    //    &query,
    //    original_url.path(),
    //)?;
    Ok((StatusCode::OK, Json(K8sAuthRoleList { roles, links: None })).into_response())
}

/// List K8 auth roles.
///
/// List available K8s auth roles.
#[utoipa::path(
    get,
    path = "/roles",
    operation_id = "/k8s_auth/role:list",
    params(
        K8sAuthRoleListParameters
    ),
    responses(
        (status = OK, description = "List of roles", body = K8sAuthRoleList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="k8s_auth_role"
)]
#[tracing::instrument(
    name = "api::v4::k8s_auth::role::list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<K8sAuthRoleListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    query.validate()?;

    let res = state
        .policy_enforcer
        .enforce(
            "identity/k8s_auth/role/list",
            &user_auth,
            to_value(&query)?,
            None,
        )
        .await?;

    let params = provider_types::K8sAuthRoleListParameters {
        auth_instance_id: query.auth_instance_id,
        name: query.name,
        domain_id: if !res.can_see_other_domain_resources.is_some_and(|x| x) {
            user_auth.user().as_ref().map(|val| val.domain_id.clone())
        } else {
            query.domain_id
        },
    };
    //let mut params = provider_types::K8sAuthRoleListParameters::default();
    //params.auth_instance_id = query.auth_instance_id;
    //params.name = query.name;
    //if !res.can_see_other_domain_resources.is_some_and(|x| x) {
    //    params.domain_id = user_auth.user().as_ref().map(|val|
    // val.domain_id.clone())
    //} else {
    //    params.domain_id = query.domain_id;
    //}

    let roles: Vec<K8sAuthRole> = state
        .provider
        .get_k8s_auth_provider()
        .list_auth_roles(&state, &params)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    //let links = build_pagination_links(
    //    &state.config,
    //    mappings.as_slice(),
    //    &query,
    //    original_url.path(),
    //)?;
    Ok((StatusCode::OK, Json(K8sAuthRoleList { roles, links: None })).into_response())
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

    use openstack_keystone_core_types::k8s_auth as provider_types;

    use super::{super::*, *};
    use crate::api::tests::get_mocked_state;
    use crate::k8s_auth::MockK8sAuthProvider;
    use crate::provider::Provider;

    #[tokio::test]
    #[traced_test]
    async fn test_list() {
        let mut provider = Provider::mocked_builder();
        let mut mock = MockK8sAuthProvider::default();
        mock.expect_list_auth_roles()
            .withf(|_, _: &provider_types::K8sAuthRoleListParameters| true)
            .returning(|_, _| {
                Ok(vec![provider_types::K8sAuthRole {
                    auth_instance_id: "cid".into(),
                    bound_audience: Some("aud".into()),
                    bound_service_account_names: vec!["san".into()],
                    bound_service_account_namespaces: vec!["ns".into()],
                    domain_id: "did".into(),
                    enabled: true,
                    id: "id".into(),
                    name: "name".into(),
                    token_restriction_id: "trid".into(),
                }])
            });

        provider = provider.mock_k8s_auth(mock);
        let state = get_mocked_state(provider, true, None, None).await;

        // Nested style
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/instances/cid/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: K8sAuthRoleList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![K8sAuthRole {
                auth_instance_id: "cid".into(),
                bound_audience: Some("aud".into()),
                bound_service_account_names: vec!["san".into()],
                bound_service_account_namespaces: vec!["ns".into()],
                domain_id: "did".into(),
                enabled: true,
                id: "id".into(),
                name: "name".into(),
                token_restriction_id: "trid".into(),
            }],
            res.roles
        );

        // flat style
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/roles")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: K8sAuthRoleList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![K8sAuthRole {
                auth_instance_id: "cid".into(),
                bound_audience: Some("aud".into()),
                bound_service_account_names: vec!["san".into()],
                bound_service_account_namespaces: vec!["ns".into()],
                domain_id: "did".into(),
                enabled: true,
                id: "id".into(),
                name: "name".into(),
                token_restriction_id: "trid".into(),
            }],
            res.roles
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_qp() {
        let mut provider = Provider::mocked_builder();
        let mut mock = MockK8sAuthProvider::default();
        mock.expect_list_auth_roles()
            .withf(|_, qp: &provider_types::K8sAuthRoleListParameters| {
                provider_types::K8sAuthRoleListParameters {
                    auth_instance_id: Some("cid".into()),
                    domain_id: Some("udid".into()),
                    name: Some("name".into()),
                } == *qp
            })
            .returning(|_, _| {
                Ok(vec![provider_types::K8sAuthRole {
                    auth_instance_id: "cid".into(),
                    bound_audience: Some("aud".into()),
                    bound_service_account_names: vec!["san".into()],
                    bound_service_account_namespaces: vec!["ns".into()],
                    domain_id: "did".into(),
                    enabled: true,
                    id: "id".into(),
                    name: "name".into(),
                    token_restriction_id: "trid".into(),
                }])
            });
        mock.expect_list_auth_roles()
            .withf(|_, qp: &provider_types::K8sAuthRoleListParameters| {
                provider_types::K8sAuthRoleListParameters {
                    domain_id: Some("udid".into()),
                    name: Some("name".into()),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| {
                Ok(vec![provider_types::K8sAuthRole {
                    auth_instance_id: "cid".into(),
                    bound_audience: Some("aud".into()),
                    bound_service_account_names: vec!["san".into()],
                    bound_service_account_namespaces: vec!["ns".into()],
                    domain_id: "did".into(),
                    enabled: true,
                    id: "id".into(),
                    name: "name".into(),
                    token_restriction_id: "trid".into(),
                }])
            });

        provider = provider.mock_k8s_auth(mock);
        let state = get_mocked_state(provider, true, None, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        // Nested style
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/instances/cid/roles?name=name")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: K8sAuthRoleList = serde_json::from_slice(&body).unwrap();

        // Flat style
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/roles?name=name")
                    .header("x-auth-token", "foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let _res: K8sAuthRoleList = serde_json::from_slice(&body).unwrap();
    }
}
