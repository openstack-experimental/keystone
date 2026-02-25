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

//! K8s auth: list auth instances.
use axum::{
    extract::{OriginalUri, Query, State},
    response::IntoResponse,
};
use mockall_double::double;
use serde_json::to_value;
use validator::Validate;

use crate::api::{KeystoneApiError, auth::Auth};
use crate::k8s_auth::{K8sAuthApi, api::types::*, types as provider_types};
use crate::keystone::ServiceState;
#[double]
use crate::policy::Policy;

/// List K8s auth instances
#[utoipa::path(
    get,
    path = "/",
    operation_id = "/k8s_auth/instance:list",
    params(K8sAuthInstanceListParameters),
    responses(
        (status = OK, description = "List of instances", body = K8sAuthInstanceList),
        (status = 500, description = "Internal error", example = json!(KeystoneApiError::InternalError(String::from("id = 1"))))
    ),
    security(("x-auth" = [])),
    tag="k8s_auth_instance"
)]
#[tracing::instrument(
    name = "api::v4::k8s_auth::instance::list",
    level = "debug",
    skip(state, user_auth, policy),
    err(Debug)
)]
pub(super) async fn list(
    Auth(user_auth): Auth,
    mut policy: Policy,
    OriginalUri(original_url): OriginalUri,
    Query(query): Query<K8sAuthInstanceListParameters>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    query.validate()?;
    let res = policy
        .enforce(
            "identity/k8s_auth/instance/list",
            &user_auth,
            to_value(&query)?,
            None,
        )
        .await?;

    let domain_id = if query.domain_id.as_ref().is_none() {
        if !res.can_see_other_domain_resources.is_some_and(|x| x) {
            user_auth.user().as_ref().map(|val| val.domain_id.clone())
        } else {
            // User can see other domain's resources and query is empty - leave it empty
            None
        }
    } else {
        // The policy is expected to verify whether the user is allowed to see into that
        // other domain
        query.domain_id.clone()
    };
    let mut list_params = provider_types::K8sAuthInstanceListParameters::from(query.clone());
    list_params.domain_id = domain_id;

    let instances: Vec<K8sAuthInstance> = state
        .provider
        .get_k8s_auth_provider()
        .list_auth_instances(&state, &list_params)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    //let links = build_pagination_links(
    //    &state.config,
    //    identity_providers.as_slice(),
    //    &query,
    //    original_url.path(),
    //)?;
    Ok(K8sAuthInstanceList {
        instances,
        links: None,
    })
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

    use super::{super::openapi_router, *};
    use crate::api::tests::get_mocked_state;
    use crate::k8s_auth::{MockK8sAuthProvider, types as provider_types};
    use crate::provider::Provider;

    #[tokio::test]
    #[traced_test]
    async fn test_list() {
        let mut provider = Provider::mocked_builder();
        let mut mock = MockK8sAuthProvider::default();
        mock.expect_list_auth_instances()
            .withf(|_, _: &provider_types::K8sAuthInstanceListParameters| true)
            .returning(|_, _| {
                Ok(vec![provider_types::K8sAuthInstance {
                    ca_cert: Some("cert".into()),
                    disable_local_ca_jwt: false,
                    domain_id: "did".into(),
                    enabled: true,
                    host: "http://host:post".into(),
                    id: "id".into(),
                    name: Some("name".into()),
                }])
            });
        provider = provider.k8s_auth(mock);
        let state = get_mocked_state(provider, true, None);

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
        let res: K8sAuthInstanceList = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            vec![K8sAuthInstance {
                ca_cert: Some("cert".into()),
                disable_local_ca_jwt: false,
                domain_id: "did".into(),
                enabled: true,
                host: "http://host:post".into(),
                id: "id".into(),
                name: Some("name".into()),
            }],
            res.instances
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_qp() {
        let mut provider = Provider::mocked_builder();
        let mut mock = MockK8sAuthProvider::default();
        mock.expect_list_auth_instances()
            .withf(|_, qp: &provider_types::K8sAuthInstanceListParameters| {
                provider_types::K8sAuthInstanceListParameters {
                    name: Some("name".into()),
                    domain_id: Some("did".into()),
                } == *qp
            })
            .returning(|_, _| {
                Ok(vec![provider_types::K8sAuthInstance {
                    ca_cert: Some("cert".into()),
                    disable_local_ca_jwt: false,
                    domain_id: "did".into(),
                    enabled: true,
                    host: "http://host:post".into(),
                    id: "id".into(),
                    name: Some("name".into()),
                }])
            });

        provider = provider.k8s_auth(mock);
        let state = get_mocked_state(provider, true, None);

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
        let _res: K8sAuthInstanceList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_forbidden() {
        let provider = Provider::mocked_builder();
        let state = get_mocked_state(provider, false, None);

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
    async fn test_list_own_not_specified() {
        let mut provider = Provider::mocked_builder();
        let mut mock = MockK8sAuthProvider::default();
        mock.expect_list_auth_instances()
            .withf(|_, qp: &provider_types::K8sAuthInstanceListParameters| {
                provider_types::K8sAuthInstanceListParameters {
                    name: Some("name".into()),
                    domain_id: Some("udid".into()),
                } == *qp
            })
            .returning(|_, _| {
                Ok(vec![provider_types::K8sAuthInstance {
                    ca_cert: Some("cert".into()),
                    disable_local_ca_jwt: false,
                    domain_id: "did".into(),
                    enabled: true,
                    host: "http://host:post".into(),
                    id: "id".into(),
                    name: Some("name".into()),
                }])
            });

        provider = provider.k8s_auth(mock);
        let state = get_mocked_state(provider, true, None);

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
        let _res: K8sAuthInstanceList = serde_json::from_slice(&body).unwrap();
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_all() {
        // Test listing ALL configs when the user does not specify the domain_id and is
        // allowed to see configs of other domains (admin)
        let mut provider = Provider::mocked_builder();
        let mut mock = MockK8sAuthProvider::default();
        mock.expect_list_auth_instances()
            .withf(|_, qp: &provider_types::K8sAuthInstanceListParameters| {
                provider_types::K8sAuthInstanceListParameters {
                    name: Some("name".into()),
                    domain_id: None,
                } == *qp
            })
            .returning(|_, _| {
                Ok(vec![provider_types::K8sAuthInstance {
                    ca_cert: Some("cert".into()),
                    disable_local_ca_jwt: false,
                    domain_id: "did".into(),
                    enabled: true,
                    host: "http://host:post".into(),
                    id: "id".into(),
                    name: Some("name".into()),
                }])
            });

        provider = provider.k8s_auth(mock);
        let state = get_mocked_state(provider, true, Some(true));

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
        let _res: K8sAuthInstanceList = serde_json::from_slice(&body).unwrap();
    }
}
