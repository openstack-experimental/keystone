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
//! Service grant: show.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::v4::service_grant::{ServiceGrant, ServiceGrantResponse};

use super::{Caller, existing_input, not_found, resolve_caller};
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Show a service grant.
///
/// Users call it with a token; the grantee service calls it on the internal
/// interface with its X.509-SVID.
#[utoipa::path(
    get,
    path = "/{grant_id}",
    operation_id = "/service_grant:show",
    params(("grant_id" = String, Path, description = "Service grant id")),
    responses(
        (status = OK, description = "Service grant", body = ServiceGrantResponse),
        (status = NOT_FOUND, description = "No such grant"),
    ),
    security(("x-auth" = [])),
    tag="service_grant"
)]
#[tracing::instrument(
    name = "api::v4::service_grant::show",
    level = "debug",
    skip(state, caller),
    err(Debug)
)]
pub(super) async fn show(
    caller: Caller,
    Path(grant_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let (vsc, grant) = resolve_caller(&state, caller, &grant_id).await?;

    state
        .policy_enforcer
        .enforce(
            "identity/service_grant/show",
            &vsc,
            serde_json::json!({"service_grant": null}),
            Some(existing_input(&grant_id, grant.as_ref())),
        )
        .await?;

    let grant = grant.ok_or_else(|| not_found(&grant_id))?;
    Ok((
        StatusCode::OK,
        Json(ServiceGrantResponse {
            service_grant: ServiceGrant::from(grant),
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

    use openstack_keystone_api_types::v4::service_grant::ServiceGrantResponse;
    use openstack_keystone_config::Interface;
    use openstack_keystone_core::common::SpiffeId;
    use openstack_keystone_core_types::resource::Domain;

    use super::super::openapi_router;
    use super::super::tests::{client, grant};
    use crate::api::tests::{get_capturing_state, get_mocked_state, test_fixture_scoped};
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::service_grant::MockServiceGrantProvider;

    fn grants_returning(found: bool) -> MockServiceGrantProvider {
        let mut mock = MockServiceGrantProvider::default();
        mock.expect_get_service_grant_by_id()
            .returning(move |_, id| Ok(found.then(|| grant(id))));
        mock
    }

    fn get(uri: &str) -> axum::http::request::Builder {
        Request::builder().uri(uri)
    }

    async fn call(
        state: crate::keystone::ServiceState,
        req: Request<Body>,
    ) -> axum::response::Response {
        openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(req)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_show() {
        let (state, policy) = get_capturing_state(
            Provider::mocked_builder().mock_service_grant(grants_returning(true)),
        )
        .await;
        let response = call(
            state,
            get("/g1")
                .extension(test_fixture_scoped())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ServiceGrantResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.service_grant.id, "g1");

        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/service_grant/show");
        crate::api::tests::policy_contract::assert_object_keys(
            &calls[0].target,
            &["service_grant"],
        );
        crate::api::tests::policy_contract::assert_existing_presence(&calls[0].existing, true);
        crate::api::tests::policy_contract::assert_object_keys(
            calls[0].existing.as_ref().unwrap(),
            &["service_grant"],
        );
        crate::api::tests::policy_contract::assert_no_secrets(&calls[0].target);
        crate::api::tests::policy_contract::assert_no_secrets(calls[0].existing.as_ref().unwrap());
        let existing = calls[0].existing.as_ref().unwrap();
        assert_eq!(
            existing["service_grant"]["grantee"]["client_id"],
            "heat-client"
        );
    }

    #[tokio::test]
    async fn test_show_policy_denied() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_service_grant(grants_returning(true)),
            false,
            None,
        )
        .await;
        let response = call(
            state,
            get("/g1")
                .extension(test_fixture_scoped())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// A missing grant is judged by the policy (id only) before the 404.
    #[tokio::test]
    async fn test_show_not_found() {
        let (state, policy) = get_capturing_state(
            Provider::mocked_builder().mock_service_grant(grants_returning(false)),
        )
        .await;
        let response = call(
            state,
            get("/missing")
                .extension(test_fixture_scoped())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].existing.as_ref().unwrap()["service_grant"],
            serde_json::json!({"id": "missing"})
        );
    }

    #[tokio::test]
    async fn test_show_unauthorized() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_service_grant(MockServiceGrantProvider::default()),
            true,
            None,
        )
        .await;
        let response = call(state, get("/g1").body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    fn service_provider() -> crate::provider::ProviderBuilder {
        let mut clients = MockOauth2ClientProvider::default();
        clients
            .expect_get_by_client_id()
            .returning(|_, _| Ok(Some(client())));
        let mut resource = MockResourceProvider::default();
        resource.expect_get_domain().returning(|_, id| {
            Ok(Some(Domain {
                id: id.to_string(),
                name: "infra".into(),
                enabled: true,
                ..Default::default()
            }))
        });
        Provider::mocked_builder()
            .mock_service_grant(grants_returning(true))
            .mock_oauth2_client(clients)
            .mock_resource(resource)
    }

    /// The grantee service is authenticated by its SVID against the grantee
    /// client and reaches the policy as a `service_client` actor.
    #[tokio::test]
    async fn test_show_by_grantee_service() {
        let (state, policy) = get_capturing_state(service_provider()).await;
        let response = call(
            state,
            get("/g1")
                .extension(Interface::Internal)
                .extension(SpiffeId::new("spiffe://td/service/heat-engine/host/h1").unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(policy.calls().len(), 1);
    }

    /// An SVID the grantee client does not accept is not authenticated, and
    /// never falls back to the mapping engine.
    #[tokio::test]
    async fn test_show_by_other_service_is_unauthorized() {
        let (state, policy) = get_capturing_state(service_provider()).await;
        let response = call(
            state,
            get("/g1")
                .extension(Interface::Internal)
                .extension(SpiffeId::new("spiffe://td/service/nova/host/h1").unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(policy.calls().is_empty());
    }
}
