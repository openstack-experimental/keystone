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
//! Delegatable services (ADR 0036 §3).
//!
//! `GET /v4/delegatable-services` lists the services the caller may name as
//! a service grant grantee: the live, enabled clients accepting grants in
//! the caller's own domain, plus every `cross_domain` one. Only the
//! `client_id`, name, domain and delegation ceilings are returned, never a
//! SPIFFE ID.
//!
//! OPA input: `input.target` is null, `input.existing` is absent.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use openstack_keystone_api_types::v4::service_grant::{DelegatableService, DelegatableServiceList};
use openstack_keystone_core::auth::ExecutionContext;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// OpenApi specification for the delegatable service listing.
#[derive(OpenApi)]
#[openapi(tags((name="delegatable_service", description="Services a user may delegate to (ADR 0036).")))]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(list))
}

/// List the services the caller may create service grants for.
#[utoipa::path(
    get,
    path = "/",
    operation_id = "/delegatable_service:list",
    responses(
        (status = OK, description = "Delegatable services", body = DelegatableServiceList),
    ),
    security(("x-auth" = [])),
    tag="delegatable_service"
)]
#[tracing::instrument(
    name = "api::v4::delegatable_service::list",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
async fn list(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/delegatable_service/list",
            &user_auth,
            serde_json::Value::Null,
            None,
        )
        .await?;

    let caller_domain = user_auth.principal().domain_id();
    let delegatable_services = state
        .provider
        .get_oauth2_client_provider()
        .list_delegatable(&ExecutionContext::from_auth(&state, &user_auth))
        .await?
        .into_iter()
        .filter_map(DelegatableService::from_client)
        .filter(|s| s.cross_domain || caller_domain.as_deref() == Some(s.domain_id.as_str()))
        .collect();

    Ok((
        StatusCode::OK,
        Json(DelegatableServiceList {
            delegatable_services,
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

    use openstack_keystone_api_types::v4::service_grant::DelegatableServiceList;

    use super::openapi_router;
    use crate::api::tests::{get_capturing_state, get_mocked_state, test_fixture_scoped};
    use crate::api::v4::service_grant::tests::client;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;

    fn clients() -> MockOauth2ClientProvider {
        let mut mock = MockOauth2ClientProvider::default();
        mock.expect_list_delegatable().returning(|_| {
            let infra = client();
            let mut local = client();
            local.client_id = "local".into();
            local.domain_id = "domain_id".into();
            if let Some(d) = local.delegation.as_mut() {
                d.cross_domain = false;
            }
            let mut foreign = client();
            foreign.client_id = "foreign".into();
            foreign.domain_id = "other".into();
            if let Some(d) = foreign.delegation.as_mut() {
                d.cross_domain = false;
            }
            Ok(vec![infra, local, foreign])
        });
        mock
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

    /// Cross-domain services and the caller's own domain's services are
    /// listed; other domains' local services are not, and no SPIFFE ID is
    /// returned.
    #[tokio::test]
    async fn test_list() {
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_oauth2_client(clients())).await;
        let response = call(
            state,
            Request::builder()
                .uri("/")
                .extension(test_fixture_scoped())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/delegatable_service/list");
        // No target and nothing stored: the policy needs only the caller.
        assert!(calls[0].target.is_null());
        crate::api::tests::policy_contract::assert_no_secrets(&calls[0].target);
        crate::api::tests::policy_contract::assert_existing_presence(&calls[0].existing, false);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains("spiffe"));
        let res: DelegatableServiceList = serde_json::from_slice(&body).unwrap();
        let ids: Vec<_> = res
            .delegatable_services
            .iter()
            .map(|s| s.client_id.as_str())
            .collect();
        assert_eq!(ids, vec!["heat-client", "local"]);
    }

    #[tokio::test]
    async fn test_list_policy_denied() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_oauth2_client(MockOauth2ClientProvider::default()),
            false,
            None,
        )
        .await;
        let response = call(
            state,
            Request::builder()
                .uri("/")
                .extension(test_fixture_scoped())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_list_unauthorized() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_oauth2_client(MockOauth2ClientProvider::default()),
            true,
            None,
        )
        .await;
        let response = call(
            state,
            Request::builder().uri("/").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
