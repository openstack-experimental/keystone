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
//! Service grant: delete.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_core::auth::ExecutionContext;

use super::{Caller, existing_input, not_found, resolve_caller};
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Delete (revoke) a service grant.
///
/// The grantor, a manager of the grant's project or domain, or the grantee
/// service (internal interface, X.509-SVID) may delete it.
#[utoipa::path(
    delete,
    path = "/{grant_id}",
    operation_id = "/service_grant:delete",
    params(("grant_id" = String, Path, description = "Service grant id")),
    responses(
        (status = NO_CONTENT, description = "Service grant deleted"),
        (status = NOT_FOUND, description = "No such grant"),
    ),
    security(("x-auth" = [])),
    tag="service_grant"
)]
#[tracing::instrument(
    name = "api::v4::service_grant::delete",
    level = "debug",
    skip(state, caller),
    err(Debug)
)]
pub(super) async fn remove(
    caller: Caller,
    Path(grant_id): Path<String>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let (vsc, grant) = resolve_caller(&state, caller, &grant_id).await?;

    state
        .policy_enforcer
        .enforce(
            "identity/service_grant/delete",
            &vsc,
            serde_json::json!({"service_grant": null}),
            Some(existing_input(&grant_id, grant.as_ref())),
        )
        .await?;

    let grant = grant.ok_or_else(|| not_found(&grant_id))?;
    state
        .provider
        .get_service_grant_provider()
        .delete_service_grant(
            &ExecutionContext::from_auth(&state, &vsc),
            &grant.domain_id,
            &grant.id,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

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

    fn grants(found: bool, expect_delete: bool) -> MockServiceGrantProvider {
        let mut mock = MockServiceGrantProvider::default();
        mock.expect_get_service_grant_by_id()
            .returning(move |_, id| Ok(found.then(|| grant(id))));
        if expect_delete {
            mock.expect_delete_service_grant()
                .withf(|_, domain_id, id| domain_id == "domain_id" && id == "g1")
                .times(1)
                .returning(|_, _, _| Ok(()));
        }
        mock
    }

    fn delete(uri: &str) -> axum::http::request::Builder {
        Request::builder().method(Method::DELETE).uri(uri)
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
    async fn test_delete() {
        let (state, policy) =
            get_capturing_state(Provider::mocked_builder().mock_service_grant(grants(true, true)))
                .await;
        let response = call(
            state,
            delete("/g1")
                .extension(test_fixture_scoped())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/service_grant/delete");
        crate::api::tests::policy_contract::assert_object_keys(
            &calls[0].target,
            &["service_grant"],
        );
        crate::api::tests::policy_contract::assert_existing_presence(&calls[0].existing, true);
        let existing = calls[0].existing.as_ref().unwrap();
        crate::api::tests::policy_contract::assert_object_keys(existing, &["service_grant"]);
        crate::api::tests::policy_contract::assert_no_secrets(&calls[0].target);
        crate::api::tests::policy_contract::assert_no_secrets(existing);
    }

    #[tokio::test]
    async fn test_delete_policy_denied() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_service_grant(grants(true, false)),
            false,
            None,
        )
        .await;
        let response = call(
            state,
            delete("/g1")
                .extension(test_fixture_scoped())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_service_grant(grants(false, false)),
            true,
            None,
        )
        .await;
        let response = call(
            state,
            delete("/g1")
                .extension(test_fixture_scoped())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_unauthorized() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_service_grant(grants(true, false)),
            true,
            None,
        )
        .await;
        let response = call(state, delete("/g1").body(Body::empty()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// The grantee service deletes its grant on the internal interface.
    #[tokio::test]
    async fn test_delete_by_grantee_service() {
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
        let (state, _) = get_capturing_state(
            Provider::mocked_builder()
                .mock_service_grant(grants(true, true))
                .mock_oauth2_client(clients)
                .mock_resource(resource),
        )
        .await;
        let response = call(
            state,
            delete("/g1")
                .extension(Interface::Internal)
                .extension(SpiffeId::new("spiffe://td/service/heat-engine/host/h1").unwrap())
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
