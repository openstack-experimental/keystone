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
//! SCIM realm: operator-triggered purge-now of a single already-
//! deprovisioned resource (ADR 0024 §6.C, last paragraph). Bypasses the
//! janitor's configured retention window -- the erasure-request path for
//! deployments under GDPR or comparable regimes.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use openstack_keystone_api_types::v4::scim_realm::ScimRealm;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::scim_resource::janitor;
use openstack_keystone_core_types::scim::ScimResourceType;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

fn parse_resource_type(raw: &str) -> Result<ScimResourceType, KeystoneApiError> {
    match raw {
        "user" => Ok(ScimResourceType::User),
        "group" => Ok(ScimResourceType::Group),
        _ => Err(KeystoneApiError::NotFound {
            resource: "scim_resource_type".into(),
            identifier: raw.to_string(),
        }),
    }
}

/// Immediately purge a single already-deprovisioned SCIM resource, ignoring
/// the configured retention window.
#[utoipa::path(
    delete,
    path = "/{domain_id}/{provider_id}/purge/{resource_type}/{keystone_id}",
    operation_id = "/scim_realm:purge",
    params(
        ("domain_id" = String, Path, description = "Domain ID"),
        ("provider_id" = String, Path, description = "Realm provider_id"),
        ("resource_type" = String, Path, description = "`user` or `group`"),
        ("keystone_id" = String, Path, description = "The resource's Keystone `User.id`/`Group.id`"),
    ),
    responses(
        (status = NO_CONTENT, description = "Resource purged"),
    ),
    security(("x-auth" = [])),
    tag="scim_realm"
)]
#[tracing::instrument(
    name = "api::v4::scim_realm::purge",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn purge(
    Auth(user_auth): Auth,
    Path((domain_id, provider_id, resource_type, keystone_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    State(state): State<ServiceState>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let resource_type = parse_resource_type(&resource_type)?;
    let exec = ExecutionContext::from_auth(&state, &user_auth);

    let current = state
        .provider
        .get_scim_realm_provider()
        .get_realm(&exec, &domain_id, &provider_id)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "scim_realm".into(),
            identifier: provider_id.clone(),
        })?;

    state
        .policy_enforcer
        .enforce(
            "identity/scim_realm/purge",
            &user_auth,
            serde_json::Value::Null,
            Some(serde_json::json!({"scim_realm": ScimRealm::from(current)})),
        )
        .await?;

    janitor::purge_now(
        &state,
        &domain_id,
        &provider_id,
        resource_type,
        &keystone_id,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core_types::scim::ScimResourceIndex;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::scim_realm::MockScimRealmProvider;
    use crate::scim_resource::MockScimResourceProvider;

    fn sample_realm_core() -> openstack_keystone_core_types::scim::ScimRealmResource {
        openstack_keystone_core_types::scim::ScimRealmResource {
            domain_id: "domain_id".into(),
            provider_id: "provider-1".into(),
            idp_id: "idp-1".into(),
            display_name: "Okta - Employees".into(),
            enabled: true,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn deprovisioned_index() -> ScimResourceIndex {
        ScimResourceIndex {
            domain_id: "domain_id".into(),
            provider_id: "provider-1".into(),
            resource_type: openstack_keystone_core_types::scim::ScimResourceType::User,
            keystone_id: "user-1".into(),
            external_id: None,
            version: 3,
            deprovisioned_at: Some(1),
            created_at: 0,
            updated_at: 0,
        }
    }

    #[tokio::test]
    async fn test_purge_deprovisioned_resource() {
        let vsc = test_fixture_scoped();
        let mut realm_mock = MockScimRealmProvider::default();
        realm_mock
            .expect_get_realm()
            .returning(|_, _, _| Ok(Some(sample_realm_core())));

        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(move |_, _, _, _, _| Ok(Some(deprovisioned_index())));
        resource_mock
            .expect_purge_index()
            .returning(|_, _, _, _, _| Ok(()));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_delete_user()
            .withf(|_, id| id == "user-1")
            .returning(|_, _| Ok(()));

        let provider = Provider::mocked_builder()
            .mock_scim_realm(realm_mock)
            .mock_scim_resource(resource_mock)
            .mock_identity(identity_mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/domain_id/provider-1/purge/user/user-1")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_purge_policy_denied() {
        let vsc = test_fixture_scoped();
        let mut realm_mock = MockScimRealmProvider::default();
        realm_mock
            .expect_get_realm()
            .returning(|_, _, _| Ok(Some(sample_realm_core())));

        let provider = Provider::mocked_builder().mock_scim_realm(realm_mock);
        let state = get_mocked_state(provider, false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/domain_id/provider-1/purge/user/user-1")
                    .extension(vsc)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_purge_unauthorized() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/domain_id/provider-1/purge/user/user-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
