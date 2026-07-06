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
//! `GET /SCIM/v2/{domain_id}/Users/{id}` (ADR 0024 §3.C Ownership Fencing).

use axum::{Json, extract::Path, extract::State};
use serde_json::json;

use openstack_keystone_core::api::KeystoneApiError;
use openstack_keystone_core::api::api_key_auth::ScimRealmAuth;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scim::ScimResourceType;

use crate::keystone::ServiceState;
use crate::scim::error::ScimApiError;
use crate::scim::types::ScimUser;

/// Fetch `(UserResponse, ScimResourceIndex)` for `id` under the caller's own
/// realm, enforcing the Ownership Fencing Algorithm (ADR 0024 §3.C): absent
/// index, or a `deprovisioned_at` stamp, is treated as `404 Not Found` —
/// indistinguishable from "does not exist", even if a same-ID resource
/// exists under a different realm or was created manually.
pub(super) async fn fetch_owned(
    state: &ServiceState,
    exec: &ExecutionContext<'_>,
    domain_id: &str,
    provider_id: &str,
    id: &str,
) -> Result<
    (
        openstack_keystone_core_types::identity::UserResponse,
        openstack_keystone_core_types::scim::ScimResourceIndex,
    ),
    KeystoneApiError,
> {
    let index = state
        .provider
        .get_scim_resource_provider()
        .get_index(exec, domain_id, provider_id, ScimResourceType::User, id)
        .await?;
    let Some(index) = index.filter(|i| i.deprovisioned_at.is_none()) else {
        return Err(KeystoneApiError::NotFound {
            resource: "user".to_string(),
            identifier: id.to_string(),
        });
    };
    let user = state
        .provider
        .get_identity_provider()
        .get_user(exec, id)
        .await?;
    let Some(user) = user else {
        return Err(KeystoneApiError::NotFound {
            resource: "user".to_string(),
            identifier: id.to_string(),
        });
    };
    Ok((user, index))
}

pub(super) async fn show(
    ScimRealmAuth { ctx, realm }: ScimRealmAuth,
    Path((_domain_id, id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<Json<ScimUser>, ScimApiError> {
    let exec = ExecutionContext::from_auth(&state, &ctx);
    let (user, index) =
        fetch_owned(&state, &exec, &realm.domain_id, &realm.provider_id, &id).await?;

    state
        .policy_enforcer
        .enforce(
            "identity/scim/user/show",
            &ctx,
            serde_json::Value::Null,
            Some(json!({"user": user})),
        )
        .await?;

    Ok(Json(ScimUser::from_domain(&user, &index)))
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core::api::api_key_auth::ScimRealmContext;
    use openstack_keystone_core::auth::ValidatedSecurityContext;
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalInfo, ScopeInfo,
        SecurityContext, UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::resource::Domain;
    use openstack_keystone_core_types::scim::ScimResourceIndex;

    use super::*;
    use crate::api::tests::get_mocked_state;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::scim_resource::MockScimResourceProvider;

    fn domain_scoped_auth(domain_id: &str) -> ScimRealmAuth {
        let user = UserIdentityInfoBuilder::default()
            .user_id("scim-provisioner")
            .build()
            .unwrap();
        let authz = AuthzInfoBuilder::default()
            .roles(Vec::new())
            .scope(ScopeInfo::Domain(Domain {
                id: domain_id.to_string(),
                name: String::new(),
                description: None,
                enabled: true,
                extra: Default::default(),
            }))
            .build()
            .unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(user),
            })
            .authorization(authz)
            .build();
        ScimRealmAuth {
            ctx: ValidatedSecurityContext::test_new(sc),
            realm: ScimRealmContext {
                domain_id: domain_id.to_string(),
                provider_id: "okta-1".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_show() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| {
                Ok(Some(ScimResourceIndex {
                    domain_id: "domain-1".to_string(),
                    provider_id: "okta-1".to_string(),
                    resource_type: ScimResourceType::User,
                    keystone_id: id.to_string(),
                    external_id: None,
                    version: 0,
                    deprovisioned_at: None,
                    created_at: 1,
                    updated_at: 1,
                }))
            });
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, id| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id(id)
                    .domain_id("domain-1")
                    .enabled(true)
                    .name("alice")
                    .build()
                    .unwrap(),
            ))
        });

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_scim_resource(resource_mock),
            true,
            None,
        )
        .await;

        let result = show(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "user-1".to_string())),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(result.id, "user-1");
    }

    #[tokio::test]
    async fn test_show_not_owned_returns_404() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, _| Ok(None));

        let state = get_mocked_state(
            Provider::mocked_builder().mock_scim_resource(resource_mock),
            true,
            None,
        )
        .await;

        let result = show(
            domain_scoped_auth("domain-1"),
            Path((
                "domain-1".to_string(),
                "user-from-another-realm".to_string(),
            )),
            State(state),
        )
        .await;
        assert!(matches!(
            result,
            Err(ScimApiError::Api(KeystoneApiError::NotFound { .. }))
        ));
    }

    #[tokio::test]
    async fn test_show_deprovisioned_returns_404() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| {
                Ok(Some(ScimResourceIndex {
                    domain_id: "domain-1".to_string(),
                    provider_id: "okta-1".to_string(),
                    resource_type: ScimResourceType::User,
                    keystone_id: id.to_string(),
                    external_id: None,
                    version: 1,
                    deprovisioned_at: Some(123),
                    created_at: 1,
                    updated_at: 1,
                }))
            });

        let state = get_mocked_state(
            Provider::mocked_builder().mock_scim_resource(resource_mock),
            true,
            None,
        )
        .await;

        let result = show(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "user-1".to_string())),
            State(state),
        )
        .await;
        assert!(matches!(
            result,
            Err(ScimApiError::Api(KeystoneApiError::NotFound { .. }))
        ));
    }
}
