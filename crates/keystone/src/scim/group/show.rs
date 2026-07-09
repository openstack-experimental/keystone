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
//! `GET /SCIM/v2/{domain_id}/Groups/{id}` (ADR 0024 §3.C Ownership Fencing).

use axum::{Json, extract::Path, extract::State, http::HeaderMap};
use serde_json::json;

use openstack_keystone_core::api::KeystoneApiError;
use openstack_keystone_core::api::api_key_auth::ScimRealmAuth;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scim::ScimResourceType;

use crate::keystone::ServiceState;
use crate::scim::error::ScimApiError;
use crate::scim::etag::etag_header;
use crate::scim::location::resource_location;
use crate::scim::types::ScimGroup;

/// Fetch `(Group, ScimResourceIndex)` for `id` under the caller's own realm,
/// enforcing the Ownership Fencing Algorithm (ADR 0024 §3.C): absent index,
/// or a `deprovisioned_at` stamp, is treated as `404 Not Found` —
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
        openstack_keystone_core_types::identity::Group,
        openstack_keystone_core_types::scim::ScimResourceIndex,
    ),
    KeystoneApiError,
> {
    let index = state
        .provider
        .get_scim_resource_provider()
        .get_index(exec, domain_id, provider_id, ScimResourceType::Group, id)
        .await?;
    let Some(index) = index.filter(|i| i.deprovisioned_at.is_none()) else {
        return Err(KeystoneApiError::NotFound {
            resource: "group".to_string(),
            identifier: id.to_string(),
        });
    };
    let group = state
        .provider
        .get_identity_provider()
        .get_group(exec, id)
        .await?;
    let Some(group) = group else {
        return Err(KeystoneApiError::NotFound {
            resource: "group".to_string(),
            identifier: id.to_string(),
        });
    };
    Ok((group, index))
}

pub(super) async fn show(
    ScimRealmAuth { ctx, realm }: ScimRealmAuth,
    Path((_domain_id, id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<(HeaderMap, Json<ScimGroup>), ScimApiError> {
    let exec = ExecutionContext::from_auth(&state, &ctx);
    let (group, index) =
        fetch_owned(&state, &exec, &realm.domain_id, &realm.provider_id, &id).await?;

    state
        .policy_enforcer
        .enforce(
            "identity/scim/group/show",
            &ctx,
            serde_json::Value::Null,
            Some(json!({"group": group})),
        )
        .await?;

    let member_ids = state
        .provider
        .get_identity_provider()
        .list_users_of_group(&exec, &group.id)
        .await?;

    let location = resource_location(&state, &realm.domain_id, "Groups", &id).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        "etag",
        etag_header(index.version)
            .parse()
            .expect("weak etag is valid header value"),
    );
    Ok((
        headers,
        Json(ScimGroup::from_domain(
            &group,
            &index,
            &member_ids,
            location,
        )),
    ))
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core::api::api_key_auth::ScimRealmContext;
    use openstack_keystone_core::auth::ValidatedSecurityContext;
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalInfo, ScopeInfo,
        SecurityContext, UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::identity::Group;
    use openstack_keystone_core_types::resource::Domain;
    use openstack_keystone_core_types::scim::ScimResourceIndex;

    use super::*;
    use crate::api::tests::get_mocked_state;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::scim_resource::MockScimResourceProvider;

    pub(super) fn domain_scoped_auth(domain_id: &str) -> ScimRealmAuth {
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

    pub(super) fn make_index(keystone_id: &str) -> ScimResourceIndex {
        ScimResourceIndex {
            domain_id: "domain-1".to_string(),
            provider_id: "okta-1".to_string(),
            resource_type: ScimResourceType::Group,
            keystone_id: keystone_id.to_string(),
            external_id: Some("ext-old".to_string()),
            version: 0,
            deprovisioned_at: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[tokio::test]
    async fn test_show() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| Ok(Some(make_index(id))));
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_group().returning(|_, id| {
            Ok(Some(Group {
                id: id.to_string(),
                domain_id: "domain-1".to_string(),
                name: "engineers".to_string(),
                description: None,
                extra: Default::default(),
            }))
        });
        identity_mock
            .expect_list_users_of_group()
            .returning(|_, _| Ok(vec!["user-1".to_string()]));

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_scim_resource(resource_mock),
            true,
            None,
        )
        .await;

        let (headers, Json(result)) = show(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "group-1".to_string())),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(result.id, "group-1");
        assert_eq!(result.members.len(), 1);
        assert_eq!(result.members[0].value, "user-1");
        assert_eq!(headers.get("etag").unwrap(), r#"W/"0""#);
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
                "group-from-another-realm".to_string(),
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
                    deprovisioned_at: Some(123),
                    ..make_index(id)
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
            Path(("domain-1".to_string(), "group-1".to_string())),
            State(state),
        )
        .await;
        assert!(matches!(
            result,
            Err(ScimApiError::Api(KeystoneApiError::NotFound { .. }))
        ));
    }
}
