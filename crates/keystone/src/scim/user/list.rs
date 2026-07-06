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
//! `GET /SCIM/v2/{domain_id}/Users` (ADR 0024 §3, §5.D bare pagination).

use axum::{Json, extract::Query, extract::State};
use serde::Deserialize;
use serde_json::json;

use openstack_keystone_core::api::api_key_auth::ScimRealmAuth;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scim::ScimResourceType;

use crate::keystone::ServiceState;
use crate::scim::error::ScimApiError;
use crate::scim::types::{LIST_RESPONSE_SCHEMA, ScimListResponse, ScimUser};

#[derive(Debug, Deserialize, Default)]
pub(super) struct ListParams {
    #[serde(default)]
    start_index: Option<usize>,
    #[serde(default)]
    count: Option<usize>,
}

pub(super) async fn list(
    ScimRealmAuth { ctx, realm }: ScimRealmAuth,
    State(state): State<ServiceState>,
    Query(params): Query<ListParams>,
) -> Result<Json<ScimListResponse>, ScimApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/scim/user/list",
            &ctx,
            json!({"user": {"domain_id": realm.domain_id}}),
            None,
        )
        .await?;

    let exec = ExecutionContext::from_auth(&state, &ctx);

    let indexes = state
        .provider
        .get_scim_resource_provider()
        .list_index(
            &exec,
            &realm.domain_id,
            &realm.provider_id,
            ScimResourceType::User,
        )
        .await?;

    let start_index = params.start_index.unwrap_or(1).max(1);
    let count = params.count.unwrap_or(200).min(200);
    let total_results = indexes.len();

    let mut resources = Vec::new();
    for index in indexes
        .into_iter()
        .filter(|i| i.deprovisioned_at.is_none())
        .skip(start_index.saturating_sub(1))
        .take(count)
    {
        if let Some(user) = state
            .provider
            .get_identity_provider()
            .get_user(&exec, &index.keystone_id)
            .await?
        {
            resources.push(ScimUser::from_domain(&user, &index));
        }
    }

    Ok(Json(ScimListResponse {
        schemas: vec![LIST_RESPONSE_SCHEMA.to_string()],
        total_results,
        start_index,
        items_per_page: resources.len(),
        resources,
    }))
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

    fn make_index(keystone_id: &str, deprovisioned: bool) -> ScimResourceIndex {
        ScimResourceIndex {
            domain_id: "domain-1".to_string(),
            provider_id: "okta-1".to_string(),
            resource_type: ScimResourceType::User,
            keystone_id: keystone_id.to_string(),
            external_id: None,
            version: 0,
            deprovisioned_at: if deprovisioned { Some(1) } else { None },
            created_at: 1,
            updated_at: 1,
        }
    }

    #[tokio::test]
    async fn test_list_filters_deprovisioned() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock.expect_list_index().returning(|_, _, _, _| {
            Ok(vec![
                make_index("user-1", false),
                make_index("user-2", true),
            ])
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

        let result = list(
            domain_scoped_auth("domain-1"),
            State(state),
            Query(ListParams::default()),
        )
        .await
        .unwrap();
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.resources[0].id, "user-1");
        // total_results counts everything the realm owns, deprovisioned
        // included, matching the raw index count before filtering.
        assert_eq!(result.total_results, 2);
    }

    #[tokio::test]
    async fn test_list_policy_denied() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let result = list(
            domain_scoped_auth("domain-1"),
            State(state),
            Query(ListParams::default()),
        )
        .await;
        assert!(matches!(result, Err(ScimApiError::Api(_))));
    }
}
