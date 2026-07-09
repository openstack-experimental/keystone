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
//! `GET /SCIM/v2/{domain_id}/Groups` (ADR 0024 §3, §5.B filter, §5.D
//! pagination).

use axum::{Json, extract::Query, extract::State};
use serde::Deserialize;
use serde_json::json;

use openstack_keystone_core::api::api_key_auth::ScimRealmAuth;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scim::ScimResourceType;

use crate::keystone::ServiceState;
use crate::scim::error::ScimApiError;
use crate::scim::filter::{GROUP_FILTER_ATTRS, parse_filter};
use crate::scim::location::resource_location;
use crate::scim::types::{LIST_RESPONSE_SCHEMA, ScimGroup, ScimGroupListResponse};

#[derive(Debug, Deserialize, Default)]
pub(super) struct ListParams {
    #[serde(default)]
    start_index: Option<usize>,
    #[serde(default)]
    count: Option<usize>,
    #[serde(default)]
    filter: Option<String>,
}

pub(super) async fn list(
    ScimRealmAuth { ctx, realm }: ScimRealmAuth,
    State(state): State<ServiceState>,
    Query(params): Query<ListParams>,
) -> Result<Json<ScimGroupListResponse>, ScimApiError> {
    state
        .policy_enforcer
        .enforce(
            "identity/scim/group/list",
            &ctx,
            json!({"group": {"domain_id": realm.domain_id}}),
            None,
        )
        .await?;

    let parsed_filter = params
        .filter
        .as_deref()
        .map(|f| parse_filter(f, GROUP_FILTER_ATTRS))
        .transpose()?;

    let exec = ExecutionContext::from_auth(&state, &ctx);

    let indexes = state
        .provider
        .get_scim_resource_provider()
        .list_index(
            &exec,
            &realm.domain_id,
            &realm.provider_id,
            ScimResourceType::Group,
        )
        .await?;

    let start_index = params.start_index.unwrap_or(1).max(1);
    let count = params.count.unwrap_or(200).min(200);

    // As with Users (§5.D), a `filter` requires hydrating every active
    // group up front to evaluate `displayName` -- still bounded to this
    // realm's own resource count.
    let mut matched = Vec::new();
    for index in indexes.into_iter().filter(|i| i.deprovisioned_at.is_none()) {
        let Some(group) = state
            .provider
            .get_identity_provider()
            .get_group(&exec, &index.keystone_id)
            .await?
        else {
            continue;
        };
        let matches = parsed_filter.as_ref().is_none_or(|f| {
            f.matches(|attr| match attr {
                "displayname" => Some(group.name.clone()),
                "externalid" => index.external_id.clone(),
                "id" => Some(group.id.clone()),
                _ => None,
            })
        });
        if matches {
            matched.push((group, index));
        }
    }

    let total_results = matched.len();
    let mut resources = Vec::new();
    for (group, index) in matched
        .into_iter()
        .skip(start_index.saturating_sub(1))
        .take(count)
    {
        let member_ids = state
            .provider
            .get_identity_provider()
            .list_users_of_group(&exec, &group.id)
            .await?;
        let location = resource_location(&state, &realm.domain_id, "Groups", &group.id).await;
        resources.push(ScimGroup::from_domain(
            &group,
            &index,
            &member_ids,
            location,
        ));
    }

    Ok(Json(ScimGroupListResponse {
        schemas: vec![LIST_RESPONSE_SCHEMA.to_string()],
        total_results,
        start_index,
        items_per_page: count,
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
    use openstack_keystone_core_types::identity::Group;
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
            resource_type: ScimResourceType::Group,
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
                make_index("group-1", false),
                make_index("group-2", true),
            ])
        });

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
            .returning(|_, _| Ok(vec![]));

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
        assert_eq!(result.resources[0].id, "group-1");
        assert_eq!(result.total_results, 1);
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
