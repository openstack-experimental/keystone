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
//! `PUT /SCIM/v2/{domain_id}/Groups/{id}` — full-replace update (ADR 0024
//! §3.C, §4, §5.C, §7, §11; `PATCH` is deferred to a later PR).

use std::collections::HashSet;

use axum::{Json, extract::Path, extract::State};
use serde_json::json;

use openstack_keystone_core::api::KeystoneApiError;
use openstack_keystone_core::api::api_key_auth::ScimRealmAuth;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scim::{ScimResourceIndexUpdate, ScimResourceType};

use crate::keystone::ServiceState;
use crate::scim::error::ScimApiError;
use crate::scim::group::membership::validate_members_owned_by_realm;
use crate::scim::group::show::fetch_owned;
use crate::scim::types::{MAX_GROUP_MEMBERS, ScimGroup, ScimGroupWrite};

pub(super) async fn update(
    ScimRealmAuth { ctx, realm }: ScimRealmAuth,
    Path((_domain_id, id)): Path<(String, String)>,
    State(state): State<ServiceState>,
    Json(req): Json<ScimGroupWrite>,
) -> Result<Json<ScimGroup>, ScimApiError> {
    if req.display_name.trim().is_empty() {
        return Err(KeystoneApiError::BadRequest("displayName is required".to_string()).into());
    }

    let new_member_ids = req.member_ids();
    if new_member_ids.len() > MAX_GROUP_MEMBERS {
        return Err(ScimApiError::InvalidValue(format!(
            "members must not exceed {MAX_GROUP_MEMBERS} entries"
        )));
    }

    let exec = ExecutionContext::from_auth(&state, &ctx);
    let (existing_group, existing_index) =
        fetch_owned(&state, &exec, &realm.domain_id, &realm.provider_id, &id).await?;

    state
        .policy_enforcer
        .enforce(
            "identity/scim/group/update",
            &ctx,
            json!({"group": {"display_name": req.display_name}}),
            Some(json!({"group": existing_group})),
        )
        .await?;

    // ADR 0024 §3.D: if `displayName` is changing, re-run the domain-wide
    // collision check (a no-op rename doesn't need it). The lookup is
    // case-insensitive, so exclude the resource's own id — otherwise a
    // case-only rename would collide with itself.
    if req.display_name != existing_group.name
        && let Some(matched_id) = state
            .provider
            .get_identity_provider()
            .find_group_by_name_ci(&exec, &realm.domain_id, &req.display_name)
            .await?
        && matched_id != id
    {
        return Err(ScimApiError::Uniqueness(
            "displayName already exists within this domain".to_string(),
        ));
    }

    // ADR 0024 §7: every referenced member must already be owned by this
    // same realm.
    validate_members_owned_by_realm(
        &state,
        &exec,
        &realm.domain_id,
        &realm.provider_id,
        &new_member_ids,
    )
    .await?;

    if req.external_id != existing_index.external_id {
        state
            .provider
            .get_scim_resource_provider()
            .update_index(
                &exec,
                &realm.domain_id,
                &realm.provider_id,
                ScimResourceType::Group,
                &id,
                ScimResourceIndexUpdate {
                    external_id: Some(req.external_id.clone()),
                    deprovisioned_at: None,
                },
            )
            .await?;
    }

    let group = state
        .provider
        .get_identity_provider()
        .update_group(&exec, &id, req.to_group_update())
        .await?;

    // §5.C: `PUT` does a full membership resync against the target member set,
    // not an incremental patch. Adds are attempted before removals so that a
    // failure leaves the group unchanged rather than emptying it.
    let current_member_ids: HashSet<String> = state
        .provider
        .get_identity_provider()
        .list_users_of_group(&exec, &id)
        .await?
        .into_iter()
        .collect();
    let target_member_ids: HashSet<String> = new_member_ids.iter().cloned().collect();

    let added: Vec<(&str, &str)> = target_member_ids
        .difference(&current_member_ids)
        .map(|uid| (uid.as_str(), id.as_str()))
        .collect();
    if !added.is_empty() {
        state
            .provider
            .get_identity_provider()
            .add_users_to_groups(&exec, added)
            .await?;
    }
    for removed in current_member_ids.difference(&target_member_ids) {
        state
            .provider
            .get_identity_provider()
            .remove_user_from_group(&exec, removed, &id)
            .await?;
    }

    let index = state
        .provider
        .get_scim_resource_provider()
        .get_index(
            &exec,
            &realm.domain_id,
            &realm.provider_id,
            ScimResourceType::Group,
            &id,
        )
        .await?
        .unwrap_or(existing_index);

    Ok(Json(ScimGroup::from_domain(
        &group,
        &index,
        &new_member_ids,
    )))
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core::api::KeystoneApiError;
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
    use crate::scim::types::ScimGroupMember;
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

    fn make_index(keystone_id: &str) -> ScimResourceIndex {
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

    fn write_req(display_name: &str, members: Vec<&str>) -> ScimGroupWrite {
        ScimGroupWrite {
            schemas: vec![],
            external_id: Some("ext-old".to_string()),
            display_name: display_name.to_string(),
            members: members
                .into_iter()
                .map(|v| ScimGroupMember {
                    value: v.to_string(),
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn test_update() {
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
            .expect_find_group_by_name_ci()
            .returning(|_, _, _| Ok(None));
        identity_mock.expect_update_group().returning(|_, id, req| {
            Ok(Group {
                id: id.to_string(),
                domain_id: "domain-1".to_string(),
                name: req.name.clone().unwrap(),
                description: None,
                extra: Default::default(),
            })
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

        let result = update(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "group-1".to_string())),
            State(state),
            Json(write_req("new_name", vec![])),
        )
        .await
        .unwrap();
        assert_eq!(result.display_name, "new_name");
    }

    #[tokio::test]
    async fn test_update_resyncs_membership() {
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
            .expect_find_group_by_name_ci()
            .returning(|_, _, _| Ok(None));
        identity_mock.expect_update_group().returning(|_, id, req| {
            Ok(Group {
                id: id.to_string(),
                domain_id: "domain-1".to_string(),
                name: req.name.clone().unwrap(),
                description: None,
                extra: Default::default(),
            })
        });
        // Current membership: user-old. Desired: user-new.
        identity_mock
            .expect_list_users_of_group()
            .returning(|_, _| Ok(vec!["user-old".to_string()]));
        identity_mock
            .expect_add_users_to_groups()
            .withf(|_, memberships| memberships == &vec![("user-new", "group-1")])
            .returning(|_, _| Ok(()));
        identity_mock
            .expect_remove_user_from_group()
            .withf(|_, uid, gid| uid == "user-old" && gid == "group-1")
            .returning(|_, _, _| Ok(()));

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_scim_resource(resource_mock),
            true,
            None,
        )
        .await;

        let result = update(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "group-1".to_string())),
            State(state),
            Json(write_req("engineers", vec!["user-new"])),
        )
        .await
        .unwrap();
        assert_eq!(result.members.len(), 1);
        assert_eq!(result.members[0].value, "user-new");
    }

    #[tokio::test]
    async fn test_update_rejects_member_not_owned_by_realm() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .withf(|_, _, _, rt, id| *rt == ScimResourceType::Group && id == "group-1")
            .returning(|_, _, _, _, id| Ok(Some(make_index(id))));
        resource_mock
            .expect_get_index()
            .withf(|_, _, _, rt, _| *rt == ScimResourceType::User)
            .returning(|_, _, _, _, _| Ok(None));

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
        identity_mock.expect_update_group().never();

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_scim_resource(resource_mock),
            true,
            None,
        )
        .await;

        let result = update(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "group-1".to_string())),
            State(state),
            Json(write_req("engineers", vec!["user-from-elsewhere"])),
        )
        .await;
        assert!(matches!(result, Err(ScimApiError::InvalidValue(_))));
    }

    #[tokio::test]
    async fn test_update_not_owned_returns_404() {
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

        let result = update(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "group-1".to_string())),
            State(state),
            Json(write_req("new_name", vec![])),
        )
        .await;
        assert!(matches!(
            result,
            Err(ScimApiError::Api(KeystoneApiError::NotFound { .. }))
        ));
    }
}
