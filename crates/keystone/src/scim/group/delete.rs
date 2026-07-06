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
//! `DELETE /SCIM/v2/{domain_id}/Groups/{id}` — neutralize + tombstone (ADR
//! 0024 §6.B). Role assignments are cleared immediately; membership rows are
//! deliberately retained (forensic snapshot) until the janitor purge (a
//! later PR) reclaims the group past the retention window.

use axum::{extract::Path, extract::State, http::StatusCode};
use chrono::Utc;
use serde_json::json;

use openstack_keystone_core::api::api_key_auth::ScimRealmAuth;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::assignment::RoleAssignmentListParametersBuilder;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::scim::{ScimResourceIndexUpdate, ScimResourceType};

use crate::keystone::ServiceState;
use crate::scim::error::ScimApiError;
use crate::scim::group::show::fetch_owned;

pub(super) async fn delete(
    ScimRealmAuth { ctx, realm }: ScimRealmAuth,
    Path((_domain_id, id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<StatusCode, ScimApiError> {
    let exec = ExecutionContext::from_auth(&state, &ctx);
    let (existing_group, _existing_index) =
        fetch_owned(&state, &exec, &realm.domain_id, &realm.provider_id, &id).await?;

    state
        .policy_enforcer
        .enforce(
            "identity/scim/group/delete",
            &ctx,
            serde_json::Value::Null,
            Some(json!({"group": existing_group})),
        )
        .await?;

    // §6.B step 1: clear the group's role assignments — this is the
    // security-relevant action, since a "deleted-looking" group that still
    // grants roles would be a silent escalation path.
    let params = RoleAssignmentListParametersBuilder::default()
        .group_id(id.clone())
        .build()?;
    let assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(&exec, &params)
        .await?;
    for assignment in assignments {
        state
            .provider
            .get_assignment_provider()
            .revoke_grant(&exec, assignment)
            .await?;
    }

    // §6.B step 2: stamp `deprovisioned_at` so subsequent reads under this
    // realm treat the resource as absent (§3.C). Membership rows are
    // deliberately left intact — clearing them would destroy the forensic
    // snapshot (who belonged to the group at the moment of deletion) that
    // the "preserve audit trail" rationale for not hard-deleting is meant to
    // protect.
    let now = Utc::now().timestamp();
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
                external_id: None,
                deprovisioned_at: Some(Some(now)),
            },
        )
        .await?;

    // §9: emit a CADF `disable` event for the SCIM deprovisioning semantics.
    state
        .event_dispatcher
        .emit(Event::new(
            Operation::Disable,
            EventPayload::Group { id: id.clone() },
        ))
        .await;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core::api::KeystoneApiError;
    use openstack_keystone_core::api::api_key_auth::ScimRealmContext;
    use openstack_keystone_core::auth::ValidatedSecurityContext;
    use openstack_keystone_core_types::assignment::AssignmentBuilder;
    use openstack_keystone_core_types::assignment::AssignmentType;
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalInfo, ScopeInfo,
        SecurityContext, UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::identity::Group;
    use openstack_keystone_core_types::resource::Domain;
    use openstack_keystone_core_types::scim::ScimResourceIndex;

    use super::*;
    use crate::api::tests::get_mocked_state;
    use crate::assignment::MockAssignmentProvider;
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

    fn make_index(keystone_id: &str) -> ScimResourceIndex {
        ScimResourceIndex {
            domain_id: "domain-1".to_string(),
            provider_id: "okta-1".to_string(),
            resource_type: ScimResourceType::Group,
            keystone_id: keystone_id.to_string(),
            external_id: None,
            version: 0,
            deprovisioned_at: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[tokio::test]
    async fn test_delete_neutralizes_and_tombstones() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| Ok(Some(make_index(id))));
        resource_mock
            .expect_update_index()
            .withf(|_, _, _, _, _, update| matches!(update.deprovisioned_at, Some(Some(_))))
            .returning(|_, _, _, _, id, _| Ok(make_index(id)));

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

        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_, _| {
                Ok(vec![
                    AssignmentBuilder::default()
                        .actor_id("group-1")
                        .role_id("role-1")
                        .target_id("project-1")
                        .r#type(AssignmentType::GroupProject)
                        .inherited(false)
                        .build()
                        .unwrap(),
                ])
            });
        assignment_mock
            .expect_revoke_grant()
            .returning(|_, _| Ok(()));

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_scim_resource(resource_mock)
                .mock_assignment(assignment_mock),
            true,
            None,
        )
        .await;

        let status = delete(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "group-1".to_string())),
            State(state),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_delete_not_owned_returns_404() {
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

        let result = delete(
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

    #[tokio::test]
    async fn test_delete_idempotent_on_repeat() {
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

        let result = delete(
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
