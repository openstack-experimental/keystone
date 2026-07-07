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
//! `POST /SCIM/v2/{domain_id}/Groups` (ADR 0024 §3.C, §3.D, §4, §7, §11).

use axum::{Json, extract::State, http::HeaderMap, http::StatusCode};
use serde_json::json;

use openstack_keystone_core::api::KeystoneApiError;
use openstack_keystone_core::api::api_key_auth::ScimRealmAuth;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scim::{
    ScimResourceIndexCreate, ScimResourceProviderError, ScimResourceType,
};

use crate::keystone::ServiceState;
use crate::scim::error::ScimApiError;
use crate::scim::etag::etag_header;
use crate::scim::group::membership::validate_members_owned_by_realm;
use crate::scim::types::{MAX_GROUP_MEMBERS, ScimGroup, ScimGroupWrite};

pub(super) async fn create(
    ScimRealmAuth { ctx, realm }: ScimRealmAuth,
    State(state): State<ServiceState>,
    Json(req): Json<ScimGroupWrite>,
) -> Result<(StatusCode, HeaderMap, Json<ScimGroup>), ScimApiError> {
    if req.display_name.trim().is_empty() {
        return Err(KeystoneApiError::BadRequest("displayName is required".to_string()).into());
    }

    let member_ids = req.member_ids();
    // ADR 0024 §11: reject an oversized membership push before any storage
    // mutation, not after partial application.
    if member_ids.len() > MAX_GROUP_MEMBERS {
        return Err(ScimApiError::InvalidValue(format!(
            "members must not exceed {MAX_GROUP_MEMBERS} entries"
        )));
    }

    let exec = ExecutionContext::from_auth(&state, &ctx);

    state
        .policy_enforcer
        .enforce(
            "identity/scim/group/create",
            &ctx,
            json!({"group": {"domain_id": realm.domain_id}}),
            None,
        )
        .await?;

    // ADR 0024 §3.D: domain-wide, case-insensitive `displayName` collision
    // check — regardless of which realm (or nothing) created the existing
    // group.
    if state
        .provider
        .get_identity_provider()
        .find_group_by_name_ci(&exec, &realm.domain_id, &req.display_name)
        .await?
        .is_some()
    {
        return Err(ScimApiError::Uniqueness(
            "displayName already exists within this domain".to_string(),
        ));
    }

    // ADR 0024 §7: every referenced member must already be owned by this
    // same realm (a `ScimResourceIndex` for `ScimResourceType::User` under
    // this `provider_id`) — checked before creating the group so a rejected
    // membership reference doesn't leave an orphaned empty group behind.
    validate_members_owned_by_realm(
        &state,
        &exec,
        &realm.domain_id,
        &realm.provider_id,
        &member_ids,
    )
    .await?;

    let group = state
        .provider
        .get_identity_provider()
        .create_group(&exec, req.to_group_create(&realm.domain_id))
        .await?;

    let index = match state
        .provider
        .get_scim_resource_provider()
        .create_index(
            &exec,
            ScimResourceIndexCreate {
                domain_id: realm.domain_id.clone(),
                provider_id: realm.provider_id.clone(),
                resource_type: ScimResourceType::Group,
                keystone_id: group.id.clone(),
                external_id: req.external_id.clone(),
            },
        )
        .await
    {
        Ok(index) => index,
        Err(e) => {
            // The index write failed (most likely a realm-scoped
            // `externalId` collision, ADR 0024 §3.C) after the Identity
            // group was already created. Best-effort compensating delete so
            // the orphaned group isn't left dangling.
            let _ = state
                .provider
                .get_identity_provider()
                .delete_group(&exec, &group.id)
                .await;
            return Err(match e {
                ScimResourceProviderError::Conflict(msg) => ScimApiError::Uniqueness(msg),
                other => other.into(),
            });
        }
    };

    if !member_ids.is_empty() {
        let memberships = member_ids
            .iter()
            .map(|uid| (uid.as_str(), group.id.as_str()))
            .collect();
        state
            .provider
            .get_identity_provider()
            .add_users_to_groups(&exec, memberships)
            .await?;
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        "etag",
        etag_header(index.version)
            .parse()
            .expect("weak etag is valid header value"),
    );
    Ok((
        StatusCode::CREATED,
        headers,
        Json(ScimGroup::from_domain(&group, &index, &member_ids)),
    ))
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use openstack_keystone_core::api::api_key_auth::ScimRealmContext;
    use openstack_keystone_core::auth::ValidatedSecurityContext;
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthzInfoBuilder, IdentityInfo, PrincipalInfo, ScopeInfo,
        SecurityContext, UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::identity::Group;
    use openstack_keystone_core_types::resource::Domain;
    use openstack_keystone_core_types::scim::{ScimResourceIndex, ScimResourceProviderError};

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

    fn req(display_name: &str, members: Vec<&str>) -> ScimGroupWrite {
        ScimGroupWrite {
            schemas: vec![],
            external_id: Some("ext-1".to_string()),
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
    async fn test_create() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_find_group_by_name_ci()
            .returning(|_, _, _| Ok(None));
        identity_mock.expect_create_group().returning(|_, req| {
            Ok(Group {
                id: "group-1".to_string(),
                domain_id: req.domain_id.clone(),
                name: req.name.clone(),
                description: None,
                extra: Default::default(),
            })
        });

        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock.expect_create_index().returning(|_, data| {
            Ok(ScimResourceIndex {
                domain_id: data.domain_id,
                provider_id: data.provider_id,
                resource_type: data.resource_type,
                keystone_id: data.keystone_id,
                external_id: data.external_id,
                version: 0,
                deprovisioned_at: None,
                created_at: 1,
                updated_at: 1,
            })
        });

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_scim_resource(resource_mock),
            true,
            None,
        )
        .await;

        let (status, headers, Json(body)) = create(
            domain_scoped_auth("domain-1"),
            State(state),
            Json(req("engineers", vec![])),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body.display_name, "engineers");
        assert_eq!(body.id, "group-1");
        assert_eq!(headers.get("etag").unwrap(), r#"W/"0""#);
    }

    #[tokio::test]
    async fn test_create_with_members() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_find_group_by_name_ci()
            .returning(|_, _, _| Ok(None));
        identity_mock.expect_create_group().returning(|_, req| {
            Ok(Group {
                id: "group-1".to_string(),
                domain_id: req.domain_id.clone(),
                name: req.name.clone(),
                description: None,
                extra: Default::default(),
            })
        });
        identity_mock
            .expect_add_users_to_groups()
            .withf(|_, memberships| memberships == &vec![("user-1", "group-1")])
            .returning(|_, _| Ok(()));

        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .withf(|_, _, _, rt, id| *rt == ScimResourceType::User && id == "user-1")
            .returning(|_, domain_id, provider_id, _, id| {
                Ok(Some(ScimResourceIndex {
                    domain_id: domain_id.to_string(),
                    provider_id: provider_id.to_string(),
                    resource_type: ScimResourceType::User,
                    keystone_id: id.to_string(),
                    external_id: None,
                    version: 0,
                    deprovisioned_at: None,
                    created_at: 1,
                    updated_at: 1,
                }))
            });
        resource_mock.expect_create_index().returning(|_, data| {
            Ok(ScimResourceIndex {
                domain_id: data.domain_id,
                provider_id: data.provider_id,
                resource_type: data.resource_type,
                keystone_id: data.keystone_id,
                external_id: data.external_id,
                version: 0,
                deprovisioned_at: None,
                created_at: 1,
                updated_at: 1,
            })
        });

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_scim_resource(resource_mock),
            true,
            None,
        )
        .await;

        let (status, _headers, Json(body)) = create(
            domain_scoped_auth("domain-1"),
            State(state),
            Json(req("engineers", vec!["user-1"])),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body.members.len(), 1);
        assert_eq!(body.members[0].value, "user-1");
    }

    #[tokio::test]
    async fn test_create_rejects_member_not_owned_by_realm() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_find_group_by_name_ci()
            .returning(|_, _, _| Ok(None));
        identity_mock.expect_create_group().never();

        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, _| Ok(None));

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_scim_resource(resource_mock),
            true,
            None,
        )
        .await;

        let result = create(
            domain_scoped_auth("domain-1"),
            State(state),
            Json(req("engineers", vec!["user-from-elsewhere"])),
        )
        .await;
        assert!(matches!(result, Err(ScimApiError::InvalidValue(_))));
    }

    #[tokio::test]
    async fn test_create_rejects_membership_cap_exceeded() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let members: Vec<&str> = Vec::new();
        let mut write = req("engineers", members);
        write.members = (0..1001)
            .map(|i| ScimGroupMember {
                value: format!("user-{i}"),
            })
            .collect();

        let result = create(domain_scoped_auth("domain-1"), State(state), Json(write)).await;
        assert!(matches!(result, Err(ScimApiError::InvalidValue(_))));
    }

    #[tokio::test]
    async fn test_create_rejects_domain_wide_duplicate_display_name() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_find_group_by_name_ci()
            .returning(|_, _, _| Ok(Some("other-group".to_string())));

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
        )
        .await;

        let result = create(
            domain_scoped_auth("domain-1"),
            State(state),
            Json(req("engineers", vec![])),
        )
        .await;
        assert!(matches!(result, Err(ScimApiError::Uniqueness(_))));
    }

    #[tokio::test]
    async fn test_create_rejects_realm_scoped_external_id_conflict() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_find_group_by_name_ci()
            .returning(|_, _, _| Ok(None));
        identity_mock.expect_create_group().returning(|_, req| {
            Ok(Group {
                id: "group-1".to_string(),
                domain_id: req.domain_id.clone(),
                name: req.name.clone(),
                description: None,
                extra: Default::default(),
            })
        });
        identity_mock.expect_delete_group().returning(|_, _| Ok(()));

        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_create_index()
            .returning(|_, _| Err(ScimResourceProviderError::Conflict("dup".to_string())));

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_scim_resource(resource_mock),
            true,
            None,
        )
        .await;

        let result = create(
            domain_scoped_auth("domain-1"),
            State(state),
            Json(req("engineers", vec![])),
        )
        .await;
        assert!(matches!(result, Err(ScimApiError::Uniqueness(_))));
    }

    #[tokio::test]
    async fn test_create_policy_denied() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let result = create(
            domain_scoped_auth("domain-1"),
            State(state),
            Json(req("engineers", vec![])),
        )
        .await;
        assert!(matches!(
            result,
            Err(ScimApiError::Api(KeystoneApiError::Forbidden { .. }))
        ));
    }

    #[tokio::test]
    async fn test_create_rejects_empty_display_name() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let result = create(
            domain_scoped_auth("domain-1"),
            State(state),
            Json(req("   ", vec![])),
        )
        .await;
        assert!(matches!(
            result,
            Err(ScimApiError::Api(KeystoneApiError::BadRequest(_)))
        ));
    }
}
