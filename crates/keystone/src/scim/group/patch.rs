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
//! `PATCH /SCIM/v2/{domain_id}/Groups/{id}` (ADR 0024 §5.C, §7, §11).
//!
//! `members` is `add`/`remove` only -- the "push group" pattern -- not
//! `replace`; reuses the `identity/scim/group/update` OPA policy, same as
//! `PUT`.

use std::collections::HashSet;

use axum::{Json, extract::Path, extract::State, http::HeaderMap};
use serde_json::json;

use openstack_keystone_core::api::KeystoneApiError;
use openstack_keystone_core::api::api_key_auth::ScimRealmAuth;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::identity::GroupUpdate;
use openstack_keystone_core_types::scim::{
    ScimResourceIndexUpdate, ScimResourceProviderError, ScimResourceType,
};

use crate::keystone::ServiceState;
use crate::scim::error::ScimApiError;
use crate::scim::etag::{etag_header, parse_if_match};
use crate::scim::extract::ScimJson;
use crate::scim::group::membership::validate_members_owned_by_realm;
use crate::scim::group::show::fetch_owned;
use crate::scim::location::resource_location;
use crate::scim::patch::{GROUP_PATCH_PATHS, PatchOp, ScimPatchRequest, validate_patch};
use crate::scim::types::{MAX_GROUP_MEMBERS, ScimGroup, ScimGroupMember};

fn member_ids(value: &serde_json::Value) -> Result<Vec<String>, ScimApiError> {
    serde_json::from_value::<Vec<ScimGroupMember>>(value.clone())
        .map(|members| members.into_iter().map(|m| m.value).collect())
        .map_err(|_| {
            ScimApiError::InvalidValue(
                "members value must be an array of {\"value\": \"<id>\"} objects".to_string(),
            )
        })
}

pub(super) async fn patch(
    ScimRealmAuth { ctx, realm }: ScimRealmAuth,
    Path((_domain_id, id)): Path<(String, String)>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    ScimJson(req): ScimJson<ScimPatchRequest>,
) -> Result<(HeaderMap, Json<ScimGroup>), ScimApiError> {
    req.validate_schemas().map_err(ScimApiError::InvalidValue)?;
    let ops = validate_patch(&req, GROUP_PATCH_PATHS)?;
    let expected_version = parse_if_match(&headers)?;

    let exec = ExecutionContext::from_auth(&state, &ctx);
    let (existing_group, _existing_index) =
        fetch_owned(&state, &exec, &realm.domain_id, &realm.provider_id, &id).await?;

    state
        .policy_enforcer
        .enforce(
            "identity/scim/group/update",
            &ctx,
            serde_json::Value::Null,
            Some(json!({"group": existing_group})),
        )
        .await?;

    let mut new_display_name = existing_group.name.clone();
    let mut new_external_id: Option<Option<String>> = None;
    let mut members_to_add: Vec<String> = Vec::new();
    let mut members_to_remove: Vec<String> = Vec::new();

    for validated in &ops {
        match (validated.path.as_str(), validated.op) {
            ("displayname", PatchOp::Remove) => {
                return Err(ScimApiError::InvalidValue(
                    "displayName is required and cannot be removed".to_string(),
                ));
            }
            ("displayname", _) => {
                let Some(s) = validated.value.as_str() else {
                    return Err(ScimApiError::InvalidValue(
                        "displayName must be a string".to_string(),
                    ));
                };
                if s.trim().is_empty() {
                    return Err(KeystoneApiError::BadRequest(
                        "displayName is required".to_string(),
                    )
                    .into());
                }
                new_display_name = s.to_string();
            }
            ("externalid", PatchOp::Remove) => {
                new_external_id = Some(None);
            }
            ("externalid", _) => {
                let Some(s) = validated.value.as_str() else {
                    return Err(ScimApiError::InvalidValue(
                        "externalId must be a string".to_string(),
                    ));
                };
                new_external_id = Some(Some(s.to_string()));
            }
            ("members", PatchOp::Add) => {
                members_to_add.extend(member_ids(&validated.value)?);
            }
            ("members", PatchOp::Remove) => {
                members_to_remove.extend(member_ids(&validated.value)?);
            }
            ("members", PatchOp::Replace) => {
                return Err(ScimApiError::InvalidPath(
                    "members supports add/remove only".to_string(),
                ));
            }
            (other, _) => unreachable!(
                "validate_patch already restricted paths to the allowlist, got `{other}`"
            ),
        }
    }

    if new_display_name != existing_group.name
        && let Some(matched_id) = state
            .provider
            .get_identity_provider()
            .find_group_by_name_ci(&exec, &realm.domain_id, &new_display_name)
            .await?
        && matched_id != id
    {
        return Err(ScimApiError::Uniqueness(
            "displayName already exists within this domain".to_string(),
        ));
    }

    // ADR 0024 §7: every added member must already be owned by this same
    // realm, checked before any mutation.
    if !members_to_add.is_empty() {
        validate_members_owned_by_realm(
            &state,
            &exec,
            &realm.domain_id,
            &realm.provider_id,
            &members_to_add,
        )
        .await?;
    }

    let current_member_ids: HashSet<String> = state
        .provider
        .get_identity_provider()
        .list_users_of_group(&exec, &id)
        .await?
        .into_iter()
        .collect();
    let mut resulting_member_ids = current_member_ids.clone();
    for m in &members_to_add {
        resulting_member_ids.insert(m.clone());
    }
    for m in &members_to_remove {
        resulting_member_ids.remove(m);
    }
    // ADR 0024 §11: reject an oversized resulting membership before any
    // storage mutation, not after partial application.
    if resulting_member_ids.len() > MAX_GROUP_MEMBERS {
        return Err(ScimApiError::InvalidValue(format!(
            "members must not exceed {MAX_GROUP_MEMBERS} entries"
        )));
    }

    // ADR 0024 §5.E: always bump the index version, mirroring `PUT`.
    let index = match state
        .provider
        .get_scim_resource_provider()
        .update_index(
            &exec,
            &realm.domain_id,
            &realm.provider_id,
            ScimResourceType::Group,
            &id,
            ScimResourceIndexUpdate {
                external_id: new_external_id,
                deprovisioned_at: None,
            },
            expected_version,
        )
        .await
    {
        Ok(index) => index,
        Err(ScimResourceProviderError::VersionMismatch(msg)) => {
            return Err(ScimApiError::PreconditionFailed(msg));
        }
        Err(ScimResourceProviderError::Conflict(msg)) => {
            return Err(ScimApiError::Uniqueness(msg));
        }
        Err(e) => return Err(e.into()),
    };

    let group = state
        .provider
        .get_identity_provider()
        .update_group(
            &exec,
            &id,
            GroupUpdate {
                name: Some(new_display_name),
                description: None,
                extra: Default::default(),
            },
        )
        .await?;

    let added: Vec<(&str, &str)> = members_to_add
        .iter()
        .filter(|uid| !current_member_ids.contains(uid.as_str()))
        .map(|uid| (uid.as_str(), id.as_str()))
        .collect();
    if !added.is_empty() {
        state
            .provider
            .get_identity_provider()
            .add_users_to_groups(&exec, added)
            .await?;
    }
    for removed in members_to_remove
        .iter()
        .filter(|uid| current_member_ids.contains(uid.as_str()))
    {
        state
            .provider
            .get_identity_provider()
            .remove_user_from_group(&exec, removed, &id)
            .await?;
    }

    let member_ids: Vec<String> = resulting_member_ids.into_iter().collect();
    let location = resource_location(&state, &realm.domain_id, "Groups", &id).await;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        "etag",
        etag_header(index.version)
            .parse()
            .expect("weak etag is valid header value"),
    );
    Ok((
        response_headers,
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
    use openstack_keystone_core_types::scim::{ScimResourceIndex, ScimResourceType};
    use serde_json::Value;

    use super::*;
    use crate::api::tests::get_mocked_state;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::scim::patch::ScimPatchOperation;
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
            external_id: Some("ext-1".to_string()),
            version: 0,
            deprovisioned_at: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn patch_req(op: &str, path: &str, value: Value) -> ScimPatchRequest {
        ScimPatchRequest {
            schemas: vec![crate::scim::patch::PATCH_OP_SCHEMA.to_string()],
            operations: vec![ScimPatchOperation {
                op: op.to_string(),
                path: Some(path.to_string()),
                value,
            }],
        }
    }

    fn group_mock() -> MockIdentityProvider {
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
    }

    #[tokio::test]
    async fn test_patch_display_name() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| Ok(Some(make_index(id))));
        resource_mock
            .expect_update_index()
            .returning(|_, _, _, _, id, _, _| Ok(make_index(id)));

        let mut identity_mock = group_mock();
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

        let (headers, Json(result)) = patch(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "group-1".to_string())),
            State(state),
            HeaderMap::new(),
            ScimJson(patch_req(
                "replace",
                "displayName",
                Value::String("new_name".to_string()),
            )),
        )
        .await
        .unwrap();
        assert_eq!(result.display_name, "new_name");
        assert_eq!(headers.get("etag").unwrap(), r#"W/"0""#);
    }

    #[tokio::test]
    async fn test_patch_members_add() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .withf(|_, _, _, rt, id| *rt == ScimResourceType::Group && id == "group-1")
            .returning(|_, _, _, _, id| Ok(Some(make_index(id))));
        resource_mock
            .expect_get_index()
            .withf(|_, _, _, rt, _| *rt == ScimResourceType::User)
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
        resource_mock
            .expect_update_index()
            .returning(|_, _, _, _, id, _, _| Ok(make_index(id)));

        let mut identity_mock = group_mock();
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
        identity_mock
            .expect_add_users_to_groups()
            .withf(|_, memberships| memberships == &vec![("user-new", "group-1")])
            .returning(|_, _| Ok(()));

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_scim_resource(resource_mock),
            true,
            None,
        )
        .await;

        let (_, Json(result)) = patch(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "group-1".to_string())),
            State(state),
            HeaderMap::new(),
            ScimJson(patch_req(
                "add",
                "members",
                serde_json::json!([{"value": "user-new"}]),
            )),
        )
        .await
        .unwrap();
        assert_eq!(result.members.len(), 1);
        assert_eq!(result.members[0].value, "user-new");
    }

    #[tokio::test]
    async fn test_patch_members_remove() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| Ok(Some(make_index(id))));
        resource_mock
            .expect_update_index()
            .returning(|_, _, _, _, id, _, _| Ok(make_index(id)));

        let mut identity_mock = group_mock();
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
            .returning(|_, _| Ok(vec!["user-old".to_string()]));
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

        let (_, Json(result)) = patch(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "group-1".to_string())),
            State(state),
            HeaderMap::new(),
            ScimJson(patch_req(
                "remove",
                "members",
                serde_json::json!([{"value": "user-old"}]),
            )),
        )
        .await
        .unwrap();
        assert!(result.members.is_empty());
    }

    #[tokio::test]
    async fn test_patch_members_replace_rejected() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| Ok(Some(make_index(id))));

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(group_mock())
                .mock_scim_resource(resource_mock),
            true,
            None,
        )
        .await;

        let result = patch(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "group-1".to_string())),
            State(state),
            HeaderMap::new(),
            ScimJson(patch_req(
                "replace",
                "members",
                serde_json::json!([{"value": "user-new"}]),
            )),
        )
        .await;
        assert!(matches!(result, Err(ScimApiError::InvalidPath(_))));
    }

    #[tokio::test]
    async fn test_patch_rejects_disallowed_path() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let result = patch(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "group-1".to_string())),
            State(state),
            HeaderMap::new(),
            ScimJson(patch_req(
                "replace",
                r#"emails[type eq "work"].value"#,
                Value::String("a@b.com".to_string()),
            )),
        )
        .await;
        assert!(matches!(result, Err(ScimApiError::InvalidPath(_))));
    }

    #[tokio::test]
    async fn test_patch_not_owned_returns_404() {
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

        let result = patch(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "group-1".to_string())),
            State(state),
            HeaderMap::new(),
            ScimJson(patch_req(
                "replace",
                "displayName",
                Value::String("x".to_string()),
            )),
        )
        .await;
        assert!(matches!(
            result,
            Err(ScimApiError::Api(
                openstack_keystone_core::api::KeystoneApiError::NotFound { .. }
            ))
        ));
    }
}
