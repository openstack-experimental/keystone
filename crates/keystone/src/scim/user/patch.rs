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
//! `PATCH /SCIM/v2/{domain_id}/Users/{id}` (ADR 0024 §5.C).
//!
//! Reuses the `identity/scim/user/update` OPA policy: PATCH is an
//! alternate write mechanism for the same resource/authorization concern
//! `PUT` already enforces, not a distinct one.

use serde_json::{Value, json};

use axum::{Json, extract::Path, extract::State, http::HeaderMap};

use openstack_keystone_core::api::KeystoneApiError;
use openstack_keystone_core::api::api_key_auth::ScimRealmAuth;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::identity::UserUpdate;
use openstack_keystone_core_types::scim::{
    ScimResourceIndexUpdate, ScimResourceProviderError, ScimResourceType,
};

use crate::keystone::ServiceState;
use crate::scim::error::ScimApiError;
use crate::scim::etag::{etag_header, parse_if_match};
use crate::scim::patch::{PatchOp, ScimPatchRequest, USER_PATCH_PATHS, validate_patch};
use crate::scim::types::{EXTRA_DISPLAY_NAME, EXTRA_FAMILY_NAME, EXTRA_GIVEN_NAME, ScimUser};
use crate::scim::user::show::fetch_owned;

fn str_value(value: &Value, path: &str) -> Result<String, ScimApiError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| ScimApiError::InvalidValue(format!("`{path}` value must be a string")))
}

pub(super) async fn patch(
    ScimRealmAuth { ctx, realm }: ScimRealmAuth,
    Path((_domain_id, id)): Path<(String, String)>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    Json(req): Json<ScimPatchRequest>,
) -> Result<(HeaderMap, Json<ScimUser>), ScimApiError> {
    let ops = validate_patch(&req, USER_PATCH_PATHS)?;
    let expected_version = parse_if_match(&headers)?;

    let exec = ExecutionContext::from_auth(&state, &ctx);
    let (existing_user, _existing_index) =
        fetch_owned(&state, &exec, &realm.domain_id, &realm.provider_id, &id).await?;

    state
        .policy_enforcer
        .enforce(
            "identity/scim/user/update",
            &ctx,
            serde_json::Value::Null,
            Some(json!({"user": existing_user})),
        )
        .await?;

    let mut new_user_name = existing_user.name.clone();
    let mut new_enabled = existing_user.enabled;
    let mut extra = existing_user.extra.clone();
    let mut new_external_id: Option<Option<String>> = None;

    for validated in &ops {
        match (validated.path.as_str(), validated.op) {
            ("active", PatchOp::Remove) => {
                return Err(ScimApiError::InvalidValue(
                    "active cannot be removed".to_string(),
                ));
            }
            ("active", _) => {
                new_enabled = validated.value.as_bool().ok_or_else(|| {
                    ScimApiError::InvalidValue("active must be a boolean".to_string())
                })?;
            }
            ("username", PatchOp::Remove) => {
                return Err(ScimApiError::InvalidValue(
                    "userName cannot be removed".to_string(),
                ));
            }
            ("username", _) => {
                let value = str_value(&validated.value, "userName")?;
                if value.trim().is_empty() {
                    return Err(
                        KeystoneApiError::BadRequest("userName is required".to_string()).into(),
                    );
                }
                new_user_name = value;
            }
            ("externalid", PatchOp::Remove) => {
                return Err(ScimApiError::InvalidValue(
                    "externalId is required and cannot be removed".to_string(),
                ));
            }
            ("externalid", _) => {
                new_external_id = Some(Some(str_value(&validated.value, "externalId")?));
            }
            ("displayname", PatchOp::Remove) => {
                extra.remove(EXTRA_DISPLAY_NAME);
            }
            ("displayname", _) => {
                extra.insert(
                    EXTRA_DISPLAY_NAME.to_string(),
                    Value::String(str_value(&validated.value, "displayName")?),
                );
            }
            ("name.givenname", PatchOp::Remove) => {
                extra.remove(EXTRA_GIVEN_NAME);
            }
            ("name.givenname", _) => {
                extra.insert(
                    EXTRA_GIVEN_NAME.to_string(),
                    Value::String(str_value(&validated.value, "name.givenName")?),
                );
            }
            ("name.familyname", PatchOp::Remove) => {
                extra.remove(EXTRA_FAMILY_NAME);
            }
            ("name.familyname", _) => {
                extra.insert(
                    EXTRA_FAMILY_NAME.to_string(),
                    Value::String(str_value(&validated.value, "name.familyName")?),
                );
            }
            (other, _) => unreachable!(
                "validate_patch already restricted paths to the allowlist, got `{other}`"
            ),
        }
    }

    // ADR 0024 §3.D: re-run the domain-wide collision check if `userName`
    // is actually changing (mirrors `PUT`'s equivalent check).
    if new_user_name != existing_user.name
        && let Some(matched_id) = state
            .provider
            .get_identity_provider()
            .find_user_by_name_ci(&exec, &realm.domain_id, &new_user_name)
            .await?
        && matched_id != id
    {
        return Err(ScimApiError::Uniqueness(
            "userName already exists within this domain".to_string(),
        ));
    }

    // ADR 0024 §5.E: always bump the index version, mirroring `PUT`.
    let index = match state
        .provider
        .get_scim_resource_provider()
        .update_index(
            &exec,
            &realm.domain_id,
            &realm.provider_id,
            ScimResourceType::User,
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

    let user = state
        .provider
        .get_identity_provider()
        .update_user(
            &exec,
            &id,
            UserUpdate {
                enabled: Some(new_enabled),
                extra,
                name: Some(new_user_name),
                ..Default::default()
            },
        )
        .await?;

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        "etag",
        etag_header(index.version)
            .parse()
            .expect("weak etag is valid header value"),
    );
    Ok((response_headers, Json(ScimUser::from_domain(&user, &index))))
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
            resource_type: openstack_keystone_core_types::scim::ScimResourceType::User,
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
            schemas: vec![],
            operations: vec![ScimPatchOperation {
                op: op.to_string(),
                path: Some(path.to_string()),
                value,
            }],
        }
    }

    #[tokio::test]
    async fn test_patch_active() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| Ok(Some(make_index(id))));
        resource_mock
            .expect_update_index()
            .returning(|_, _, _, _, id, _, _| Ok(make_index(id)));

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
        identity_mock.expect_update_user().returning(|_, id, req| {
            assert_eq!(req.enabled, Some(false));
            Ok(UserResponseBuilder::default()
                .id(id)
                .domain_id("domain-1")
                .enabled(false)
                .name("alice")
                .build()
                .unwrap())
        });

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
            Path(("domain-1".to_string(), "user-1".to_string())),
            State(state),
            HeaderMap::new(),
            Json(patch_req("replace", "active", Value::Bool(false))),
        )
        .await
        .unwrap();
        assert!(!result.active);
        assert_eq!(headers.get("etag").unwrap(), r#"W/"0""#);
    }

    #[tokio::test]
    async fn test_patch_username() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| Ok(Some(make_index(id))));
        resource_mock
            .expect_update_index()
            .returning(|_, _, _, _, id, _, _| Ok(make_index(id)));

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
        identity_mock
            .expect_find_user_by_name_ci()
            .returning(|_, _, _| Ok(None));
        identity_mock.expect_update_user().returning(|_, id, req| {
            Ok(UserResponseBuilder::default()
                .id(id)
                .domain_id("domain-1")
                .enabled(true)
                .name(req.name.clone().unwrap())
                .build()
                .unwrap())
        });

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
            Path(("domain-1".to_string(), "user-1".to_string())),
            State(state),
            HeaderMap::new(),
            Json(patch_req(
                "replace",
                "userName",
                Value::String("bob".to_string()),
            )),
        )
        .await
        .unwrap();
        assert_eq!(result.user_name, "bob");
    }

    #[tokio::test]
    async fn test_patch_display_name_and_given_name() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| Ok(Some(make_index(id))));
        resource_mock
            .expect_update_index()
            .returning(|_, _, _, _, id, _, _| Ok(make_index(id)));

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
        identity_mock.expect_update_user().returning(|_, id, req| {
            Ok(UserResponseBuilder::default()
                .id(id)
                .domain_id("domain-1")
                .enabled(true)
                .name("alice")
                .extra(req.extra.clone())
                .build()
                .unwrap())
        });

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
            Path(("domain-1".to_string(), "user-1".to_string())),
            State(state),
            HeaderMap::new(),
            Json(ScimPatchRequest {
                schemas: vec![],
                operations: vec![
                    ScimPatchOperation {
                        op: "replace".to_string(),
                        path: Some("displayName".to_string()),
                        value: Value::String("Alice A.".to_string()),
                    },
                    ScimPatchOperation {
                        op: "replace".to_string(),
                        path: Some("name.givenName".to_string()),
                        value: Value::String("Alice".to_string()),
                    },
                    ScimPatchOperation {
                        op: "replace".to_string(),
                        path: Some("name.familyName".to_string()),
                        value: Value::String("Anderson".to_string()),
                    },
                ],
            }),
        )
        .await
        .unwrap();
        assert_eq!(result.display_name.as_deref(), Some("Alice A."));
        assert_eq!(
            result.name.as_ref().and_then(|n| n.given_name.as_deref()),
            Some("Alice")
        );
        assert_eq!(
            result.name.as_ref().and_then(|n| n.family_name.as_deref()),
            Some("Anderson")
        );
    }

    #[tokio::test]
    async fn test_patch_external_id_remove_rejected() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| Ok(Some(make_index(id))));

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

        let result = patch(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "user-1".to_string())),
            State(state),
            HeaderMap::new(),
            Json(patch_req("remove", "externalId", Value::Null)),
        )
        .await;
        assert!(matches!(result, Err(ScimApiError::InvalidValue(_))));
    }

    #[tokio::test]
    async fn test_patch_rejects_disallowed_path() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let result = patch(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "user-1".to_string())),
            State(state),
            HeaderMap::new(),
            Json(patch_req(
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
            Path(("domain-1".to_string(), "user-1".to_string())),
            State(state),
            HeaderMap::new(),
            Json(patch_req("replace", "active", Value::Bool(false))),
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
