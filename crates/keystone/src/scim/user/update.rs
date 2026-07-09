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
//! `PUT /SCIM/v2/{domain_id}/Users/{id}` — full-replace update (ADR 0024
//! §3.C, §4, §5.E).

use axum::{Json, extract::Path, extract::State, http::HeaderMap};
use serde_json::json;

use openstack_keystone_core::api::api_key_auth::ScimRealmAuth;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::scim::{
    ScimResourceIndexUpdate, ScimResourceProviderError, ScimResourceType,
};

use crate::keystone::ServiceState;
use crate::scim::error::ScimApiError;
use crate::scim::etag::{etag_header, parse_if_match};
use crate::scim::extract::ScimJson;
use crate::scim::location::resource_location;
use crate::scim::types::{ScimUser, ScimUserWrite};
use crate::scim::user::show::fetch_owned;

pub(super) async fn update(
    ScimRealmAuth { ctx, realm }: ScimRealmAuth,
    Path((_domain_id, id)): Path<(String, String)>,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    ScimJson(req): ScimJson<ScimUserWrite>,
) -> Result<(HeaderMap, Json<ScimUser>), ScimApiError> {
    req.validate_schemas().map_err(ScimApiError::InvalidValue)?;
    if req.user_name.trim().is_empty() {
        return Err(openstack_keystone_core::api::KeystoneApiError::BadRequest(
            "userName is required".to_string(),
        )
        .into());
    }
    let expected_version = parse_if_match(&headers)?;

    let exec = ExecutionContext::from_auth(&state, &ctx);
    let (existing_user, existing_index) =
        fetch_owned(&state, &exec, &realm.domain_id, &realm.provider_id, &id).await?;

    state
        .policy_enforcer
        .enforce(
            "identity/scim/user/update",
            &ctx,
            json!({"user": {"user_name": req.user_name}}),
            Some(json!({"user": existing_user})),
        )
        .await?;

    // ADR 0024 §3.D: if the `userName` is changing, re-run the domain-wide
    // collision check (a no-op rename doesn't need it). The lookup is
    // case-insensitive, so exclude the resource's own id — otherwise a
    // case-only rename (e.g. `Bob` -> `BOB`) would collide with itself.
    if req.user_name != existing_user.name
        && let Some(matched_id) = state
            .provider
            .get_identity_provider()
            .find_user_by_name_ci(&exec, &realm.domain_id, &req.user_name)
            .await?
        && matched_id != id
    {
        return Err(ScimApiError::Uniqueness(
            "userName already exists within this domain".to_string(),
        ));
    }

    // ADR 0024 §5.E: the index write always happens (even when `externalId`
    // is unchanged) so `version` bumps -- and the CAS below can be checked
    // -- on every PUT, not just ones that touch `externalId`. A rejected
    // CAS here means a concurrent writer won the race, so this request
    // aborts before ever touching core Identity.
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
                external_id: if req.external_id != existing_index.external_id {
                    Some(req.external_id.clone())
                } else {
                    None
                },
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
        .update_user(&exec, &id, req.to_user_update())
        .await?;

    let location = resource_location(&state, &realm.domain_id, "Users", &id).await;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        "etag",
        etag_header(index.version)
            .parse()
            .expect("weak etag is valid header value"),
    );
    Ok((
        response_headers,
        Json(ScimUser::from_domain(&user, &index, location)),
    ))
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

    fn make_index(keystone_id: &str) -> ScimResourceIndex {
        ScimResourceIndex {
            domain_id: "domain-1".to_string(),
            provider_id: "okta-1".to_string(),
            resource_type: openstack_keystone_core_types::scim::ScimResourceType::User,
            keystone_id: keystone_id.to_string(),
            external_id: Some("ext-old".to_string()),
            version: 0,
            deprovisioned_at: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn write_req(user_name: &str, external_id: Option<&str>) -> ScimUserWrite {
        ScimUserWrite {
            schemas: vec![crate::scim::types::USER_SCHEMA.to_string()],
            external_id: external_id.map(str::to_string),
            user_name: user_name.to_string(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
        }
    }

    #[tokio::test]
    async fn test_update() {
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
                    .name("old_name")
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

        let (headers, Json(result)) = update(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "user-1".to_string())),
            State(state),
            HeaderMap::new(),
            ScimJson(write_req("new_name", Some("ext-old"))),
        )
        .await
        .unwrap();
        assert_eq!(result.user_name, "new_name");
        assert_eq!(headers.get("etag").unwrap(), r#"W/"0""#);
    }

    #[tokio::test]
    async fn test_update_case_only_rename_does_not_self_conflict() {
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
                    .name("Bob")
                    .build()
                    .unwrap(),
            ))
        });
        // Case-insensitive lookup matches the resource's own id -- must not
        // be treated as a collision with another user.
        identity_mock
            .expect_find_user_by_name_ci()
            .returning(|_, _, _| Ok(Some("user-1".to_string())));
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

        let (_, Json(result)) = update(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "user-1".to_string())),
            State(state),
            HeaderMap::new(),
            ScimJson(write_req("BOB", Some("ext-old"))),
        )
        .await
        .unwrap();
        assert_eq!(result.user_name, "BOB");
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
            Path(("domain-1".to_string(), "user-1".to_string())),
            State(state),
            HeaderMap::new(),
            ScimJson(write_req("new_name", None)),
        )
        .await;
        assert!(matches!(
            result,
            Err(ScimApiError::Api(KeystoneApiError::NotFound { .. }))
        ));
    }

    #[tokio::test]
    async fn test_update_stale_if_match_returns_412() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| Ok(Some(make_index(id))));
        resource_mock
            .expect_update_index()
            .returning(|_, _, _, _, id, _, _| {
                Err(
                    openstack_keystone_core_types::scim::ScimResourceProviderError::VersionMismatch(
                        format!("stale version for {id}"),
                    ),
                )
            });

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, id| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id(id)
                    .domain_id("domain-1")
                    .enabled(true)
                    .name("old_name")
                    .build()
                    .unwrap(),
            ))
        });
        identity_mock
            .expect_find_user_by_name_ci()
            .returning(|_, _, _| Ok(None));

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_scim_resource(resource_mock),
            true,
            None,
        )
        .await;

        let mut headers = HeaderMap::new();
        headers.insert("if-match", r#"W/"5""#.parse().unwrap());

        let result = update(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "user-1".to_string())),
            State(state),
            headers,
            ScimJson(write_req("new_name", Some("ext-old"))),
        )
        .await;
        assert!(matches!(result, Err(ScimApiError::PreconditionFailed(_))));
    }
}
