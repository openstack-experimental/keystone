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
//! `POST /SCIM/v2/{domain_id}/Users` (ADR 0024 §3.C, §3.D, §4).

use axum::{Json, extract::State, http::HeaderMap, http::StatusCode};
use serde_json::json;

use openstack_keystone_core::api::KeystoneApiError;
use openstack_keystone_core::api::api_key_auth::ScimRealmAuth;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::identity::generate_public_id;
use openstack_keystone_core_types::scim::{
    ScimResourceIndexCreate, ScimResourceProviderError, ScimResourceType,
};

use crate::keystone::ServiceState;
use crate::scim::error::ScimApiError;
use crate::scim::etag::etag_header;
use crate::scim::extract::ScimJson;
use crate::scim::location::resource_location;
use crate::scim::types::{ScimUser, ScimUserWrite};

pub(super) async fn create(
    ScimRealmAuth { ctx, realm }: ScimRealmAuth,
    State(state): State<ServiceState>,
    ScimJson(req): ScimJson<ScimUserWrite>,
) -> Result<(StatusCode, HeaderMap, Json<ScimUser>), ScimApiError> {
    req.validate_schemas().map_err(ScimApiError::InvalidValue)?;
    if req.user_name.trim().is_empty() {
        return Err(KeystoneApiError::BadRequest("userName is required".to_string()).into());
    }
    let Some(external_id) = req.external_id.as_deref().filter(|s| !s.trim().is_empty()) else {
        return Err(KeystoneApiError::BadRequest("externalId is required".to_string()).into());
    };

    let exec = ExecutionContext::from_auth(&state, &ctx);

    state
        .policy_enforcer
        .enforce(
            "identity/scim/user/create",
            &ctx,
            json!({"user": {"domain_id": realm.domain_id}}),
            None,
        )
        .await?;

    // ADR 0024 §3.D: domain-wide, case-insensitive `userName` collision
    // check — regardless of which realm (or nothing) created the existing
    // user. Best-effort pre-flight; the realm-scoped `externalId` claim
    // below is the atomic guarantee.
    if state
        .provider
        .get_identity_provider()
        .find_user_by_name_ci(&exec, &realm.domain_id, &req.user_name)
        .await?
        .is_some()
    {
        return Err(ScimApiError::Uniqueness(
            "userName already exists within this domain".to_string(),
        ));
    }

    // ADR 0024 dedup fix: the user id this create would derive is
    // deterministic (`generate_public_id(domain_id, externalId, "user")`),
    // the same one a federated JIT login for the same person may already
    // have claimed. Check for it explicitly so that case surfaces as a
    // clean SCIM 409 instead of an opaque driver error from a primary-key
    // collision inside `create_user` below.
    let user_id = generate_public_id(&realm.domain_id, external_id, "user");
    if state
        .provider
        .get_identity_provider()
        .get_user(&exec, &user_id)
        .await?
        .is_some()
    {
        return Err(ScimApiError::Uniqueness(
            "a user already exists for this externalId".to_string(),
        ));
    }

    let user = state
        .provider
        .get_identity_provider()
        .create_user(&exec, req.to_user_create(&realm.domain_id, external_id))
        .await?;

    let index = match state
        .provider
        .get_scim_resource_provider()
        .create_index(
            &exec,
            ScimResourceIndexCreate {
                domain_id: realm.domain_id.clone(),
                provider_id: realm.provider_id.clone(),
                resource_type: ScimResourceType::User,
                keystone_id: user.id.clone(),
                external_id: req.external_id.clone(),
            },
        )
        .await
    {
        Ok(index) => index,
        Err(e) => {
            // The index write failed (most likely a realm-scoped
            // `externalId` collision, ADR 0024 §3.C) after the Identity
            // user was already created. Best-effort compensating delete so
            // the orphaned user isn't left dangling — the SCIM create as a
            // whole still fails either way.
            let _ = state
                .provider
                .get_identity_provider()
                .delete_user(&exec, &user.id)
                .await;
            return Err(match e {
                ScimResourceProviderError::Conflict(msg) => ScimApiError::Uniqueness(msg),
                other => other.into(),
            });
        }
    };

    let location = resource_location(&state, &realm.domain_id, "Users", &user.id).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        "etag",
        etag_header(index.version)
            .parse()
            .expect("weak etag is valid header value"),
    );
    headers.insert(
        "location",
        location
            .parse()
            .expect("scim location is a valid header value"),
    );
    Ok((
        StatusCode::CREATED,
        headers,
        Json(ScimUser::from_domain(&user, &index, location)),
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
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::resource::Domain;
    use openstack_keystone_core_types::scim::{ScimResourceIndex, ScimResourceProviderError};

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
            .roles(vec![openstack_keystone_core_types::role::RoleRef {
                id: "scim-provisioner-role".to_string(),
                name: Some("scim_provisioner".to_string()),
                domain_id: None,
            }])
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
    async fn test_create() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_find_user_by_name_ci()
            .returning(|_, _, _| Ok(None));
        identity_mock.expect_get_user().returning(|_, _| Ok(None));
        identity_mock.expect_create_user().returning(|_, req| {
            Ok(UserResponseBuilder::default()
                .id("user-1")
                .domain_id(req.domain_id.clone())
                .enabled(true)
                .name(req.name.clone())
                .build()
                .unwrap())
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

        let req = ScimUserWrite {
            schemas: vec![crate::scim::types::USER_SCHEMA.to_string()],
            external_id: Some("ext-1".to_string()),
            user_name: "alice".to_string(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
        };

        let (status, headers, Json(body)) =
            create(domain_scoped_auth("domain-1"), State(state), ScimJson(req))
                .await
                .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body.user_name, "alice");
        assert_eq!(body.id, "user-1");
        assert_eq!(body.external_id.as_deref(), Some("ext-1"));
        assert_eq!(headers.get("etag").unwrap(), r#"W/"0""#);
    }

    #[tokio::test]
    async fn test_create_rejects_domain_wide_duplicate_username() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_find_user_by_name_ci()
            .returning(|_, _, _| Ok(Some("other-user".to_string())));

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
        )
        .await;

        let req = ScimUserWrite {
            schemas: vec![crate::scim::types::USER_SCHEMA.to_string()],
            external_id: Some("ext-1".to_string()),
            user_name: "alice".to_string(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
        };

        let result = create(domain_scoped_auth("domain-1"), State(state), ScimJson(req)).await;
        assert!(matches!(result, Err(ScimApiError::Uniqueness(_))));
    }

    #[tokio::test]
    async fn test_create_rejects_realm_scoped_external_id_conflict() {
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_find_user_by_name_ci()
            .returning(|_, _, _| Ok(None));
        identity_mock.expect_get_user().returning(|_, _| Ok(None));
        identity_mock.expect_create_user().returning(|_, req| {
            Ok(UserResponseBuilder::default()
                .id("user-1")
                .domain_id(req.domain_id.clone())
                .enabled(true)
                .name(req.name.clone())
                .build()
                .unwrap())
        });
        identity_mock.expect_delete_user().returning(|_, _| Ok(()));

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

        let req = ScimUserWrite {
            schemas: vec![crate::scim::types::USER_SCHEMA.to_string()],
            external_id: Some("ext-1".to_string()),
            user_name: "alice".to_string(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
        };

        let result = create(domain_scoped_auth("domain-1"), State(state), ScimJson(req)).await;
        assert!(matches!(result, Err(ScimApiError::Uniqueness(_))));
    }

    #[tokio::test]
    async fn test_create_rejects_deterministic_id_collision() {
        // A federated JIT login for the same person (matching externalId ==
        // sub) may already have claimed the deterministic id this create
        // would derive. Must surface as a clean SCIM 409, not an opaque
        // driver error from a primary-key collision inside `create_user`.
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_find_user_by_name_ci()
            .returning(|_, _, _| Ok(None));
        identity_mock.expect_get_user().returning(|_, id| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id(id.to_string())
                    .domain_id("domain-1".to_string())
                    .enabled(true)
                    .name("jit-user".to_string())
                    .build()
                    .unwrap(),
            ))
        });
        identity_mock.expect_create_user().never();

        let state = get_mocked_state(
            Provider::mocked_builder().mock_identity(identity_mock),
            true,
            None,
        )
        .await;

        let req = ScimUserWrite {
            schemas: vec![crate::scim::types::USER_SCHEMA.to_string()],
            external_id: Some("ext-1".to_string()),
            user_name: "alice".to_string(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
        };

        let result = create(domain_scoped_auth("domain-1"), State(state), ScimJson(req)).await;
        assert!(matches!(result, Err(ScimApiError::Uniqueness(_))));
    }

    #[tokio::test]
    async fn test_create_policy_denied() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;

        let req = ScimUserWrite {
            schemas: vec![crate::scim::types::USER_SCHEMA.to_string()],
            external_id: Some("ext-1".to_string()),
            user_name: "alice".to_string(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
        };

        let result = create(domain_scoped_auth("domain-1"), State(state), ScimJson(req)).await;
        assert!(matches!(
            result,
            Err(ScimApiError::Api(KeystoneApiError::Forbidden { .. }))
        ));
    }

    #[tokio::test]
    async fn test_create_rejects_empty_username() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let req = ScimUserWrite {
            schemas: vec![crate::scim::types::USER_SCHEMA.to_string()],
            external_id: None,
            user_name: "   ".to_string(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
        };

        let result = create(domain_scoped_auth("domain-1"), State(state), ScimJson(req)).await;
        assert!(matches!(
            result,
            Err(ScimApiError::Api(KeystoneApiError::BadRequest(_)))
        ));
    }

    #[tokio::test]
    async fn test_create_rejects_missing_external_id() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;

        let req = ScimUserWrite {
            schemas: vec![crate::scim::types::USER_SCHEMA.to_string()],
            external_id: None,
            user_name: "alice".to_string(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
        };

        let result = create(domain_scoped_auth("domain-1"), State(state), ScimJson(req)).await;
        assert!(matches!(
            result,
            Err(ScimApiError::Api(KeystoneApiError::BadRequest(_)))
        ));
    }
}
