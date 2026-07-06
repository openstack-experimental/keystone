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
//! `DELETE /SCIM/v2/{domain_id}/Users/{id}` — soft-disable only (ADR 0024
//! §6.A). Never hard-deletes; the janitor purge (a later PR) reclaims
//! tombstoned rows past the retention window.

use axum::{extract::Path, extract::State, http::StatusCode};
use chrono::Utc;
use serde_json::json;

use openstack_keystone_core::api::api_key_auth::ScimRealmAuth;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::identity::UserUpdate;
use openstack_keystone_core_types::revoke::RevocationEventCreate;
use openstack_keystone_core_types::scim::{ScimResourceIndexUpdate, ScimResourceType};

use crate::keystone::ServiceState;
use crate::scim::error::ScimApiError;
use crate::scim::user::show::fetch_owned;

pub(super) async fn delete(
    ScimRealmAuth { ctx, realm }: ScimRealmAuth,
    Path((_domain_id, id)): Path<(String, String)>,
    State(state): State<ServiceState>,
) -> Result<StatusCode, ScimApiError> {
    let exec = ExecutionContext::from_auth(&state, &ctx);
    let (existing_user, _existing_index) =
        fetch_owned(&state, &exec, &realm.domain_id, &realm.provider_id, &id).await?;

    state
        .policy_enforcer
        .enforce(
            "identity/scim/user/delete",
            &ctx,
            serde_json::Value::Null,
            Some(json!({"user": existing_user})),
        )
        .await?;

    // §6.A step 1: disable the user (audited as `Operation::Update` by the
    // existing `IdentityApi::update_user` path).
    state
        .provider
        .get_identity_provider()
        .update_user(
            &exec,
            &id,
            UserUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;

    // §6.A step 2: stamp `deprovisioned_at` so subsequent reads under this
    // realm treat the resource as absent (§3.C).
    let now = Utc::now().timestamp();
    state
        .provider
        .get_scim_resource_provider()
        .update_index(
            &exec,
            &realm.domain_id,
            &realm.provider_id,
            ScimResourceType::User,
            &id,
            ScimResourceIndexUpdate {
                external_id: None,
                deprovisioned_at: Some(Some(now)),
            },
        )
        .await?;

    // §6.A step 3: revoke live sessions immediately.
    state
        .provider
        .get_revoke_provider()
        .create_revocation_event(
            &exec,
            RevocationEventCreate {
                domain_id: Some(realm.domain_id.clone()),
                project_id: None,
                user_id: Some(id.clone()),
                role_id: None,
                trust_id: None,
                consumer_id: None,
                access_token_id: None,
                issued_before: Utc::now(),
                expires_at: None,
                audit_id: None,
                audit_chain_id: None,
                revoked_at: Utc::now(),
            },
        )
        .await?;

    // §6.A step 4: emit a CADF `disable` event. `update_user` above already
    // audited an `Update`; this is an additional, ADR-mandated `Disable`
    // event enriching the audit trail for the SCIM deprovisioning
    // semantics specifically (a judgment call — §9 does not otherwise
    // define a dedicated disable-audit call site for Identity users).
    state
        .event_dispatcher
        .emit(Event::new(
            Operation::Disable,
            EventPayload::User { id: id.clone() },
        ))
        .await;

    Ok(StatusCode::NO_CONTENT)
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
    use openstack_keystone_core_types::revoke::RevocationEvent;
    use openstack_keystone_core_types::scim::ScimResourceIndex;

    use super::*;
    use crate::api::tests::get_mocked_state;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::revoke::MockRevokeProvider;
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

    #[tokio::test]
    async fn test_delete_soft_disables() {
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| {
                Ok(Some(ScimResourceIndex {
                    domain_id: "domain-1".to_string(),
                    provider_id: "okta-1".to_string(),
                    resource_type: openstack_keystone_core_types::scim::ScimResourceType::User,
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
            .withf(|_, _, _, _, _, update| matches!(update.deprovisioned_at, Some(Some(_))))
            .returning(|_, _, _, _, id, _| {
                Ok(ScimResourceIndex {
                    domain_id: "domain-1".to_string(),
                    provider_id: "okta-1".to_string(),
                    resource_type: openstack_keystone_core_types::scim::ScimResourceType::User,
                    keystone_id: id.to_string(),
                    external_id: None,
                    version: 1,
                    deprovisioned_at: Some(999),
                    created_at: 1,
                    updated_at: 2,
                })
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

        let mut revoke_mock = MockRevokeProvider::default();
        revoke_mock
            .expect_create_revocation_event()
            .returning(|_, event| {
                Ok(RevocationEvent {
                    domain_id: event.domain_id,
                    project_id: event.project_id,
                    user_id: event.user_id,
                    role_id: event.role_id,
                    trust_id: event.trust_id,
                    consumer_id: event.consumer_id,
                    access_token_id: event.access_token_id,
                    issued_before: event.issued_before,
                    expires_at: event.expires_at,
                    audit_id: event.audit_id,
                    audit_chain_id: event.audit_chain_id,
                    revoked_at: event.revoked_at,
                })
            });

        let state = get_mocked_state(
            Provider::mocked_builder()
                .mock_identity(identity_mock)
                .mock_scim_resource(resource_mock)
                .mock_revoke(revoke_mock),
            true,
            None,
        )
        .await;

        let status = delete(
            domain_scoped_auth("domain-1"),
            Path(("domain-1".to_string(), "user-1".to_string())),
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
            Path(("domain-1".to_string(), "user-1".to_string())),
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
        // A second DELETE on an already-deprovisioned resource is a 404
        // (RFC 7644 re-delete guidance), not a second successful disable.
        let mut resource_mock = MockScimResourceProvider::default();
        resource_mock
            .expect_get_index()
            .returning(|_, _, _, _, id| {
                Ok(Some(ScimResourceIndex {
                    domain_id: "domain-1".to_string(),
                    provider_id: "okta-1".to_string(),
                    resource_type: openstack_keystone_core_types::scim::ScimResourceType::User,
                    keystone_id: id.to_string(),
                    external_id: None,
                    version: 1,
                    deprovisioned_at: Some(123),
                    created_at: 1,
                    updated_at: 1,
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
            Path(("domain-1".to_string(), "user-1".to_string())),
            State(state),
        )
        .await;
        assert!(matches!(
            result,
            Err(ScimApiError::Api(KeystoneApiError::NotFound { .. }))
        ));
    }
}
