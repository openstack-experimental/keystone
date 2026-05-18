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

pub mod auth;
pub mod common;
pub mod v3;
pub mod v4;

pub use openstack_keystone_api_types::error::KeystoneApiError;

#[cfg(any(test, feature = "mock"))]
pub mod tests {
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;

    use crate::auth::ValidatedSecurityContext;
    use openstack_keystone_config::{Config, ConfigManager};
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, AuthzInfo, IdentityInfo, PrincipalInfo, ScopeInfo, SecurityContext,
        UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::resource::Project;
    use openstack_keystone_core_types::role::RoleRef;

    use crate::keystone::{Service, ServiceState};
    use crate::policy::{MockPolicy, PolicyError, PolicyEvaluationResult};
    use crate::provider::ProviderBuilder;

    /// Build a project-scoped ValidatedSecurityContext with admin role for unit
    /// tests.
    ///
    /// Directly constructs the struct via `ValidatedSecurityContext::test_new`
    /// so no provider mocks are needed. The `fully_resolved` check passes
    /// because `authorization` contains a non-empty roles list.
    pub fn test_fixture_scoped() -> ValidatedSecurityContext {
        let user = openstack_keystone_core_types::identity::UserResponseBuilder::default()
            .id("uid")
            .domain_id("domain_id")
            .enabled(true)
            .name("testuser")
            .build()
            .unwrap();

        ValidatedSecurityContext::test_new(SecurityContext {
            audit_ids: vec!["audit_1".to_string()],
            authentication_context: AuthenticationContext::Password,
            auth_methods: std::collections::HashSet::from_iter(vec!["password".to_string()]),
            authorization: Some(AuthzInfo {
                roles: Some(vec![RoleRef {
                    id: "admin".to_string(),
                    name: Some("admin".to_string()),
                    domain_id: None,
                }]),
                scope: ScopeInfo::Project(Project {
                    id: "project_id".to_string(),
                    domain_id: "domain_id".to_string(),
                    enabled: true,
                    name: "admin".to_string(),
                    ..Default::default()
                }),
            }),
            expires_at: None,
            principal: PrincipalInfo {
                domain_id: Some("domain_id".to_string()),
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .user(user)
                        .build()
                        .unwrap(),
                ),
            },
            token_restriction: None,
        })
    }

    /// Initialize the mocked service state.
    ///
    /// # Arguments
    /// * `provider_builder` - The provider builder with mock expectations set.
    /// * `policy_allow` - Whether the mock policy should allow all requests or
    ///   not.
    /// * `policy_allow_see_other_domains` - Policy extension flag to include
    ///   "allow_to_see_other_domain" in the response.
    pub async fn get_mocked_state(
        provider_builder: ProviderBuilder,
        policy_allow: bool,
        policy_allow_see_other_domains: Option<bool>,
    ) -> ServiceState {
        let provider = provider_builder.build().unwrap();

        let mut policy_enforcer_mock = MockPolicy::default();

        policy_enforcer_mock
            .expect_enforce()
            .returning(move |_, _, _, _| {
                if policy_allow {
                    if policy_allow_see_other_domains.is_some_and(|x| x) {
                        Ok(PolicyEvaluationResult::allowed_admin())
                    } else {
                        Ok(PolicyEvaluationResult::allowed())
                    }
                } else {
                    Err(PolicyError::Forbidden(PolicyEvaluationResult::forbidden()))
                }
            });

        policy_enforcer_mock
            .expect_health_check()
            .returning(|| Ok(()));

        Arc::new(
            Service::new(
                ConfigManager::not_watched(Config::default()),
                DatabaseConnection::Disconnected,
                provider,
                Arc::new(policy_enforcer_mock),
            )
            .await
            .unwrap(),
        )
    }
}
