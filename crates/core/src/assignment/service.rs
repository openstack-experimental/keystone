// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! # Assignments provider
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Arc;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::assignment::*;
use openstack_keystone_core_types::revoke::RevocationEventCreate;
use openstack_keystone_core_types::role::{Role, RoleListParameters};

use crate::assignment::{AssignmentApi, AssignmentProviderError, backend::AssignmentBackend};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::revoke::RevokeApi;
use crate::role::RoleApi;

pub struct AssignmentService {
    backend_driver: Arc<dyn AssignmentBackend>,
}

impl AssignmentService {
    /// Create a new instance of `AssignmentService`.
    ///
    /// # Parameters
    /// - `config`: The system configuration.
    /// - `plugin_manager`: The plugin manager used to resolve the assignment
    ///   backend.
    ///
    /// # Returns
    /// - `Result<Self, AssignmentProviderError>` - The new service instance or
    ///   an error.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, AssignmentProviderError> {
        let backend_driver = plugin_manager
            .get_assignment_backend(config.assignment.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl AssignmentApi for AssignmentService {
    /// Create assignment grant.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `grant`: The assignment creation parameters.
    ///
    /// # Returns
    /// - `Result<Assignment, AssignmentProviderError>` - The created assignment
    ///   or an error.
    async fn create_grant(
        &self,
        state: &ServiceState,
        grant: AssignmentCreate,
    ) -> Result<Assignment, AssignmentProviderError> {
        self.backend_driver.create_grant(state, grant).await
    }

    /// List role assignments.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: The parameters for listing assignments.
    ///
    /// # Returns
    /// - `Result<Vec<Assignment>, AssignmentProviderError>` - A list of
    ///   assignments or an error.
    async fn list_role_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        let mut assignments = self.backend_driver.list_assignments(state, params).await?;
        if !assignments.is_empty() && params.include_names.is_some_and(|x| x) {
            let roles: BTreeMap<String, Role> = state
                .provider
                .get_role_provider()
                .list_roles(state, &RoleListParameters::default())
                .await?
                .into_iter()
                .map(|x| (x.id.clone(), x))
                .collect();
            for assignment in assignments.iter_mut() {
                assignment.role_name = roles.get(&assignment.role_id).map(|role| role.name.clone());
            }
        }

        Ok(assignments)
    }

    /// Revoke grant.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `grant`: The assignment to revoke.
    ///
    /// # Returns
    /// - `Result<(), AssignmentProviderError>` - Ok on success, or an error.
    async fn revoke_grant(
        &self,
        state: &ServiceState,
        grant: Assignment,
    ) -> Result<(), AssignmentProviderError> {
        // Call backend with reference (no move)
        self.backend_driver.revoke_grant(state, &grant).await?;

        // Determine user_id or group_id
        let user_id = match &grant.r#type {
            AssignmentType::UserDomain
            | AssignmentType::UserProject
            | AssignmentType::UserSystem => Some(grant.actor_id.clone()),

            AssignmentType::GroupDomain
            | AssignmentType::GroupProject
            | AssignmentType::GroupSystem => None,
        };

        // Determine project_id or domain_id
        let (project_id, domain_id) = match &grant.r#type {
            AssignmentType::UserProject | AssignmentType::GroupProject => {
                (Some(grant.target_id.clone()), None)
            }
            AssignmentType::UserDomain | AssignmentType::GroupDomain => {
                (None, Some(grant.target_id.clone()))
            }
            AssignmentType::UserSystem | AssignmentType::GroupSystem => (None, None),
        };

        let revocation_event = RevocationEventCreate {
            domain_id,
            project_id,
            user_id,
            role_id: Some(grant.role_id.clone()),
            trust_id: None,
            consumer_id: None,
            access_token_id: None,
            issued_before: chrono::Utc::now(),
            expires_at: None,
            audit_id: None,
            audit_chain_id: None,
            revoked_at: chrono::Utc::now(),
        };

        state
            .provider
            .get_revoke_provider()
            .create_revocation_event(state, revocation_event)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use openstack_keystone_core_types::revoke::*;
    use openstack_keystone_core_types::role::*;

    use super::*;
    use crate::assignment::backend::MockAssignmentBackend;
    use crate::provider::Provider;
    use crate::revoke::MockRevokeProvider;
    use crate::role::MockRoleProvider;
    use crate::tests::get_mocked_state;

    #[tokio::test]
    async fn test_crate_grant() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockAssignmentBackend::default();
        backend.expect_create_grant().returning(|_, _| {
            Ok(AssignmentBuilder::default()
                .actor_id("actor")
                .role_id("rid1")
                .target_id("target_id")
                .r#type(AssignmentType::UserProject)
                .build()
                .unwrap())
        });

        let provider = AssignmentService {
            backend_driver: Arc::new(backend),
        };

        assert!(
            provider
                .create_grant(
                    &state,
                    AssignmentCreate::user_project("actor_id", "target_id", "role_id", false)
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_list_assignments() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockAssignmentBackend::default();
        backend
            .expect_list_assignments()
            .returning(|_, _| Ok(vec![]));

        let provider = AssignmentService {
            backend_driver: Arc::new(backend),
        };

        assert!(
            provider
                .list_role_assignments(
                    &state,
                    &RoleAssignmentListParameters {
                        role_id: Some("rid".into()),
                        ..Default::default()
                    },
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_list_assignments_include_names() {
        let mut role_mock = MockRoleProvider::default();
        role_mock.expect_list_roles().returning(|_, _| {
            Ok(vec![
                RoleBuilder::default()
                    .id("rid1")
                    .name("rid1_name")
                    .build()
                    .unwrap(),
                RoleBuilder::default()
                    .id("rid2")
                    .name("rid2_name")
                    .build()
                    .unwrap(),
            ])
        });
        let state =
            get_mocked_state(None, Some(Provider::mocked_builder().mock_role(role_mock))).await;
        let mut backend = MockAssignmentBackend::default();
        backend
            .expect_list_assignments()
            .withf(|_, params: &RoleAssignmentListParameters| {
                params.role_id == Some("rid".into()) && params.include_names.is_some_and(|x| x)
            })
            .returning(|_, _| {
                Ok(vec![
                    AssignmentBuilder::default()
                        .actor_id("actor")
                        .role_id("rid1")
                        .target_id("target_id")
                        .r#type(AssignmentType::UserProject)
                        .build()
                        .unwrap(),
                ])
            });

        let provider = AssignmentService {
            backend_driver: Arc::new(backend),
        };

        let res = provider
            .list_role_assignments(
                &state,
                &RoleAssignmentListParameters {
                    role_id: Some("rid".into()),
                    include_names: Some(true),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(
            res.iter()
                .find(|x| x.role_id == "rid1" && x.role_name == Some("rid1_name".into()))
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_revoke_grant() {
        let mut revoke_mock = MockRevokeProvider::default();
        revoke_mock
            .expect_create_revocation_event()
            .withf(|_, params: &RevocationEventCreate| {
                params.project_id == Some("target_id".into())
                    && params.user_id == Some("actor".into())
                    && params.role_id == Some("rid1".into())
            })
            .returning(|_, _| Ok(RevocationEvent::default()));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_revoke(revoke_mock)),
        )
        .await;
        let mut backend = MockAssignmentBackend::default();
        let assignment = AssignmentBuilder::default()
            .actor_id("actor")
            .role_id("rid1")
            .target_id("target_id")
            .r#type(AssignmentType::UserProject)
            .build()
            .unwrap();
        let assignment_clone = assignment.clone();
        backend
            .expect_revoke_grant()
            .withf(move |_, params: &Assignment| *params == assignment_clone)
            .returning(|_, _| Ok(()));

        let provider = AssignmentService {
            backend_driver: Arc::new(backend),
        };

        assert!(provider.revoke_grant(&state, assignment).await.is_ok());
    }
}
