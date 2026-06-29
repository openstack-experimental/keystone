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
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::revoke::RevocationEventCreate;
use openstack_keystone_core_types::role::{Role, RoleListParameters};

use crate::assignment::{AssignmentApi, AssignmentProviderError, backend::AssignmentBackend};
use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;

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

/// Build a `RoleAssignment` event payload from assignment fields.
fn role_assignment_payload(
    role_id: String,
    actor_id: &str,
    target_id: &str,
    assignment_type: &AssignmentType,
) -> EventPayload {
    EventPayload::RoleAssignment {
        role_id,
        user_id: match assignment_type {
            AssignmentType::UserDomain
            | AssignmentType::UserProject
            | AssignmentType::UserSystem => Some(actor_id.to_string()),
            _ => None,
        },
        group_id: match assignment_type {
            AssignmentType::GroupDomain
            | AssignmentType::GroupProject
            | AssignmentType::GroupSystem => Some(actor_id.to_string()),
            _ => None,
        },
        domain_id: match assignment_type {
            AssignmentType::UserDomain | AssignmentType::GroupDomain => {
                Some(target_id.to_string())
            }
            _ => None,
        },
        project_id: match assignment_type {
            AssignmentType::UserProject | AssignmentType::GroupProject => {
                Some(target_id.to_string())
            }
            _ => None,
        },
        system_id: match assignment_type {
            AssignmentType::UserSystem | AssignmentType::GroupSystem => {
                Some(target_id.to_string())
            }
            _ => None,
        },
    }
}

#[async_trait]
impl AssignmentApi for AssignmentService {
    async fn create_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        grant: AssignmentCreate,
    ) -> Result<Assignment, AssignmentProviderError> {
        if let Some(vsc) = ctx.ctx() {
            // Pre-build event payload from grant fields before grant is consumed.
            let event = Event::new(
                Operation::Create,
                role_assignment_payload(
                    grant.role_id.clone(),
                    &grant.actor_id,
                    &grant.target_id,
                    &grant.r#type,
                ),
            );
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: event,
                operation: async { backend_driver.create_grant(state, grant).await },
                on_audit_error: |_: AuditDispatchError| AssignmentProviderError::Driver("audit dispatch failed".into()),
            }
        } else {
            let assignment = self.backend_driver.create_grant(ctx.state(), grant).await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    role_assignment_payload(
                        assignment.role_id.clone(),
                        &assignment.actor_id,
                        &assignment.target_id,
                        &assignment.r#type,
                    ),
                ))
                .await;
            Ok(assignment)
        }
    }

    async fn list_role_assignments<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        let mut assignments = self
            .backend_driver
            .list_assignments(ctx.state(), params)
            .await?;
        if !assignments.is_empty() && params.include_names.is_some_and(|x| x) {
            let roles: BTreeMap<String, Role> = ctx
                .state()
                .provider
                .get_role_provider()
                .list_roles(ctx, &RoleListParameters::default())
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

    async fn revoke_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        grant: Assignment,
    ) -> Result<(), AssignmentProviderError> {
        // Pre-extract fields needed for both revocation event and audit payload.
        let user_id = match &grant.r#type {
            AssignmentType::UserDomain
            | AssignmentType::UserProject
            | AssignmentType::UserSystem => Some(grant.actor_id.clone()),
            _ => None,
        };
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
            domain_id: domain_id.clone(),
            project_id: project_id.clone(),
            user_id: user_id.clone(),
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

        if let Some(vsc) = ctx.ctx() {
            let event = Event::new(
                Operation::Delete,
                role_assignment_payload(
                    grant.role_id.clone(),
                    &grant.actor_id,
                    &grant.target_id,
                    &grant.r#type,
                ),
            );
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: event,
                operation: async {
                    backend_driver.revoke_grant(state, &grant).await?;
                    state
                        .provider
                        .get_revoke_provider()
                        .create_revocation_event(ctx, revocation_event)
                        .await?;
                    Ok::<(), AssignmentProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| AssignmentProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver.revoke_grant(ctx.state(), &grant).await?;
            ctx.state()
                .provider
                .get_revoke_provider()
                .create_revocation_event(ctx, revocation_event)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    role_assignment_payload(
                        grant.role_id.clone(),
                        &grant.actor_id,
                        &grant.target_id,
                        &grant.r#type,
                    ),
                ))
                .await;
        }
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
                    &ExecutionContext::internal(&state),
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
                    &ExecutionContext::internal(&state),
                    &RoleAssignmentListParameters {
                        role_id: Some("rid".into()),
                        resolve_implied_roles: false,
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
                &ExecutionContext::internal(&state),
                &RoleAssignmentListParameters {
                    role_id: Some("rid".into()),
                    include_names: Some(true),
                    resolve_implied_roles: false,
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

        assert!(
            provider
                .revoke_grant(&ExecutionContext::internal(&state), assignment)
                .await
                .is_ok()
        );
    }
}
