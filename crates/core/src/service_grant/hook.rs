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
//! Service grant lifecycle hook (ADR 0036 §8).
//!
//! Disables or deletes grants when the objects they depend on change. This
//! is an optimisation, not the security control: every redemption re-runs
//! the live checks (§5.1), so a grant the hook misses (an inherited
//! assignment, an external assignment driver) is still unredeemable and is
//! marked on its next redemption.

use std::collections::BTreeMap;

use async_trait::async_trait;
use tracing::warn;

use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::service_grant::*;

use crate::auth::ExecutionContext;
use crate::events::ProviderHooks;
use crate::keystone::ServiceState;
use crate::service_grant::service::{assigned_role_ids, disable_grant};

/// Hook keeping service grants in step with their grantor, project and
/// grantee client.
pub struct ServiceGrantHook {
    state: ServiceState,
}

impl ServiceGrantHook {
    /// Create a new hook bound to the given service state.
    pub fn new(state: ServiceState) -> Self {
        Self { state }
    }

    async fn delete_all(&self, grants: Vec<ServiceGrant>) {
        for grant in grants {
            if let Err(e) = self
                .state
                .provider
                .get_service_grant_provider()
                .delete_service_grant(
                    &ExecutionContext::internal(&self.state),
                    &grant.domain_id,
                    &grant.id,
                )
                .await
            {
                warn!(grant_id = %grant.id, error = %e, "service grant hook: failed to delete grant");
            }
        }
    }

    async fn disable(&self, grant: &ServiceGrant, reason: DisabledReason) {
        if let Err(e) = disable_grant(&self.state, grant, reason).await {
            warn!(grant_id = %grant.id, error = %e, "service grant hook: failed to disable grant");
        }
    }

    /// Disable every enabled grant in `grants` for `reason`.
    async fn disable_all(&self, grants: Vec<ServiceGrant>, reason: DisabledReason) {
        for grant in grants.into_iter().filter(|g| g.enabled) {
            self.disable(&grant, reason).await;
        }
    }

    /// The grants matching `params`; a failure is logged and yields none.
    async fn grants(&self, params: ServiceGrantListParameters) -> Vec<ServiceGrant> {
        match self
            .state
            .provider
            .get_service_grant_provider()
            .list_service_grants(&ExecutionContext::internal(&self.state), &params)
            .await
        {
            Ok(grants) => grants,
            Err(ServiceGrantProviderError::RaftNotAvailable) => Vec::new(),
            Err(e) => {
                warn!(error = %e, "service grant hook: failed to list grants");
                Vec::new()
            }
        }
    }

    /// Disable as `GranteeRemoved` the enabled grants held by clients of
    /// `domain_id` that are gone or no longer accept grants. The event
    /// names the client by provider id, which a deleted client can no
    /// longer be resolved from, so every grantee of the domain is
    /// re-checked; client changes are rare.
    async fn on_client_change(&self, domain_id: &str) {
        let grants: Vec<ServiceGrant> = self
            .grants(ServiceGrantListParameters {
                enabled: Some(true),
                ..Default::default()
            })
            .await
            .into_iter()
            .filter(|g| g.grantee.client_domain_id() == domain_id)
            .collect();
        let mut accepts: BTreeMap<String, bool> = BTreeMap::new();
        for grant in grants {
            let client_id = grant.grantee.client_id().to_string();
            let accepted = match accepts.get(&client_id) {
                Some(accepted) => *accepted,
                None => {
                    let accepted = match self
                        .state
                        .provider
                        .get_oauth2_client_provider()
                        .get_by_client_id(&ExecutionContext::internal(&self.state), &client_id)
                        .await
                    {
                        Ok(client) => client.is_some_and(|c| {
                            c.domain_id == domain_id && c.service_grant_policy().is_some()
                        }),
                        Err(e) => {
                            warn!(error = %e, "service grant hook: failed to load client");
                            // Leave the grant alone; redemption re-checks.
                            true
                        }
                    };
                    accepts.insert(client_id, accepted);
                    accepted
                }
            };
            if !accepted {
                self.disable(&grant, DisabledReason::GranteeRemoved).await;
            }
        }
    }

    /// Disable as `RoleLost` every enabled grant in `grants` whose grantor
    /// no longer holds any of its roles on its project.
    async fn recheck_roles(&self, grants: Vec<ServiceGrant>) {
        for grant in grants.into_iter().filter(|g| g.enabled) {
            match assigned_role_ids(
                &self.state,
                &grant.grantor_user_id,
                grant.target.project_id(),
            )
            .await
            {
                Ok(held) if !grant.role_ids.iter().any(|r| held.contains(r)) => {
                    self.disable(&grant, DisabledReason::RoleLost).await;
                }
                Ok(_) => {}
                Err(e) => warn!(
                    grant_id = %grant.id,
                    error = %e,
                    "service grant hook: failed to resolve grantor roles"
                ),
            }
        }
    }
}

fn by_grantor(user_id: &str) -> ServiceGrantListParameters {
    ServiceGrantListParameters {
        grantor_user_id: Some(user_id.to_string()),
        ..Default::default()
    }
}

fn by_project(project_id: &str) -> ServiceGrantListParameters {
    ServiceGrantListParameters {
        project_id: Some(project_id.to_string()),
        ..Default::default()
    }
}

#[async_trait]
impl ProviderHooks for ServiceGrantHook {
    async fn on_event(&self, event: &Event) {
        match (&event.operation, &event.payload) {
            (Operation::Disable, EventPayload::User { id }) => {
                let grants = self.grants(by_grantor(id)).await;
                self.disable_all(grants, DisabledReason::GrantorDisabled)
                    .await;
            }
            (Operation::Delete, EventPayload::User { id }) => {
                let grants = self.grants(by_grantor(id)).await;
                self.delete_all(grants).await;
            }
            (Operation::Disable, EventPayload::Project { id }) => {
                let grants = self.grants(by_project(id)).await;
                self.disable_all(grants, DisabledReason::TargetDisabled)
                    .await;
            }
            (Operation::Delete, EventPayload::Project { id }) => {
                let grants = self.grants(by_project(id)).await;
                self.delete_all(grants).await;
            }
            // A direct assignment removed from a grantor, or a group
            // assignment removed from a project.
            (
                Operation::Delete,
                EventPayload::RoleAssignment {
                    user_id,
                    group_id,
                    project_id: Some(project_id),
                    ..
                },
            ) => {
                let mut params = by_project(project_id);
                if group_id.is_none() {
                    let Some(user_id) = user_id else {
                        return;
                    };
                    params.grantor_user_id = Some(user_id.clone());
                }
                let grants = self.grants(params).await;
                self.recheck_roles(grants).await;
            }
            // A grantor removed from groups, or its groups replaced.
            (
                Operation::Delete | Operation::Update,
                EventPayload::GroupMembership { user_id, .. },
            ) => {
                let grants = self.grants(by_grantor(user_id)).await;
                self.recheck_roles(grants).await;
            }
            (
                Operation::Update | Operation::Disable | Operation::Delete,
                EventPayload::Oauth2Client { domain_id, .. },
            ) => {
                self.on_client_change(domain_id).await;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use chrono::Utc;

    use openstack_keystone_core_types::assignment::{Assignment, AssignmentType};
    use openstack_keystone_core_types::oauth2_client::{DelegationPolicy, OAuth2ClientResource};

    use super::*;
    use crate::assignment::MockAssignmentProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::{Provider, ProviderBuilder};
    use crate::service_grant::MockServiceGrantProvider;
    use crate::tests::get_mocked_state;

    fn grant(id: &str, client_domain_id: &str, enabled: bool) -> ServiceGrant {
        ServiceGrant {
            id: id.into(),
            version: 1,
            domain_id: "d1".into(),
            grantor_user_id: "u1".into(),
            grantee: Grantee::Client {
                client_id: format!("{id}-client"),
                client_domain_id: client_domain_id.into(),
            },
            target: GrantTarget::Project {
                project_id: "p1".into(),
                project_domain_id: "d1".into(),
            },
            role_ids: vec!["member".into()],
            expires_at: None,
            description: None,
            enabled,
            created_at: Utc::now(),
            last_redeemed_at: None,
            disabled_reason: None,
        }
    }

    fn client(client_id: &str, delegation: Option<DelegationPolicy>) -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_id: client_id.into(),
            provider_id: "backup".into(),
            domain_id: "infra".into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: "tls_client_auth".into(),
            grant_types: vec![],
            require_pkce: false,
            allowed_scopes: vec![],
            pre_authorized: false,
            enabled: true,
            claims_template: HashMap::new(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
            name: "Backup".into(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            spiffe_ids: vec![],
            delegation,
        }
    }

    /// Writes the hook made: `(grant id, Some(reason))` for a disable,
    /// `(grant id, None)` for a delete.
    type Writes = Arc<Mutex<Vec<(String, Option<DisabledReason>)>>>;

    /// A grant provider listing `grants` (recording the list parameters
    /// into `params`) and recording every write into the returned log.
    fn grant_mock(
        grants: Vec<ServiceGrant>,
        params: Arc<Mutex<Vec<ServiceGrantListParameters>>>,
    ) -> (MockServiceGrantProvider, Writes) {
        let writes: Writes = Arc::default();
        let mut mock = MockServiceGrantProvider::default();
        mock.expect_list_service_grants().returning(move |_, p| {
            params.lock().unwrap().push(p.clone());
            Ok(grants.clone())
        });
        let log = writes.clone();
        mock.expect_update_service_grant()
            .returning(move |_, _, id, update, _| {
                log.lock()
                    .unwrap()
                    .push((id.to_string(), update.disabled_reason));
                Ok(grant(id, "infra", false))
            });
        let log = writes.clone();
        mock.expect_delete_service_grant()
            .returning(move |_, _, id| {
                log.lock().unwrap().push((id.to_string(), None));
                Ok(())
            });
        (mock, writes)
    }

    async fn hook(builder: ProviderBuilder) -> ServiceGrantHook {
        ServiceGrantHook::new(get_mocked_state(None, Some(builder)).await)
    }

    #[tokio::test]
    async fn test_grantor_disable_disables_enabled_grants() {
        let params = Arc::default();
        let (mock, writes) = grant_mock(
            vec![grant("g1", "infra", true), grant("g2", "infra", false)],
            Arc::clone(&params),
        );
        hook(Provider::mocked_builder().mock_service_grant(mock))
            .await
            .on_event(&Event::new(
                Operation::Disable,
                EventPayload::User { id: "u1".into() },
            ))
            .await;
        assert_eq!(
            *writes.lock().unwrap(),
            vec![("g1".to_string(), Some(DisabledReason::GrantorDisabled))]
        );
        assert_eq!(
            params.lock().unwrap()[0].grantor_user_id.as_deref(),
            Some("u1")
        );
    }

    #[tokio::test]
    async fn test_grantor_delete_deletes_grants() {
        let (mock, writes) = grant_mock(
            vec![grant("g1", "infra", true), grant("g2", "infra", false)],
            Arc::default(),
        );
        hook(Provider::mocked_builder().mock_service_grant(mock))
            .await
            .on_event(&Event::new(
                Operation::Delete,
                EventPayload::User { id: "u1".into() },
            ))
            .await;
        assert_eq!(
            *writes.lock().unwrap(),
            vec![("g1".to_string(), None), ("g2".to_string(), None)]
        );
    }

    #[tokio::test]
    async fn test_project_disable_disables_grants() {
        let params = Arc::default();
        let (mock, writes) = grant_mock(vec![grant("g1", "infra", true)], Arc::clone(&params));
        hook(Provider::mocked_builder().mock_service_grant(mock))
            .await
            .on_event(&Event::new(
                Operation::Disable,
                EventPayload::Project { id: "p1".into() },
            ))
            .await;
        assert_eq!(
            *writes.lock().unwrap(),
            vec![("g1".to_string(), Some(DisabledReason::TargetDisabled))]
        );
        assert_eq!(params.lock().unwrap()[0].project_id.as_deref(), Some("p1"));
    }

    #[tokio::test]
    async fn test_disable_retries_on_version_conflict() {
        let versions = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&versions);
        let mut mock = MockServiceGrantProvider::default();
        mock.expect_list_service_grants()
            .returning(|_, _| Ok(vec![grant("g1", "infra", true)]));
        mock.expect_update_service_grant()
            .returning(move |_, _, _, _, version| {
                seen.lock().unwrap().push(version);
                if version == 1 {
                    Err(ServiceGrantProviderError::Conflict("stale".into()))
                } else {
                    Ok(grant("g1", "infra", false))
                }
            });
        // A redemption touched the grant in between.
        mock.expect_get_service_grant().returning(|_, _, _| {
            let mut current = grant("g1", "infra", true);
            current.version = 2;
            Ok(Some(current))
        });
        hook(Provider::mocked_builder().mock_service_grant(mock))
            .await
            .on_event(&Event::new(
                Operation::Disable,
                EventPayload::User { id: "u1".into() },
            ))
            .await;
        assert_eq!(*versions.lock().unwrap(), vec![1, 2]);
    }

    #[tokio::test]
    async fn test_disable_stops_when_grant_was_disabled_meanwhile() {
        let mut mock = MockServiceGrantProvider::default();
        mock.expect_list_service_grants()
            .returning(|_, _| Ok(vec![grant("g1", "infra", true)]));
        mock.expect_update_service_grant()
            .times(1)
            .returning(|_, _, _, _, _| Err(ServiceGrantProviderError::Conflict("stale".into())));
        mock.expect_get_service_grant()
            .returning(|_, _, _| Ok(Some(grant("g1", "infra", false))));
        hook(Provider::mocked_builder().mock_service_grant(mock))
            .await
            .on_event(&Event::new(
                Operation::Disable,
                EventPayload::User { id: "u1".into() },
            ))
            .await;
    }

    fn assignments(held: &'static [&'static str]) -> MockAssignmentProvider {
        let mut mock = MockAssignmentProvider::default();
        mock.expect_list_role_assignments().returning(move |_, _| {
            Ok(held
                .iter()
                .map(|r| Assignment {
                    actor_id: "u1".into(),
                    role_id: (*r).into(),
                    role_name: None,
                    target_id: "p1".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                })
                .collect())
        });
        mock
    }

    fn unassigned(user_id: Option<&str>, group_id: Option<&str>) -> Event {
        Event::new(
            Operation::Delete,
            EventPayload::RoleAssignment {
                role_id: "member".into(),
                user_id: user_id.map(str::to_string),
                group_id: group_id.map(str::to_string),
                project_id: Some("p1".into()),
                domain_id: None,
                system_id: None,
            },
        )
    }

    #[tokio::test]
    async fn test_lost_role_disables_grant() {
        let params = Arc::default();
        let (mock, writes) = grant_mock(vec![grant("g1", "infra", true)], Arc::clone(&params));
        hook(
            Provider::mocked_builder()
                .mock_service_grant(mock)
                .mock_assignment(assignments(&["reader"])),
        )
        .await
        .on_event(&unassigned(Some("u1"), None))
        .await;
        assert_eq!(
            *writes.lock().unwrap(),
            vec![("g1".to_string(), Some(DisabledReason::RoleLost))]
        );
        let params = params.lock().unwrap();
        assert_eq!(params[0].grantor_user_id.as_deref(), Some("u1"));
        assert_eq!(params[0].project_id.as_deref(), Some("p1"));
    }

    #[tokio::test]
    async fn test_retained_role_keeps_grant() {
        let (mock, writes) = grant_mock(vec![grant("g1", "infra", true)], Arc::default());
        hook(
            Provider::mocked_builder()
                .mock_service_grant(mock)
                .mock_assignment(assignments(&["member"])),
        )
        .await
        .on_event(&unassigned(Some("u1"), None))
        .await;
        assert!(writes.lock().unwrap().is_empty());
    }

    /// A group assignment can back any grantor's roles, so every grant on
    /// the project is re-checked.
    #[tokio::test]
    async fn test_group_unassignment_rechecks_every_grantor() {
        let params = Arc::default();
        let (mock, writes) = grant_mock(vec![grant("g1", "infra", true)], Arc::clone(&params));
        hook(
            Provider::mocked_builder()
                .mock_service_grant(mock)
                .mock_assignment(assignments(&[])),
        )
        .await
        .on_event(&unassigned(None, Some("grp")))
        .await;
        assert_eq!(writes.lock().unwrap().len(), 1);
        assert_eq!(params.lock().unwrap()[0].grantor_user_id, None);
    }

    #[tokio::test]
    async fn test_membership_removal_rechecks_grantor() {
        let (mock, writes) = grant_mock(vec![grant("g1", "infra", true)], Arc::default());
        hook(
            Provider::mocked_builder()
                .mock_service_grant(mock)
                .mock_assignment(assignments(&[])),
        )
        .await
        .on_event(&Event::new(
            Operation::Delete,
            EventPayload::GroupMembership {
                user_id: "u1".into(),
                group_ids: vec!["grp".into()],
            },
        ))
        .await;
        assert_eq!(
            *writes.lock().unwrap(),
            vec![("g1".to_string(), Some(DisabledReason::RoleLost))]
        );
    }

    /// Deleting a client disables its grants; grants of clients that still
    /// accept grants, and of clients in other domains, are left alone.
    #[tokio::test]
    async fn test_client_change_disables_grants_of_removed_clients() {
        let (mock, writes) = grant_mock(
            vec![
                grant("gone", "infra", true),
                grant("optout", "infra", true),
                grant("kept", "infra", true),
                grant("other", "elsewhere", true),
            ],
            Arc::default(),
        );
        let mut clients = MockOauth2ClientProvider::default();
        clients.expect_get_by_client_id().returning(|_, client_id| {
            Ok(match client_id {
                "optout-client" => Some(client(client_id, None)),
                "kept-client" => Some(client(
                    client_id,
                    Some(DelegationPolicy {
                        service_grants: true,
                        ..Default::default()
                    }),
                )),
                _ => None,
            })
        });
        hook(
            Provider::mocked_builder()
                .mock_service_grant(mock)
                .mock_oauth2_client(clients),
        )
        .await
        .on_event(&Event::new(
            Operation::Delete,
            EventPayload::Oauth2Client {
                domain_id: "infra".into(),
                provider_id: "backup".into(),
            },
        ))
        .await;
        assert_eq!(
            *writes.lock().unwrap(),
            vec![
                ("gone".to_string(), Some(DisabledReason::GranteeRemoved)),
                ("optout".to_string(), Some(DisabledReason::GranteeRemoved)),
            ]
        );
    }
}
