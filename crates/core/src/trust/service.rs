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
//! # Trust provider.

use std::collections::{HashMap, HashSet};
use std::hash::RandomState;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tracing::debug;
use uuid::Uuid;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::assignment::RoleAssignmentListParametersBuilder;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::revoke::RevocationEventCreate;
use openstack_keystone_core_types::role::*;
use openstack_keystone_core_types::trust::*;

use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;
use crate::trust::{TrustApi, TrustProviderError, backend::TrustBackend};

/// Trust provider.
pub struct TrustService {
    /// Backend driver.
    backend_driver: Arc<dyn TrustBackend>,
}

impl TrustService {
    /// Creates a new TrustService instance.
    ///
    /// # Parameters
    /// - `config`: The service configuration.
    /// - `plugin_manager`: The plugin manager to resolve the backend driver.
    ///
    /// # Returns
    /// - `Ok(Self)` if the service was initialized successfully.
    /// - `Err(TrustProviderError)` if the backend driver could not be found.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, TrustProviderError> {
        let backend_driver = plugin_manager
            .get_trust_backend(config.trust.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

impl TrustService {
    /// Walk a prospective trust delegation chain (oldest ancestor first is
    /// not required; iterated newest-to-oldest via `.rev()`) and enforce the
    /// redelegation invariants. Shared by `validate_trust_delegation_chain`
    /// (chain already persisted) and `create_trust` (chain includes the
    /// not-yet-persisted trust being created).
    fn validate_chain(
        chain: &[Trust],
        max_redelegation_count: usize,
    ) -> Result<bool, TrustProviderError> {
        if chain.len() > max_redelegation_count {
            return Err(TrustProviderError::RedelegationDeepnessExceed {
                length: chain.len(),
                max_depth: max_redelegation_count,
            });
        }
        let mut parent_trust: Option<Trust> = None;
        let mut parent_expiration: Option<DateTime<Utc>> = None;
        for delegation in chain.iter().rev() {
            // None of the trusts can specify the redelegation_count > delegation_count of
            // the top level trust
            if let Some(current_redelegation_count) = delegation.redelegation_count
                && current_redelegation_count > max_redelegation_count as u32
            {
                return Err(TrustProviderError::RedelegationDeepnessExceed {
                    length: current_redelegation_count as usize,
                    max_depth: max_redelegation_count,
                });
            }
            if delegation.remaining_uses.is_some() {
                return Err(TrustProviderError::RemainingUsesMustBeUnset);
            }
            // Check that the parent trust is not expiring earlier than the redelegated
            if let Some(trust_expiry) = delegation.expires_at {
                if let Some(parent_expiry) = parent_trust
                    .as_ref()
                    .and_then(|x| x.expires_at)
                    .or(parent_expiration)
                {
                    if trust_expiry > parent_expiry {
                        return Err(TrustProviderError::ExpirationImpossible);
                    }
                    // reset the parent_expiration to the one of the current delegation.
                    parent_expiration = Some(trust_expiry);
                }
                // Ensure we set the parent_expiration with the first met value.
                if parent_expiration.is_none() {
                    parent_expiration = Some(trust_expiry);
                }
            }
            // Check that the redelegation is not adding new roles
            if let Some(parent_trust) = &parent_trust
                && !HashSet::<String, RandomState>::from_iter(
                    delegation
                        .roles
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .map(|role| role.id.clone()),
                )
                .is_subset(&HashSet::from_iter(
                    parent_trust
                        .roles
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .map(|role| role.id.clone()),
                ))
            {
                debug!(
                    "Trust roles {:?} are missing for the trustor {:?}",
                    delegation.roles, parent_trust.roles,
                );
                return Err(TrustProviderError::RedelegatedRolesNotAvailable);
            }
            // Check the impersonation
            if delegation.impersonation && !parent_trust.is_some_and(|x| x.impersonation) {
                return Err(TrustProviderError::RedelegatedImpersonationNotAllowed);
            }
            parent_trust = Some(delegation.clone());
        }
        Ok(true)
    }
}

#[async_trait]
impl TrustApi for TrustService {
    /// Create a new trust.
    ///
    /// - `project_id` and `roles` must both be set, or both be unset.
    /// - the trustor must currently hold every requested role on `project_id`.
    /// - if `redelegated_trust_id` is set, the prospective chain (this trust
    ///   prepended to the parent's persisted chain) must satisfy the same
    ///   redelegation invariants as `validate_trust_delegation_chain`.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `trust`: The trust creation data.
    ///
    /// # Returns
    /// - `Result<Trust, TrustProviderError>` - The created trust or an error.
    async fn create_trust<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        trust: TrustCreate,
    ) -> Result<Trust, TrustProviderError> {
        if trust.project_id.is_some() != !trust.roles.is_empty() {
            return Err(TrustProviderError::ProjectRolesPairingInvalid);
        }

        if let Some(project_id) = &trust.project_id {
            let trustor_assignments = ctx
                .state()
                .provider
                .get_assignment_provider()
                .list_role_assignments(
                    &ExecutionContext::internal(ctx.state()),
                    &RoleAssignmentListParametersBuilder::default()
                        .user_id(trust.trustor_user_id.clone())
                        .project_id(project_id.clone())
                        .include_names(true)
                        .effective(true)
                        .resolve_implied_roles(true)
                        .build()?,
                )
                .await?;
            let trustor_role_ids: HashSet<String> =
                trustor_assignments.into_iter().map(|a| a.role_id).collect();
            let mut requested_roles = trust.roles.clone();
            ctx.state()
                .provider
                .get_role_provider()
                .expand_implied_roles(ctx, &mut requested_roles)
                .await?;
            for role in &requested_roles {
                if !trustor_role_ids.contains(&role.id) {
                    return Err(TrustProviderError::RoleNotGranted {
                        role_id: role.id.clone(),
                    });
                }
            }
        }

        let id = trust
            .id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
        let prospective = Trust {
            deleted_at: None,
            expires_at: trust.expires_at,
            extra: trust.extra.clone(),
            id: id.clone(),
            impersonation: trust.impersonation,
            project_id: trust.project_id.clone(),
            remaining_uses: trust.remaining_uses,
            redelegated_trust_id: trust.redelegated_trust_id.clone(),
            redelegation_count: trust.redelegation_count,
            roles: if trust.roles.is_empty() {
                None
            } else {
                Some(trust.roles.clone())
            },
            trustor_user_id: trust.trustor_user_id.clone(),
            trustee_user_id: trust.trustee_user_id.clone(),
        };

        if let Some(parent_id) = &trust.redelegated_trust_id {
            let config = ctx.state().config_manager.config.read().await;
            let mut prospective_chain = vec![prospective.clone()];
            if let Some(parent_chain) = self.get_trust_delegation_chain(ctx, parent_id).await? {
                prospective_chain.extend(parent_chain);
            }
            Self::validate_chain(&prospective_chain, config.trust.max_redelegation_count)?;
        }

        let mut trust = trust;
        trust.id = Some(id);

        let created = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let trust_clone = trust.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::Trust { id: trust_clone.id.clone().unwrap_or_default() },
                ),
                operation: async {
                    backend_driver.create_trust(ctx.state(), trust_clone).await
                },
                on_audit_error: |_: AuditDispatchError| TrustProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let created = self.backend_driver.create_trust(ctx.state(), trust).await?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Trust {
                        id: created.id.clone(),
                    },
                ))
                .await;

            created
        };

        Ok(created)
    }

    /// Delete a trust by ID.
    ///
    /// Emits a revocation event for the trust so any tokens issued from it
    /// are immediately revoked, per the trust immutability/deletion contract.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `id`: The ID of the trust to delete.
    ///
    /// # Returns
    /// - `Result<(), TrustProviderError>` - `Ok(())` on success, or an error.
    async fn delete_trust<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), TrustProviderError> {
        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::Trust { id: id.to_string() },
                ),
                operation: async {
                    backend_driver.delete_trust(ctx.state(), id).await
                },
                on_audit_error: |_: AuditDispatchError| TrustProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver.delete_trust(ctx.state(), id).await?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::Trust { id: id.to_string() },
                ))
                .await;
        }

        let now = Utc::now();
        ctx.state()
            .provider
            .get_revoke_provider()
            .create_revocation_event(
                ctx,
                RevocationEventCreate {
                    trust_id: Some(id.to_string()),
                    issued_before: now,
                    revoked_at: now,
                    ..Default::default()
                },
            )
            .await?;

        Ok(())
    }

    /// Get trust by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The ID of the trust to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<Trust>, TrustProviderError>` - A `Result` containing an
    ///   `Option` with the trust if found, or an `Error`.
    async fn get_trust<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Trust>, TrustProviderError> {
        if let Some(mut trust) = self.backend_driver.get_trust(ctx.state(), id).await? {
            let all_roles: HashMap<String, Role> = HashMap::from_iter(
                ctx.state()
                    .provider
                    .get_role_provider()
                    .list_roles(
                        ctx,
                        &RoleListParameters {
                            domain_id: Some(None),
                            ..Default::default()
                        },
                    )
                    .await?
                    .iter()
                    .map(|role| (role.id.clone(), role.to_owned())),
            );
            if let Some(ref mut roles) = trust.roles {
                for role in roles.iter_mut() {
                    if let Some(erole) = all_roles.get(&role.id) {
                        role.domain_id = erole.domain_id.clone();
                        role.name = Some(erole.name.clone());
                    }
                }
                // Drop all roles for which name is not set (it is a signal that the processing
                // above has not found the role matching the parameters.
                roles.retain_mut(|role| role.name.is_some());
            }
            return Ok(Some(trust));
        }
        Ok(None)
    }

    /// Resolve trust delegation chain by the trust ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The ID of the trust to resolve the chain for.
    ///
    /// # Returns
    /// - `Result<Option<Vec<Trust>>, TrustProviderError>` - A `Result`
    ///   containing an `Option` with the trust delegation chain if found, or an
    ///   `Error`.
    async fn get_trust_delegation_chain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Vec<Trust>>, TrustProviderError> {
        self.backend_driver
            .get_trust_delegation_chain(ctx.state(), id)
            .await
    }

    /// List trusts.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: The parameters for listing trusts.
    ///
    /// # Returns
    /// - `Result<Vec<Trust>, TrustProviderError>` - A list of trusts or an
    ///   error.
    async fn list_trusts<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &TrustListParameters,
    ) -> Result<Vec<Trust>, TrustProviderError> {
        let mut trusts = self.backend_driver.list_trusts(ctx.state(), params).await?;

        let all_roles: HashMap<String, Role> = HashMap::from_iter(
            ctx.state()
                .provider
                .get_role_provider()
                .list_roles(
                    ctx,
                    &RoleListParameters {
                        domain_id: Some(None),
                        ..Default::default()
                    },
                )
                .await?
                .iter()
                .map(|role| (role.id.clone(), role.to_owned())),
        );
        for trust in trusts.iter_mut() {
            if let Some(ref mut roles) = trust.roles {
                for role in roles.iter_mut() {
                    if let Some(erole) = all_roles.get(&role.id) {
                        role.domain_id = erole.domain_id.clone();
                        role.name = Some(erole.name.clone());
                    }
                }
                // Drop all roles for which name is not set (it is a signal that the processing
                // above has not found the role matching the parameters.
                roles.retain_mut(|role| role.name.is_some());
            }
        }

        Ok(trusts)
    }

    /// Validate trust delegation chain.
    ///
    /// - redelegation deepness cannot exceed the global limit.
    /// - redelegated trusts must not specify use limit.
    /// - validate redelegated trust expiration is not later than of the
    ///   original.
    /// - redelegated trust must not add new roles.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `trust`: The trust to validate.
    ///
    /// # Returns
    /// - `Result<bool, TrustProviderError>` - Ok(true) if the chain is valid,
    ///   or an error.
    async fn validate_trust_delegation_chain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        trust: &Trust,
    ) -> Result<bool, TrustProviderError> {
        if trust.redelegated_trust_id.is_some()
            && let Some(chain) = self.get_trust_delegation_chain(ctx, &trust.id).await?
        {
            let config = ctx.state().config_manager.config.read().await;
            Self::validate_chain(&chain, config.trust.max_redelegation_count)?;
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use std::sync::Arc;

    use openstack_keystone_core_types::role::*;

    use super::*;
    use crate::provider::Provider;
    use crate::role::MockRoleProvider;
    use crate::tests::get_mocked_state;
    use crate::trust::backend::MockTrustBackend;

    fn create_trust_service(backend: MockTrustBackend) -> TrustService {
        TrustService {
            backend_driver: Arc::new(backend),
        }
    }

    #[tokio::test]
    async fn test_get_trust() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .withf(|_, qp: &RoleListParameters| {
                RoleListParameters {
                    domain_id: Some(None),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));
        let provider_builder = Provider::mocked_builder().mock_role(role_mock);
        let state = get_mocked_state(None, Some(provider_builder)).await;

        let mut backend = MockTrustBackend::new();
        backend
            .expect_get_trust()
            .withf(|_, id: &'_ str| id == "fake_trust")
            .returning(|_, _| {
                Ok(Some(Trust {
                    id: "fake_trust".into(),
                    ..Default::default()
                }))
            });

        let trust_provider = create_trust_service(backend);

        let trust: Trust = trust_provider
            .get_trust(&ExecutionContext::internal(&state), "fake_trust")
            .await
            .unwrap()
            .expect("trust found");
        assert_eq!(trust.id, "fake_trust");
    }

    #[tokio::test]
    async fn test_get_trust_delegation_chain() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .withf(|_, qp: &RoleListParameters| {
                RoleListParameters {
                    domain_id: Some(None),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));
        let provider_builder = Provider::mocked_builder().mock_role(role_mock);
        let state = get_mocked_state(None, Some(provider_builder)).await;

        let mut backend = MockTrustBackend::new();
        backend
            .expect_get_trust_delegation_chain()
            .withf(|_, id: &'_ str| id == "fake_trust")
            .returning(|_, _| {
                Ok(Some(vec![
                    Trust {
                        id: "redelegated_trust".into(),
                        redelegated_trust_id: Some("trust_id".into()),
                        ..Default::default()
                    },
                    Trust {
                        id: "trust_id".into(),
                        ..Default::default()
                    },
                ]))
            });

        let trust_provider = create_trust_service(backend);

        let chain = trust_provider
            .get_trust_delegation_chain(&ExecutionContext::internal(&state), "fake_trust")
            .await
            .unwrap()
            .expect("chain fetched");
        assert_eq!(chain.len(), 2);
    }

    #[tokio::test]
    async fn test_validate_trust_delegation_chain_not_redelegated() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .withf(|_, qp: &RoleListParameters| {
                RoleListParameters {
                    domain_id: Some(None),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));
        let provider_builder = Provider::mocked_builder().mock_role(role_mock);
        let state = get_mocked_state(None, Some(provider_builder)).await;

        let mut backend = MockTrustBackend::new();
        backend
            .expect_get_trust()
            .withf(|_, id: &'_ str| id == "fake_trust")
            .returning(|_, _| {
                Ok(Some(Trust {
                    id: "fake_trust".into(),
                    ..Default::default()
                }))
            });

        let trust_provider = create_trust_service(backend);
        let trust = trust_provider
            .get_trust(&ExecutionContext::internal(&state), "fake_trust")
            .await
            .unwrap()
            .expect("trust found");
        trust_provider
            .validate_trust_delegation_chain(&ExecutionContext::internal(&state), &trust)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_validate_trust_delegation_chain() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .withf(|_, qp: &RoleListParameters| {
                RoleListParameters {
                    domain_id: Some(None),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));
        let provider_builder = Provider::mocked_builder().mock_role(role_mock);
        let state = get_mocked_state(None, Some(provider_builder)).await;
        let mut backend = MockTrustBackend::new();
        backend
            .expect_get_trust()
            .withf(|_, id: &'_ str| id == "redelegated_trust")
            .returning(|_, _| {
                Ok(Some(Trust {
                    id: "redelegated_trust".into(),
                    redelegated_trust_id: Some("trust_id".into()),
                    ..Default::default()
                }))
            });
        backend
            .expect_get_trust_delegation_chain()
            .withf(|_, id: &'_ str| id == "redelegated_trust")
            .returning(|_, _| {
                Ok(Some(vec![
                    Trust {
                        id: "redelegated_trust".into(),
                        redelegated_trust_id: Some("trust_id".into()),
                        ..Default::default()
                    },
                    Trust {
                        id: "trust_id".into(),
                        ..Default::default()
                    },
                ]))
            });

        let trust_provider = create_trust_service(backend);
        let trust = trust_provider
            .get_trust(&ExecutionContext::internal(&state), "redelegated_trust")
            .await
            .unwrap()
            .expect("trust found");
        trust_provider
            .validate_trust_delegation_chain(&ExecutionContext::internal(&state), &trust)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_validate_trust_delegation_chain_expiration() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .withf(|_, qp: &RoleListParameters| {
                RoleListParameters {
                    domain_id: Some(None),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));
        let provider_builder = Provider::mocked_builder().mock_role(role_mock);
        let state = get_mocked_state(None, Some(provider_builder)).await;
        let mut backend = MockTrustBackend::new();
        backend
            .expect_get_trust()
            .withf(|_, id: &'_ str| id == "redelegated_trust2")
            .returning(|_, _| {
                Ok(Some(Trust {
                    id: "redelegated_trust2".into(),
                    redelegated_trust_id: Some("redelegated_trust1".into()),
                    ..Default::default()
                }))
            });
        backend
            .expect_get_trust_delegation_chain()
            .withf(|_, id: &'_ str| id == "redelegated_trust2")
            .returning(|_, _| {
                Ok(Some(vec![
                    Trust {
                        id: "redelegated_trust2".into(),
                        redelegated_trust_id: Some("redelegated_trust1".into()),
                        expires_at: Some(DateTime::<Utc>::MAX_UTC),
                        ..Default::default()
                    },
                    Trust {
                        id: "redelegated_trust1".into(),
                        redelegated_trust_id: Some("trust_id".into()),
                        ..Default::default()
                    },
                    Trust {
                        id: "trust_id".into(),
                        expires_at: Some(Utc::now()),
                        ..Default::default()
                    },
                ]))
            });

        let trust_provider = create_trust_service(backend);
        let trust = trust_provider
            .get_trust(&ExecutionContext::internal(&state), "redelegated_trust2")
            .await
            .unwrap()
            .expect("trust found");
        if let Err(TrustProviderError::ExpirationImpossible) = trust_provider
            .validate_trust_delegation_chain(&ExecutionContext::internal(&state), &trust)
            .await
        {
        } else {
            panic!("redelegated trust cannot expire later than the parent");
        };
    }

    #[tokio::test]
    async fn test_validate_trust_delegation_chain_no_new_roles() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .withf(|_, qp: &RoleListParameters| {
                RoleListParameters {
                    domain_id: Some(None),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));
        let provider_builder = Provider::mocked_builder().mock_role(role_mock);
        let state = get_mocked_state(None, Some(provider_builder)).await;
        let mut backend = MockTrustBackend::new();
        backend
            .expect_get_trust()
            .withf(|_, id: &'_ str| id == "redelegated_trust")
            .returning(|_, _| {
                Ok(Some(Trust {
                    id: "redelegated_trust".into(),
                    redelegated_trust_id: Some("trust_id".into()),
                    ..Default::default()
                }))
            });
        backend
            .expect_get_trust_delegation_chain()
            .withf(|_, id: &'_ str| id == "redelegated_trust")
            .returning(|_, _| {
                Ok(Some(vec![
                    Trust {
                        id: "redelegated_trust".into(),
                        redelegated_trust_id: Some("trust_id".into()),
                        roles: Some(vec![
                            RoleRef {
                                id: "rid1".into(),
                                name: None,
                                domain_id: None,
                            },
                            RoleRef {
                                id: "rid2".into(),
                                name: None,
                                domain_id: None,
                            },
                        ]),
                        ..Default::default()
                    },
                    Trust {
                        id: "trust_id".into(),
                        roles: Some(vec![RoleRef {
                            id: "rid1".into(),
                            name: None,
                            domain_id: None,
                        }]),
                        ..Default::default()
                    },
                ]))
            });

        let trust_provider = create_trust_service(backend);
        let trust = trust_provider
            .get_trust(&ExecutionContext::internal(&state), "redelegated_trust")
            .await
            .unwrap()
            .expect("trust found");

        if let Err(TrustProviderError::RedelegatedRolesNotAvailable) = trust_provider
            .validate_trust_delegation_chain(&ExecutionContext::internal(&state), &trust)
            .await
        {
        } else {
            panic!("adding new roles on redelegation should be disallowed");
        };
    }

    #[tokio::test]
    async fn test_validate_trust_delegation_chain_impersonation() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .withf(|_, qp: &RoleListParameters| {
                RoleListParameters {
                    domain_id: Some(None),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));
        let provider_builder = Provider::mocked_builder().mock_role(role_mock);
        let state = get_mocked_state(None, Some(provider_builder)).await;
        let mut backend = MockTrustBackend::new();
        backend
            .expect_get_trust()
            .withf(|_, id: &'_ str| id == "redelegated_trust2")
            .returning(|_, _| {
                Ok(Some(Trust {
                    id: "redelegated_trust2".into(),
                    redelegated_trust_id: Some("redelegated_trust1".into()),
                    ..Default::default()
                }))
            });
        backend
            .expect_get_trust_delegation_chain()
            .withf(|_, id: &'_ str| id == "redelegated_trust2")
            .returning(|_, _| {
                Ok(Some(vec![
                    Trust {
                        id: "redelegated_trust2".into(),
                        redelegated_trust_id: Some("redelegated_trust1".into()),
                        ..Default::default()
                    },
                    Trust {
                        id: "redelegated_trust1".into(),
                        redelegated_trust_id: Some("trust_id".into()),
                        impersonation: true,
                        ..Default::default()
                    },
                    Trust {
                        id: "trust_id".into(),
                        impersonation: false,
                        ..Default::default()
                    },
                ]))
            });

        let trust_provider = create_trust_service(backend);
        let trust = trust_provider
            .get_trust(&ExecutionContext::internal(&state), "redelegated_trust2")
            .await
            .unwrap()
            .expect("trust found");
        match trust_provider
            .validate_trust_delegation_chain(&ExecutionContext::internal(&state), &trust)
            .await
        {
            Err(TrustProviderError::RedelegatedImpersonationNotAllowed) => {}
            other => {
                panic!(
                    "redelegated trust impersonation cannot be enabled, {:?}",
                    other
                );
            }
        }
    }

    #[tokio::test]
    async fn test_validate_trust_delegation_chain_deepness() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .withf(|_, qp: &RoleListParameters| {
                RoleListParameters {
                    domain_id: Some(None),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));
        let provider_builder = Provider::mocked_builder().mock_role(role_mock);
        let state = get_mocked_state(None, Some(provider_builder)).await;
        let mut backend = MockTrustBackend::new();
        backend
            .expect_get_trust()
            .withf(|_, id: &'_ str| id == "redelegated_trust2")
            .returning(|_, _| {
                Ok(Some(Trust {
                    id: "redelegated_trust2".into(),
                    redelegated_trust_id: Some("redelegated_trust1".into()),
                    ..Default::default()
                }))
            });
        backend
            .expect_get_trust()
            .withf(|_, id: &'_ str| id == "redelegated_trust_long")
            .returning(|_, _| {
                Ok(Some(Trust {
                    id: "redelegated_trust_long".into(),
                    redelegated_trust_id: Some("redelegated_trust2".into()),
                    ..Default::default()
                }))
            });
        backend
            .expect_get_trust_delegation_chain()
            .withf(|_, id: &'_ str| id == "redelegated_trust2")
            .returning(|_, _| {
                Ok(Some(vec![
                    Trust {
                        id: "redelegated_trust2".into(),
                        redelegated_trust_id: Some("redelegated_trust1".into()),
                        redelegation_count: Some(4),
                        ..Default::default()
                    },
                    Trust {
                        id: "redelegated_trust1".into(),
                        redelegated_trust_id: Some("trust_id".into()),
                        ..Default::default()
                    },
                    Trust {
                        id: "trust_id".into(),
                        ..Default::default()
                    },
                ]))
            });

        backend
            .expect_get_trust_delegation_chain()
            .withf(|_, id: &'_ str| id == "redelegated_trust_long")
            .returning(|_, _| {
                Ok(Some(vec![
                    Trust {
                        id: "redelegated_trust_long".into(),
                        redelegated_trust_id: Some("redelegated_trust2".into()),
                        ..Default::default()
                    },
                    Trust {
                        id: "redelegated_trust2".into(),
                        redelegated_trust_id: Some("redelegated_trust1".into()),
                        ..Default::default()
                    },
                    Trust {
                        id: "redelegated_trust1".into(),
                        redelegated_trust_id: Some("trust_id".into()),
                        ..Default::default()
                    },
                    Trust {
                        id: "trust_id".into(),
                        ..Default::default()
                    },
                ]))
            });

        let trust_provider = create_trust_service(backend);
        let trust = trust_provider
            .get_trust(&ExecutionContext::internal(&state), "redelegated_trust2")
            .await
            .unwrap()
            .expect("trust found");
        match trust_provider
            .validate_trust_delegation_chain(&ExecutionContext::internal(&state), &trust)
            .await
        {
            Err(TrustProviderError::RedelegationDeepnessExceed { .. }) => {}
            other => {
                panic!(
                    "redelegated trust redelegation_count exceeds limit, but {:?}",
                    other
                );
            }
        }

        let trust = trust_provider
            .get_trust(
                &ExecutionContext::internal(&state),
                "redelegated_trust_long",
            )
            .await
            .unwrap()
            .expect("trust found");
        match trust_provider
            .validate_trust_delegation_chain(&ExecutionContext::internal(&state), &trust)
            .await
        {
            Err(TrustProviderError::RedelegationDeepnessExceed { .. }) => {}
            other => {
                panic!("trust redelegation chain exceeds limit, but {:?}", other);
            }
        }
    }

    #[tokio::test]
    async fn test_list_trusts() {
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_list_roles()
            .withf(|_, qp: &RoleListParameters| {
                RoleListParameters {
                    domain_id: Some(None),
                    ..Default::default()
                } == *qp
            })
            .returning(|_, _| Ok(Vec::new()));
        let provider_builder = Provider::mocked_builder().mock_role(role_mock);
        let state = get_mocked_state(None, Some(provider_builder)).await;

        let mut backend = MockTrustBackend::new();
        backend
            .expect_list_trusts()
            .withf(|_, params: &TrustListParameters| *params == TrustListParameters::default())
            .returning(|_, _| {
                Ok(vec![
                    Trust {
                        id: "redelegated_trust".into(),
                        redelegated_trust_id: Some("trust_id".into()),
                        ..Default::default()
                    },
                    Trust {
                        id: "trust_id".into(),
                        ..Default::default()
                    },
                ])
            });

        let trust_provider = create_trust_service(backend);

        let list = trust_provider
            .list_trusts(
                &ExecutionContext::internal(&state),
                &TrustListParameters::default(),
            )
            .await
            .unwrap();
        assert_eq!(list.len(), 2);
    }

    // ---- create_trust / delete_trust ----

    use openstack_keystone_core_types::assignment::*;
    use openstack_keystone_core_types::revoke::RevocationEvent;

    use crate::assignment::MockAssignmentProvider;
    use crate::revoke::MockRevokeProvider;

    fn assignment_with_role(rid: impl Into<String>) -> Assignment {
        Assignment {
            actor_id: "trustor".into(),
            role_id: rid.into(),
            role_name: Some("admin".to_string()),
            target_id: "pid".to_string(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: None,
        }
    }

    #[tokio::test]
    async fn test_create_trust_project_roles_pairing_invalid() {
        let backend = MockTrustBackend::new();
        let state = get_mocked_state(None, None).await;
        let trust_provider = create_trust_service(backend);

        let create = TrustCreateBuilder::default()
            .trustor_user_id("trustor")
            .trustee_user_id("trustee")
            .project_id("pid")
            .build()
            .unwrap();

        match trust_provider
            .create_trust(&ExecutionContext::internal(&state), create)
            .await
        {
            Err(TrustProviderError::ProjectRolesPairingInvalid) => {}
            other => panic!("expected ProjectRolesPairingInvalid, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_create_trust_role_not_granted() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .returning(|_e, _q| Ok(Vec::new()));
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_expand_implied_roles()
            .returning(|_e, _roles| Ok(()));
        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_role(role_mock);
        let state = get_mocked_state(None, Some(provider_builder)).await;

        let backend = MockTrustBackend::new();
        let trust_provider = create_trust_service(backend);

        let create = TrustCreateBuilder::default()
            .trustor_user_id("trustor")
            .trustee_user_id("trustee")
            .project_id("pid")
            .roles(vec![RoleRefBuilder::default().id("rid1").build().unwrap()])
            .build()
            .unwrap();

        match trust_provider
            .create_trust(&ExecutionContext::internal(&state), create)
            .await
        {
            Err(TrustProviderError::RoleNotGranted { role_id }) => assert_eq!(role_id, "rid1"),
            other => panic!("expected RoleNotGranted, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_create_trust_success() {
        let mut assignment_mock = MockAssignmentProvider::default();
        assignment_mock
            .expect_list_role_assignments()
            .withf(|_, q: &RoleAssignmentListParameters| {
                q.user_id.as_deref() == Some("trustor") && q.project_id.as_deref() == Some("pid")
            })
            .returning(|_e, _q| Ok(vec![assignment_with_role("rid1")]));
        let mut role_mock = MockRoleProvider::default();
        role_mock
            .expect_expand_implied_roles()
            .returning(|_e, _roles| Ok(()));
        let provider_builder = Provider::mocked_builder()
            .mock_assignment(assignment_mock)
            .mock_role(role_mock);
        let state = get_mocked_state(None, Some(provider_builder)).await;

        let mut backend = MockTrustBackend::new();
        backend
            .expect_create_trust()
            .withf(|_, t: &TrustCreate| {
                t.trustor_user_id == "trustor" && t.roles.iter().any(|r| r.id == "rid1")
            })
            .returning(|_, t| {
                Ok(Trust {
                    id: t.id.clone().unwrap_or_default(),
                    trustor_user_id: t.trustor_user_id.clone(),
                    trustee_user_id: t.trustee_user_id.clone(),
                    project_id: t.project_id.clone(),
                    roles: Some(t.roles.clone()),
                    ..Default::default()
                })
            });

        let trust_provider = create_trust_service(backend);

        let create = TrustCreateBuilder::default()
            .trustor_user_id("trustor")
            .trustee_user_id("trustee")
            .project_id("pid")
            .roles(vec![RoleRefBuilder::default().id("rid1").build().unwrap()])
            .build()
            .unwrap();

        let created = trust_provider
            .create_trust(&ExecutionContext::internal(&state), create)
            .await
            .unwrap();
        assert_eq!(created.trustor_user_id, "trustor");
        assert!(!created.id.is_empty());
    }

    #[tokio::test]
    async fn test_delete_trust() {
        let mut revoke_mock = MockRevokeProvider::default();
        revoke_mock
            .expect_create_revocation_event()
            .withf(
                |_, e: &openstack_keystone_core_types::revoke::RevocationEventCreate| {
                    e.trust_id.as_deref() == Some("trust_id")
                },
            )
            .returning(|_, _| Ok(RevocationEvent::default()));
        let provider_builder = Provider::mocked_builder().mock_revoke(revoke_mock);
        let state = get_mocked_state(None, Some(provider_builder)).await;

        let mut backend = MockTrustBackend::new();
        backend
            .expect_delete_trust()
            .withf(|_, id: &'_ str| id == "trust_id")
            .returning(|_, _| Ok(()));

        let trust_provider = create_trust_service(backend);

        trust_provider
            .delete_trust(&ExecutionContext::internal(&state), "trust_id")
            .await
            .unwrap();
    }
}
