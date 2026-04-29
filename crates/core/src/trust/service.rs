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

use openstack_keystone_config::Config;
use openstack_keystone_core_types::role::*;
use openstack_keystone_core_types::trust::*;

use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::role::RoleApi;
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

#[async_trait]
impl TrustApi for TrustService {
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
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Trust>, TrustProviderError> {
        if let Some(mut trust) = self.backend_driver.get_trust(state, id).await? {
            let all_roles: HashMap<String, Role> = HashMap::from_iter(
                state
                    .provider
                    .get_role_provider()
                    .list_roles(
                        state,
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
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Vec<Trust>>, TrustProviderError> {
        self.backend_driver
            .get_trust_delegation_chain(state, id)
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
    async fn list_trusts(
        &self,
        state: &ServiceState,
        params: &TrustListParameters,
    ) -> Result<Vec<Trust>, TrustProviderError> {
        let mut trusts = self.backend_driver.list_trusts(state, params).await?;

        let all_roles: HashMap<String, Role> = HashMap::from_iter(
            state
                .provider
                .get_role_provider()
                .list_roles(
                    state,
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
    async fn validate_trust_delegation_chain(
        &self,
        state: &ServiceState,
        trust: &Trust,
    ) -> Result<bool, TrustProviderError> {
        if trust.redelegated_trust_id.is_some()
            && let Some(chain) = self.get_trust_delegation_chain(state, &trust.id).await?
        {
            if chain.len() > state.config.trust.max_redelegation_count {
                return Err(TrustProviderError::RedelegationDeepnessExceed {
                    length: chain.len(),
                    max_depth: state.config.trust.max_redelegation_count,
                });
            }
            let mut parent_trust: Option<Trust> = None;
            let mut parent_expiration: Option<DateTime<Utc>> = None;
            for delegation in chain.iter().rev() {
                // None of the trusts can specify the redelegation_count > delegation_count of
                // the top level trust
                if let Some(current_redelegation_count) = delegation.redelegation_count
                    && current_redelegation_count > state.config.trust.max_redelegation_count as u32
                {
                    return Err(TrustProviderError::RedelegationDeepnessExceed {
                        length: current_redelegation_count as usize,
                        max_depth: state.config.trust.max_redelegation_count,
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
                        trust.roles, parent_trust.roles,
                    );
                    return Err(TrustProviderError::RedelegatedRolesNotAvailable);
                }
                // Check the impersonation
                if delegation.impersonation && !parent_trust.is_some_and(|x| x.impersonation) {
                    return Err(TrustProviderError::RedelegatedImpersonationNotAllowed);
                }
                parent_trust = Some(delegation.clone());
            }
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

        let trust_provider = TrustService {
            backend_driver: Arc::new(backend),
        };

        let trust: Trust = trust_provider
            .get_trust(&state, "fake_trust")
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

        let trust_provider = TrustService {
            backend_driver: Arc::new(backend),
        };

        let chain = trust_provider
            .get_trust_delegation_chain(&state, "fake_trust")
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

        let trust_provider = TrustService {
            backend_driver: Arc::new(backend),
        };
        let trust = trust_provider
            .get_trust(&state, "fake_trust")
            .await
            .unwrap()
            .expect("trust found");
        trust_provider
            .validate_trust_delegation_chain(&state, &trust)
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

        let trust_provider = TrustService {
            backend_driver: Arc::new(backend),
        };
        let trust = trust_provider
            .get_trust(&state, "redelegated_trust")
            .await
            .unwrap()
            .expect("trust found");
        trust_provider
            .validate_trust_delegation_chain(&state, &trust)
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

        let trust_provider = TrustService {
            backend_driver: Arc::new(backend),
        };
        let trust = trust_provider
            .get_trust(&state, "redelegated_trust2")
            .await
            .unwrap()
            .expect("trust found");
        if let Err(TrustProviderError::ExpirationImpossible) = trust_provider
            .validate_trust_delegation_chain(&state, &trust)
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

        let trust_provider = TrustService {
            backend_driver: Arc::new(backend),
        };
        let trust = trust_provider
            .get_trust(&state, "redelegated_trust")
            .await
            .unwrap()
            .expect("trust found");

        if let Err(TrustProviderError::RedelegatedRolesNotAvailable) = trust_provider
            .validate_trust_delegation_chain(&state, &trust)
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

        let trust_provider = TrustService {
            backend_driver: Arc::new(backend),
        };
        let trust = trust_provider
            .get_trust(&state, "redelegated_trust2")
            .await
            .unwrap()
            .expect("trust found");
        match trust_provider
            .validate_trust_delegation_chain(&state, &trust)
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

        let trust_provider = TrustService {
            backend_driver: Arc::new(backend),
        };
        let trust = trust_provider
            .get_trust(&state, "redelegated_trust2")
            .await
            .unwrap()
            .expect("trust found");
        match trust_provider
            .validate_trust_delegation_chain(&state, &trust)
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
            .get_trust(&state, "redelegated_trust_long")
            .await
            .unwrap()
            .expect("trust found");
        match trust_provider
            .validate_trust_delegation_chain(&state, &trust)
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

        let trust_provider = TrustService {
            backend_driver: Arc::new(backend),
        };

        let list = trust_provider
            .list_trusts(&state, &TrustListParameters::default())
            .await
            .unwrap();
        assert_eq!(list.len(), 2);
    }
}
