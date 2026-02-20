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
//!
//! Trusts.
//!
//! A trust represents a user's (the trustor) authorization to delegate roles to
//! another user (the trustee), and optionally allow the trustee to impersonate
//! the trustor. After the trustor has created a trust, the trustee can specify
//! the trust's id attribute as part of an authentication request to then create
//! a token representing the delegated authority of the trustor.
//!
//! The trust contains constraints on the delegated attributes. A token created
//! based on a trust will convey a subset of the trustor's roles on the
//! specified project. Optionally, the trust may only be valid for a specified
//! time period, as defined by expires_at. If no expires_at is specified, then
//! the trust is valid until it is explicitly revoked.
//!
//! The impersonation flag allows the trustor to optionally delegate
//! impersonation abilities to the trustee. To services validating the token,
//! the trustee will appear as the trustor, although the token will also contain
//! the impersonation flag to indicate that this behavior is in effect.
//!
//! A project_id may not be specified without at least one role, and vice versa.
//! In other words, there is no way of implicitly delegating all roles to a
//! trustee, in order to prevent users accidentally creating trust that are much
//! more broad in scope than intended. A trust without a project_id or any
//! delegated roles is unscoped, and therefore does not represent authorization
//! on a specific resource.
//!
//! Trusts are immutable. If the trustee or trustor wishes to modify the
//! attributes of the trust, they should create a new trust and delete the old
//! trust. If a trust is deleted, any tokens generated based on the trust are
//! immediately revoked.
//!
//! If the trustor loses access to any delegated attributes, the trust becomes
//! immediately invalid and any tokens generated based on the trust are
//! immediately revoked.
//!
//! Trusts can also be chained, meaning, a trust can be created by using a trust
//! scoped token.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::hash::RandomState;
use std::sync::Arc;
use tracing::debug;

pub mod api;
pub mod backend;
pub mod error;
#[cfg(test)]
mod mock;
pub mod types;

use crate::config::Config;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;
use backend::{SqlBackend, TrustBackend};

pub use error::TrustProviderError;
#[cfg(test)]
pub use mock::MockTrustProvider;
pub use types::*;

/// Trust provider.
pub struct TrustProvider {
    /// Backend driver.
    backend_driver: Arc<dyn TrustBackend>,
}

impl TrustProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, TrustProviderError> {
        let backend_driver =
            if let Some(driver) = plugin_manager.get_trust_backend(config.trust.driver.clone()) {
                driver.clone()
            } else {
                match config.trust.driver.as_str() {
                    "sql" => Arc::new(SqlBackend::default()),
                    _ => {
                        return Err(TrustProviderError::UnsupportedDriver(
                            config.trust.driver.clone(),
                        ));
                    }
                }
            };
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl TrustApi for TrustProvider {
    /// Get trust by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_trust<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Trust>, TrustProviderError> {
        self.backend_driver.get_trust(state, id).await
    }

    /// Resolve trust delegation chain by the trust ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
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
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_trusts(
        &self,
        state: &ServiceState,
        params: &TrustListParameters,
    ) -> Result<Vec<Trust>, TrustProviderError> {
        self.backend_driver.list_trusts(state, params).await
    }

    /// Validate trust delegation chain.
    ///
    /// - redelegation deepness cannot exceed the global limit.
    /// - redelegated trusts must not specify use limit.
    /// - validate redelegated trust expiration is not later than of the
    ///   original.
    /// - redelegated trust must not add new roles.
    #[tracing::instrument(level = "debug", skip(self, state))]
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
    use sea_orm::DatabaseConnection;
    use std::sync::Arc;

    use super::backend::MockTrustBackend;
    use super::*;
    use crate::config::Config;
    use crate::keystone::Service;
    use crate::policy::MockPolicyFactory;
    use crate::provider::Provider;
    use crate::role::types::Role;

    fn get_state_mock() -> Arc<Service> {
        Arc::new(
            Service::new(
                Config::default(),
                DatabaseConnection::Disconnected,
                Provider::mocked_builder().build().unwrap(),
                MockPolicyFactory::default(),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn test_get_trust() {
        let state = get_state_mock();

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

        let trust_provider = TrustProvider {
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
        let state = get_state_mock();

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

        let trust_provider = TrustProvider {
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
        let state = get_state_mock();

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

        let trust_provider = TrustProvider {
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
        let state = get_state_mock();
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

        let trust_provider = TrustProvider {
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
        let state = get_state_mock();
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

        let trust_provider = TrustProvider {
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
        let state = get_state_mock();
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
                            Role {
                                id: "rid1".into(),
                                ..Default::default()
                            },
                            Role {
                                id: "rid2".into(),
                                ..Default::default()
                            },
                        ]),
                        ..Default::default()
                    },
                    Trust {
                        id: "trust_id".into(),
                        roles: Some(vec![Role {
                            id: "rid1".into(),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                ]))
            });

        let trust_provider = TrustProvider {
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
        let state = get_state_mock();
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

        let trust_provider = TrustProvider {
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
        let state = get_state_mock();
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

        let trust_provider = TrustProvider {
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
        let state = get_state_mock();

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

        let trust_provider = TrustProvider {
            backend_driver: Arc::new(backend),
        };

        let list = trust_provider
            .list_trusts(&state, &TrustListParameters::default())
            .await
            .unwrap();
        assert_eq!(list.len(), 2);
    }
}
