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

//! # Identity provider
//!
//! Following identity concepts are covered by the identity provider:
//!
//! ## Group
//!
//! An Identity service API v3 entity. Groups are a collection of users
//! owned by a domain. A group role, granted to a domain or project, applies to
//! all users in the group. Adding or removing users to or from a group grants
//! or revokes their role and authentication to the associated domain or
//! project.
//!
//! ## User
//!
//! A digital representation of a person, system, or service that uses
//! OpenStack cloud services. The Identity service validates that incoming
//! requests are made by the user who claims to be making the call. Users have a
//! login and can access resources by using assigned tokens. Users can be
//! directly assigned to a particular project and behave as if they are
//! contained in that project.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashSet;

pub mod backend;
pub mod error;
#[cfg(any(test, feature = "mock"))]
pub mod mock;
pub mod types;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockIdentityProvider;
pub mod service;

use crate::auth::AuthenticatedInfo;
use crate::config::Config;
use crate::identity::types::*;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use service::IdentityService;

pub use error::IdentityProviderError;
pub use types::IdentityApi;

/// Identity provider.
pub enum IdentityProvider {
    Service(IdentityService),
    #[cfg(any(test, feature = "mock"))]
    Mock(MockIdentityProvider),
}

impl IdentityProvider {
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, IdentityProviderError> {
        Ok(Self::Service(IdentityService::new(config, plugin_manager)?))
    }
}

#[async_trait]
impl IdentityApi for IdentityProvider {
    #[tracing::instrument(skip(self, state))]
    async fn add_user_to_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.add_user_to_group(state, user_id, group_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.add_user_to_group(state, user_id, group_id).await,
        }
    }

    #[tracing::instrument(skip(self, state))]
    async fn add_user_to_group_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        match self {
            Self::Service(provider) => {
                provider
                    .add_user_to_group_expiring(state, user_id, group_id, idp_id)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .add_user_to_group_expiring(state, user_id, group_id, idp_id)
                    .await
            }
        }
    }

    #[tracing::instrument(skip(self, state))]
    async fn add_users_to_groups<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
    ) -> Result<(), IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.add_users_to_groups(state, memberships).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.add_users_to_groups(state, memberships).await,
        }
    }

    #[tracing::instrument(skip(self, state))]
    async fn add_users_to_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        match self {
            Self::Service(provider) => {
                provider
                    .add_users_to_groups_expiring(state, memberships, idp_id)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .add_users_to_groups_expiring(state, memberships, idp_id)
                    .await
            }
        }
    }

    /// Authenticate user with the password auth method.
    #[tracing::instrument(skip(self, state, auth))]
    async fn authenticate_by_password(
        &self,
        state: &ServiceState,
        auth: &UserPasswordAuthRequest,
    ) -> Result<AuthenticatedInfo, IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.authenticate_by_password(state, auth).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.authenticate_by_password(state, auth).await,
        }
    }

    /// Create group.
    #[tracing::instrument(skip(self, state))]
    async fn create_group(
        &self,
        state: &ServiceState,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.create_group(state, group).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_group(state, group).await,
        }
    }

    /// Create service account.
    #[tracing::instrument(skip(self, state))]
    async fn create_service_account(
        &self,
        state: &ServiceState,
        sa: ServiceAccountCreate,
    ) -> Result<ServiceAccount, IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.create_service_account(state, sa).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_service_account(state, sa).await,
        }
    }

    /// Create user.
    #[tracing::instrument(skip(self, state))]
    async fn create_user(
        &self,
        state: &ServiceState,
        user: UserCreate,
    ) -> Result<UserResponse, IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.create_user(state, user).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.create_user(state, user).await,
        }
    }

    /// Delete group.
    #[tracing::instrument(skip(self, state))]
    async fn delete_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.delete_group(state, group_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_group(state, group_id).await,
        }
    }

    /// Delete user.
    #[tracing::instrument(skip(self, state))]
    async fn delete_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.delete_user(state, user_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.delete_user(state, user_id).await,
        }
    }

    /// Get a service account by ID.
    #[tracing::instrument(skip(self, state))]
    async fn get_service_account<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<ServiceAccount>, IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.get_service_account(state, user_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_service_account(state, user_id).await,
        }
    }

    /// Get single user.
    #[tracing::instrument(skip(self, state))]
    async fn get_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.get_user(state, user_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_user(state, user_id).await,
        }
    }

    /// Get `domain_id` of a user.
    ///
    /// When the caching is enabled check for the cached value there. When no
    /// data is present for the key - invoke the backend driver and place
    /// the new value into the cache. Other operations (`get_user`,
    /// `delete_user`) update the cache with `delete_user` purging the value
    /// from the cache.
    async fn get_user_domain_id<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<String, IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.get_user_domain_id(state, user_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_user_domain_id(state, user_id).await,
        }
    }

    /// Find federated user by `idp_id` and `unique_id`.
    #[tracing::instrument(skip(self, state))]
    async fn find_federated_user<'a>(
        &self,
        state: &ServiceState,
        idp_id: &'a str,
        unique_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.find_federated_user(state, idp_id, unique_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.find_federated_user(state, idp_id, unique_id).await,
        }
    }

    /// List users.
    #[tracing::instrument(skip(self, state))]
    async fn list_users(
        &self,
        state: &ServiceState,
        params: &UserListParameters,
    ) -> Result<Vec<UserResponse>, IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.list_users(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_users(state, params).await,
        }
    }

    /// List groups.
    #[tracing::instrument(skip(self, state))]
    async fn list_groups(
        &self,
        state: &ServiceState,
        params: &GroupListParameters,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.list_groups(state, params).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_groups(state, params).await,
        }
    }

    /// Get single group.
    #[tracing::instrument(skip(self, state))]
    async fn get_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<Option<Group>, IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.get_group(state, group_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.get_group(state, group_id).await,
        }
    }

    /// List groups a user is a member of.
    #[tracing::instrument(skip(self, state))]
    async fn list_groups_of_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.list_groups_of_user(state, user_id).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.list_groups_of_user(state, user_id).await,
        }
    }

    #[tracing::instrument(skip(self, state))]
    async fn remove_user_from_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        match self {
            Self::Service(provider) => {
                provider
                    .remove_user_from_group(state, user_id, group_id)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .remove_user_from_group(state, user_id, group_id)
                    .await
            }
        }
    }

    #[tracing::instrument(skip(self, state))]
    async fn remove_user_from_group_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        match self {
            Self::Service(provider) => {
                provider
                    .remove_user_from_group_expiring(state, user_id, group_id, idp_id)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .remove_user_from_group_expiring(state, user_id, group_id, idp_id)
                    .await
            }
        }
    }

    #[tracing::instrument(skip(self, state))]
    async fn remove_user_from_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        match self {
            Self::Service(provider) => {
                provider
                    .remove_user_from_groups(state, user_id, group_ids)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .remove_user_from_groups(state, user_id, group_ids)
                    .await
            }
        }
    }

    #[tracing::instrument(skip(self, state))]
    async fn remove_user_from_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        match self {
            Self::Service(provider) => {
                provider
                    .remove_user_from_groups_expiring(state, user_id, group_ids, idp_id)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .remove_user_from_groups_expiring(state, user_id, group_ids, idp_id)
                    .await
            }
        }
    }

    #[tracing::instrument(skip(self, state))]
    async fn set_user_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        match self {
            Self::Service(provider) => provider.set_user_groups(state, user_id, group_ids).await,
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => provider.set_user_groups(state, user_id, group_ids).await,
        }
    }

    #[tracing::instrument(skip(self, state))]
    async fn set_user_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
        idp_id: &'a str,
        last_verified: Option<&'a DateTime<Utc>>,
    ) -> Result<(), IdentityProviderError> {
        match self {
            Self::Service(provider) => {
                provider
                    .set_user_groups_expiring(state, user_id, group_ids, idp_id, last_verified)
                    .await
            }
            #[cfg(any(test, feature = "mock"))]
            Self::Mock(provider) => {
                provider
                    .set_user_groups_expiring(state, user_id, group_ids, idp_id, last_verified)
                    .await
            }
        }
    }
}
