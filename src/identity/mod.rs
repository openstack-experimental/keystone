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
//! project. OpenStackClient
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
use uuid::Uuid;
use validator::Validate;

pub mod backends;
pub mod error;
#[cfg(test)]
pub mod mock;
pub mod types;
#[cfg(test)]
pub use mock::MockIdentityProvider;

use crate::auth::AuthenticatedInfo;
use crate::config::Config;
use crate::identity::backends::{IdentityBackend, sql::SqlBackend};
use crate::identity::error::IdentityProviderError;
use crate::identity::types::{
    Group, GroupCreate, GroupListParameters, UserCreate, UserListParameters,
    UserPasswordAuthRequest, UserResponse,
};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;
use crate::resource::{ResourceApi, error::ResourceProviderError};

pub use types::IdentityApi;

#[derive(Clone, Debug)]
pub struct IdentityProvider {
    backend_driver: Box<dyn IdentityBackend>,
}

impl IdentityProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, IdentityProviderError> {
        let mut backend_driver = if let Some(driver) =
            plugin_manager.get_identity_backend(config.identity.driver.clone())
        {
            driver.clone()
        } else {
            match config.identity.driver.as_str() {
                "sql" => Box::new(SqlBackend::default()),
                _ => {
                    return Err(IdentityProviderError::UnsupportedDriver(
                        config.identity.driver.clone(),
                    ));
                }
            }
        };
        backend_driver.set_config(config.clone());
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl IdentityApi for IdentityProvider {
    /// Authenticate user with the password auth method
    #[tracing::instrument(level = "info", skip(self, state, auth))]
    async fn authenticate_by_password(
        &self,
        state: &ServiceState,
        auth: &UserPasswordAuthRequest,
    ) -> Result<AuthenticatedInfo, IdentityProviderError> {
        let mut auth = auth.clone();
        if auth.id.is_none() {
            if auth.name.is_none() {
                return Err(IdentityProviderError::UserIdOrNameWithDomain);
            }

            if let Some(ref mut domain) = auth.domain {
                if let Some(dname) = &domain.name {
                    let d = state
                        .provider
                        .get_resource_provider()
                        .find_domain_by_name(state, dname)
                        .await?
                        .ok_or(ResourceProviderError::DomainNotFound(dname.clone()))?;
                    domain.id = Some(d.id);
                } else if domain.id.is_none() {
                    return Err(IdentityProviderError::UserIdOrNameWithDomain);
                }
            } else {
                return Err(IdentityProviderError::UserIdOrNameWithDomain);
            }
        }

        self.backend_driver
            .authenticate_by_password(state, &auth)
            .await
    }

    /// List users
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_users(
        &self,
        state: &ServiceState,
        params: &UserListParameters,
    ) -> Result<impl IntoIterator<Item = UserResponse>, IdentityProviderError> {
        self.backend_driver.list_users(state, params).await
    }

    /// Get single user
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        self.backend_driver.get_user(state, user_id).await
    }

    /// Find federated user by IDP and Unique ID
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn find_federated_user<'a>(
        &self,
        state: &ServiceState,
        idp_id: &'a str,
        unique_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        self.backend_driver
            .find_federated_user(state, idp_id, unique_id)
            .await
    }

    /// Create user
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_user(
        &self,
        state: &ServiceState,
        user: UserCreate,
    ) -> Result<UserResponse, IdentityProviderError> {
        let mut mod_user = user;
        if mod_user.id.is_none() {
            mod_user.id = Some(Uuid::new_v4().simple().to_string());
        }
        if mod_user.enabled.is_none() {
            mod_user.enabled = Some(true);
        }
        mod_user.validate()?;
        self.backend_driver.create_user(state, mod_user).await
    }

    /// Delete user
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn delete_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver.delete_user(state, user_id).await
    }

    /// List groups
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_groups(
        &self,
        state: &ServiceState,
        params: &GroupListParameters,
    ) -> Result<impl IntoIterator<Item = Group>, IdentityProviderError> {
        self.backend_driver.list_groups(state, params).await
    }

    /// Get single group
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<Option<Group>, IdentityProviderError> {
        self.backend_driver.get_group(state, group_id).await
    }

    /// Create group
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_group(
        &self,
        state: &ServiceState,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError> {
        let mut res = group;
        res.id = Some(Uuid::new_v4().simple().to_string());
        self.backend_driver.create_group(state, res).await
    }

    /// Delete group
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn delete_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver.delete_group(state, group_id).await
    }

    /// List groups a user is a member of.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_groups_of_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<impl IntoIterator<Item = Group>, IdentityProviderError> {
        self.backend_driver
            .list_groups_of_user(state, user_id)
            .await
    }

    #[tracing::instrument(level = "info", skip(self, state))]
    async fn add_user_to_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver
            .add_user_to_group(state, user_id, group_id)
            .await
    }

    #[tracing::instrument(level = "info", skip(self, state))]
    async fn add_user_to_group_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver
            .add_user_to_group_expiring(state, user_id, group_id, idp_id)
            .await
    }

    #[tracing::instrument(level = "info", skip(self, state))]
    async fn add_users_to_groups<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver
            .add_users_to_groups(state, memberships)
            .await
    }

    #[tracing::instrument(level = "info", skip(self, state))]
    async fn add_users_to_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver
            .add_users_to_groups_expiring(state, memberships, idp_id)
            .await
    }

    #[tracing::instrument(level = "info", skip(self, state))]
    async fn remove_user_from_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver
            .remove_user_from_group(state, user_id, group_id)
            .await
    }

    #[tracing::instrument(level = "info", skip(self, state))]
    async fn remove_user_from_group_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver
            .remove_user_from_group_expiring(state, user_id, group_id, idp_id)
            .await
    }

    #[tracing::instrument(level = "info", skip(self, state))]
    async fn remove_user_from_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver
            .remove_user_from_groups(state, user_id, group_ids)
            .await
    }

    #[tracing::instrument(level = "info", skip(self, state))]
    async fn remove_user_from_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver
            .remove_user_from_groups_expiring(state, user_id, group_ids, idp_id)
            .await
    }

    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn set_user_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver
            .set_user_groups(state, user_id, group_ids)
            .await
    }

    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn set_user_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
        idp_id: &'a str,
        last_verified: Option<&'a DateTime<Utc>>,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver
            .set_user_groups_expiring(state, user_id, group_ids, idp_id, last_verified)
            .await
    }
}
