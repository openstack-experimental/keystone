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
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use validator::Validate;

pub mod backend;
pub mod error;
#[cfg(test)]
pub mod mock;
pub mod types;
#[cfg(test)]
pub use mock::MockIdentityProvider;

use crate::auth::AuthenticatedInfo;
use crate::config::Config;
use crate::identity::backend::{IdentityBackend, sql::SqlBackend};
use crate::identity::error::IdentityProviderError;
use crate::identity::types::{
    Group, GroupCreate, GroupListParameters, UserCreate, UserListParameters,
    UserPasswordAuthRequest, UserResponse,
};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;
use crate::resource::{ResourceApi, error::ResourceProviderError};

pub use types::IdentityApi;

/// Identity provider.
pub struct IdentityProvider {
    backend_driver: Arc<dyn IdentityBackend>,
    /// Caching flag. When enabled certain data can be cached (i.e. `domain_id`
    /// by `user_id`).
    caching: bool,
    /// Internal cache of `user_id` to `domain_id` mappings. This information if
    /// fully static and can never change (well, except with a direct SQL
    /// update).
    user_id_domain_id_cache: RwLock<HashMap<String, String>>,
}

impl IdentityProvider {
    pub fn new(
        config: &Config,
        plugin_manager: &PluginManager,
    ) -> Result<Self, IdentityProviderError> {
        let backend_driver = if let Some(driver) =
            plugin_manager.get_identity_backend(config.identity.driver.clone())
        {
            driver.clone()
        } else {
            match config.identity.driver.as_str() {
                "sql" => Arc::new(SqlBackend::default()),
                _ => {
                    return Err(IdentityProviderError::UnsupportedDriver(
                        config.identity.driver.clone(),
                    ));
                }
            }
        };
        Ok(Self {
            backend_driver,
            caching: config.identity.caching,
            user_id_domain_id_cache: HashMap::new().into(),
        })
    }

    pub fn from_driver<I: IdentityBackend + 'static>(driver: I) -> Self {
        Self {
            backend_driver: Arc::new(driver),
            caching: false,
            user_id_domain_id_cache: HashMap::new().into(),
        }
    }
}

#[async_trait]
impl IdentityApi for IdentityProvider {
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

    /// Authenticate user with the password auth method.
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

    /// Create user.
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

    /// Delete group.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn delete_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver.delete_group(state, group_id).await
    }

    /// Delete user.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn delete_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        self.backend_driver.delete_user(state, user_id).await?;
        if self.caching {
            self.user_id_domain_id_cache.write().await.remove(user_id);
        }
        Ok(())
    }

    /// Get single user.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        let user = self.backend_driver.get_user(state, user_id).await?;
        if self.caching
            && let Some(user) = &user
        {
            self.user_id_domain_id_cache
                .write()
                .await
                .insert(user_id.to_string(), user.domain_id.clone());
        }
        Ok(user)
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
    ) -> Result<Option<String>, IdentityProviderError> {
        if self.caching {
            if let Some(domain_id) = self.user_id_domain_id_cache.read().await.get(user_id) {
                return Ok(Some(domain_id.clone()));
            } else {
                let domain_id = self
                    .backend_driver
                    .get_user_domain_id(state, user_id)
                    .await?;
                if let Some(did) = &domain_id {
                    self.user_id_domain_id_cache
                        .write()
                        .await
                        .insert(user_id.to_string(), did.clone());
                }
                return Ok(domain_id);
            }
        } else {
            Ok(self
                .backend_driver
                .get_user_domain_id(state, user_id)
                .await?)
        }
    }

    /// Find federated user by `idp_id` and `unique_id`.
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

    /// List users.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_users(
        &self,
        state: &ServiceState,
        params: &UserListParameters,
    ) -> Result<impl IntoIterator<Item = UserResponse>, IdentityProviderError> {
        self.backend_driver.list_users(state, params).await
    }

    /// List groups.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn list_groups(
        &self,
        state: &ServiceState,
        params: &GroupListParameters,
    ) -> Result<impl IntoIterator<Item = Group>, IdentityProviderError> {
        self.backend_driver.list_groups(state, params).await
    }

    /// Get single group.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn get_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<Option<Group>, IdentityProviderError> {
        self.backend_driver.get_group(state, group_id).await
    }

    /// Create group.
    #[tracing::instrument(level = "info", skip(self, state))]
    async fn create_group(
        &self,
        state: &ServiceState,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError> {
        let mut res = group;
        if res.id.is_none() {
            res.id = Some(Uuid::new_v4().simple().to_string());
        }
        self.backend_driver.create_group(state, res).await
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

#[cfg(test)]
mod tests {
    use super::backend::MockIdentityBackend;
    use super::types::user::UserCreateBuilder;
    use super::*;
    use crate::tests::get_state_mock;

    #[tokio::test]
    async fn test_create_user() {
        let state = get_state_mock();
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_create_user()
            .returning(|_, _| Ok(UserResponse::default()));
        let provider = IdentityProvider::from_driver(backend);

        assert_eq!(
            provider
                .create_user(
                    &state,
                    UserCreateBuilder::default()
                        .name("uname")
                        .domain_id("did")
                        .build()
                        .unwrap()
                )
                .await
                .unwrap(),
            UserResponse::default()
        );
    }

    #[tokio::test]
    async fn test_get_user() {
        let state = get_state_mock();
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_get_user()
            .withf(|_, uid: &'_ str| uid == "uid")
            .returning(|_, _| Ok(Some(UserResponse::default())));
        let provider = IdentityProvider::from_driver(backend);

        assert_eq!(
            provider
                .get_user(&state, "uid")
                .await
                .unwrap()
                .expect("user should be there"),
            UserResponse::default()
        );
    }

    #[tokio::test]
    async fn test_get_user_domain_id() {
        let state = get_state_mock();
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_get_user_domain_id()
            .withf(|_, uid: &'_ str| uid == "uid")
            .times(2) // only 2 times
            .returning(|_, _| Ok(Some("did".into())));
        backend
            .expect_get_user_domain_id()
            .withf(|_, uid: &'_ str| uid == "missing")
            .returning(|_, _| Ok(None));
        let mut provider = IdentityProvider::from_driver(backend);
        provider.caching = true;

        assert_eq!(
            provider
                .get_user_domain_id(&state, "uid")
                .await
                .unwrap()
                .expect("domain_id should be there"),
            "did"
        );
        assert_eq!(
            provider
                .get_user_domain_id(&state, "uid")
                .await
                .unwrap()
                .expect("domain_id should be there"),
            "did",
            "second time data extracted from cache"
        );
        assert!(
            provider
                .get_user_domain_id(&state, "missing")
                .await
                .unwrap()
                .is_none()
        );
        provider.caching = false;
        assert_eq!(
            provider
                .get_user_domain_id(&state, "uid")
                .await
                .unwrap()
                .expect("domain_id should be there"),
            "did",
            "third time backend is again triggered causing total of 2 invocations"
        );
    }

    #[tokio::test]
    async fn test_delete_user() {
        let state = get_state_mock();
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_delete_user()
            .withf(|_, uid: &'_ str| uid == "uid")
            .returning(|_, _| Ok(()));
        let provider = IdentityProvider::from_driver(backend);

        assert!(provider.delete_user(&state, "uid").await.is_ok());
    }
}
