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
//! # OpenStack Keystone SQL driver for the identity provider
use std::collections::HashSet;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{DatabaseConnection, Schema, sea_query::Index};

use openstack_keystone_core::auth::AuthenticatedInfo;
use openstack_keystone_core::identity::IdentityProviderError;
use openstack_keystone_core::identity::backend::IdentityBackend;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::{
    SqlDriver, SqlDriverRegistration,
    db::{create_index, create_table},
    error::DatabaseError,
};
use openstack_keystone_core_types::identity::*;

mod authenticate;
pub mod entity;
mod federated_user;
mod group;
mod local_user;
mod nonlocal_user;
mod password;
mod service_account;
mod user;
mod user_group;
mod user_option;

#[derive(Default)]
pub struct SqlBackend {}

// Submit the plugin to the registry at compile-time
static PLUGIN: SqlBackend = SqlBackend {};
inventory::submit! {
    SqlDriverRegistration { driver: &PLUGIN }
}

#[async_trait]
impl IdentityBackend for SqlBackend {
    /// Add the user into the group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_id`: The ID of the group.
    ///
    /// # Returns
    /// A `Result` containing `()` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn add_user_to_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::add_user_to_group(&state.db, user_id, group_id).await?)
    }

    /// Add the user to the group with expiration.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_id`: The ID of the group.
    /// - `idp_id`: The ID of the identity provider.
    ///
    /// # Returns
    /// A `Result` containing `()` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn add_user_to_group_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(
            user_group::add_user_to_group_expiring(&state.db, user_id, group_id, idp_id, None)
                .await?,
        )
    }

    /// Add user group membership relations.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `memberships`: A list of user and group ID pairs.
    ///
    /// # Returns
    /// A `Result` containing `()` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn add_users_to_groups<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::add_users_to_groups(&state.db, memberships).await?)
    }

    /// Add expiring user group membership relations.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `memberships`: A list of user and group ID pairs.
    /// - `idp_id`: The ID of the identity provider.
    ///
    /// # Returns
    /// A `Result` containing `()` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn add_users_to_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::add_users_to_groups_expiring(&state.db, memberships, idp_id, None).await?)
    }

    /// Authenticate a user by a password.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `auth`: The authentication request.
    ///
    /// # Returns
    /// A `Result` containing `AuthenticatedInfo` if successful, or an `Error`.
    async fn authenticate_by_password(
        &self,
        state: &ServiceState,
        auth: &UserPasswordAuthRequest,
    ) -> Result<AuthenticatedInfo, IdentityProviderError> {
        let config = state.config_manager.config.read().await;
        Ok(authenticate::authenticate_by_password(&config, &state.db, auth).await?)
    }

    /// Create group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group`: The group creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Group` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn create_group(
        &self,
        state: &ServiceState,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError> {
        Ok(group::create(&state.db, group).await?)
    }

    /// Create service account.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `sa`: The service account creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `ServiceAccount` if successful, or an
    /// `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn create_service_account(
        &self,
        state: &ServiceState,
        sa: ServiceAccountCreate,
    ) -> Result<ServiceAccount, IdentityProviderError> {
        let config = state.config_manager.config.read().await;
        Ok(service_account::create(&config, &state.db, sa, None).await?)
    }

    /// Create user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user`: The user creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the `UserResponse` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn create_user(
        &self,
        state: &ServiceState,
        user: UserCreate,
    ) -> Result<UserResponse, IdentityProviderError> {
        let config = state.config_manager.config.read().await;
        Ok(user::create(&config, &state.db, user).await?)
    }

    /// Delete group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group_id`: The ID of the group to delete.
    ///
    /// # Returns
    /// A `Result` containing `()` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn delete_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(group::delete(&state.db, group_id).await?)
    }

    /// Delete user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user to delete.
    ///
    /// # Returns
    /// A `Result` containing `()` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn delete_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user::delete(&state.db, user_id).await?)
    }

    /// Get single group by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group_id`: The ID of the group to retrieve.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Group` if found, or an
    /// `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn get_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<Option<Group>, IdentityProviderError> {
        Ok(group::get(&state.db, group_id).await?)
    }

    /// Get single service account by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `ServiceAccount` if found, or
    /// an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn get_service_account<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<ServiceAccount>, IdentityProviderError> {
        let config = state.config_manager.config.read().await;
        Ok(service_account::get(&config, &state.db, user_id).await?)
    }

    /// Get single user by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user to retrieve.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `UserResponse` if found, or
    /// an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn get_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        let config = state.config_manager.config.read().await;
        Ok(user::get(&config, &state.db, user_id).await?)
    }

    /// Get single user by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    ///
    /// # Returns
    /// A `Result` containing the domain ID of the user, or an `Error`.
    async fn get_user_domain_id<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<String, IdentityProviderError> {
        Ok(user::get_user_domain_id(&state.db, user_id).await?)
    }

    /// Find federated user by IDP and Unique ID
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `idp_id`: The ID of the identity provider.
    /// - `unique_id`: The unique ID of the federated user.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `UserResponse` if found, or
    /// an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn find_federated_user<'a>(
        &self,
        state: &ServiceState,
        idp_id: &'a str,
        unique_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        if let Some(federated_user) =
            federated_user::find_by_idp_and_unique_id(&state.db, idp_id, unique_id).await?
        {
            let config = state.config_manager.config.read().await;
            return user::get(&config, &state.db, &federated_user.user_id).await;
        }
        Ok(None)
    }

    /// List groups
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The parameters for listing groups.
    ///
    /// # Returns
    /// A `Result` containing a list of `Group`s, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn list_groups(
        &self,
        state: &ServiceState,
        params: &GroupListParameters,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        Ok(group::list(&state.db, params).await?)
    }

    /// List groups a user is member of.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    ///
    /// # Returns
    /// A `Result` containing a list of `Group`s, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn list_groups_of_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        let cutoff_time = state
            .config_manager
            .config
            .read()
            .await
            .federation
            .get_expiring_user_group_membership_cutof_datetime();
        Ok(user_group::list_user_groups(&state.db, user_id, &cutoff_time).await?)
    }

    /// Fetch users from the database.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The parameters for listing users.
    ///
    /// # Returns
    /// A `Result` containing a list of `UserResponse`s, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn list_users(
        &self,
        state: &ServiceState,
        params: &UserListParameters,
    ) -> Result<Vec<UserResponse>, IdentityProviderError> {
        let config = state.config_manager.config.read().await;
        Ok(user::list(&config, &state.db, params).await?)
    }

    /// Remove the user from the group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_id`: The ID of the group.
    ///
    /// # Returns
    /// A `Result` containing `()` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn remove_user_from_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::remove_user_from_group(&state.db, user_id, group_id).await?)
    }

    /// Remove the user from the group with expiration.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_id`: The ID of the group.
    /// - `idp_id`: The ID of the identity provider.
    ///
    /// # Returns
    /// A `Result` containing `()` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn remove_user_from_group_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(
            user_group::remove_user_from_group_expiring(&state.db, user_id, group_id, idp_id)
                .await?,
        )
    }

    /// Remove the user from multiple groups.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_ids`: A set of group IDs to remove.
    ///
    /// # Returns
    /// A `Result` containing `()` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn remove_user_from_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::remove_user_from_groups(&state.db, user_id, group_ids).await?)
    }

    /// Remove the user from multiple expiring groups.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_ids`: A set of group IDs to remove.
    /// - `idp_id`: The ID of the identity provider.
    ///
    /// # Returns
    /// A `Result` containing `()` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn remove_user_from_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(
            user_group::remove_user_from_groups_expiring(&state.db, user_id, group_ids, idp_id)
                .await?,
        )
    }

    /// Set group memberships of the user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_ids`: A set of group IDs to set.
    ///
    /// # Returns
    /// A `Result` containing `()` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn set_user_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::set_user_groups(&state.db, user_id, group_ids).await?)
    }

    /// Set expiring group memberships for the user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_ids`: A set of group IDs to set.
    /// - `idp_id`: The ID of the identity provider.
    /// - `last_verified`: The last verification datetime.
    ///
    /// # Returns
    /// A `Result` containing `()` if successful, or an `Error`.
    #[tracing::instrument(skip(self, state))]
    async fn set_user_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
        idp_id: &'a str,
        last_verified: Option<&'a DateTime<Utc>>,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::set_user_groups_expiring(
            &state.db,
            user_id,
            group_ids,
            idp_id,
            last_verified,
        )
        .await?)
    }
}

#[async_trait]
impl SqlDriver for SqlBackend {
    /// Set up the database tables and indices.
    ///
    /// # Parameters
    /// - `connection`: The database connection.
    /// - `schema`: The database schema.
    ///
    /// # Returns
    /// A `Result` containing `()` if successful, or an `Error`.
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(connection, schema, crate::entity::prelude::User).await?;
        create_index(
            connection,
            Index::create()
                .name("ixu_user_id_domain_id")
                .table(crate::entity::prelude::User)
                .col(crate::entity::user::Column::Id)
                .col(crate::entity::user::Column::DomainId)
                .unique()
                .to_owned(),
        )
        .await?;
        create_table(connection, schema, crate::entity::prelude::UserOption).await?;
        create_table(connection, schema, crate::entity::prelude::LocalUser).await?;
        create_table(connection, schema, crate::entity::prelude::Password).await?;
        create_table(connection, schema, crate::entity::prelude::NonlocalUser).await?;
        create_table(connection, schema, crate::entity::prelude::FederatedUser).await?;
        create_table(connection, schema, crate::entity::prelude::Group).await?;
        create_table(
            connection,
            schema,
            crate::entity::prelude::UserGroupMembership,
        )
        .await?;
        create_table(
            connection,
            schema,
            crate::entity::prelude::ExpiringUserGroupMembership,
        )
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {}
