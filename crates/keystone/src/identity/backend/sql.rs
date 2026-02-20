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

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashSet;

mod authenticate;
mod federated_user;
mod group;
mod local_user;
mod nonlocal_user;
mod password;
mod service_account;
mod user;
mod user_group;
mod user_option;

use super::super::types::*;
use crate::auth::AuthenticatedInfo;
use crate::identity::IdentityProviderError;
use crate::identity::backend::IdentityBackend;
use crate::keystone::ServiceState;

#[derive(Default)]
pub struct SqlBackend {}

#[async_trait]
impl IdentityBackend for SqlBackend {
    /// Add the user into the group.
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
    #[tracing::instrument(skip(self, state))]
    async fn add_users_to_groups<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::add_users_to_groups(&state.db, memberships).await?)
    }

    /// Add expiring user group membership relations.
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
    async fn authenticate_by_password(
        &self,
        state: &ServiceState,
        auth: &UserPasswordAuthRequest,
    ) -> Result<AuthenticatedInfo, IdentityProviderError> {
        Ok(authenticate::authenticate_by_password(&state.config, &state.db, auth).await?)
    }

    /// Create group.
    #[tracing::instrument(skip(self, state))]
    async fn create_group(
        &self,
        state: &ServiceState,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError> {
        Ok(group::create(&state.db, group).await?)
    }

    /// Create service account.
    #[tracing::instrument(skip(self, state))]
    async fn create_service_account(
        &self,
        state: &ServiceState,
        sa: ServiceAccountCreate,
    ) -> Result<ServiceAccount, IdentityProviderError> {
        Ok(service_account::create(&state.config, &state.db, sa, None).await?)
    }

    /// Create user.
    #[tracing::instrument(skip(self, state))]
    async fn create_user(
        &self,
        state: &ServiceState,
        user: UserCreate,
    ) -> Result<UserResponse, IdentityProviderError> {
        Ok(user::create(&state.config, &state.db, user).await?)
    }

    /// Delete group.
    #[tracing::instrument(skip(self, state))]
    async fn delete_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(group::delete(&state.db, group_id).await?)
    }

    /// Delete user.
    #[tracing::instrument(skip(self, state))]
    async fn delete_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user::delete(&state.db, user_id).await?)
    }

    /// Get single group by ID.
    #[tracing::instrument(skip(self, state))]
    async fn get_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<Option<Group>, IdentityProviderError> {
        Ok(group::get(&state.db, group_id).await?)
    }

    /// Get single service account by ID.
    #[tracing::instrument(skip(self, state))]
    async fn get_service_account<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<ServiceAccount>, IdentityProviderError> {
        Ok(service_account::get(&state.config, &state.db, user_id).await?)
    }

    /// Get single user by ID.
    #[tracing::instrument(skip(self, state))]
    async fn get_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        Ok(user::get(&state.config, &state.db, user_id).await?)
    }

    /// Get single user by ID.
    async fn get_user_domain_id<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<String, IdentityProviderError> {
        Ok(user::get_user_domain_id(&state.db, user_id).await?)
    }

    /// Find federated user by IDP and Unique ID
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
            return Ok(user::get(&state.config, &state.db, &federated_user.user_id).await?);
        }
        Ok(None)
    }

    /// List groups
    #[tracing::instrument(skip(self, state))]
    async fn list_groups(
        &self,
        state: &ServiceState,
        params: &GroupListParameters,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        Ok(group::list(&state.db, params).await?)
    }

    /// List groups a user is member of.
    #[tracing::instrument(skip(self, state))]
    async fn list_groups_of_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        Ok(user_group::list_user_groups(
            &state.db,
            user_id,
            &state
                .config
                .federation
                .get_expiring_user_group_membership_cutof_datetime(),
        )
        .await?)
    }

    /// Fetch users from the database.
    #[tracing::instrument(skip(self, state))]
    async fn list_users(
        &self,
        state: &ServiceState,
        params: &UserListParameters,
    ) -> Result<Vec<UserResponse>, IdentityProviderError> {
        Ok(user::list(&state.config, &state.db, params).await?)
    }

    /// Remove the user from the group.
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

impl From<crate::error::DatabaseError> for IdentityProviderError {
    fn from(source: crate::error::DatabaseError) -> Self {
        match source {
            cfl @ crate::error::DatabaseError::Conflict { .. } => Self::Conflict(cfl.to_string()),
            other => Self::Driver(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {}
