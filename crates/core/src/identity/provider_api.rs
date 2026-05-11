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

use openstack_keystone_core_types::identity::*;

use crate::auth::AuthenticationResult;
use crate::identity::IdentityProviderError;
use crate::keystone::ServiceState;

#[async_trait]
pub trait IdentityApi: Send + Sync {
    /// Add the user to the single group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_id`: The ID of the group.
    async fn add_user_to_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Add the user to the single group with expiration.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_id`: The ID of the group.
    /// - `idp_id`: The ID of the identity provider.
    async fn add_user_to_group_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Add user group memberships as specified by (uid, gid) tuples.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `memberships`: A list of (user ID, group ID) tuples.
    async fn add_users_to_groups<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
    ) -> Result<(), IdentityProviderError>;

    /// Add expiring user group memberships as specified by (uid, gid) tuples.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `memberships`: A list of (user ID, group ID) tuples.
    /// - `idp_id`: The ID of the identity provider.
    async fn add_users_to_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Authenticate a user by their password.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `auth`: The password authentication request.
    async fn authenticate_by_password(
        &self,
        state: &ServiceState,
        auth: &UserPasswordAuthRequest,
    ) -> Result<AuthenticationResult, IdentityProviderError>;

    /// Create a new group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group`: The group details to create.
    async fn create_group(
        &self,
        state: &ServiceState,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError>;

    /// Create service account.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `sa`: The service account details to create.
    async fn create_service_account(
        &self,
        state: &ServiceState,
        sa: ServiceAccountCreate,
    ) -> Result<ServiceAccount, IdentityProviderError>;

    /// Create a new user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user`: The user details to create.
    async fn create_user(
        &self,
        state: &ServiceState,
        user: UserCreate,
    ) -> Result<UserResponse, IdentityProviderError>;

    /// Delete a user by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user to delete.
    async fn delete_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Get a group by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group_id`: The ID of the group to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<Group>, IdentityProviderError>` - A `Result` containing
    ///   an `Option` with the group if found, or an `Error`.
    async fn get_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<Option<Group>, IdentityProviderError>;

    /// Get single service account by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the service account to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<ServiceAccount>, IdentityProviderError>` - A `Result`
    ///   containing an `Option` with the service account if found, or an
    ///   `Error`.
    async fn get_service_account<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<ServiceAccount>, IdentityProviderError>;

    /// Get a user by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<UserResponse>, IdentityProviderError>` - A `Result`
    ///   containing an `Option` with the user if found, or an `Error`.
    async fn get_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError>;

    /// Get single user by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    async fn get_user_domain_id<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<String, IdentityProviderError>;

    /// Find a federated user by IDP and unique ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `idp_id`: The ID of the identity provider.
    /// - `unique_id`: The unique ID of the federated user.
    ///
    /// # Returns
    /// - `Result<Option<UserResponse>, IdentityProviderError>` - A `Result`
    ///   containing an `Option` with the user if found, or an `Error`.
    async fn find_federated_user<'a>(
        &self,
        state: &ServiceState,
        idp_id: &'a str,
        unique_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError>;

    /// List groups based on parameters.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The parameters for listing groups.
    async fn list_groups(
        &self,
        state: &ServiceState,
        params: &GroupListParameters,
    ) -> Result<Vec<Group>, IdentityProviderError>;

    /// List users based on parameters.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The parameters for listing users.
    async fn list_users(
        &self,
        state: &ServiceState,
        params: &UserListParameters,
    ) -> Result<Vec<UserResponse>, IdentityProviderError>;

    /// Delete a group by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group_id`: The ID of the group to delete.
    async fn delete_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// List groups the user is a member of.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    async fn list_groups_of_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<Group>, IdentityProviderError>;

    /// Remove the user from the single group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_id`: The ID of the group.
    async fn remove_user_from_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Remove the user from the single group with expiration.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_id`: The ID of the group.
    /// - `idp_id`: The ID of the identity provider.
    async fn remove_user_from_group_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Remove the user from specified groups.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_ids`: A set of group IDs.
    async fn remove_user_from_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError>;

    /// Remove the user from specified groups with expiration.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_ids`: A set of group IDs.
    /// - `idp_id`: The ID of the identity provider.
    async fn remove_user_from_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Set group memberships of the user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_ids`: A set of group IDs.
    async fn set_user_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError>;

    /// Set expiring group memberships of the user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_ids`: A set of group IDs.
    /// - `idp_id`: The ID of the identity provider.
    /// - `last_verified`: The last verified date, if any.
    async fn set_user_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
        idp_id: &'a str,
        last_verified: Option<&'a DateTime<Utc>>,
    ) -> Result<(), IdentityProviderError>;
}
