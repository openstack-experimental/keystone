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
use secrecy::SecretString;
use std::collections::HashSet;

use openstack_keystone_core_types::identity::*;

use crate::auth::AuthenticationResult;
use crate::identity::IdentityProviderError;
use crate::keystone::ServiceState;

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait IdentityBackend: Send + Sync {
    /// Add the user to the group.
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

    /// Add the user to the group with expiration.
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

    /// Add user group membership relations.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `memberships`: A list of (user ID, group ID) tuples.
    async fn add_users_to_groups<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
    ) -> Result<(), IdentityProviderError>;

    /// Add expiring user group membership relations.
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

    /// Authenticate a user by a password.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `auth`: The password authentication request.
    async fn authenticate_by_password(
        &self,
        state: &ServiceState,
        auth: &UserPasswordAuthRequest,
    ) -> Result<AuthenticationResult, IdentityProviderError>;

    /// Cheaply resolve a user reference (ID, or name with domain ID) to the
    /// canonical user ID, verifying that the account exists and is enabled.
    ///
    /// This is the inexpensive existence probe backing per-user rate
    /// limiting at the provider level (ADR-0022, Invariant 8): the service
    /// keys the `[rate_limit_user_auth]` bucket on the returned ID before
    /// invoking any expensive credential verification. Implementations MUST
    /// keep this cheap: point lookups only, no joins, no password or option
    /// loading.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The user ID, when the caller authenticates by ID.
    /// - `name`: The user name, when the caller authenticates by name.
    /// - `domain_id`: The resolved domain ID owning `name`.
    ///
    /// # Returns
    /// The canonical user ID, [`IdentityProviderError::UserNotFound`] when no
    /// such user exists, or an authentication error when the user is
    /// disabled.
    async fn check_user_exist<'a>(
        &self,
        state: &ServiceState,
        user_id: Option<&'a str>,
        name: Option<&'a str>,
        domain_id: Option<&'a str>,
    ) -> Result<String, IdentityProviderError>;

    /// Create group.
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

    /// Create user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user`: The user details to create.
    async fn create_user(
        &self,
        state: &ServiceState,
        user: UserCreate,
    ) -> Result<UserResponse, IdentityProviderError>;

    /// Delete group by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group_id`: The ID of the group to delete.
    async fn delete_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Delete user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user to delete.
    async fn delete_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Get single group by ID.
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

    /// Get single user by ID.
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

    /// Find the `user_id` of any user in `domain_id` whose name matches
    /// `name`, case-insensitively, regardless of which realm (or nothing)
    /// created it (ADR 0024 §3.D domain-wide uniqueness check).
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The domain to search within.
    /// - `name`: The name to match, case-insensitively.
    async fn find_user_by_name_ci<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        name: &'a str,
    ) -> Result<Option<String>, IdentityProviderError>;

    /// Find federated user by IDP and Unique ID.
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

    /// List groups.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The parameters for listing groups.
    async fn list_groups(
        &self,
        state: &ServiceState,
        params: &GroupListParameters,
    ) -> Result<Vec<Group>, IdentityProviderError>;

    /// List Users.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The parameters for listing users.
    async fn list_users(
        &self,
        state: &ServiceState,
        params: &UserListParameters,
    ) -> Result<Vec<UserResponse>, IdentityProviderError>;

    /// List groups a user is member of.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    async fn list_groups_of_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<Group>, IdentityProviderError>;

    /// List the IDs of users that are members of a group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group_id`: The ID of the group.
    async fn list_users_of_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<Vec<String>, IdentityProviderError>;

    /// Find any group in `domain_id` whose name matches `name`,
    /// case-insensitively, regardless of which realm (or nothing) created it.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The domain to search within.
    /// - `name`: The name to match, case-insensitively.
    async fn find_group_by_name_ci<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        name: &'a str,
    ) -> Result<Option<String>, IdentityProviderError>;

    /// Update group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group_id`: The ID of the group to update.
    /// - `group`: The group update request.
    async fn update_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
        group: GroupUpdate,
    ) -> Result<Group, IdentityProviderError>;

    /// Remove the user from the group.
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

    /// Remove the user from the group with expiration.
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

    /// Remove the user from multiple groups.
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

    /// Remove the user from multiple expiring groups.
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

    /// Set group memberships for the user.
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

    /// Update user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user to update.
    /// - `user`: The user details to update.
    async fn update_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        user: UserUpdate,
    ) -> Result<UserResponse, IdentityProviderError>;

    /// Update user password.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user to update.
    /// - `original_password`: The current password for verification.
    /// - `new_password`: The new password to set.
    async fn update_user_password<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        original_password: SecretString,
        new_password: SecretString,
    ) -> Result<(), IdentityProviderError>;

    /// Set expiring group memberships for the user.
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
