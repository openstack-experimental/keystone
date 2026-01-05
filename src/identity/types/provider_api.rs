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

use crate::auth::AuthenticatedInfo;
use crate::identity::IdentityProviderError;
use crate::identity::types::{group::*, user::*};
use crate::keystone::ServiceState;

#[async_trait]
pub trait IdentityApi: Send + Sync {
    /// Add the user to the single group.
    async fn add_user_to_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Add the user to the single group with expiration.
    async fn add_user_to_group_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Add user group memberships as specified by (uid, gid) tuples.
    async fn add_users_to_groups<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
    ) -> Result<(), IdentityProviderError>;

    /// Add expiring user group memberships as specified by (uid, gid) tuples.
    async fn add_users_to_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    async fn authenticate_by_password(
        &self,
        state: &ServiceState,
        auth: &UserPasswordAuthRequest,
    ) -> Result<AuthenticatedInfo, IdentityProviderError>;

    async fn create_group(
        &self,
        state: &ServiceState,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError>;

    async fn create_user(
        &self,
        state: &ServiceState,
        user: UserCreate,
    ) -> Result<UserResponse, IdentityProviderError>;

    async fn delete_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    async fn get_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<Option<Group>, IdentityProviderError>;

    async fn get_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError>;

    /// Get single user by ID.
    async fn get_user_domain_id<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<String>, IdentityProviderError>;

    async fn find_federated_user<'a>(
        &self,
        state: &ServiceState,
        idp_id: &'a str,
        unique_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError>;

    async fn list_groups(
        &self,
        state: &ServiceState,
        params: &GroupListParameters,
    ) -> Result<impl IntoIterator<Item = Group>, IdentityProviderError>;

    async fn list_users(
        &self,
        state: &ServiceState,
        params: &UserListParameters,
    ) -> Result<impl IntoIterator<Item = UserResponse>, IdentityProviderError>;

    async fn delete_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// List groups the user is a member of.
    async fn list_groups_of_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<impl IntoIterator<Item = Group>, IdentityProviderError>;

    /// Remove the user from the single group.
    async fn remove_user_from_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Remove the user from the single group with expiration.
    async fn remove_user_from_group_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Remove the user from specified groups.
    async fn remove_user_from_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError>;

    /// Remove the user from specified groups with expiration.
    async fn remove_user_from_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError>;

    /// Set group memberships of the user.
    async fn set_user_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError>;

    /// Set expiring group memberships of the user.
    async fn set_user_groups_expiring<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
        idp_id: &'a str,
        last_verified: Option<&'a DateTime<Utc>>,
    ) -> Result<(), IdentityProviderError>;
}
