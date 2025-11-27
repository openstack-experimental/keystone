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
use std::collections::HashSet;
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration};

mod authenticate;
mod federated_user;
mod group;
mod local_user;
mod nonlocal_user;
mod password;
mod user;
mod user_group;
mod user_option;
mod webauthn;

use super::super::types::*;
use crate::auth::AuthenticatedInfo;
use crate::config::Config;
use crate::identity::IdentityProviderError;
use crate::identity::backends::IdentityBackend;
use crate::identity::backends::error::{IdentityDatabaseError, db_err};
use crate::keystone::ServiceState;

#[derive(Clone, Debug, Default)]
pub struct SqlBackend {
    pub config: Config,
}

impl SqlBackend {}

#[async_trait]
impl IdentityBackend for SqlBackend {
    /// Set config
    fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// Authenticate a user by a password
    async fn authenticate_by_password(
        &self,
        state: &ServiceState,
        auth: &UserPasswordAuthRequest,
    ) -> Result<AuthenticatedInfo, IdentityProviderError> {
        Ok(authenticate::authenticate_by_password(&self.config, &state.db, auth).await?)
    }

    /// Fetch users from the database
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_users(
        &self,
        state: &ServiceState,
        params: &UserListParameters,
    ) -> Result<Vec<UserResponse>, IdentityProviderError> {
        Ok(user::list(&self.config, &state.db, params).await?)
    }

    /// Get single user by ID
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        Ok(user::get(&self.config, &state.db, user_id).await?)
    }

    /// Find federated user by IDP and Unique ID
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn find_federated_user<'a>(
        &self,
        state: &ServiceState,
        idp_id: &'a str,
        unique_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        if let Some(federated_user) =
            federated_user::find_by_idp_and_unique_id(&self.config, &state.db, idp_id, unique_id)
                .await?
        {
            return Ok(user::get(&self.config, &state.db, &federated_user.user_id).await?);
        }
        Ok(None)
    }

    /// Create user
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_user(
        &self,
        state: &ServiceState,
        user: UserCreate,
    ) -> Result<UserResponse, IdentityProviderError> {
        Ok(user::create(&self.config, &state.db, user).await?)
    }

    /// Delete user
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user::delete(&self.config, &state.db, user_id).await?)
    }

    /// List groups
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_groups(
        &self,
        state: &ServiceState,
        params: &GroupListParameters,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        Ok(group::list(&self.config, &state.db, params).await?)
    }

    /// Get single group by ID
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<Option<Group>, IdentityProviderError> {
        Ok(group::get(&self.config, &state.db, group_id).await?)
    }

    /// Create group
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_group(
        &self,
        state: &ServiceState,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError> {
        Ok(group::create(&self.config, &state.db, group).await?)
    }

    /// Delete group
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(group::delete(&self.config, &state.db, group_id).await?)
    }

    /// List groups a user is member of.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_groups_of_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        Ok(user_group::list_user_groups(&state.db, user_id).await?)
    }

    /// Add the user into the group.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn add_user_to_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::add_user_to_group(&state.db, user_id, group_id).await?)
    }

    /// Add user group membership relations.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn add_users_to_groups<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::add_users_to_groups(&state.db, memberships).await?)
    }

    /// Remove the user from the group.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn remove_user_from_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::remove_user_from_group(&state.db, user_id, group_id).await?)
    }

    /// Remove the user from multiple groups.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn remove_user_from_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::remove_user_from_groups(&state.db, user_id, group_ids).await?)
    }

    /// Set group memberships of the user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn set_user_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::set_user_groups(&state.db, user_id, group_ids).await?)
    }

    /// Create webauthn credential for the user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_user_webauthn_credential<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        credential: &Passkey,
        description: Option<&'a str>,
    ) -> Result<WebauthnCredential, IdentityProviderError> {
        Ok(webauthn::credential::create(&state.db, user_id, credential, description, None).await?)
    }

    /// List user webauthn credentials.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_user_webauthn_credentials<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<Passkey>, IdentityProviderError> {
        Ok(webauthn::credential::list(&state.db, user_id).await?)
    }

    /// Save webauthn credential registration state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        reg_state: PasskeyRegistration,
    ) -> Result<(), IdentityProviderError> {
        Ok(webauthn::state::create_register(&state.db, user_id, reg_state).await?)
    }

    /// Save webauthn credential auth state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        auth_state: PasskeyAuthentication,
    ) -> Result<(), IdentityProviderError> {
        Ok(webauthn::state::create_auth(&state.db, user_id, auth_state).await?)
    }

    /// Get webauthn credential registration state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<PasskeyRegistration>, IdentityProviderError> {
        Ok(webauthn::state::get_register(&state.db, user_id).await?)
    }

    /// Get webauthn credential auth state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<PasskeyAuthentication>, IdentityProviderError> {
        Ok(webauthn::state::get_auth(&state.db, user_id).await?)
    }

    /// Delete webauthn credential registration state for the user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(webauthn::state::delete(&state.db, user_id).await?)
    }

    /// Delete webauthn credential auth state for a user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(webauthn::state::delete(&state.db, user_id).await?)
    }
}

#[cfg(test)]
mod tests {}
