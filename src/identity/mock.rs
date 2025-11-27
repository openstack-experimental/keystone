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
use mockall::mock;
use std::collections::HashSet;
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration};

use crate::auth::AuthenticatedInfo;
use crate::config::Config;
use crate::identity::IdentityApi;
use crate::identity::error::IdentityProviderError;
use crate::identity::types::{
    Group, GroupCreate, GroupListParameters, UserCreate, UserListParameters,
    UserPasswordAuthRequest, UserResponse, WebauthnCredential,
};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManager;

mock! {
    pub IdentityProvider {
        pub fn new(cfg: &Config, plugin_manager: &PluginManager) -> Result<Self, IdentityProviderError>;
    }

    #[async_trait]
    impl IdentityApi for IdentityProvider {
        async fn authenticate_by_password(
            &self,
            state: &ServiceState,
            auth: &UserPasswordAuthRequest,
        ) -> Result<AuthenticatedInfo, IdentityProviderError>;

        async fn list_users(
            &self,
            state: &ServiceState,
            params: &UserListParameters,
        ) -> Result<Vec<UserResponse>, IdentityProviderError>;

        async fn get_user<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<Option<UserResponse>, IdentityProviderError>;

        async fn find_federated_user<'a>(
            &self,
            state: &ServiceState,
            idp_id: &'a str,
            unique_id: &'a str,
        ) -> Result<Option<UserResponse>, IdentityProviderError>;

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

        async fn list_groups(
            &self,
            state: &ServiceState,
            params: &GroupListParameters,
        ) -> Result<Vec<Group>, IdentityProviderError>;

        async fn get_group<'a>(
            &self,
            state: &ServiceState,
            group_id: &'a str,
        ) -> Result<Option<Group>, IdentityProviderError>;

        async fn create_group(
            &self,
            state: &ServiceState,
            group: GroupCreate,
        ) -> Result<Group, IdentityProviderError>;

        async fn delete_group<'a>(
            &self,
            state: &ServiceState,
            group_id: &'a str,
        ) -> Result<(), IdentityProviderError>;

        async fn list_groups_of_user<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<Vec<Group>, IdentityProviderError>;

        async fn add_user_to_group<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
            group_id: &'a str,
        ) -> Result<(), IdentityProviderError>;

        async fn add_users_to_groups<'a>(
            &self,
            state: &ServiceState,
            memberships: Vec<(&'a str, &'a str)>
        ) -> Result<(), IdentityProviderError>;

        async fn remove_user_from_group<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
            group_id: &'a str,
        ) -> Result<(), IdentityProviderError>;

        async fn remove_user_from_groups<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
            group_ids: HashSet<&'a str>,
        ) -> Result<(), IdentityProviderError>;

        async fn set_user_groups<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
            group_ids: HashSet<&'a str>,
        ) -> Result<(), IdentityProviderError>;

        async fn list_user_webauthn_credentials<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<Vec<Passkey>, IdentityProviderError>;

        async fn create_user_webauthn_credential<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
            passkey: &Passkey,
            description: Option<&'a str>
        ) -> Result<WebauthnCredential, IdentityProviderError>;

        async fn save_user_webauthn_credential_registration_state<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
            auth_state: PasskeyRegistration,
        ) -> Result<(), IdentityProviderError>;

        async fn save_user_webauthn_credential_authentication_state<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
            auth_state: PasskeyAuthentication,
        ) -> Result<(), IdentityProviderError>;

        async fn get_user_webauthn_credential_registration_state<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<Option<PasskeyRegistration>, IdentityProviderError>;

        async fn get_user_webauthn_credential_authentication_state<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<Option<PasskeyAuthentication>, IdentityProviderError>;

        async fn delete_user_webauthn_credential_registration_state<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<(), IdentityProviderError>;

        async fn delete_user_webauthn_credential_authentication_state<'a>(
            &self,
            state: &ServiceState,
            user_id: &'a str,
        ) -> Result<(), IdentityProviderError>;
    }

    impl Clone for IdentityProvider {
        fn clone(&self) -> Self;
    }

}
