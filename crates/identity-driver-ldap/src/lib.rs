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
//! # OpenStack Keystone LDAP driver for the identity provider (ADR-0027)
//!
//! Read-only identity backend backed by an external LDAP directory
//! (FreeIPA, Active Directory, OpenLDAP, ...), configuration-compatible
//! with Python Keystone's `[ldap]` section. See
//! `doc/src/adr/0027-ldap-identity-driver.md`.
use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrecy::SecretString;

use openstack_keystone_config::LdapProvider;
use openstack_keystone_core::auth::AuthenticationResult;
use openstack_keystone_core::identity::IdentityProviderError;
use openstack_keystone_core::identity::backend::IdentityBackend;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core_types::identity::*;

mod authenticate;
mod connection;
mod enabled;
mod filter;
mod group;
mod id_dn;
#[cfg(test)]
mod live_tests;
mod models;
mod user;

use connection::{AuthPool, ServicePool};

fn readonly(operation: &str) -> IdentityProviderError {
    IdentityProviderError::Readonly(format!(
        "ldap identity driver is read-only: {operation} is not permitted"
    ))
}

fn not_implemented(operation: &str) -> IdentityProviderError {
    IdentityProviderError::NotImplemented(format!(
        "ldap identity driver does not support {operation}"
    ))
}

/// The read-only LDAP identity backend.
pub struct LdapBackend {
    config: Arc<LdapProvider>,
    service_pool: ServicePool,
    auth_pool: AuthPool,
}

impl LdapBackend {
    /// Construct the backend and verify the directory is reachable with the
    /// configured service bind credentials. Fails fast rather than
    /// registering a backend that can never serve a request (mirrors the
    /// JWS token provider's `load_keys().await?` precedent in
    /// `crates/keystone/src/plugin_manager.rs`).
    pub async fn new(cfg: &LdapProvider) -> eyre::Result<Self> {
        if cfg.tls_cacertfile.is_some() || cfg.tls_cacertdir.is_some() {
            tracing::warn!(
                "[ldap] tls_cacertfile/tls_cacertdir are configured but not yet applied by this \
                 driver; TLS verification uses the platform/rustls default trust store instead. \
                 Install the CA into the system trust store, or set tls_req_cert = never for a \
                 test directory."
            );
        }
        let config = Arc::new(cfg.clone());
        let service_pool = ServicePool::new(config.clone());
        let auth_pool = AuthPool::new(config.clone());
        service_pool
            .health_check()
            .await
            .map_err(|e| eyre::eyre!("{e}"))?;
        Ok(Self {
            config,
            service_pool,
            auth_pool,
        })
    }

    async fn default_domain_id(&self, state: &ServiceState) -> String {
        state
            .config_manager
            .config
            .read()
            .await
            .identity
            .default_domain_id
            .clone()
    }
}

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping this crate visible even before it is registered with the
/// `PluginManager`.
#[allow(dead_code)]
pub fn anchor() {}

#[async_trait]
impl IdentityBackend for LdapBackend {
    async fn add_user_to_group<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Err(readonly("add_user_to_group"))
    }

    async fn add_user_to_group_expiring<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _group_id: &'a str,
        _idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Err(not_implemented("expiring group membership"))
    }

    async fn add_users_to_groups<'a>(
        &self,
        _state: &ServiceState,
        _memberships: Vec<(&'a str, &'a str)>,
    ) -> Result<(), IdentityProviderError> {
        Err(readonly("add_users_to_groups"))
    }

    async fn add_users_to_groups_expiring<'a>(
        &self,
        _state: &ServiceState,
        _memberships: Vec<(&'a str, &'a str)>,
        _idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Err(not_implemented("expiring group membership"))
    }

    #[tracing::instrument(skip(self, state, auth))]
    async fn authenticate_by_password(
        &self,
        state: &ServiceState,
        auth: &UserPasswordAuthRequest,
    ) -> Result<AuthenticationResult, IdentityProviderError> {
        let default_domain_id = self.default_domain_id(state).await;
        authenticate::authenticate_by_password(
            &self.service_pool,
            &self.auth_pool,
            &self.config,
            &default_domain_id,
            auth,
        )
        .await
    }

    #[tracing::instrument(skip(self, state))]
    async fn check_user_exist<'a>(
        &self,
        state: &ServiceState,
        user_id: Option<&'a str>,
        name: Option<&'a str>,
        domain_id: Option<&'a str>,
    ) -> Result<String, IdentityProviderError> {
        let default_domain_id = self.default_domain_id(state).await;
        user::check_user_exist(
            &self.service_pool,
            &self.config,
            &default_domain_id,
            user_id,
            name,
            domain_id,
        )
        .await
    }

    async fn create_group(
        &self,
        _state: &ServiceState,
        _group: GroupCreate,
    ) -> Result<Group, IdentityProviderError> {
        Err(readonly("create_group"))
    }

    async fn create_service_account(
        &self,
        _state: &ServiceState,
        _sa: ServiceAccountCreate,
    ) -> Result<ServiceAccount, IdentityProviderError> {
        Err(not_implemented("service accounts"))
    }

    async fn create_user(
        &self,
        _state: &ServiceState,
        _user: UserCreate,
    ) -> Result<UserResponse, IdentityProviderError> {
        Err(readonly("create_user"))
    }

    async fn delete_group<'a>(
        &self,
        _state: &ServiceState,
        _group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Err(readonly("delete_group"))
    }

    async fn delete_user<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Err(readonly("delete_user"))
    }

    #[tracing::instrument(skip(self, state))]
    async fn get_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<Option<Group>, IdentityProviderError> {
        let default_domain_id = self.default_domain_id(state).await;
        group::get(
            &self.service_pool,
            &self.config,
            &default_domain_id,
            group_id,
        )
        .await
    }

    async fn get_service_account<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
    ) -> Result<Option<ServiceAccount>, IdentityProviderError> {
        Ok(None)
    }

    #[tracing::instrument(skip(self, state))]
    async fn get_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        let default_domain_id = self.default_domain_id(state).await;
        user::get(
            &self.service_pool,
            &self.config,
            &default_domain_id,
            user_id,
        )
        .await
    }

    async fn get_user_domain_id<'a>(
        &self,
        state: &ServiceState,
        _user_id: &'a str,
    ) -> Result<String, IdentityProviderError> {
        Ok(self.default_domain_id(state).await)
    }

    #[tracing::instrument(skip(self, state))]
    async fn find_user_by_name_ci<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        name: &'a str,
    ) -> Result<Option<String>, IdentityProviderError> {
        let default_domain_id = self.default_domain_id(state).await;
        user::find_by_name_ci(
            &self.service_pool,
            &self.config,
            &default_domain_id,
            domain_id,
            name,
        )
        .await
    }

    async fn find_federated_user<'a>(
        &self,
        _state: &ServiceState,
        _idp_id: &'a str,
        _unique_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        // LDAP users bypass the SQL identity/federation tables entirely
        // (ADR-0027 §11): there is no `idmapping`/`nonlocal_user` concept to
        // resolve a federated identity against.
        Err(not_implemented("federated users"))
    }

    #[tracing::instrument(skip(self, state))]
    async fn list_groups(
        &self,
        state: &ServiceState,
        params: &GroupListParameters,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        let default_domain_id = self.default_domain_id(state).await;
        group::list(&self.service_pool, &self.config, &default_domain_id, params).await
    }

    #[tracing::instrument(skip(self, state))]
    async fn list_users(
        &self,
        state: &ServiceState,
        params: &UserListParameters,
    ) -> Result<Vec<UserResponse>, IdentityProviderError> {
        let default_domain_id = self.default_domain_id(state).await;
        user::list(&self.service_pool, &self.config, &default_domain_id, params).await
    }

    #[tracing::instrument(skip(self, state))]
    async fn list_groups_of_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        let default_domain_id = self.default_domain_id(state).await;
        // Mirrors Python's `list_groups_for_user`: membership is keyed on
        // the user's DN, unless `group_members_are_ids` is set, in which
        // case group member attributes hold the user's ID directly.
        let member_value = if self.config.group_members_are_ids {
            user_id.to_string()
        } else {
            match user::resolve_dn(&self.service_pool, &self.config, Some(user_id), None).await? {
                Some(dn) => dn,
                None => return Ok(vec![]),
            }
        };
        group::list_groups_of_user_dn(
            &self.service_pool,
            &self.config,
            &default_domain_id,
            &member_value,
        )
        .await
    }

    #[tracing::instrument(skip(self, _state))]
    async fn list_users_of_group<'a>(
        &self,
        _state: &ServiceState,
        group_id: &'a str,
    ) -> Result<Vec<String>, IdentityProviderError> {
        group::list_users_of_group(&self.service_pool, &self.config, group_id).await
    }

    #[tracing::instrument(skip(self, state))]
    async fn find_group_by_name_ci<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        name: &'a str,
    ) -> Result<Option<String>, IdentityProviderError> {
        let default_domain_id = self.default_domain_id(state).await;
        group::find_by_name_ci(
            &self.service_pool,
            &self.config,
            &default_domain_id,
            domain_id,
            name,
        )
        .await
    }

    async fn update_group<'a>(
        &self,
        _state: &ServiceState,
        _group_id: &'a str,
        _group: GroupUpdate,
    ) -> Result<Group, IdentityProviderError> {
        Err(readonly("update_group"))
    }

    async fn remove_user_from_group<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Err(readonly("remove_user_from_group"))
    }

    async fn remove_user_from_group_expiring<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _group_id: &'a str,
        _idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Err(not_implemented("expiring group membership"))
    }

    async fn remove_user_from_groups<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        Err(readonly("remove_user_from_groups"))
    }

    async fn remove_user_from_groups_expiring<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _group_ids: HashSet<&'a str>,
        _idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Err(not_implemented("expiring group membership"))
    }

    async fn set_user_groups<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        Err(readonly("set_user_groups"))
    }

    async fn update_user<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _user: UserUpdate,
    ) -> Result<UserResponse, IdentityProviderError> {
        Err(readonly("update_user"))
    }

    async fn update_user_password<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _original_password: SecretString,
        _new_password: SecretString,
    ) -> Result<(), IdentityProviderError> {
        Err(readonly("update_user_password"))
    }

    async fn set_user_groups_expiring<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _group_ids: HashSet<&'a str>,
        _idp_id: &'a str,
        _last_verified: Option<&'a DateTime<Utc>>,
    ) -> Result<(), IdentityProviderError> {
        Err(not_implemented("expiring group membership"))
    }
}

#[cfg(test)]
mod tests {}
