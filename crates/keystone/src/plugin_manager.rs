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
//! # Plugin manager
//!
//! A driver, also known as a backend, is an important architectural component
//! of Keystone. It is an abstraction around the data access needed by a
//! particular subsystem. This pluggable implementation is not only how Keystone
//! implements its own data access, but how you can implement your own!
//!
//! The [PluginManager] is responsible for picking the proper backend driver for
//! the provider.
use std::collections::HashMap;
use std::sync::Arc;

use openstack_keystone_config::Config;
use openstack_keystone_core::application_credential::{
    ApplicationCredentialProviderError, backend::ApplicationCredentialBackend,
};
use openstack_keystone_core::assignment::backend::AssignmentBackend;
use openstack_keystone_core::assignment::error::AssignmentProviderError;
use openstack_keystone_core::catalog::backend::CatalogBackend;
use openstack_keystone_core::catalog::error::CatalogProviderError;
use openstack_keystone_core::federation::backend::FederationBackend;
use openstack_keystone_core::federation::error::FederationProviderError;
use openstack_keystone_core::identity::backend::IdentityBackend;
use openstack_keystone_core::identity::error::IdentityProviderError;
use openstack_keystone_core::identity_mapping::IdentityMappingProviderError;
use openstack_keystone_core::identity_mapping::backend::IdentityMappingBackend;
use openstack_keystone_core::k8s_auth::K8sAuthProviderError;
use openstack_keystone_core::k8s_auth::backend::K8sAuthBackend;
use openstack_keystone_core::resource::backend::ResourceBackend;
use openstack_keystone_core::resource::error::ResourceProviderError;
use openstack_keystone_core::revoke::RevokeProviderError;
use openstack_keystone_core::revoke::backend::RevokeBackend;
use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core::role::backend::RoleBackend;
use openstack_keystone_core::token::TokenProviderError;
use openstack_keystone_core::token::backend::{TokenBackend, TokenRestrictionBackend};
use openstack_keystone_core::trust::TrustProviderError;
use openstack_keystone_core::trust::backend::TrustBackend;

pub use openstack_keystone_core::plugin_manager::*;

/// Plugin manager allowing to pass custom backend plugins implementing required
/// trait during the service start.
#[derive(Clone)]
pub struct PluginManager {
    /// Application credentials backend plugin.
    application_credential_backends: HashMap<String, Arc<dyn ApplicationCredentialBackend>>,
    /// Assignments backend plugin.
    assignment_backends: HashMap<String, Arc<dyn AssignmentBackend>>,
    /// Catalog backend plugins.
    catalog_backends: HashMap<String, Arc<dyn CatalogBackend>>,
    /// Federation backend plugins.
    federation_backends: HashMap<String, Arc<dyn FederationBackend>>,
    /// Identity backend plugins.
    identity_backends: HashMap<String, Arc<dyn IdentityBackend>>,
    /// Identity mapping backend plugins.
    identity_mapping_backends: HashMap<String, Arc<dyn IdentityMappingBackend>>,
    /// K8s auth backend plugins.
    k8s_auth_backends: HashMap<String, Arc<dyn K8sAuthBackend>>,
    /// Resource backend plugins.
    resource_backends: HashMap<String, Arc<dyn ResourceBackend>>,
    /// Revoke backend plugins.
    revoke_backends: HashMap<String, Arc<dyn RevokeBackend>>,
    /// Role backend plugins.
    role_backends: HashMap<String, Arc<dyn RoleBackend>>,
    /// Token backend plugins.
    token_backends: HashMap<String, Arc<dyn TokenBackend>>,
    /// Token restriction backend plugins.
    token_restriction_backends: HashMap<String, Arc<dyn TokenRestrictionBackend>>,
    /// Trust backend plugins.
    trust_backends: HashMap<String, Arc<dyn TrustBackend>>,
}

impl PluginManagerApi for PluginManager {
    /// Get registered application credential backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `ApplicationCredentialBackend`
    /// if found, or an `ApplicationCredentialProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_application_credential_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn ApplicationCredentialBackend>, ApplicationCredentialProviderError> {
        self.application_credential_backends
            .get(name.as_ref())
            .ok_or(ApplicationCredentialProviderError::UnsupportedDriver(
                name.as_ref().to_string(),
            ))
    }

    /// Get registered assignment backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `AssignmentBackend` if found,
    /// or an `AssignmentProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_assignment_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn AssignmentBackend>, AssignmentProviderError> {
        self.assignment_backends.get(name.as_ref()).ok_or(
            AssignmentProviderError::UnsupportedDriver(name.as_ref().to_string()),
        )
    }

    /// Get registered catalog backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `CatalogBackend` if found, or a
    /// `CatalogProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_catalog_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn CatalogBackend>, CatalogProviderError> {
        self.catalog_backends
            .get(name.as_ref())
            .ok_or(CatalogProviderError::UnsupportedDriver(
                name.as_ref().to_string(),
            ))
    }

    /// Get registered federation backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `FederationBackend` if found,
    /// or a `FederationProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_federation_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn FederationBackend>, FederationProviderError> {
        self.federation_backends.get(name.as_ref()).ok_or(
            FederationProviderError::UnsupportedDriver(name.as_ref().to_string()),
        )
    }

    /// Get registered identity backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `IdentityBackend` if found, or
    /// an `IdentityProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_identity_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn IdentityBackend>, IdentityProviderError> {
        self.identity_backends
            .get(name.as_ref())
            .ok_or(IdentityProviderError::UnsupportedDriver(
                name.as_ref().to_string(),
            ))
    }

    /// Get registered identity mapping backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `IdentityMappingBackend` if
    /// found, or an `IdentityMappingProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_identity_mapping_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn IdentityMappingBackend>, IdentityMappingProviderError> {
        self.identity_mapping_backends.get(name.as_ref()).ok_or(
            IdentityMappingProviderError::UnsupportedDriver(name.as_ref().to_string()),
        )
    }

    /// Get registered k8s auth backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `K8sAuthBackend` if found, or a
    /// `K8sAuthProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_k8s_auth_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn K8sAuthBackend>, K8sAuthProviderError> {
        self.k8s_auth_backends
            .get(name.as_ref())
            .ok_or(K8sAuthProviderError::UnsupportedDriver(
                name.as_ref().to_string(),
            ))
    }

    /// Get registered resource backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `ResourceBackend` if found, or
    /// a `ResourceProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_resource_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn ResourceBackend>, ResourceProviderError> {
        self.resource_backends
            .get(name.as_ref())
            .ok_or(ResourceProviderError::UnsupportedDriver(
                name.as_ref().to_string(),
            ))
    }

    /// Get registered revoke backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `RevokeBackend` if found, or a
    /// `RevokeProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_revoke_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn RevokeBackend>, RevokeProviderError> {
        self.revoke_backends
            .get(name.as_ref())
            .ok_or(RevokeProviderError::UnsupportedDriver(
                name.as_ref().to_string(),
            ))
    }

    /// Get role resource backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `RoleBackend` if found, or a
    /// `RoleProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_role_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn RoleBackend>, RoleProviderError> {
        self.role_backends
            .get(name.as_ref())
            .ok_or(RoleProviderError::UnsupportedDriver(
                name.as_ref().to_string(),
            ))
    }

    /// Get registered token backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `TokenBackend` if found, or a
    /// `TokenProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_token_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn TokenBackend>, TokenProviderError> {
        self.token_backends
            .get(name.as_ref())
            .ok_or(TokenProviderError::UnsupportedDriver(
                name.as_ref().to_string(),
            ))
    }

    /// Get registered token restriction backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `TokenRestrictionBackend` if
    /// found, or a `TokenProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_token_restriction_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn TokenRestrictionBackend>, TokenProviderError> {
        self.token_restriction_backends.get(name.as_ref()).ok_or(
            TokenProviderError::UnsupportedTRDriver(name.as_ref().to_string()),
        )
    }

    /// Get registered trust backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `TrustBackend` if found, or a
    /// `TrustProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_trust_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn TrustBackend>, TrustProviderError> {
        self.trust_backends
            .get(name.as_ref())
            .ok_or(TrustProviderError::UnsupportedDriver(
                name.as_ref().to_string(),
            ))
    }

    /// Register application credential backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_application_credential_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn ApplicationCredentialBackend>,
    ) {
        self.application_credential_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register assignment backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_assignment_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn AssignmentBackend>,
    ) {
        self.assignment_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register catalog backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_catalog_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn CatalogBackend>,
    ) {
        self.catalog_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register federation backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_federation_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn FederationBackend>,
    ) {
        self.federation_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register identity backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_identity_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn IdentityBackend>,
    ) {
        self.identity_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register identity mapping backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_identity_mapping_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn IdentityMappingBackend>,
    ) {
        self.identity_mapping_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register k8s_auth backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_k8s_auth_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn K8sAuthBackend>,
    ) {
        self.k8s_auth_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register resource backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_resource_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn ResourceBackend>,
    ) {
        self.resource_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register revoke backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_revoke_backend<S: AsRef<str>>(&mut self, name: S, plugin: Arc<dyn RevokeBackend>) {
        self.revoke_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register role backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_role_backend<S: AsRef<str>>(&mut self, name: S, plugin: Arc<dyn RoleBackend>) {
        self.role_backends.insert(name.as_ref().to_string(), plugin);
    }

    /// Register token backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_token_backend<S: AsRef<str>>(&mut self, name: S, plugin: Arc<dyn TokenBackend>) {
        self.token_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register token restriction backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_token_restriction_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn TokenRestrictionBackend>,
    ) {
        self.token_restriction_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register trust backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_trust_backend<S: AsRef<str>>(&mut self, name: S, plugin: Arc<dyn TrustBackend>) {
        self.trust_backends
            .insert(name.as_ref().to_string(), plugin);
    }
}

impl PluginManager {
    /// Register default SQL drivers in the [PluginManager]
    fn register_sql_drivers(&mut self) {
        self.register_application_credential_backend(
            "sql",
            Arc::new(openstack_keystone_appcred_sql::SqlBackend::default()),
        );
        self.register_assignment_backend(
            "sql",
            Arc::new(openstack_keystone_assignment_sql::SqlBackend::default()),
        );
        self.register_catalog_backend(
            "sql",
            Arc::new(openstack_keystone_catalog_sql::SqlBackend::default()),
        );
        self.register_federation_backend(
            "sql",
            Arc::new(openstack_keystone_federation_sql::SqlBackend::default()),
        );
        self.register_identity_backend(
            "sql",
            Arc::new(openstack_keystone_identity_sql::SqlBackend::default()),
        );
        self.register_identity_mapping_backend(
            "sql",
            Arc::new(openstack_keystone_idmapping_sql::SqlBackend::default()),
        );
        self.register_k8s_auth_backend(
            "sql",
            Arc::new(openstack_keystone_k8s_auth_sql::SqlBackend::default()),
        );
        self.register_resource_backend(
            "sql",
            Arc::new(openstack_keystone_resource_sql::SqlBackend::default()),
        );
        self.register_revoke_backend(
            "sql",
            Arc::new(openstack_keystone_revoke_sql::SqlBackend::default()),
        );
        self.register_role_backend(
            "sql",
            Arc::new(openstack_keystone_role_sql::SqlBackend::default()),
        );
        self.register_token_restriction_backend(
            "sql",
            Arc::new(openstack_keystone_token_restriction_sql::SqlBackend::default()),
        );
        self.register_trust_backend(
            "sql",
            Arc::new(openstack_keystone_trust_sql::SqlBackend::default()),
        );
    }

    /// Initialize the [PluginManager] with the initialized [Config].
    ///
    /// # Parameters
    /// * `config` - The configuration to use for initialization.
    ///
    /// # Returns
    /// A new instance of `PluginManager`.
    pub fn with_config(config: &Config) -> Self {
        let mut slf = Self {
            application_credential_backends: HashMap::new(),
            assignment_backends: HashMap::new(),
            catalog_backends: HashMap::new(),
            federation_backends: HashMap::new(),
            identity_backends: HashMap::new(),
            identity_mapping_backends: HashMap::new(),
            k8s_auth_backends: HashMap::new(),
            resource_backends: HashMap::new(),
            revoke_backends: HashMap::new(),
            role_backends: HashMap::new(),
            token_backends: HashMap::new(),
            token_restriction_backends: HashMap::new(),
            trust_backends: HashMap::new(),
        };
        slf.register_sql_drivers();
        slf.register_token_backend(
            "fernet",
            Arc::new(openstack_keystone_token_fernet::FernetTokenProvider::new(
                config.clone(),
            )),
        );
        slf.register_k8s_auth_backend(
            "raft",
            Arc::new(openstack_keystone_k8s_auth_raft::RaftBackend::default()),
        );
        slf
    }
}

impl Default for PluginManager {
    /// Returns the default instance of the [PluginManager].
    ///
    /// # Returns
    /// A `PluginManager` instance initialized with default configuration.
    fn default() -> Self {
        Self::with_config(&Config::default())
    }
}
