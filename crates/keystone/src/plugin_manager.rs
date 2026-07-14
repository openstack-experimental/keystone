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
use openstack_keystone_core::api_key::ApiKeyProviderError;
use openstack_keystone_core::api_key::backend::ApiKeyBackend;
use openstack_keystone_core::application_credential::{
    ApplicationCredentialProviderError, backend::ApplicationCredentialBackend,
};
use openstack_keystone_core::assignment::backend::AssignmentBackend;
use openstack_keystone_core::assignment::error::AssignmentProviderError;
use openstack_keystone_core::auth_plugin_identity::AuthPluginIdentityProviderError;
use openstack_keystone_core::auth_plugin_identity::backend::DynamicPluginIdentityBackend;
use openstack_keystone_core::catalog::backend::CatalogBackend;
use openstack_keystone_core::catalog::error::CatalogProviderError;
use openstack_keystone_core::credential::CredentialProviderError;
use openstack_keystone_core::credential::backend::CredentialBackend;
use openstack_keystone_core::federation::backend::FederationBackend;
use openstack_keystone_core::federation::error::FederationProviderError;
use openstack_keystone_core::identity::backend::IdentityBackend;
use openstack_keystone_core::identity::error::IdentityProviderError;
use openstack_keystone_core::idmapping::IdMappingProviderError;
use openstack_keystone_core::idmapping::backend::IdMappingBackend;
use openstack_keystone_core::k8s_auth::K8sAuthProviderError;
use openstack_keystone_core::k8s_auth::backend::K8sAuthBackend;
use openstack_keystone_core::mapping::MappingBackend;
use openstack_keystone_core::mapping::MappingProviderError;
use openstack_keystone_core::oauth2_client::Oauth2ClientProviderError;
use openstack_keystone_core::oauth2_client::backend::Oauth2ClientBackend;
use openstack_keystone_core::oauth2_key::Oauth2KeyProviderError;
use openstack_keystone_core::oauth2_key::backend::Oauth2KeyBackend;
use openstack_keystone_core::oauth2_session::Oauth2SessionProviderError;
use openstack_keystone_core::oauth2_session::backend::Oauth2SessionBackend;
use openstack_keystone_core::resource::backend::ResourceBackend;
use openstack_keystone_core::resource::error::ResourceProviderError;
use openstack_keystone_core::revoke::RevokeProviderError;
use openstack_keystone_core::revoke::backend::RevokeBackend;
use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core::role::backend::RoleBackend;
use openstack_keystone_core::scim_realm::ScimRealmProviderError;
use openstack_keystone_core::scim_realm::backend::ScimRealmBackend;
use openstack_keystone_core::scim_resource::ScimResourceProviderError;
use openstack_keystone_core::scim_resource::backend::ScimResourceBackend;
use openstack_keystone_core::token::TokenProviderError;
use openstack_keystone_core::token::backend::{TokenBackend, TokenRestrictionBackend};
use openstack_keystone_core::trust::TrustProviderError;
use openstack_keystone_core::trust::backend::TrustBackend;

pub use openstack_keystone_core::plugin_manager::*;

/// Plugin manager allowing to pass custom backend plugins implementing required
/// trait during the service start.
#[derive(Clone)]
pub struct PluginManager {
    /// API Key backend plugins.
    api_key_backends: HashMap<String, Arc<dyn ApiKeyBackend>>,
    /// Application credentials backend plugin.
    application_credential_backends: HashMap<String, Arc<dyn ApplicationCredentialBackend>>,
    /// Assignments backend plugin.
    assignment_backends: HashMap<String, Arc<dyn AssignmentBackend>>,
    /// Catalog backend plugins.
    catalog_backends: HashMap<String, Arc<dyn CatalogBackend>>,
    /// Credential backend plugins.
    credential_backends: HashMap<String, Arc<dyn CredentialBackend>>,
    /// Dynamic plugin identity-binding index backend plugins.
    auth_plugin_identity_backends: HashMap<String, Arc<dyn DynamicPluginIdentityBackend>>,
    /// Federation backend plugins.
    federation_backends: HashMap<String, Arc<dyn FederationBackend>>,
    /// Identity backend plugins.
    identity_backends: HashMap<String, Arc<dyn IdentityBackend>>,
    /// IdMapping backend plugins.
    idmapping_backends: HashMap<String, Arc<dyn IdMappingBackend>>,
    /// Mapping backend plugins.
    mapping_backends: HashMap<String, Arc<dyn MappingBackend>>,
    /// OAuth2 client backend plugins.
    oauth2_client_backends: HashMap<String, Arc<dyn Oauth2ClientBackend>>,
    /// OAuth2 signing key backend plugins.
    oauth2_key_backends: HashMap<String, Arc<dyn Oauth2KeyBackend>>,
    /// OAuth2 browser session backend plugins.
    oauth2_session_backends: HashMap<String, Arc<dyn Oauth2SessionBackend>>,
    /// K8s auth backend plugins.
    k8s_auth_backends: HashMap<String, Arc<dyn K8sAuthBackend>>,
    /// Resource backend plugins.
    resource_backends: HashMap<String, Arc<dyn ResourceBackend>>,
    /// Revoke backend plugins.
    revoke_backends: HashMap<String, Arc<dyn RevokeBackend>>,
    /// Role backend plugins.
    role_backends: HashMap<String, Arc<dyn RoleBackend>>,
    /// SCIM realm backend plugins.
    scim_realm_backends: HashMap<String, Arc<dyn ScimRealmBackend>>,
    /// SCIM resource ownership index backend plugins.
    scim_resource_backends: HashMap<String, Arc<dyn ScimResourceBackend>>,
    /// Token backend plugins.
    token_backends: HashMap<String, Arc<dyn TokenBackend>>,
    /// Token restriction backend plugins.
    token_restriction_backends: HashMap<String, Arc<dyn TokenRestrictionBackend>>,
    /// Trust backend plugins.
    trust_backends: HashMap<String, Arc<dyn TrustBackend>>,
}

impl PluginManagerApi for PluginManager {
    /// Get registered API Key backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `ApiKeyBackend` if found, or
    /// an `ApiKeyProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_api_key_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn ApiKeyBackend>, ApiKeyProviderError> {
        self.api_key_backends
            .get(name.as_ref())
            .ok_or(ApiKeyProviderError::UnsupportedDriver(
                name.as_ref().to_string(),
            ))
    }

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

    /// Get registered credential backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `CredentialBackend` if found,
    /// or a `CredentialProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_credential_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn CredentialBackend>, CredentialProviderError> {
        self.credential_backends.get(name.as_ref()).ok_or(
            CredentialProviderError::UnsupportedDriver(name.as_ref().to_string()),
        )
    }

    /// Get registered dynamic plugin identity-binding index backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the
    /// `DynamicPluginIdentityBackend` if found, or a
    /// `AuthPluginIdentityProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_auth_plugin_identity_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn DynamicPluginIdentityBackend>, AuthPluginIdentityProviderError> {
        self.auth_plugin_identity_backends.get(name.as_ref()).ok_or(
            AuthPluginIdentityProviderError::UnsupportedDriver(name.as_ref().to_string()),
        )
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

    /// Get registered idmapping backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `IdMappingBackend` if
    /// found, or an `IdMappingProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_idmapping_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn IdMappingBackend>, IdMappingProviderError> {
        self.idmapping_backends
            .get(name.as_ref())
            .ok_or(IdMappingProviderError::UnsupportedDriver(
                name.as_ref().to_string(),
            ))
    }

    /// Get registered mapping backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `MappingBackend` if found, or a
    /// `MappingProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_mapping_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn MappingBackend>, MappingProviderError> {
        self.mapping_backends
            .get(name.as_ref())
            .ok_or(MappingProviderError::UnsupportedDriver(
                name.as_ref().to_string(),
            ))
    }

    /// Get registered OAuth2 client backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `Oauth2ClientBackend` if
    /// found, or a `Oauth2ClientProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_oauth2_client_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn Oauth2ClientBackend>, Oauth2ClientProviderError> {
        self.oauth2_client_backends.get(name.as_ref()).ok_or(
            Oauth2ClientProviderError::UnsupportedDriver(name.as_ref().to_string()),
        )
    }

    /// Get registered OAuth2 signing key backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `Oauth2KeyBackend` if found,
    /// or a `Oauth2KeyProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_oauth2_key_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn Oauth2KeyBackend>, Oauth2KeyProviderError> {
        self.oauth2_key_backends.get(name.as_ref()).ok_or(
            Oauth2KeyProviderError::UnsupportedDriver(name.as_ref().to_string()),
        )
    }

    /// Get registered OAuth2 browser session backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `Oauth2SessionBackend` if
    /// found, or a `Oauth2SessionProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_oauth2_session_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn Oauth2SessionBackend>, Oauth2SessionProviderError> {
        self.oauth2_session_backends.get(name.as_ref()).ok_or(
            Oauth2SessionProviderError::UnsupportedDriver(name.as_ref().to_string()),
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

    /// Get registered SCIM realm backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `ScimRealmBackend` if found,
    /// or a `ScimRealmProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_scim_realm_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn ScimRealmBackend>, ScimRealmProviderError> {
        self.scim_realm_backends.get(name.as_ref()).ok_or(
            ScimRealmProviderError::UnsupportedDriver(name.as_ref().to_string()),
        )
    }

    /// Get registered SCIM resource ownership index backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to retrieve.
    ///
    /// # Returns
    /// A `Result` containing a reference to the `ScimResourceBackend` if
    /// found, or a `ScimResourceProviderError`.
    #[allow(clippy::borrowed_box)]
    fn get_scim_resource_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn ScimResourceBackend>, ScimResourceProviderError> {
        self.scim_resource_backends.get(name.as_ref()).ok_or(
            ScimResourceProviderError::UnsupportedDriver(name.as_ref().to_string()),
        )
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

    /// Register API Key backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_api_key_backend<S: AsRef<str>>(&mut self, name: S, plugin: Arc<dyn ApiKeyBackend>) {
        self.api_key_backends
            .insert(name.as_ref().to_string(), plugin);
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

    /// Register credential backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation.
    fn register_credential_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn CredentialBackend>,
    ) {
        self.credential_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register dynamic plugin identity-binding index backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation.
    fn register_auth_plugin_identity_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn DynamicPluginIdentityBackend>,
    ) {
        self.auth_plugin_identity_backends
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

    /// Register idmapping backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_idmapping_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn IdMappingBackend>,
    ) {
        self.idmapping_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register mapping backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_mapping_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn MappingBackend>,
    ) {
        self.mapping_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register OAuth2 client backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_oauth2_client_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn Oauth2ClientBackend>,
    ) {
        self.oauth2_client_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register OAuth2 signing key backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_oauth2_key_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn Oauth2KeyBackend>,
    ) {
        self.oauth2_key_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register OAuth2 browser session backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_oauth2_session_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn Oauth2SessionBackend>,
    ) {
        self.oauth2_session_backends
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

    /// Register SCIM realm backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_scim_realm_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn ScimRealmBackend>,
    ) {
        self.scim_realm_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register SCIM resource ownership index backend.
    ///
    /// # Parameters
    /// * `name` - The name of the backend to register.
    /// * `plugin` - The backend implementation to register.
    fn register_scim_resource_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn ScimResourceBackend>,
    ) {
        self.scim_resource_backends
            .insert(name.as_ref().to_string(), plugin);
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
            Arc::new(openstack_keystone_appcred_driver_sql::SqlBackend::default()),
        );
        self.register_assignment_backend(
            "sql",
            Arc::new(openstack_keystone_assignment_driver_sql::SqlBackend::default()),
        );
        self.register_catalog_backend(
            "sql",
            Arc::new(openstack_keystone_catalog_driver_sql::SqlBackend::default()),
        );
        self.register_credential_backend(
            "sql",
            Arc::new(openstack_keystone_credential_driver_sql::SqlBackend::default()),
        );
        self.register_federation_backend(
            "sql",
            Arc::new(openstack_keystone_federation_driver_sql::SqlBackend::default()),
        );
        self.register_identity_backend(
            "sql",
            Arc::new(openstack_keystone_identity_driver_sql::SqlBackend::default()),
        );
        self.register_idmapping_backend(
            "sql",
            Arc::new(openstack_keystone_idmapping_driver_sql::SqlBackend::default()),
        );
        self.register_k8s_auth_backend(
            "sql",
            Arc::new(openstack_keystone_k8s_auth_driver_sql::SqlBackend::default()),
        );
        self.register_resource_backend(
            "sql",
            Arc::new(openstack_keystone_resource_driver_sql::SqlBackend::default()),
        );
        self.register_revoke_backend(
            "sql",
            Arc::new(openstack_keystone_revoke_driver_sql::SqlBackend::default()),
        );
        self.register_role_backend(
            "sql",
            Arc::new(openstack_keystone_role_driver_sql::SqlBackend::default()),
        );
        self.register_token_restriction_backend(
            "sql",
            Arc::new(openstack_keystone_token_restriction_driver_sql::SqlBackend::default()),
        );
        self.register_trust_backend(
            "sql",
            Arc::new(openstack_keystone_trust_driver_sql::SqlBackend::default()),
        );
    }

    /// Initialize the [PluginManager] with the initialized [Config].
    ///
    /// # Parameters
    /// * `config` - The configuration to use for initialization.
    ///
    /// # Returns
    /// A new instance of `PluginManager`.
    pub async fn with_config(config: &Config) -> eyre::Result<Self> {
        let mut slf = Self {
            api_key_backends: HashMap::new(),
            application_credential_backends: HashMap::new(),
            assignment_backends: HashMap::new(),
            catalog_backends: HashMap::new(),
            credential_backends: HashMap::new(),
            auth_plugin_identity_backends: HashMap::new(),
            federation_backends: HashMap::new(),
            identity_backends: HashMap::new(),
            idmapping_backends: HashMap::new(),
            mapping_backends: HashMap::new(),
            oauth2_client_backends: HashMap::new(),
            oauth2_key_backends: HashMap::new(),
            oauth2_session_backends: HashMap::new(),
            k8s_auth_backends: HashMap::new(),
            resource_backends: HashMap::new(),
            revoke_backends: HashMap::new(),
            role_backends: HashMap::new(),
            scim_realm_backends: HashMap::new(),
            scim_resource_backends: HashMap::new(),
            token_backends: HashMap::new(),
            token_restriction_backends: HashMap::new(),
            trust_backends: HashMap::new(),
        };
        slf.register_sql_drivers();
        let mut fernet_token_provider =
            openstack_keystone_token_driver_fernet::FernetTokenProvider::new(config.clone());
        // Eagerly start the auto-refreshing key cache here, before the
        // provider is erased behind `Arc<dyn TokenBackend>`: `decrypt`/
        // `encrypt` are synchronous (called on every request) and require
        // `load_keys` to have already run.
        fernet_token_provider.load_keys().await?;
        slf.register_token_backend("fernet", Arc::new(fernet_token_provider));
        // Only load/register the JWS backend when actually selected: unlike
        // Fernet (always eagerly loaded, ADR 0019), a `[jws_tokens]` key
        // repository need not exist for a Fernet-only deployment, and
        // eagerly requiring one would break every existing installation.
        // When `[token] provider = jws` *is* selected, fail loudly here
        // (ADR 0026 §10, Phase 0) rather than silently falling back to
        // Fernet if the repository is empty or unloadable.
        if config.token.provider == openstack_keystone_config::TokenProviderDriver::Jws {
            let mut jws_token_provider =
                openstack_keystone_token_driver_jws::JwsTokenProvider::new(config.clone());
            jws_token_provider.load_keys().await?;
            slf.register_token_backend("jws", Arc::new(jws_token_provider));
        }
        slf.register_k8s_auth_backend(
            "raft",
            Arc::new(openstack_keystone_k8s_auth_driver_raft::RaftBackend::default()),
        );
        slf.register_mapping_backend(
            "raft",
            Arc::new(openstack_keystone_mapping_driver_raft::RaftBackend::default()),
        );
        slf.register_oauth2_key_backend(
            "raft",
            Arc::new(openstack_keystone_oauth2_key_driver_raft::RaftOauth2KeyBackend::default()),
        );
        slf.register_oauth2_client_backend(
            "raft",
            Arc::new(
                openstack_keystone_oauth2_client_driver_raft::RaftOauth2ClientBackend::default(),
            ),
        );
        slf.register_oauth2_session_backend(
            "raft",
            Arc::new(
                openstack_keystone_oauth2_session_driver_raft::RaftOauth2SessionBackend::default(),
            ),
        );
        slf.register_api_key_backend(
            "raft",
            Arc::new(openstack_keystone_api_key_driver_raft::RaftBackend::default()),
        );
        let scim_raft_backend =
            Arc::new(openstack_keystone_scim_driver_raft::RaftBackend::default());
        slf.register_scim_realm_backend("raft", scim_raft_backend.clone());
        slf.register_scim_resource_backend("raft", scim_raft_backend);
        slf.register_auth_plugin_identity_backend(
            "raft",
            Arc::new(openstack_keystone_auth_plugin_identity_driver_raft::RaftBackend::default()),
        );
        Ok(slf)
    }
}
