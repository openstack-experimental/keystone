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

use crate::application_credential::{
    ApplicationCredentialProviderError, backend::ApplicationCredentialBackend,
};
use crate::assignment::backend::AssignmentBackend;
use crate::assignment::error::AssignmentProviderError;
use crate::catalog::backend::CatalogBackend;
use crate::catalog::error::CatalogProviderError;
use crate::federation::backend::FederationBackend;
use crate::federation::error::FederationProviderError;
use crate::identity::backend::IdentityBackend;
use crate::identity::error::IdentityProviderError;
use crate::identity_mapping::IdentityMappingProviderError;
use crate::identity_mapping::backend::IdentityMappingBackend;
use crate::k8s_auth::K8sAuthProviderError;
use crate::k8s_auth::backend::K8sAuthBackend;
use crate::resource::backend::ResourceBackend;
use crate::resource::error::ResourceProviderError;
use crate::revoke::RevokeProviderError;
use crate::revoke::backend::RevokeBackend;
use crate::role::RoleProviderError;
use crate::role::backend::RoleBackend;
use crate::token::TokenProviderError;
use crate::token::backend::TokenRestrictionBackend;
use crate::trust::TrustProviderError;
use crate::trust::backend::TrustBackend;

/// Plugin manager allowing to pass custom backend plugins implementing required
/// trait during the service start.
#[derive(Clone, Default)]
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
    /// Token restriction backend plugins.
    token_restriction_backends: HashMap<String, Arc<dyn TokenRestrictionBackend>>,
    /// Trust backend plugins.
    trust_backends: HashMap<String, Arc<dyn TrustBackend>>,
}

impl PluginManager {
    /// Get registered application credential backend.
    #[allow(clippy::borrowed_box)]
    pub fn get_application_credential_backend<S: AsRef<str>>(
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
    #[allow(clippy::borrowed_box)]
    pub fn get_assignment_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn AssignmentBackend>, AssignmentProviderError> {
        self.assignment_backends.get(name.as_ref()).ok_or(
            AssignmentProviderError::UnsupportedDriver(name.as_ref().to_string()),
        )
    }

    /// Get registered catalog backend.
    #[allow(clippy::borrowed_box)]
    pub fn get_catalog_backend<S: AsRef<str>>(
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
    #[allow(clippy::borrowed_box)]
    pub fn get_federation_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn FederationBackend>, FederationProviderError> {
        self.federation_backends.get(name.as_ref()).ok_or(
            FederationProviderError::UnsupportedDriver(name.as_ref().to_string()),
        )
    }

    /// Get registered identity backend.
    #[allow(clippy::borrowed_box)]
    pub fn get_identity_backend<S: AsRef<str>>(
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
    #[allow(clippy::borrowed_box)]
    pub fn get_identity_mapping_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn IdentityMappingBackend>, IdentityMappingProviderError> {
        self.identity_mapping_backends.get(name.as_ref()).ok_or(
            IdentityMappingProviderError::UnsupportedDriver(name.as_ref().to_string()),
        )
    }

    /// Get registered k8s auth backend.
    #[allow(clippy::borrowed_box)]
    pub fn get_k8s_auth_backend<S: AsRef<str>>(
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
    #[allow(clippy::borrowed_box)]
    pub fn get_resource_backend<S: AsRef<str>>(
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
    #[allow(clippy::borrowed_box)]
    pub fn get_revoke_backend<S: AsRef<str>>(
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
    #[allow(clippy::borrowed_box)]
    pub fn get_role_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn RoleBackend>, RoleProviderError> {
        self.role_backends
            .get(name.as_ref())
            .ok_or(RoleProviderError::UnsupportedDriver(
                name.as_ref().to_string(),
            ))
    }

    /// Get registered token restriction backend.
    #[allow(clippy::borrowed_box)]
    pub fn get_token_restriction_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn TokenRestrictionBackend>, TokenProviderError> {
        self.token_restriction_backends.get(name.as_ref()).ok_or(
            TokenProviderError::UnsupportedTRDriver(name.as_ref().to_string()),
        )
    }

    /// Get registered trust backend.
    #[allow(clippy::borrowed_box)]
    pub fn get_trust_backend<S: AsRef<str>>(
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
    pub fn register_application_credential_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn ApplicationCredentialBackend>,
    ) {
        self.application_credential_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register assignment backend.
    pub fn register_assignment_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn AssignmentBackend>,
    ) {
        self.assignment_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register catalog backend.
    pub fn register_catalog_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn CatalogBackend>,
    ) {
        self.catalog_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register federation backend.
    pub fn register_federation_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn FederationBackend>,
    ) {
        self.federation_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register identity backend.
    pub fn register_identity_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn IdentityBackend>,
    ) {
        self.identity_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register identity mapping backend.
    pub fn register_identity_mapping_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn IdentityMappingBackend>,
    ) {
        self.identity_mapping_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register k8s_auth backend.
    pub fn register_k8s_auth_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn K8sAuthBackend>,
    ) {
        self.k8s_auth_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register resource backend.
    pub fn register_resource_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn ResourceBackend>,
    ) {
        self.resource_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register revoke backend.
    pub fn register_revoke_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn RevokeBackend>,
    ) {
        self.revoke_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register role backend.
    pub fn register_role_backend<S: AsRef<str>>(&mut self, name: S, plugin: Arc<dyn RoleBackend>) {
        self.role_backends.insert(name.as_ref().to_string(), plugin);
    }

    /// Register token restriction backend.
    pub fn register_token_restriction_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn TokenRestrictionBackend>,
    ) {
        self.token_restriction_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Register trust backend.
    pub fn register_trust_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn TrustBackend>,
    ) {
        self.trust_backends
            .insert(name.as_ref().to_string(), plugin);
    }
}
