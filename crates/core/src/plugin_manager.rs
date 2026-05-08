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
//! The [PluginManagerApi] is responsible for picking the proper backend driver
//! for the provider.
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
use crate::spiffe::SpiffeProviderError;
use crate::spiffe::backend::SpiffeBackend;
use crate::token::TokenProviderError;
use crate::token::backend::TokenBackend;
use crate::token::backend::TokenRestrictionBackend;
use crate::trust::TrustProviderError;
use crate::trust::backend::TrustBackend;

/// Plugin manager trait.
pub trait PluginManagerApi {
    /// Get registered application credential backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn ApplicationCredentialBackend>)` if found, otherwise
    ///   `Err(ApplicationCredentialProviderError)`.
    fn get_application_credential_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn ApplicationCredentialBackend>, ApplicationCredentialProviderError>;

    /// Get registered assignment backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn AssignmentBackend>)` if found, otherwise
    ///   `Err(AssignmentProviderError)`.
    fn get_assignment_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn AssignmentBackend>, AssignmentProviderError>;

    /// Get registered catalog backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn CatalogBackend>)` if found, otherwise
    ///   `Err(CatalogProviderError)`.
    fn get_catalog_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn CatalogBackend>, CatalogProviderError>;

    /// Get registered federation backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn FederationBackend>)` if found, otherwise
    ///   `Err(FederationProviderError)`.
    fn get_federation_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn FederationBackend>, FederationProviderError>;

    /// Get registered identity backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn IdentityBackend>)` if found, otherwise
    ///   `Err(IdentityProviderError)`.
    fn get_identity_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn IdentityBackend>, IdentityProviderError>;

    /// Get registered identity mapping backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn IdentityMappingBackend>)` if found, otherwise
    ///   `Err(IdentityMappingProviderError)`.
    fn get_identity_mapping_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn IdentityMappingBackend>, IdentityMappingProviderError>;

    /// Get registered k8s auth backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn K8sAuthBackend>)` if found, otherwise
    ///   `Err(K8sAuthProviderError)`.
    fn get_k8s_auth_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn K8sAuthBackend>, K8sAuthProviderError>;

    /// Get registered spiffe backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn SpiffeBackend>)` if found, otherwise
    ///   `Err(SpiffeProviderError)`.
    fn get_spiffe_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn SpiffeBackend>, SpiffeProviderError>;

    /// Get registered resource backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn ResourceBackend>)` if found, otherwise
    ///   `Err(ResourceProviderError)`.
    fn get_resource_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn ResourceBackend>, ResourceProviderError>;

    /// Get registered revoke backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn RevokeBackend>)` if found, otherwise
    ///   `Err(RevokeProviderError)`.
    fn get_revoke_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn RevokeBackend>, RevokeProviderError>;

    /// Get role resource backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn RoleBackend>)` if found, otherwise
    ///   `Err(RoleProviderError)`.
    fn get_role_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn RoleBackend>, RoleProviderError>;

    /// Get registered token backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn TokenBackend>)` if found, otherwise
    ///   `Err(TokenProviderError)`.
    fn get_token_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn TokenBackend>, TokenProviderError>;

    /// Get registered token restriction backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn TokenRestrictionBackend>)` if found, otherwise
    ///   `Err(TokenProviderError)`.
    fn get_token_restriction_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn TokenRestrictionBackend>, TokenProviderError>;

    /// Get registered trust backend.
    ///
    /// # Parameters
    /// - `name`: The name of the backend to retrieve.
    ///
    /// # Returns
    /// - `Ok(&Arc<dyn TrustBackend>)` if found, otherwise
    ///   `Err(TrustProviderError)`.
    fn get_trust_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Result<&Arc<dyn TrustBackend>, TrustProviderError>;

    /// Register application credential backend.
    ///
    /// # Parameters
    /// - `name`: The name to register the backend under.
    /// - `plugin`: The backend implementation.
    fn register_application_credential_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn ApplicationCredentialBackend>,
    );

    /// Register assignment backend.
    ///
    /// # Parameters
    /// - `name`: The name to register the backend under.
    /// - `plugin`: The backend implementation.
    fn register_assignment_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn AssignmentBackend>,
    );

    /// Register catalog backend.
    ///
    /// # Parameters
    /// - `name`: The name to register the backend under.
    /// - `plugin`: The backend implementation.
    fn register_catalog_backend<S: AsRef<str>>(&mut self, name: S, plugin: Arc<dyn CatalogBackend>);

    /// Register federation backend.
    ///
    /// # Parameters
    /// - `name`: The name to register the backend under.
    /// - `plugin`: The backend implementation.
    fn register_federation_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn FederationBackend>,
    );

    /// Register identity backend.
    ///
    /// # Parameters
    /// - `name`: The name to register the backend under.
    /// - `plugin`: The backend implementation.
    fn register_identity_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn IdentityBackend>,
    );

    /// Register identity mapping backend.
    ///
    /// # Parameters
    /// - `name`: The name to register the backend under.
    /// - `plugin`: The backend implementation.
    fn register_identity_mapping_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn IdentityMappingBackend>,
    );

    /// Register k8s_auth backend.
    ///
    /// # Parameters
    /// - `name`: The name to register the backend under.
    /// - `plugin`: The backend implementation.
    fn register_k8s_auth_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn K8sAuthBackend>,
    );

    /// Register resource backend.
    ///
    /// # Parameters
    /// - `name`: The name to register the backend under.
    /// - `plugin`: The backend implementation.
    fn register_resource_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn ResourceBackend>,
    );

    /// Register revoke backend.
    ///
    /// # Parameters
    /// - `name`: The name to register the backend under.
    /// - `plugin`: The backend implementation.
    fn register_revoke_backend<S: AsRef<str>>(&mut self, name: S, plugin: Arc<dyn RevokeBackend>);

    /// Register role backend.
    ///
    /// # Parameters
    /// - `name`: The name to register the backend under.
    /// - `plugin`: The backend implementation.
    fn register_role_backend<S: AsRef<str>>(&mut self, name: S, plugin: Arc<dyn RoleBackend>);

    /// Register token backend.
    ///
    /// # Parameters
    /// - `name`: The name to register the backend under.
    /// - `plugin`: The backend implementation.
    fn register_token_backend<S: AsRef<str>>(&mut self, name: S, plugin: Arc<dyn TokenBackend>);

    /// Register token restriction backend.
    ///
    /// # Parameters
    /// - `name`: The name to register the backend under.
    /// - `plugin`: The backend implementation.
    fn register_token_restriction_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Arc<dyn TokenRestrictionBackend>,
    );

    /// Register trust backend.
    ///
    /// # Parameters
    /// - `name`: The name to register the backend under.
    /// - `plugin`: The backend implementation.
    fn register_trust_backend<S: AsRef<str>>(&mut self, name: S, plugin: Arc<dyn TrustBackend>);
}
