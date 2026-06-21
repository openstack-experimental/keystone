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
//! # Provider manager
//!
//! Provider manager provides access to the individual service providers. This
//! gives an easy interact for passing overall manager down to the individual
//! providers that might need to call other providers while also allowing an
//! easy injection of mocked providers.
use derive_builder::Builder;
use std::sync::Arc;

use openstack_keystone_config::Config;

use crate::application_credential::ApplicationCredentialApi;
use crate::application_credential::ApplicationCredentialService;
use crate::assignment::AssignmentApi;
use crate::assignment::AssignmentService;
use crate::catalog::CatalogApi;
use crate::catalog::CatalogService;
use crate::error::KeystoneError;
use crate::federation::FederationApi;
use crate::federation::FederationService;
use crate::identity::IdentityApi;
use crate::identity::IdentityService;
use crate::idmapping::IdMappingApi;
use crate::idmapping::IdMappingService;
use crate::k8s_auth::K8sAuthApi;
use crate::k8s_auth::K8sAuthService;
use crate::k8s_auth::K8sHttpClient;
use crate::mapping::MappingApi;
use crate::mapping::MappingService;
use crate::plugin_manager::PluginManagerApi;
use crate::resource::ResourceApi;
use crate::resource::ResourceService;
use crate::revoke::RevokeApi;
use crate::revoke::RevokeService;
use crate::role::RoleApi;
use crate::role::RoleService;
use crate::token::TokenApi;
use crate::token::TokenService;
use crate::trust::TrustApi;
use crate::trust::TrustService;

/// Global provider manager.
#[derive(Builder)]
// It is necessary to use the owned pattern since otherwise builder invokes clone which immediately
// confuses mockall used in tests
#[builder(pattern = "owned")]
pub struct Provider {
    /// Application credential provider.
    application_credential: Box<dyn ApplicationCredentialApi>,
    /// Assignment provider.
    assignment: Box<dyn AssignmentApi>,
    /// Catalog provider.
    catalog: Box<dyn CatalogApi>,
    /// Federation provider.
    federation: Box<dyn FederationApi>,
    /// Identity provider.
    identity: Box<dyn IdentityApi>,
    /// IdMapping provider.
    idmapping: Box<dyn IdMappingApi>,
    /// Mapping provider.
    mapping: Box<dyn MappingApi>,
    /// K8s auth provider.
    k8s_auth: Box<dyn K8sAuthApi>,
    /// Resource provider.
    resource: Box<dyn ResourceApi>,
    /// Revoke provider.
    revoke: Box<dyn RevokeApi>,
    /// Role provider.
    role: Box<dyn RoleApi>,
    /// Token provider.
    token: Box<dyn TokenApi>,
    /// Trust provider.
    trust: Box<dyn TrustApi>,
}

impl ProviderBuilder {
    pub fn mock_application_credential(
        self,
        value: impl ApplicationCredentialApi + 'static,
    ) -> Self {
        let mut new = self;
        new.application_credential = Some(Box::new(value));
        new
    }

    pub fn mock_assignment(self, value: impl AssignmentApi + 'static) -> Self {
        let mut new = self;
        new.assignment = Some(Box::new(value));
        new
    }

    pub fn mock_catalog(self, value: impl CatalogApi + 'static) -> Self {
        let mut new = self;
        new.catalog = Some(Box::new(value));
        new
    }

    pub fn mock_federation(self, value: impl FederationApi + 'static) -> Self {
        let mut new = self;
        new.federation = Some(Box::new(value));
        new
    }

    pub fn mock_identity(self, value: impl IdentityApi + 'static) -> Self {
        let mut new = self;
        new.identity = Some(Box::new(value));
        new
    }
    pub fn mock_idmapping(self, value: impl IdMappingApi + 'static) -> Self {
        let mut new = self;
        new.idmapping = Some(Box::new(value));
        new
    }
    pub fn mock_mapping(self, value: impl MappingApi + 'static) -> Self {
        let mut new = self;
        new.mapping = Some(Box::new(value));
        new
    }
    pub fn mock_k8s_auth(self, value: impl K8sAuthApi + 'static) -> Self {
        let mut new = self;
        new.k8s_auth = Some(Box::new(value));
        new
    }
    pub fn mock_resource(self, value: impl ResourceApi + 'static) -> Self {
        let mut new = self;
        new.resource = Some(Box::new(value));
        new
    }
    pub fn mock_revoke(self, value: impl RevokeApi + 'static) -> Self {
        let mut new = self;
        new.revoke = Some(Box::new(value));
        new
    }
    pub fn mock_role(self, value: impl RoleApi + 'static) -> Self {
        let mut new = self;
        new.role = Some(Box::new(value));
        new
    }
    pub fn mock_token(self, value: impl TokenApi + 'static) -> Self {
        let mut new = self;
        new.token = Some(Box::new(value));
        new
    }
    pub fn mock_trust(self, value: impl TrustApi + 'static) -> Self {
        let mut new = self;
        new.trust = Some(Box::new(value));
        new
    }
}

impl Provider {
    /// Create a new Provider manager.
    pub fn new<P: PluginManagerApi>(
        cfg: &Config,
        plugin_manager: &P,
        k8s_http_client: Arc<dyn K8sHttpClient>,
    ) -> Result<Self, KeystoneError> {
        let application_credential = ApplicationCredentialService::new(cfg, plugin_manager)
            .map_err(|e| KeystoneError::ApplicationCredential { source: e })?;
        let assignment = AssignmentService::new(cfg, plugin_manager)
            .map_err(|e| KeystoneError::AssignmentProvider { source: e })?;
        let catalog = CatalogService::new(cfg, plugin_manager)
            .map_err(|e| KeystoneError::CatalogProvider { source: e })?;
        let federation = FederationService::new(cfg, plugin_manager)
            .map_err(|e| KeystoneError::FederationProvider { source: e })?;
        let identity = IdentityService::new(cfg, plugin_manager)
            .map_err(|e| KeystoneError::IdentityProvider { source: e })?;
        let idmapping = IdMappingService::new(cfg, plugin_manager)
            .map_err(|e| KeystoneError::IdMapping { source: e })?;
        let mapping = MappingService::new(cfg, plugin_manager)
            .map_err(|e| KeystoneError::Mapping { source: e })?;
        let k8s_auth = K8sAuthService::new(cfg, plugin_manager, k8s_http_client)
            .map_err(|e| KeystoneError::K8sAuthProvider { source: e })?;
        let resource = ResourceService::new(cfg, plugin_manager)
            .map_err(|e| KeystoneError::ResourceProvider { source: e })?;
        let revoke = RevokeService::new(cfg, plugin_manager)
            .map_err(|e| KeystoneError::RevokeProvider { source: e })?;
        let role = RoleService::new(cfg, plugin_manager)
            .map_err(|e| KeystoneError::RoleProvider { source: e })?;
        let token = TokenService::new(cfg, plugin_manager)
            .map_err(|e| KeystoneError::TokenProvider { source: e })?;
        let trust = TrustService::new(cfg, plugin_manager)
            .map_err(|e| KeystoneError::TrustProvider { source: e })?;

        Ok(Self {
            application_credential: Box::new(application_credential),
            assignment: Box::new(assignment),
            catalog: Box::new(catalog),
            federation: Box::new(federation),
            identity: Box::new(identity),
            idmapping: Box::new(idmapping),
            mapping: Box::new(mapping),
            k8s_auth: Box::new(k8s_auth),
            resource: Box::new(resource),
            revoke: Box::new(revoke),
            role: Box::new(role),
            token: Box::new(token),
            trust: Box::new(trust),
        })
    }

    /// Get the application credential provider.
    pub fn get_application_credential_provider(&self) -> &dyn ApplicationCredentialApi {
        &*self.application_credential
    }

    /// Get the assignment provider.
    pub fn get_assignment_provider(&self) -> &dyn AssignmentApi {
        &*self.assignment
    }

    /// Get the catalog provider.
    pub fn get_catalog_provider(&self) -> &dyn CatalogApi {
        &*self.catalog
    }

    /// Get the federation provider.
    pub fn get_federation_provider(&self) -> &dyn FederationApi {
        &*self.federation
    }

    /// Get the identity provider.
    pub fn get_identity_provider(&self) -> &dyn IdentityApi {
        &*self.identity
    }

    /// Get the idmapping provider.
    pub fn get_idmapping_provider(&self) -> &dyn IdMappingApi {
        &*self.idmapping
    }

    /// Get the mapping provider.
    pub fn get_mapping_provider(&self) -> &dyn MappingApi {
        &*self.mapping
    }

    /// Get the K8s auth provider.
    pub fn get_k8s_auth_provider(&self) -> &dyn K8sAuthApi {
        &*self.k8s_auth
    }

    /// Get the resource provider.
    pub fn get_resource_provider(&self) -> &dyn ResourceApi {
        &*self.resource
    }

    /// Get the revocation provider.
    pub fn get_revoke_provider(&self) -> &dyn RevokeApi {
        &*self.revoke
    }

    /// Get the role provider.
    pub fn get_role_provider(&self) -> &dyn RoleApi {
        &*self.role
    }

    /// Get the token provider.
    pub fn get_token_provider(&self) -> &dyn TokenApi {
        &*self.token
    }

    /// Get the trust provider.
    pub fn get_trust_provider(&self) -> &dyn TrustApi {
        &*self.trust
    }

    /// Returns a `ProviderBuilder` pre-configured with default mock providers
    /// for all 13 provider slots. Each slot is set to `Box::new(MockXxx::default())`.
    ///
    /// Individual providers can be overridden by chaining `.mock_xxx((custom_mock))`
    /// calls on the returned builder.
    #[cfg(any(test, feature = "mock"))]
    pub fn mocked_builder() -> ProviderBuilder {
        use crate::application_credential::MockApplicationCredentialProvider;
        use crate::assignment::MockAssignmentProvider;
        use crate::catalog::MockCatalogProvider;
        use crate::federation::MockFederationProvider;
        use crate::identity::MockIdentityProvider;
        use crate::idmapping::MockIdMappingProvider;
        use crate::k8s_auth::MockK8sAuthProvider;
        use crate::mapping::MockMappingProvider;
        use crate::resource::MockResourceProvider;
        use crate::revoke::MockRevokeProvider;
        use crate::role::MockRoleProvider;
        use crate::token::MockTokenProvider;
        use crate::trust::MockTrustProvider;

        ProviderBuilder::default()
            .application_credential(Box::new(MockApplicationCredentialProvider::default()))
            .assignment(Box::new(MockAssignmentProvider::default()))
            .catalog(Box::new(MockCatalogProvider::default()))
            .federation(Box::new(MockFederationProvider::default()))
            .identity(Box::new(MockIdentityProvider::default()))
            .idmapping(Box::new(MockIdMappingProvider::default()))
            .mapping(Box::new(MockMappingProvider::default()))
            .k8s_auth(Box::new(MockK8sAuthProvider::default()))
            .resource(Box::new(MockResourceProvider::default()))
            .revoke(Box::new(MockRevokeProvider::default()))
            .role(Box::new(MockRoleProvider::default()))
            .token(Box::new(MockTokenProvider::default()))
            .trust(Box::new(MockTrustProvider::default()))
    }
}
