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

use crate::api_key::ApiKeyApi;
#[cfg(any(test, feature = "mock"))]
use crate::api_key::MockApiKeyProvider;
use crate::application_credential::ApplicationCredentialApi;
#[cfg(any(test, feature = "mock"))]
use crate::application_credential::MockApplicationCredentialProvider;
use crate::assignment::AssignmentApi;
#[cfg(any(test, feature = "mock"))]
use crate::assignment::MockAssignmentProvider;
use crate::catalog::CatalogApi;
#[cfg(any(test, feature = "mock"))]
use crate::catalog::MockCatalogProvider;
use crate::credential::CredentialApi;
#[cfg(any(test, feature = "mock"))]
use crate::credential::MockCredentialProvider;
use crate::dynamic_plugin_identity::DynamicPluginIdentityApi;
#[cfg(any(test, feature = "mock"))]
use crate::dynamic_plugin_identity::MockDynamicPluginIdentityProvider;
use crate::error::KeystoneError;
use crate::federation::FederationApi;
#[cfg(any(test, feature = "mock"))]
use crate::federation::MockFederationProvider;
use crate::identity::IdentityApi;
#[cfg(any(test, feature = "mock"))]
use crate::identity::MockIdentityProvider;
use crate::idmapping::IdMappingApi;
#[cfg(any(test, feature = "mock"))]
use crate::idmapping::MockIdMappingProvider;
use crate::k8s_auth::K8sAuthApi;
use crate::k8s_auth::K8sHttpClient;
#[cfg(any(test, feature = "mock"))]
use crate::k8s_auth::MockK8sAuthProvider;
use crate::mapping::MappingApi;
#[cfg(any(test, feature = "mock"))]
use crate::mapping::MockMappingProvider;
use crate::plugin_manager::PluginManagerApi;
#[cfg(any(test, feature = "mock"))]
use crate::resource::MockResourceProvider;
use crate::resource::ResourceApi;
#[cfg(any(test, feature = "mock"))]
use crate::revoke::MockRevokeProvider;
use crate::revoke::RevokeApi;
#[cfg(any(test, feature = "mock"))]
use crate::role::MockRoleProvider;
use crate::role::RoleApi;
#[cfg(any(test, feature = "mock"))]
use crate::scim_realm::MockScimRealmProvider;
use crate::scim_realm::ScimRealmApi;
#[cfg(any(test, feature = "mock"))]
use crate::scim_resource::MockScimResourceProvider;
use crate::scim_resource::ScimResourceApi;
#[cfg(any(test, feature = "mock"))]
use crate::token::MockTokenProvider;
use crate::token::TokenApi;
#[cfg(any(test, feature = "mock"))]
use crate::trust::MockTrustProvider;
use crate::trust::TrustApi;

/// Global provider manager.
#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct Provider {
    /// API Key provider.
    api_key: Box<dyn ApiKeyApi>,
    /// Application credential provider.
    application_credential: Box<dyn ApplicationCredentialApi>,
    /// Assignment provider.
    assignment: Box<dyn AssignmentApi>,
    /// Catalog provider.
    catalog: Box<dyn CatalogApi>,
    /// Credential provider.
    credential: Box<dyn CredentialApi>,
    /// Dynamic plugin identity-binding index provider.
    dynamic_plugin_identity: Box<dyn DynamicPluginIdentityApi>,
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
    /// SCIM realm provider.
    scim_realm: Box<dyn ScimRealmApi>,
    /// SCIM resource ownership index provider.
    scim_resource: Box<dyn ScimResourceApi>,
    /// Token provider.
    token: Box<dyn TokenApi>,
    /// Trust provider.
    trust: Box<dyn TrustApi>,
}

#[cfg(any(test, feature = "mock"))]
impl ProviderBuilder {
    pub fn mock_api_key(self, value: impl ApiKeyApi + 'static) -> Self {
        let mut new = self;
        new.api_key = Some(Box::new(value));
        new
    }

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

    pub fn mock_credential(self, value: impl CredentialApi + 'static) -> Self {
        let mut new = self;
        new.credential = Some(Box::new(value));
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

    pub fn mock_dynamic_plugin_identity(
        self,
        value: impl DynamicPluginIdentityApi + 'static,
    ) -> Self {
        let mut new = self;
        new.dynamic_plugin_identity = Some(Box::new(value));
        new
    }

    pub fn mock_scim_realm(self, value: impl ScimRealmApi + 'static) -> Self {
        let mut new = self;
        new.scim_realm = Some(Box::new(value));
        new
    }

    pub fn mock_scim_resource(self, value: impl ScimResourceApi + 'static) -> Self {
        let mut new = self;
        new.scim_resource = Some(Box::new(value));
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
        let api_key = Box::new(crate::api_key::ApiKeyService::new(cfg, plugin_manager)?);
        let application_credential = Box::new(
            crate::application_credential::ApplicationCredentialService::new(cfg, plugin_manager)?,
        );
        let assignment = Box::new(crate::assignment::AssignmentService::new(
            cfg,
            plugin_manager,
        )?);
        let catalog = Box::new(crate::catalog::CatalogService::new(cfg, plugin_manager)?);
        let credential = Box::new(crate::credential::CredentialService::new(
            cfg,
            plugin_manager,
        )?);
        let dynamic_plugin_identity = Box::new(
            crate::dynamic_plugin_identity::DynamicPluginIdentityService::new(cfg, plugin_manager)?,
        );
        let federation = Box::new(crate::federation::FederationService::new(
            cfg,
            plugin_manager,
        )?);
        let identity = Box::new(crate::identity::IdentityService::new(cfg, plugin_manager)?);
        let idmapping = Box::new(crate::idmapping::IdMappingService::new(
            cfg,
            plugin_manager,
        )?);
        let mapping = Box::new(crate::mapping::MappingService::new(cfg, plugin_manager)?);
        let k8s_auth = Box::new(
            crate::k8s_auth::K8sAuthService::new(cfg, plugin_manager, k8s_http_client)
                .map_err(|e| KeystoneError::K8sAuthProvider { source: e })?,
        );
        let resource = Box::new(crate::resource::ResourceService::new(cfg, plugin_manager)?);
        let revoke = Box::new(crate::revoke::RevokeService::new(cfg, plugin_manager)?);
        let role = Box::new(crate::role::RoleService::new(cfg, plugin_manager)?);
        let scim_realm = Box::new(crate::scim_realm::ScimRealmService::new(
            cfg,
            plugin_manager,
        )?);
        let scim_resource = Box::new(crate::scim_resource::ScimResourceService::new(
            cfg,
            plugin_manager,
        )?);
        let token = Box::new(crate::token::TokenService::new(cfg, plugin_manager)?);
        let trust = Box::new(crate::trust::TrustService::new(cfg, plugin_manager)?);

        Ok(Self {
            api_key,
            application_credential,
            assignment,
            catalog,
            credential,
            dynamic_plugin_identity,
            federation,
            identity,
            idmapping,
            mapping,
            k8s_auth,
            resource,
            revoke,
            role,
            scim_realm,
            scim_resource,
            token,
            trust,
        })
    }

    /// Create a mocked Provider builder.
    #[cfg(any(test, feature = "mock"))]
    pub fn mocked_builder() -> ProviderBuilder {
        ProviderBuilder::default()
            .mock_api_key(MockApiKeyProvider::default())
            .mock_application_credential(MockApplicationCredentialProvider::default())
            .mock_assignment(MockAssignmentProvider::default())
            .mock_catalog(MockCatalogProvider::default())
            .mock_credential(MockCredentialProvider::default())
            .mock_dynamic_plugin_identity(MockDynamicPluginIdentityProvider::default())
            .mock_identity(MockIdentityProvider::default())
            .mock_idmapping(MockIdMappingProvider::default())
            .mock_mapping(MockMappingProvider::default())
            .mock_federation(MockFederationProvider::default())
            .mock_k8s_auth(MockK8sAuthProvider::default())
            .mock_resource(MockResourceProvider::default())
            .mock_revoke(MockRevokeProvider::default())
            .mock_role(MockRoleProvider::default())
            .mock_scim_realm(MockScimRealmProvider::default())
            .mock_scim_resource(MockScimResourceProvider::default())
            .mock_token(MockTokenProvider::default())
            .mock_trust(MockTrustProvider::default())
    }

    /// Get the API Key provider.
    pub fn get_api_key_provider(&self) -> &dyn ApiKeyApi {
        &*self.api_key
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

    /// Get the credential provider.
    pub fn get_credential_provider(&self) -> &dyn CredentialApi {
        &*self.credential
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

    /// Get the dynamic plugin identity-binding index provider.
    pub fn get_dynamic_plugin_identity_provider(&self) -> &dyn DynamicPluginIdentityApi {
        &*self.dynamic_plugin_identity
    }

    /// Get the SCIM realm provider.
    pub fn get_scim_realm_provider(&self) -> &dyn ScimRealmApi {
        &*self.scim_realm
    }

    /// Get the SCIM resource ownership index provider.
    pub fn get_scim_resource_provider(&self) -> &dyn ScimResourceApi {
        &*self.scim_resource
    }

    /// Get the token provider.
    pub fn get_token_provider(&self) -> &dyn TokenApi {
        &*self.token
    }

    /// Get the trust provider.
    pub fn get_trust_provider(&self) -> &dyn TrustApi {
        &*self.trust
    }
}
