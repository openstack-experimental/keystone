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

use openstack_keystone_config::Config;

use crate::application_credential::ApplicationCredentialProvider;
#[cfg(any(test, feature = "mock"))]
use crate::application_credential::MockApplicationCredentialProvider;
use crate::assignment::AssignmentProvider;
#[cfg(any(test, feature = "mock"))]
use crate::assignment::MockAssignmentProvider;
use crate::catalog::CatalogProvider;
#[cfg(any(test, feature = "mock"))]
use crate::catalog::MockCatalogProvider;
use crate::error::KeystoneError;
use crate::federation::FederationProvider;
#[cfg(any(test, feature = "mock"))]
use crate::federation::MockFederationProvider;
use crate::identity::IdentityProvider;
#[cfg(any(test, feature = "mock"))]
use crate::identity::MockIdentityProvider;
use crate::identity_mapping::IdentityMappingProvider;
#[cfg(any(test, feature = "mock"))]
use crate::identity_mapping::MockIdentityMappingProvider;
use crate::k8s_auth::K8sAuthProvider;
#[cfg(any(test, feature = "mock"))]
use crate::k8s_auth::MockK8sAuthProvider;
use crate::plugin_manager::PluginManagerApi;
#[cfg(any(test, feature = "mock"))]
use crate::resource::MockResourceProvider;
use crate::resource::ResourceProvider;
#[cfg(any(test, feature = "mock"))]
use crate::revoke::MockRevokeProvider;
use crate::revoke::RevokeProvider;
#[cfg(any(test, feature = "mock"))]
use crate::role::MockRoleProvider;
use crate::role::RoleProvider;
#[cfg(any(test, feature = "mock"))]
use crate::spiffe::MockSpiffeProvider;
use crate::spiffe::SpiffeProvider;
#[cfg(any(test, feature = "mock"))]
use crate::token::MockTokenProvider;
use crate::token::TokenProvider;
#[cfg(any(test, feature = "mock"))]
use crate::trust::MockTrustProvider;
use crate::trust::TrustProvider;

/// Global provider manager.
#[derive(Builder)]
// It is necessary to use the owned pattern since otherwise builder invokes clone which immediately
// confuses mockall used in tests
#[builder(pattern = "owned")]
pub struct Provider {
    /// Application credential provider.
    application_credential: ApplicationCredentialProvider,
    /// Assignment provider.
    assignment: AssignmentProvider,
    /// Catalog provider.
    catalog: CatalogProvider,
    /// Federation provider.
    federation: FederationProvider,
    /// Identity provider.
    identity: IdentityProvider,
    /// Identity mapping provider.
    identity_mapping: IdentityMappingProvider,
    /// K8s auth provider.
    k8s_auth: K8sAuthProvider,
    /// Spiffe provider.
    spiffe: SpiffeProvider,
    /// Resource provider.
    resource: ResourceProvider,
    /// Revoke provider.
    revoke: RevokeProvider,
    /// Role provider.
    role: RoleProvider,
    /// Token provider.
    token: TokenProvider,
    /// Trust provider.
    trust: TrustProvider,
}

#[cfg(any(test, feature = "mock"))]
impl ProviderBuilder {
    pub fn mock_application_credential(self, value: MockApplicationCredentialProvider) -> Self {
        let mut new = self;
        new.application_credential = Some(ApplicationCredentialProvider::Mock(value));
        new
    }

    pub fn mock_assignment(self, value: MockAssignmentProvider) -> Self {
        let mut new = self;
        new.assignment = Some(AssignmentProvider::Mock(value));
        new
    }

    pub fn mock_catalog(self, value: MockCatalogProvider) -> Self {
        let mut new = self;
        new.catalog = Some(CatalogProvider::Mock(value));
        new
    }

    pub fn mock_federation(self, value: MockFederationProvider) -> Self {
        let mut new = self;
        new.federation = Some(FederationProvider::Mock(value));
        new
    }

    pub fn mock_identity(self, value: MockIdentityProvider) -> Self {
        let mut new = self;
        new.identity = Some(IdentityProvider::Mock(value));
        new
    }
    pub fn mock_identity_mapping(self, value: MockIdentityMappingProvider) -> Self {
        let mut new = self;
        new.identity_mapping = Some(IdentityMappingProvider::Mock(value));
        new
    }
    pub fn mock_k8s_auth(self, value: MockK8sAuthProvider) -> Self {
        let mut new = self;
        new.k8s_auth = Some(K8sAuthProvider::Mock(value));
        new
    }
    pub fn mock_spiffe(self, value: MockSpiffeProvider) -> Self {
        let mut new = self;
        new.spiffe = Some(SpiffeProvider::Mock(value));
        new
    }
    pub fn mock_resource(self, value: MockResourceProvider) -> Self {
        let mut new = self;
        new.resource = Some(ResourceProvider::Mock(value));
        new
    }
    pub fn mock_revoke(self, value: MockRevokeProvider) -> Self {
        let mut new = self;
        new.revoke = Some(RevokeProvider::Mock(value));
        new
    }
    pub fn mock_role(self, value: MockRoleProvider) -> Self {
        let mut new = self;
        new.role = Some(RoleProvider::Mock(value));
        new
    }
    pub fn mock_token(self, value: MockTokenProvider) -> Self {
        let mut new = self;
        new.token = Some(TokenProvider::Mock(value));
        new
    }
    pub fn mock_trust(self, value: MockTrustProvider) -> Self {
        let mut new = self;
        new.trust = Some(TrustProvider::Mock(value));
        new
    }
}

impl Provider {
    /// Create a new Provider manager.
    pub fn new<P: PluginManagerApi>(
        cfg: &Config,
        plugin_manager: &P,
    ) -> Result<Self, KeystoneError> {
        let application_credential_provider =
            ApplicationCredentialProvider::new(&cfg, plugin_manager)?;
        let assignment_provider = AssignmentProvider::new(&cfg, plugin_manager)?;
        let catalog_provider = CatalogProvider::new(&cfg, plugin_manager)?;
        let federation_provider = FederationProvider::new(&cfg, plugin_manager)?;
        let identity_provider = IdentityProvider::new(&cfg, plugin_manager)?;
        let identity_mapping_provider = IdentityMappingProvider::new(&cfg, plugin_manager)?;
        let k8s_auth_provider = K8sAuthProvider::new(&cfg, plugin_manager)?;
        let spiffe_provider = SpiffeProvider::new(&cfg, plugin_manager)?;
        let resource_provider = ResourceProvider::new(&cfg, plugin_manager)?;
        let revoke_provider = RevokeProvider::new(&cfg, plugin_manager)?;
        let role_provider = RoleProvider::new(&cfg, plugin_manager)?;
        let token_provider = TokenProvider::new(&cfg, plugin_manager)?;
        let trust_provider = TrustProvider::new(&cfg, plugin_manager)?;

        Ok(Self {
            application_credential: application_credential_provider,
            assignment: assignment_provider,
            catalog: catalog_provider,
            federation: federation_provider,
            identity: identity_provider,
            identity_mapping: identity_mapping_provider,
            k8s_auth: k8s_auth_provider,
            spiffe: spiffe_provider,
            resource: resource_provider,
            revoke: revoke_provider,
            role: role_provider,
            token: token_provider,
            trust: trust_provider,
        })
    }

    /// Create a mocked Provider builder.
    #[cfg(any(test, feature = "mock"))]
    pub fn mocked_builder() -> ProviderBuilder {
        let application_credential_mock =
            crate::application_credential::MockApplicationCredentialProvider::default();
        let assignment_mock = crate::assignment::MockAssignmentProvider::default();
        let catalog_mock = crate::catalog::MockCatalogProvider::default();
        let identity_mock = crate::identity::MockIdentityProvider::default();
        let identity_mapping_mock = crate::identity_mapping::MockIdentityMappingProvider::default();
        let federation_mock = crate::federation::MockFederationProvider::default();
        let k8s_auth_mock = crate::k8s_auth::MockK8sAuthProvider::default();
        let spiffe_mock = crate::spiffe::MockSpiffeProvider::default();
        let resource_mock = crate::resource::MockResourceProvider::default();
        let revoke_mock = crate::revoke::MockRevokeProvider::default();
        let role_mock = crate::role::MockRoleProvider::default();
        let token_mock = crate::token::MockTokenProvider::default();
        let trust_mock = crate::trust::MockTrustProvider::default();

        ProviderBuilder::default()
            .mock_application_credential(application_credential_mock)
            .mock_assignment(assignment_mock)
            .mock_catalog(catalog_mock)
            .mock_identity(identity_mock)
            .mock_identity_mapping(identity_mapping_mock)
            .mock_federation(federation_mock)
            .mock_k8s_auth(k8s_auth_mock)
            .mock_spiffe(spiffe_mock)
            .mock_resource(resource_mock)
            .mock_revoke(revoke_mock)
            .mock_role(role_mock)
            .mock_token(token_mock)
            .mock_trust(trust_mock)
    }

    /// Get the application credential provider.
    pub fn get_application_credential_provider(&self) -> &ApplicationCredentialProvider {
        &self.application_credential
    }

    /// Get the assignment provider.
    pub fn get_assignment_provider(&self) -> &AssignmentProvider {
        &self.assignment
    }

    /// Get the catalog provider.
    pub fn get_catalog_provider(&self) -> &CatalogProvider {
        &self.catalog
    }

    /// Get the federation provider.
    pub fn get_federation_provider(&self) -> &FederationProvider {
        &self.federation
    }

    /// Get the identity provider.
    pub fn get_identity_provider(&self) -> &IdentityProvider {
        &self.identity
    }

    /// Get the identity mapping provider.
    pub fn get_identity_mapping_provider(&self) -> &IdentityMappingProvider {
        &self.identity_mapping
    }

    /// Get the K8s auth provider.
    pub fn get_k8s_auth_provider(&self) -> &K8sAuthProvider {
        &self.k8s_auth
    }

    /// Get the spiffe provider.
    pub fn get_spiffe_provider(&self) -> &SpiffeProvider {
        &self.spiffe
    }

    /// Get the resource provider.
    pub fn get_resource_provider(&self) -> &ResourceProvider {
        &self.resource
    }

    /// Get the revocation provider.
    pub fn get_revoke_provider(&self) -> &RevokeProvider {
        &self.revoke
    }

    /// Get the role provider.
    pub fn get_role_provider(&self) -> &RoleProvider {
        &self.role
    }

    /// Get the token provider.
    pub fn get_token_provider(&self) -> &TokenProvider {
        &self.token
    }

    /// Get the trust provider.
    pub fn get_trust_provider(&self) -> &TrustProvider {
        &self.trust
    }
}
