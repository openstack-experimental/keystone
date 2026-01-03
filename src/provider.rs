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
use mockall_double::double;

use crate::application_credential::ApplicationCredentialApi;
#[double]
use crate::application_credential::ApplicationCredentialProvider;
use crate::assignment::AssignmentApi;
#[double]
use crate::assignment::AssignmentProvider;
use crate::catalog::CatalogApi;
#[double]
use crate::catalog::CatalogProvider;
use crate::config::Config;
use crate::error::KeystoneError;
use crate::federation::FederationApi;
#[double]
use crate::federation::FederationProvider;
use crate::identity::IdentityApi;
#[double]
use crate::identity::IdentityProvider;
use crate::identity_mapping::IdentityMappingApi;
#[double]
use crate::identity_mapping::IdentityMappingProvider;
use crate::plugin_manager::PluginManager;
use crate::resource::ResourceApi;
#[double]
use crate::resource::ResourceProvider;
use crate::revoke::RevokeApi;
#[double]
use crate::revoke::RevokeProvider;
use crate::token::TokenApi;
#[double]
use crate::token::TokenProvider;
use crate::trust::TrustApi;
#[double]
use crate::trust::TrustProvider;

//pub trait Provider: Clone + Send + Sync {
//    fn get_identity_provider(&self) -> &impl IdentityApi;
//    fn get_token_provider(&self) -> &impl TokenApi;
//}

/// Global provider manager.
#[derive(Builder, Clone)]
// It is necessary to use the owned pattern since otherwise builder invokes clone which immediately
// confuses mockall used in tests
#[builder(pattern = "owned")]
pub struct Provider {
    /// Configuration.
    pub config: Config,
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
    /// Resource provider.
    resource: ResourceProvider,
    /// Revoke provider.
    revoke: RevokeProvider,
    /// Token provider.
    token: TokenProvider,
    /// Trust provider.
    trust: TrustProvider,
}

impl Provider {
    pub fn new(cfg: Config, plugin_manager: PluginManager) -> Result<Self, KeystoneError> {
        let application_credential_provider =
            ApplicationCredentialProvider::new(&cfg, &plugin_manager)?;
        let assignment_provider = AssignmentProvider::new(&cfg, &plugin_manager)?;
        let catalog_provider = CatalogProvider::new(&cfg, &plugin_manager)?;
        let federation_provider = FederationProvider::new(&cfg, &plugin_manager)?;
        let identity_provider = IdentityProvider::new(&cfg, &plugin_manager)?;
        let identity_mapping_provider = IdentityMappingProvider::new(&cfg, &plugin_manager)?;
        let resource_provider = ResourceProvider::new(&cfg, &plugin_manager)?;
        let revoke_provider = RevokeProvider::new(&cfg, &plugin_manager)?;
        let token_provider = TokenProvider::new(&cfg)?;
        let trust_provider = TrustProvider::new(&cfg, &plugin_manager)?;

        Ok(Self {
            config: cfg,
            application_credential: application_credential_provider,
            assignment: assignment_provider,
            catalog: catalog_provider,
            federation: federation_provider,
            identity: identity_provider,
            identity_mapping: identity_mapping_provider,
            resource: resource_provider,
            revoke: revoke_provider,
            token: token_provider,
            trust: trust_provider,
        })
    }

    /// Get the application credential provider.
    pub fn get_application_credential_provider(&self) -> &impl ApplicationCredentialApi {
        &self.application_credential
    }

    /// Get the assignment provider.
    pub fn get_assignment_provider(&self) -> &impl AssignmentApi {
        &self.assignment
    }

    /// Get the catalog provider.
    pub fn get_catalog_provider(&self) -> &impl CatalogApi {
        &self.catalog
    }

    /// Get the federation provider.
    pub fn get_federation_provider(&self) -> &impl FederationApi {
        &self.federation
    }

    /// Get the identity provider.
    pub fn get_identity_provider(&self) -> &impl IdentityApi {
        &self.identity
    }

    /// Get the identity mapping provider.
    pub fn get_identity_mapping_provider(&self) -> &impl IdentityMappingApi {
        &self.identity_mapping
    }

    /// Get the resource provider.
    pub fn get_resource_provider(&self) -> &impl ResourceApi {
        &self.resource
    }

    /// Get the revocation provider.
    pub fn get_revoke_provider(&self) -> &impl RevokeApi {
        &self.revoke
    }

    /// Get the token provider.
    pub fn get_token_provider(&self) -> &impl TokenApi {
        &self.token
    }

    /// Get the trust provider.
    pub fn get_trust_provider(&self) -> &impl TrustApi {
        &self.trust
    }
}

#[cfg(test)]
impl Provider {
    pub fn mocked_builder() -> ProviderBuilder {
        let config = Config::default();
        let application_credential_mock =
            crate::application_credential::MockApplicationCredentialProvider::default();
        let assignment_mock = crate::assignment::MockAssignmentProvider::default();
        let catalog_mock = crate::catalog::MockCatalogProvider::default();
        let identity_mock = crate::identity::MockIdentityProvider::default();
        let identity_mapping_mock = crate::identity_mapping::MockIdentityMappingProvider::default();
        let federation_mock = crate::federation::MockFederationProvider::default();
        let resource_mock = crate::resource::MockResourceProvider::default();
        let revoke_mock = crate::revoke::MockRevokeProvider::default();
        let token_mock = crate::token::MockTokenProvider::default();
        let trust_mock = crate::trust::MockTrustProvider::default();

        ProviderBuilder::default()
            .config(config.clone())
            .application_credential(application_credential_mock)
            .assignment(assignment_mock)
            .catalog(catalog_mock)
            .identity(identity_mock)
            .identity_mapping(identity_mapping_mock)
            .federation(federation_mock)
            .resource(resource_mock)
            .revoke(revoke_mock)
            .token(token_mock)
            .trust(trust_mock)
    }
}
