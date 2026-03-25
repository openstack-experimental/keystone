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
//! Federated identity provider types.

use openstack_keystone_core_types::federation as provider_types;

use crate::federation::identity_provider as api_types;

impl From<provider_types::IdentityProvider> for api_types::IdentityProvider {
    fn from(value: provider_types::IdentityProvider) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain_id: value.domain_id,
            enabled: value.enabled,
            oidc_discovery_url: value.oidc_discovery_url,
            oidc_client_id: value.oidc_client_id,
            oidc_response_mode: value.oidc_response_mode,
            oidc_response_types: value.oidc_response_types,
            jwks_url: value.jwks_url,
            jwt_validation_pubkeys: value.jwt_validation_pubkeys,
            bound_issuer: value.bound_issuer,
            default_mapping_name: value.default_mapping_name,
            provider_config: value.provider_config,
        }
    }
}

impl From<api_types::IdentityProviderCreateRequest> for provider_types::IdentityProviderCreate {
    fn from(value: api_types::IdentityProviderCreateRequest) -> Self {
        Self {
            id: None,
            name: value.identity_provider.name,
            domain_id: value.identity_provider.domain_id,
            enabled: value.identity_provider.enabled,
            oidc_discovery_url: value.identity_provider.oidc_discovery_url,
            oidc_client_id: value.identity_provider.oidc_client_id,
            oidc_client_secret: value.identity_provider.oidc_client_secret,
            oidc_response_mode: value.identity_provider.oidc_response_mode,
            oidc_response_types: value.identity_provider.oidc_response_types,
            jwks_url: value.identity_provider.jwks_url,
            jwt_validation_pubkeys: value.identity_provider.jwt_validation_pubkeys,
            bound_issuer: value.identity_provider.bound_issuer,
            default_mapping_name: value.identity_provider.default_mapping_name,
            provider_config: value.identity_provider.provider_config,
        }
    }
}

impl From<api_types::IdentityProviderUpdateRequest> for provider_types::IdentityProviderUpdate {
    fn from(value: api_types::IdentityProviderUpdateRequest) -> Self {
        Self {
            name: value.identity_provider.name,
            enabled: value.identity_provider.enabled,
            oidc_discovery_url: value.identity_provider.oidc_discovery_url,
            oidc_client_id: value.identity_provider.oidc_client_id,
            oidc_client_secret: value.identity_provider.oidc_client_secret,
            oidc_response_mode: value.identity_provider.oidc_response_mode,
            oidc_response_types: value.identity_provider.oidc_response_types,
            jwks_url: value.identity_provider.jwks_url,
            jwt_validation_pubkeys: value.identity_provider.jwt_validation_pubkeys,
            bound_issuer: value.identity_provider.bound_issuer,
            default_mapping_name: value.identity_provider.default_mapping_name,
            provider_config: value.identity_provider.provider_config,
        }
    }
}

impl From<api_types::IdentityProviderListParameters>
    for provider_types::IdentityProviderListParameters
{
    fn from(value: api_types::IdentityProviderListParameters) -> Self {
        Self {
            name: value.name,
            domain_ids: None, //value.domain_id,
            limit: value.limit,
            marker: value.marker,
        }
    }
}
