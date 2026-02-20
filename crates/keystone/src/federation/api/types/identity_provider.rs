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
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use openstack_keystone_api_types::federation::identity_provider;

pub use identity_provider::IdentityProvider;
pub use identity_provider::IdentityProviderCreate;
pub use identity_provider::IdentityProviderCreateRequest;
pub use identity_provider::IdentityProviderList;
pub use identity_provider::IdentityProviderListParameters;
pub use identity_provider::IdentityProviderResponse;
pub use identity_provider::IdentityProviderUpdate;
pub use identity_provider::IdentityProviderUpdateRequest;

use crate::federation::types;

use crate::api::common::{QueryParameterPagination, ResourceIdentifier};

impl From<types::IdentityProvider> for IdentityProvider {
    fn from(value: types::IdentityProvider) -> Self {
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

impl From<IdentityProviderCreateRequest> for types::IdentityProviderCreate {
    fn from(value: IdentityProviderCreateRequest) -> Self {
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

impl From<IdentityProviderUpdateRequest> for types::IdentityProviderUpdate {
    fn from(value: IdentityProviderUpdateRequest) -> Self {
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

impl IntoResponse for types::IdentityProvider {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            Json(IdentityProviderResponse {
                identity_provider: IdentityProvider::from(self),
            }),
        )
            .into_response()
    }
}

impl From<IdentityProviderListParameters> for types::IdentityProviderListParameters {
    fn from(value: IdentityProviderListParameters) -> Self {
        Self {
            name: value.name,
            domain_ids: None, //value.domain_id,
            limit: value.limit,
            marker: value.marker,
        }
    }
}

impl ResourceIdentifier for IdentityProvider {
    fn get_id(&self) -> String {
        self.id.clone()
    }
}

impl QueryParameterPagination for IdentityProviderListParameters {
    fn get_limit(&self) -> Option<u64> {
        self.limit
    }

    fn set_marker(&mut self, marker: String) -> &mut Self {
        self.marker = Some(marker);
        self
    }
}
