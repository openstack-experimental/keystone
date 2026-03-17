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
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "validate")]
use validator::Validate;

use crate::Link;

/// Identity provider data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(
    feature = "builder",
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityProvider {
    /// The ID of the federated identity provider.
    pub id: String,

    /// The Name of the federated identity provider.
    pub name: String,

    /// The ID of the domain this identity provider belongs to. Empty value
    /// identifies that the identity provider can be used by other domains
    /// as well.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id: Option<String>,

    /// Identity provider `enabled` property. Inactive Identity Providers can
    /// not be used for login.
    pub enabled: bool,

    /// OIDC discovery endpoint for the identity provider.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_discovery_url: Option<String>,

    /// The oidc `client_id` to use for the private client. The `client_secret`
    /// is never returned and can be only overwritten.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_client_id: Option<String>,

    /// The oidc response mode.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_response_mode: Option<String>,

    /// List of supported response types.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_response_types: Option<Vec<String>>,

    /// URL to fetch JsonWebKeySet. This must be set for "jwt" mapping when the
    /// provider does not provide discovery endpoint or when it is not
    /// standard compliant.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,

    /// List of the jwt validation public keys.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_validation_pubkeys: Option<Vec<String>>,

    /// The bound issuer that is verified when using the identity provider.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_issuer: Option<String>,

    /// Default attribute mapping name which is automatically used when no
    /// mapping is explicitly requested. The referred attribute mapping must
    /// exist.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_mapping_name: Option<String>,

    /// Additional provider configuration.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_config: Option<Value>,
}

/// Identity provider response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(
    feature = "builder",
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityProviderResponse {
    /// Identity provider object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub identity_provider: IdentityProvider,
}

/// Identity provider data.
#[derive(Clone, Default, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(
    feature = "builder",
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityProviderCreate {
    // TODO: add ID
    /// Identity provider name.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: String,

    /// The ID of the domain this identity provider belongs to. Empty value
    /// identifies that the identity provider can be used by other domains
    /// as well.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id: Option<String>,

    /// Identity provider `enabled` property. Inactive Identity Providers can
    /// not be used for login.
    #[serde(default = "crate::default_true")]
    pub enabled: bool,

    /// OIDC discovery endpoint for the identity provider.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(url, length(max = 255)))]
    pub oidc_discovery_url: Option<String>,

    /// The oidc `client_id` to use for the private client.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub oidc_client_id: Option<String>,

    /// The oidc `client_secret` to use for the private client. It is never
    /// returned back.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub oidc_client_secret: Option<String>,

    /// The oidc response mode.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub oidc_response_mode: Option<String>,

    /// List of supported response types.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_response_types: Option<Vec<String>>,

    /// Optional URL to fetch JsonWebKeySet. Must be specified for JWT
    /// authentication when discovery for the provider is not available or
    /// not standard compliant.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(url))]
    pub jwks_url: Option<String>,

    /// List of the jwt validation public keys.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt_validation_pubkeys: Option<Vec<String>>,

    /// The bound issuer that is verified when using the identity provider.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub bound_issuer: Option<String>,

    /// Default attribute mapping name which is automatically used when no
    /// mapping is explicitly requested. The referred attribute mapping must
    /// exist.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub default_mapping_name: Option<String>,

    /// Additional special provider specific configuration.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(value_type = Object, nullable = false))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_config: Option<Value>,
}

/// New identity provider data.
#[derive(Clone, Default, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(
    feature = "builder",
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityProviderUpdate {
    /// The new name of the federated identity provider.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,

    /// Identity provider `enabled` property. Inactive Identity Providers can
    /// not be used for login.
    #[cfg_attr(feature = "builder", builder(default))]
    pub enabled: Option<bool>,

    /// The new OIDC discovery endpoint for the identity provider.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(url, length(max = 255)))]
    pub oidc_discovery_url: Option<Option<String>>,

    /// The new oidc `client_id` to use for the private client.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub oidc_client_id: Option<Option<String>>,

    /// The new oidc `client_secret` to use for the private client.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub oidc_client_secret: Option<Option<String>>,

    /// The new oidc response mode.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub oidc_response_mode: Option<Option<String>>,

    /// The new oidc response mode.
    #[cfg_attr(feature = "builder", builder(default))]
    pub oidc_response_types: Option<Option<Vec<String>>>,

    /// New URL to fetch JsonWebKeySet. This must be set for "jwt" mapping when
    /// the provider does not provide discovery endpoint or when it is not
    /// standard compliant.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(url))]
    pub jwks_url: Option<Option<String>>,

    /// The list of the jwt validation public keys.
    #[cfg_attr(feature = "builder", builder(default))]
    pub jwt_validation_pubkeys: Option<Option<Vec<String>>>,

    /// The new bound issuer that is verified when using the identity provider.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub bound_issuer: Option<Option<String>>,

    /// New default attribute mapping name which is automatically used when no
    /// mapping is explicitly requested. The referred attribute mapping must
    /// exist.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub default_mapping_name: Option<Option<String>>,

    /// New additional provider configuration.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub provider_config: Option<Option<Value>>,
}

/// Identity provider create request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(
    feature = "builder",
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityProviderCreateRequest {
    /// Identity provider object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub identity_provider: IdentityProviderCreate,
}

/// Identity provider update request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(
    feature = "builder",
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityProviderUpdateRequest {
    /// Identity provider object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub identity_provider: IdentityProviderUpdate,
}

/// List of Identity Providers.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityProviderList {
    /// Collection of identity provider objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub identity_providers: Vec<IdentityProvider>,

    /// Pagination links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
}

/// Query parameters for listing federated identity providers.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityProviderListParameters {
    /// Filters the response by IDP name.
    #[cfg_attr(feature = "openapi", param(nullable = false))]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,

    /// Filters the response by a domain ID.
    #[cfg_attr(feature = "openapi", param(nullable = false))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: Option<String>,

    /// Limit number of entries on the single response page.
    #[serde(default = "default_list_limit")]
    pub limit: Option<u64>,

    /// Page marker (id of the last entry on the previous page.
    pub marker: Option<String>,
}

fn default_list_limit() -> Option<u64> {
    Some(20)
}
