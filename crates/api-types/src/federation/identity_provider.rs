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
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "validate")]
use validator::Validate;

use crate::Link;

/// Identity provider data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
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

    /// List of OIDC scopes to request during the OIDC authorization flow.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_scopes: Option<Vec<String>>,

    /// List of allowed redirect URIs for OIDC flows.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_redirect_uris: Option<Vec<String>>,

    /// Additional provider configuration.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_config: Option<Value>,
}

/// Identity provider response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityProviderResponse {
    /// Identity provider object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub identity_provider: IdentityProvider,
}

/// Identity provider data.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
#[cfg_attr(
    feature = "validate",
    validate(schema(function = "validate_identity_provider_create_secret"))
)]
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
    #[cfg_attr(feature = "builder", builder(default = "true"))]
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
    #[cfg_attr(feature = "openapi", schema(value_type = String, nullable = false))]
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::common::serialize_optional_secret"
    )]
    pub oidc_client_secret: Option<SecretString>,

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_mapping_name: Option<String>,

    /// List of OIDC scopes to request during the OIDC authorization flow.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_scopes: Option<Vec<String>>,

    /// List of allowed redirect URIs for OIDC flows. When set, the redirect
    /// URI passed at auth-init must match one of these values.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_redirect_uris: Option<Vec<String>>,

    /// Additional special provider specific configuration.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(value_type = Object, nullable = false))]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_config: Option<Value>,
}

impl IdentityProviderCreate {
    #[must_use]
    pub fn to_policy_input(&self) -> serde_json::Value {
        let mut input = serde_json::Map::new();
        input.insert("name".to_string(), serde_json::json!(self.name));
        input.insert("enabled".to_string(), serde_json::json!(self.enabled));
        if let Some(value) = &self.domain_id {
            input.insert("domain_id".to_string(), serde_json::json!(value));
        }
        if let Some(value) = &self.oidc_discovery_url {
            input.insert("oidc_discovery_url".to_string(), serde_json::json!(value));
        }
        if let Some(value) = &self.oidc_client_id {
            input.insert("oidc_client_id".to_string(), serde_json::json!(value));
        }
        if self.oidc_client_secret.is_some() {
            input.insert(
                "oidc_client_secret".to_string(),
                serde_json::json!("[REDACTED]"),
            );
        }
        if let Some(value) = &self.oidc_response_mode {
            input.insert("oidc_response_mode".to_string(), serde_json::json!(value));
        }
        if let Some(value) = &self.oidc_response_types {
            input.insert("oidc_response_types".to_string(), serde_json::json!(value));
        }
        if let Some(value) = &self.jwks_url {
            input.insert("jwks_url".to_string(), serde_json::json!(value));
        }
        if let Some(value) = &self.jwt_validation_pubkeys {
            input.insert(
                "jwt_validation_pubkeys".to_string(),
                serde_json::json!(value),
            );
        }
        if let Some(value) = &self.bound_issuer {
            input.insert("bound_issuer".to_string(), serde_json::json!(value));
        }
        if let Some(value) = &self.default_mapping_name {
            input.insert("default_mapping_name".to_string(), serde_json::json!(value));
        }
        if let Some(value) = &self.oidc_scopes {
            input.insert("oidc_scopes".to_string(), serde_json::json!(value));
        }
        if let Some(value) = &self.allowed_redirect_uris {
            input.insert(
                "allowed_redirect_uris".to_string(),
                serde_json::json!(value),
            );
        }
        if let Some(value) = &self.provider_config {
            input.insert("provider_config".to_string(), value.clone());
        }
        serde_json::Value::Object(input)
    }
}

#[cfg(feature = "validate")]
fn validate_identity_provider_create_secret(
    value: &IdentityProviderCreate,
) -> Result<(), validator::ValidationError> {
    crate::common::validate_optional_secret_length(&value.oidc_client_secret, 255)
}

/// New identity provider data.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(
    feature = "builder",
    derive(derive_builder::Builder),
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
#[cfg_attr(
    feature = "validate",
    validate(schema(function = "validate_identity_provider_update_secret"))
)]
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
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    #[serde(
        default,
        serialize_with = "crate::common::serialize_nested_optional_secret"
    )]
    pub oidc_client_secret: Option<Option<SecretString>>,

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

    /// List of OIDC scopes to request during the OIDC authorization flow.
    #[cfg_attr(feature = "builder", builder(default))]
    pub oidc_scopes: Option<Option<Vec<String>>>,

    /// List of allowed redirect URIs for OIDC flows.
    #[cfg_attr(feature = "builder", builder(default))]
    pub allowed_redirect_uris: Option<Option<Vec<String>>>,

    /// New additional provider configuration.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub provider_config: Option<Option<Value>>,
}

impl IdentityProviderUpdate {
    #[must_use]
    pub fn to_policy_input(&self) -> serde_json::Value {
        let mut input = serde_json::Map::new();
        input.insert("name".to_string(), serde_json::json!(self.name));
        input.insert("enabled".to_string(), serde_json::json!(self.enabled));
        input.insert(
            "oidc_discovery_url".to_string(),
            serde_json::json!(self.oidc_discovery_url),
        );
        input.insert(
            "oidc_client_id".to_string(),
            serde_json::json!(self.oidc_client_id),
        );
        if self.oidc_client_secret.is_some() {
            input.insert(
                "oidc_client_secret".to_string(),
                serde_json::json!("[REDACTED]"),
            );
        }
        input.insert(
            "oidc_response_mode".to_string(),
            serde_json::json!(self.oidc_response_mode),
        );
        input.insert(
            "oidc_response_types".to_string(),
            serde_json::json!(self.oidc_response_types),
        );
        input.insert("jwks_url".to_string(), serde_json::json!(self.jwks_url));
        input.insert(
            "jwt_validation_pubkeys".to_string(),
            serde_json::json!(self.jwt_validation_pubkeys),
        );
        input.insert(
            "bound_issuer".to_string(),
            serde_json::json!(self.bound_issuer),
        );
        input.insert(
            "default_mapping_name".to_string(),
            serde_json::json!(self.default_mapping_name),
        );
        input.insert(
            "oidc_scopes".to_string(),
            serde_json::json!(self.oidc_scopes),
        );
        input.insert(
            "allowed_redirect_uris".to_string(),
            serde_json::json!(self.allowed_redirect_uris),
        );
        input.insert(
            "provider_config".to_string(),
            serde_json::json!(self.provider_config),
        );
        serde_json::Value::Object(input)
    }
}

#[cfg(feature = "validate")]
fn validate_identity_provider_update_secret(
    value: &IdentityProviderUpdate,
) -> Result<(), validator::ValidationError> {
    crate::common::validate_nested_optional_secret_length(&value.oidc_client_secret, 255)
}

/// Identity provider create request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityProviderCreateRequest {
    /// Identity provider object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub identity_provider: IdentityProviderCreate,
}

/// Identity provider update request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityProviderUpdateRequest {
    /// Identity provider object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub identity_provider: IdentityProviderUpdate,
}

/// List of Identity Providers.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Serialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The client secret must never leak through the DTO's `Debug` (the tracing
    /// / logging vector), while remaining available via `expose_secret` for the
    /// storage write.
    #[test]
    fn idp_create_debug_does_not_leak_client_secret() {
        use secrecy::ExposeSecret;
        let create: IdentityProviderCreate =
            serde_json::from_str(r#"{"name":"idp","oidc_client_secret":"CSLEAK"}"#).unwrap();
        assert!(
            !format!("{create:?}").contains("CSLEAK"),
            "Debug leaked client secret: {create:?}"
        );
        assert_eq!(
            create
                .oidc_client_secret
                .as_ref()
                .map(|s| s.expose_secret()),
            Some("CSLEAK")
        );
    }

    /// Same for the update DTO (nested `Option<Option<SecretString>>`).
    #[test]
    fn idp_update_debug_does_not_leak_client_secret() {
        let update: IdentityProviderUpdate =
            serde_json::from_str(r#"{"oidc_client_secret":"CSLEAK2"}"#).unwrap();
        assert!(
            !format!("{update:?}").contains("CSLEAK2"),
            "Debug leaked client secret: {update:?}"
        );
    }

    #[test]
    fn idp_policy_input_redacts_client_secret() {
        let create: IdentityProviderCreate =
            serde_json::from_str(r#"{"name":"idp","oidc_client_secret":"CSLEAK"}"#).unwrap();
        let rendered = create.to_policy_input().to_string();
        assert!(
            !rendered.contains("CSLEAK"),
            "policy input leaked client secret: {rendered}"
        );

        let update: IdentityProviderUpdate =
            serde_json::from_str(r#"{"oidc_client_secret":"CSLEAK2"}"#).unwrap();
        let input = update.to_policy_input();
        let rendered = input.to_string();
        assert!(
            !rendered.contains("CSLEAK2"),
            "policy input leaked client secret: {rendered}"
        );
        assert_eq!(
            input.get("oidc_client_secret").and_then(|v| v.as_str()),
            Some("[REDACTED]")
        );
    }

    /// Regression guard: the read/response DTO has no client-secret field, so a
    /// client secret can never be returned — even if one is (wrongly) supplied.
    #[test]
    fn identity_provider_response_never_exposes_client_secret() {
        let idp: IdentityProvider = serde_json::from_str(
            r#"{"id":"1","name":"idp","enabled":true,
                "oidc_client_secret":"SHOULD_BE_IGNORED"}"#,
        )
        .unwrap();
        let rendered = serde_json::to_string(&idp).unwrap();
        assert!(
            !rendered.contains("client_secret"),
            "response exposed a client_secret field: {rendered}"
        );
        assert!(
            !rendered.contains("SHOULD_BE_IGNORED"),
            "response leaked the secret value: {rendered}"
        );
    }
}
