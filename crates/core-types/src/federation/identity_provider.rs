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
//! # Federated identity provider types

use derive_builder::Builder;
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, Serializer};
use serde_json::Value;

use crate::error::BuilderError;

/// Serialize an optional secret as a fixed redaction marker so that it never
/// leaks in Debug/policy/audit payloads while still signalling presence.
fn serialize_secret_redacted<S>(
    secret: &Option<SecretString>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match secret {
        Some(_) => serializer.serialize_str("[REDACTED]"),
        None => serializer.serialize_none(),
    }
}

/// Identity provider resource.
///
/// `PartialEq` is intentionally not derived: `oidc_client_secret` is wrapped in
/// [`SecretString`], which does not implement `PartialEq` by design.
#[derive(Builder, Clone, Debug, Default, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct IdentityProvider {
    /// Federation provider ID.
    pub id: String,

    /// Provider name.
    pub name: String,

    /// Domain ID.
    #[builder(default)]
    pub domain_id: Option<String>,

    /// Whether the identity provider is enabled.
    #[builder(default)]
    pub enabled: bool,

    /// OIDC discovery url.
    #[builder(default)]
    pub oidc_discovery_url: Option<String>,

    #[builder(default)]
    pub oidc_client_id: Option<String>,

    /// The OIDC client secret. Wrapped in [`SecretString`] to prevent accidental
    /// exposure via Debug/tracing; redacted (never exposed) when serialized into
    /// policy/audit payloads.
    #[builder(default)]
    #[serde(serialize_with = "serialize_secret_redacted")]
    pub oidc_client_secret: Option<SecretString>,

    #[builder(default)]
    pub oidc_response_mode: Option<String>,

    #[builder(default)]
    pub oidc_response_types: Option<Vec<String>>,

    #[builder(default)]
    pub jwks_url: Option<String>,

    #[builder(default)]
    pub jwt_validation_pubkeys: Option<Vec<String>>,

    #[builder(default)]
    pub bound_issuer: Option<String>,

    #[builder(default)]
    pub default_mapping_name: Option<String>,

    /// List of OIDC scopes to request during the OIDC authorization flow.
    #[builder(default)]
    pub oidc_scopes: Option<Vec<String>>,

    /// List of allowed redirect URIs for OIDC flows. When set, the redirect
    /// URI passed at auth-init must match one of these values. An empty list
    /// means no restriction is applied, which is the default for backward
    /// compatibility.
    #[builder(default)]
    pub allowed_redirect_uris: Option<Vec<String>>,

    #[builder(default)]
    pub provider_config: Option<Value>,
}

/// Manual `PartialEq` (the derive cannot be used because `oidc_client_secret`
/// is a [`SecretString`], which does not implement `PartialEq`). Preserves the
/// pre-wrapping equality contract by comparing the exposed secret values.
impl PartialEq for IdentityProvider {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.name == other.name
            && self.domain_id == other.domain_id
            && self.enabled == other.enabled
            && self.oidc_discovery_url == other.oidc_discovery_url
            && self.oidc_client_id == other.oidc_client_id
            && self
                .oidc_client_secret
                .as_ref()
                .map(ExposeSecret::expose_secret)
                == other
                    .oidc_client_secret
                    .as_ref()
                    .map(ExposeSecret::expose_secret)
            && self.oidc_response_mode == other.oidc_response_mode
            && self.oidc_response_types == other.oidc_response_types
            && self.jwks_url == other.jwks_url
            && self.jwt_validation_pubkeys == other.jwt_validation_pubkeys
            && self.bound_issuer == other.bound_issuer
            && self.default_mapping_name == other.default_mapping_name
            && self.oidc_scopes == other.oidc_scopes
            && self.allowed_redirect_uris == other.allowed_redirect_uris
            && self.provider_config == other.provider_config
    }
}

/// New Identity provider data.
///
/// `PartialEq` is intentionally not derived: `oidc_client_secret` is wrapped in
/// [`SecretString`], which does not implement `PartialEq` by design.
#[derive(Builder, Clone, Debug, Default)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct IdentityProviderCreate {
    /// Federation provider ID.
    pub id: Option<String>,

    /// Provider name.
    pub name: String,

    /// Domain ID.
    #[builder(default)]
    pub domain_id: Option<String>,

    /// Whether the identity provider is enabled.
    #[builder(default)]
    pub enabled: bool,

    /// OIDC discovery url.
    #[builder(default)]
    pub oidc_discovery_url: Option<String>,

    #[builder(default)]
    pub oidc_client_id: Option<String>,

    /// The OIDC client secret. Wrapped in [`SecretString`] to prevent accidental
    /// exposure via Debug/tracing.
    #[builder(default)]
    pub oidc_client_secret: Option<SecretString>,

    #[builder(default)]
    pub oidc_response_mode: Option<String>,

    #[builder(default)]
    pub oidc_response_types: Option<Vec<String>>,

    #[builder(default)]
    pub jwks_url: Option<String>,

    #[builder(default)]
    pub jwt_validation_pubkeys: Option<Vec<String>>,

    #[builder(default)]
    pub bound_issuer: Option<String>,

    #[builder(default)]
    pub default_mapping_name: Option<String>,

    /// List of OIDC scopes to request during the OIDC authorization flow.
    #[builder(default)]
    pub oidc_scopes: Option<Vec<String>>,

    /// List of allowed redirect URIs for OIDC flows.
    #[builder(default)]
    pub allowed_redirect_uris: Option<Vec<String>>,

    #[builder(default)]
    pub provider_config: Option<Value>,
}

/// Identity provider update data.
///
/// `PartialEq` is intentionally not derived: `oidc_client_secret` is wrapped in
/// [`SecretString`], which does not implement `PartialEq` by design.
#[derive(Builder, Clone, Debug, Default)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into))]
pub struct IdentityProviderUpdate {
    /// Provider name.
    pub name: Option<String>,

    /// Enabled flag.
    pub enabled: Option<bool>,

    #[builder(default)]
    pub oidc_discovery_url: Option<Option<String>>,

    #[builder(default)]
    pub oidc_client_id: Option<Option<String>>,

    /// The OIDC client secret. Wrapped in [`SecretString`] to prevent accidental
    /// exposure via Debug/tracing. Outer `Option` = present-in-request,
    /// inner `Option` = set-or-clear.
    #[builder(default)]
    pub oidc_client_secret: Option<Option<SecretString>>,

    #[builder(default)]
    pub oidc_response_mode: Option<Option<String>>,

    #[builder(default)]
    pub oidc_response_types: Option<Option<Vec<String>>>,

    #[builder(default)]
    pub jwks_url: Option<Option<String>>,

    #[builder(default)]
    pub jwt_validation_pubkeys: Option<Option<Vec<String>>>,

    #[builder(default)]
    pub bound_issuer: Option<Option<String>>,

    #[builder(default)]
    pub default_mapping_name: Option<Option<String>>,

    /// List of OIDC scopes to request during the OIDC authorization flow.
    #[builder(default)]
    pub oidc_scopes: Option<Option<Vec<String>>>,

    /// List of allowed redirect URIs for OIDC flows.
    #[builder(default)]
    pub allowed_redirect_uris: Option<Option<Vec<String>>>,

    #[builder(default)]
    pub provider_config: Option<Option<Value>>,
}

/// Identity provider list request.
#[derive(Builder, Clone, Debug, Default, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct IdentityProviderListParameters {
    /// Filters the response by a domain_id ID. It is an optional list of
    /// optional strings to represent fetching of null and non-null values
    /// in a single request.
    pub domain_ids: Option<std::collections::HashSet<Option<String>>>,

    /// Limit number of entries on the single response page.
    #[builder(default)]
    pub limit: Option<u64>,

    /// Page marker (id of the last entry on the previous page.
    #[builder(default)]
    pub marker: Option<String>,
    ///
    /// Filters the response by IDP name.
    pub name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "oidc-top-secret";

    #[test]
    fn identity_provider_never_leaks_client_secret() {
        let idp = IdentityProviderBuilder::default()
            .id("1")
            .name("idp")
            .oidc_client_secret(SECRET)
            .build()
            .unwrap();

        // Debug (the #[instrument] / log vector) must not leak.
        assert!(
            !format!("{idp:?}").contains(SECRET),
            "Debug leaked client secret"
        );

        // Serialization into the OPA policy / audit payload must redact.
        let json = serde_json::to_string(&idp).unwrap();
        assert!(
            !json.contains(SECRET),
            "serialize leaked client secret: {json}"
        );
        assert!(
            json.contains("[REDACTED]"),
            "client secret not redacted: {json}"
        );
    }

    #[test]
    fn partial_eq_still_compares_client_secret() {
        let base = IdentityProviderBuilder::default()
            .id("1")
            .name("idp")
            .oidc_client_secret(SECRET)
            .build()
            .unwrap();
        let same = base.clone();
        let different = IdentityProviderBuilder::default()
            .id("1")
            .name("idp")
            .oidc_client_secret("other-secret")
            .build()
            .unwrap();
        assert_eq!(base, same);
        assert_ne!(base, different);
    }
}
