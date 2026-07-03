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
use secrecy::SecretString;
use serde::Serialize;
use serde_json::Value;

use crate::error::BuilderError;

/// Identity provider resource.
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

    /// The OIDC client secret. It is never returned back, so it is skipped on
    /// serialization; `SecretString` additionally keeps it out of `Debug`.
    #[builder(default)]
    #[serde(skip_serializing)]
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

/// New Identity provider data.
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

    /// The OIDC client secret.
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

    /// The OIDC client secret. Outer `Option` = present-in-request, inner
    /// `Option` = set-or-clear.
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
    fn identity_provider_debug_does_not_leak_client_secret() {
        let idp = IdentityProviderBuilder::default()
            .id("1")
            .name("idp")
            .oidc_client_secret(SecretString::from(SECRET))
            .build()
            .unwrap();

        // Debug (the #[instrument] / log vector) must not leak the secret.
        assert!(
            !format!("{idp:?}").contains(SECRET),
            "Debug leaked client secret"
        );
    }

    #[test]
    fn identity_provider_does_not_serialize_client_secret() {
        let idp = IdentityProviderBuilder::default()
            .id("1")
            .name("idp")
            .oidc_client_secret(SecretString::from(SECRET))
            .build()
            .unwrap();

        // The secret is never returned back, so it must not appear on the wire.
        let json = serde_json::to_string(&idp).unwrap();
        assert!(!json.contains(SECRET), "serialize leaked client secret");
        assert!(!json.contains("oidc_client_secret"));
    }
}
