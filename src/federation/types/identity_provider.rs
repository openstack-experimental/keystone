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
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Identity provider resource.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(strip_option, into))]
pub struct IdentityProvider {
    /// Federation provider ID.
    pub id: String,

    /// Provider name.
    pub name: String,

    /// Domain ID,
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

    #[builder(default)]
    pub oidc_client_secret: Option<String>,

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

    #[builder(default)]
    pub provider_config: Option<Value>,
}

/// Identity provider update data.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(into))]
pub struct IdentityProviderUpdate {
    /// Provider name
    pub name: Option<String>,

    /// Enabled flag.
    pub enabled: Option<bool>,

    #[builder(default)]
    pub oidc_discovery_url: Option<Option<String>>,

    #[builder(default)]
    pub oidc_client_id: Option<Option<String>>,

    #[builder(default)]
    pub oidc_client_secret: Option<Option<String>>,

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

    #[builder(default)]
    pub provider_config: Option<Option<Value>>,
}

/// Identity provider list request.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(strip_option, into))]
pub struct IdentityProviderListParameters {
    /// Filters the response by IDP name.
    pub name: Option<String>,
    /// Filters the response by a domain_id ID. It is an optional list of
    /// optional strings to represent fetching of null and non-null values
    /// in a single request.
    pub domain_ids: Option<std::collections::HashSet<Option<String>>>,
}
