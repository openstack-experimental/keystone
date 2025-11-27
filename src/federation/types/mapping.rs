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

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Attribute mapping data.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(strip_option, into))]
pub struct Mapping {
    /// Federation IDP attribute mapping ID.
    pub id: String,

    /// Attribute mapping name.
    pub name: String,

    /// ID of the domain for the attribute mapping.
    #[builder(default)]
    pub domain_id: Option<String>,

    /// Identity provider for the attribute mapping.
    pub idp_id: String,

    /// Mapping type.
    pub r#type: MappingType,

    /// List of allowed redirect_uri for the oidc mapping.
    #[builder(default)]
    pub allowed_redirect_uris: Option<Vec<String>>,

    /// Claim attribute name to extract `user_id`.
    #[builder(default)]
    pub user_id_claim: String,

    /// Claim attribute name to extract `user_name`.
    #[builder(default)]
    pub user_name_claim: String,

    /// Claim attribute name to extract `domain_id`.
    #[builder(default)]
    pub domain_id_claim: Option<String>,

    /// Claim attribute name to extract list of groups.
    #[builder(default)]
    pub groups_claim: Option<String>,

    /// Fixed (JWT) audiences that the assertion must be issued for.
    #[builder(default)]
    pub bound_audiences: Option<Vec<String>>,

    /// Fixed subject that the assertion (jwt) must be issued for.
    #[builder(default)]
    pub bound_subject: Option<String>,

    /// Additional claims to further restrict the attribute mapping.
    #[builder(default)]
    pub bound_claims: Option<Value>,

    /// List of the oidc scopes to request in the oidc flow.
    #[builder(default)]
    pub oidc_scopes: Option<Vec<String>>,

    //#[builder(default)]
    //pub claim_mappings: Option<Value>,
    /// Fixed `project_id` scope of the token to issue for successful
    /// authentication.
    #[builder(default)]
    pub token_project_id: Option<String>,

    /// ID of the token restrictions.
    #[builder(default)]
    pub token_restriction_id: Option<String>,
}

/// Update attribute mapping data.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(into))]
pub struct MappingUpdate {
    /// Attribute mapping name.
    pub name: Option<String>,

    /// Identity provider for the attribute mapping.
    #[builder(default)]
    pub idp_id: Option<String>,

    /// Mapping type.
    #[builder(default)]
    pub r#type: Option<MappingType>,

    /// List of allowed redirect_uri for the oidc mapping.
    #[builder(default)]
    pub allowed_redirect_uris: Option<Option<Vec<String>>>,

    /// Claim attribute name to extract `user_id`.
    #[builder(default)]
    pub user_id_claim: Option<String>,

    /// Claim attribute name to extract `user_name`.
    #[builder(default)]
    pub user_name_claim: Option<String>,

    /// Claim attribute name to extract `domain_id`.
    #[builder(default)]
    pub domain_id_claim: Option<String>,

    /// claim attribute name to extract list of groups.
    #[builder(default)]
    pub groups_claim: Option<Option<String>>,

    /// Fixed (JWT) audiences that the assertion must be issued for.
    #[builder(default)]
    pub bound_audiences: Option<Option<Vec<String>>>,

    /// Fixed subject that the assertion (jwt) must be issued for.
    #[builder(default)]
    pub bound_subject: Option<Option<String>>,

    /// Additional claims to further restrict the attribute mapping.
    #[builder(default)]
    pub bound_claims: Option<Value>,

    /// List of the oidc scopes to request in the oidc flow.
    #[builder(default)]
    pub oidc_scopes: Option<Option<Vec<String>>>,

    /// Fixed `project_id` scope of the token to issue for successful
    /// authentication.
    #[builder(default)]
    pub token_project_id: Option<Option<String>>,

    /// ID of the token restrictions.
    #[builder(default)]
    pub token_restriction_id: Option<String>,
}

/// Attribute mapping type.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum MappingType {
    #[default]
    /// OIDC
    Oidc,
    /// JWT
    Jwt,
}

/// List attribute mappings request.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(setter(strip_option, into))]
pub struct MappingListParameters {
    /// Filters the response by Mapping name.
    pub name: Option<String>,
    /// Filters the response by a domain_id ID.
    pub domain_id: Option<String>,
    /// Filters the response by IDP ID.
    pub idp_id: Option<String>,
    /// Filters mappings by the type
    pub r#type: Option<MappingType>,
}
