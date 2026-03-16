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
//! Federated attribute mapping types.
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::Validate;

use crate::Link;
use crate::error::BuilderError;

/// OIDC/JWT mapping data.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Mapping {
    /// Attribute mapping ID for federated logins.
    pub id: String,

    /// Attribute mapping name for federated logins.
    pub name: String,

    /// `domain_id` owning the attribute mapping.
    ///
    /// Unset `domain_id` means the attribute mapping is shared and can be used
    /// by different domains. This requires `domain_id_claim` to be present.
    /// Attribute mapping can be only shared when the referred identity
    /// provider is also shared (does not set the `domain_id` attribute).
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id: Option<String>,

    /// ID of the federated identity provider for which this attribute mapping
    /// can be used.
    pub idp_id: String,

    /// Attribute mapping type ([oidc, jwt]).
    pub r#type: MappingType,

    /// Mapping enabled property. Inactive mappings can not be used for login.
    pub enabled: bool,

    /// List of allowed redirect urls (only for `oidc` type).
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_redirect_uris: Option<Vec<String>>,

    /// `user_id` claim name.
    pub user_id_claim: String,

    /// `user_name` claim name.
    pub user_name_claim: String,

    /// `domain_id` claim name.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_id_claim: Option<String>,

    /// `groups` claim name.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups_claim: Option<String>,

    /// List of audiences that must be present in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_audiences: Option<Vec<String>>,

    /// Token subject value that must be set in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_subject: Option<String>,

    /// Additional claims that must be present in the token.
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_claims: Option<Value>,

    /// List of OIDC scopes.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_scopes: Option<Vec<String>>,

    /// Fixed project_id for the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_project_id: Option<String>,

    /// Token restrictions to be applied to the granted token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_restriction_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MappingResponse {
    /// Mapping object.
    #[validate(nested)]
    pub mapping: Mapping,
}

/// OIDC/JWT attribute mapping create data.
#[derive(Builder, Clone, Default, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MappingCreate {
    /// Attribute mapping ID for federated logins.
    #[validate(length(max = 64))]
    pub id: Option<String>,

    /// Attribute mapping name for federated logins.
    #[validate(length(max = 266))]
    pub name: String,

    /// `domain_id` owning the attribute mapping.
    ///
    /// Unset `domain_id` means the attribute mapping is shared and can be used
    /// by different domains. This requires `domain_id_claim` to be present.
    /// Attribute mapping can be only shared when the referred identity
    /// provider is also shared (does not set the `domain_id` attribute).
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub domain_id: Option<String>,

    /// ID of the federated identity provider for which this attribute mapping
    /// can be used.
    #[validate(length(max = 64))]
    pub idp_id: String,

    /// Attribute mapping type ([oidc, jwt]).
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<MappingType>,

    /// Mapping enabled property. Inactive mappings can not be used for login.
    #[serde(default = "crate::default_true")]
    pub enabled: bool,

    /// List of allowed redirect urls (only for `oidc` type).
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_redirect_uris: Option<Vec<String>>,

    /// `user_id` claim name.
    #[validate(length(max = 64))]
    pub user_id_claim: String,

    /// `user_name` claim name.
    #[validate(length(max = 64))]
    pub user_name_claim: String,

    /// `domain_id` claim name.
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub domain_id_claim: Option<String>,

    /// `groups` claim name.
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub groups_claim: Option<String>,

    /// List of audiences that must be present in the token.
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_audiences: Option<Vec<String>>,

    /// Token subject value that must be set in the token.
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub bound_subject: Option<String>,

    /// Additional claims that must be present in the token.
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_claims: Option<Value>,

    /// List of OIDC scopes.
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_scopes: Option<Vec<String>>,

    /// Fixed project_id for the token.
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub token_project_id: Option<String>,

    /// Token restrictions to be applied to the granted token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub token_restriction_id: Option<String>,
}

/// OIDC/JWT attribute mapping update data.
#[derive(Builder, Clone, Default, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MappingUpdate {
    /// Attribute mapping name for federated logins.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 255))]
    pub name: Option<String>,

    /// `domain_id` owning the attribute mapping.
    ///
    /// Unset `domain_id` means the attribute mapping is shared and can be used
    /// by different domains. This requires `domain_id_claim` to be present.
    /// Attribute mapping can be only shared when the referred identity
    /// provider is also shared (does not set the `domain_id` attribute).
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub domain_id: Option<Option<String>>,

    /// ID of the federated identity provider for which this attribute mapping
    /// can be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub idp_id: Option<String>,

    /// Attribute mapping type ([oidc, jwt]).
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<MappingType>,

    /// Mapping enabled property. Inactive mappings can not be used for login.
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// List of allowed redirect urls (only for `oidc` type).
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_redirect_uris: Option<Option<Vec<String>>>,

    /// `user_id` claim name.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub user_id_claim: Option<String>,

    /// `user_name` claim name.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub user_name_claim: Option<String>,

    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub domain_id_claim: Option<String>,

    /// `groups` claim name.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub groups_claim: Option<Option<String>>,

    /// List of audiences that must be present in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub bound_audiences: Option<Option<Vec<String>>>,

    /// Token subject value that must be set in the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub bound_subject: Option<Option<String>>,

    /// Additional claims that must be present in the token.
    #[builder(default)]
    #[cfg_attr(feature = "openapi", schema(nullable = false, value_type = Object))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_claims: Option<Value>,

    /// List of OIDC scopes.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_scopes: Option<Option<Vec<String>>>,

    /// Fixed project_id for the token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub token_project_id: Option<Option<String>>,

    /// Token restrictions to be applied to the granted token.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub token_restriction_id: Option<String>,
}

/// OIDC/JWT attribute mapping create request.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MappingCreateRequest {
    /// Mapping object.
    #[validate(nested)]
    pub mapping: MappingCreate,
}

/// OIDC/JWT attribute mapping update request.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MappingUpdateRequest {
    /// Mapping object.
    #[validate(nested)]
    pub mapping: MappingUpdate,
}

/// Attribute mapping type.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum MappingType {
    #[default]
    /// OIDC.
    Oidc,
    /// JWT.
    Jwt,
}

/// List of OIDC/JWT attribute mappings.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MappingList {
    /// Collection of identity provider objects.
    pub mappings: Vec<Mapping>,

    /// Pagination links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
}

/// Query parameters for listing OIDC/JWT attribute mappings.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct MappingListParameters {
    /// Filters the response by a domain ID.
    #[cfg_attr(feature = "openapi", param(nullable = false))]
    #[validate(length(max = 64))]
    pub domain_id: Option<String>,

    /// Filters the response by a idp ID.
    #[cfg_attr(feature = "openapi", param(nullable = false))]
    #[validate(length(max = 64))]
    pub idp_id: Option<String>,

    /// Filters the response by IDP name.
    #[cfg_attr(feature = "openapi", param(nullable = false))]
    #[validate(length(max = 255))]
    pub name: Option<String>,

    /// Limit number of entries on the single response page (Maximal 100).
    #[validate(range(min = 1, max = 100))]
    pub limit: Option<u64>,

    /// Page marker (id of the last entry on the previous page.
    #[validate(length(max = 64))]
    pub marker: Option<String>,

    /// Filters the response by a mapping type.
    #[cfg_attr(feature = "openapi", param(nullable = false))]
    pub r#type: Option<MappingType>,
}
