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
//! # K8s Auth role types.

use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

use crate::Link;

/// K8s authentication role.
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
pub struct K8sAuthRole {
    /// ID of the K8s auth instance this role belongs to.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub auth_instance_id: String,

    ///  Optional Audience claim to verify in the JWT.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub bound_audience: Option<String>,

    /// List of service account names able to access this role.
    pub bound_service_account_names: Vec<String>,

    /// List of namespaces allowed to access this role.
    pub bound_service_account_namespaces: Vec<String>,

    /// Domain ID owning the K8s auth role configuration. It must always match
    /// the `domain_id` of the referred configuration.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: String,

    pub enabled: bool,

    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,

    /// K8s auth role name.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: String,

    /// A token restriction ID that is used to bind the K8s token to the
    /// Keystone Identity and Authorization mapping.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub token_restriction_id: String,
}

/// K8s auth role response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct K8sAuthRoleResponse {
    /// K8s auth role object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub role: K8sAuthRole,
}

/// New K8s authentication role.
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
pub struct K8sAuthRoleCreate {
    // /// ID of the K8s auth instance this role belongs to.
    // #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    // pub auth_configuration_id: String,
    ///  Optional Audience claim to verify in the JWT.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub bound_audience: Option<String>,

    /// List of service account names able to access this role.
    pub bound_service_account_names: Vec<String>,

    /// List of namespaces allowed to access this role.
    pub bound_service_account_namespaces: Vec<String>,

    // /// Domain ID owning the K8s auth role configuration. It must always match
    // /// the `domain_id` of the referred configuration.
    // #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    // pub domain_id: String,
    pub enabled: bool,

    /// K8s auth role name.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: String,

    /// A token restriction ID that is used to bind the K8s token to the
    /// Keystone Identity and Authorization mapping.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub token_restriction_id: String,
}

/// K8s auth role create request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct K8sAuthRoleCreateRequest {
    /// K8s auth role object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub role: K8sAuthRoleCreate,
}

/// Update K8s authentication role.
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
pub struct K8sAuthRoleUpdate {
    ///  Optional Audience claim to verify in the JWT.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub bound_audience: Option<String>,

    /// List of service account names able to access this role.
    #[cfg_attr(feature = "builder", builder(default))]
    pub bound_service_account_names: Option<Vec<String>>,

    /// List of namespaces allowed to access this role.
    #[cfg_attr(feature = "builder", builder(default))]
    pub bound_service_account_namespaces: Option<Vec<String>>,

    #[cfg_attr(feature = "builder", builder(default))]
    pub enabled: Option<bool>,

    /// K8s auth role name.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,

    /// A token restriction ID that is used to bind the K8s token to the
    /// Keystone Identity and Authorization mapping.
    #[cfg_attr(feature = "builder", builder(default))]
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub token_restriction_id: Option<String>,
}

/// K8s auth role update request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct K8sAuthRoleUpdateRequest {
    /// K8s auth role object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub role: K8sAuthRoleUpdate,
}

/// List of K8s auth roles.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct K8sAuthRoleList {
    /// Collection of k8s auth role objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub roles: Vec<K8sAuthRole>,

    /// Pagination links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
}

/// Path parameters for the nested implementation of the K8s Auth role list.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct K8sAuthRolePathParams {
    /// The ID of the K8s auth instance.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub instance_id: String,

    /// The ID of the K8s auth role.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub id: String,
}

/// K8s Auth role list parameters (nested).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct K8sAuthRoleListParametersNested {
    /// Name.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,
}

/// K8s Auth role list parameters.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct K8sAuthRoleListParameters {
    /// K8s auth instance id.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub auth_instance_id: Option<String>,

    /// Domain id.
    ///
    /// Bu default only user with corresponding privileges is allowed to list
    /// roles of the domain other than in the current scope.
    #[cfg_attr(feature = "validate", validate(length(max = 64)))]
    pub domain_id: Option<String>,

    /// Name.
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub name: Option<String>,
}
