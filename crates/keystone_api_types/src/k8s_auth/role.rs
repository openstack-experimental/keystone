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

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::Link;
use crate::error::BuilderError;

/// K8s authentication role.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthRole {
    /// ID of the K8s auth instance this role belongs to.
    #[validate(length(max = 64))]
    pub auth_instance_id: String,

    ///  Optional Audience claim to verify in the JWT.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub bound_audience: Option<String>,

    /// List of service account names able to access this role.
    pub bound_service_account_names: Vec<String>,

    /// List of namespaces allowed to access this role.
    pub bound_service_account_namespaces: Vec<String>,

    /// Domain ID owning the K8s auth role configuration. It must always match
    /// the `domain_id` of the referred configuration.
    #[validate(length(max = 64))]
    pub domain_id: String,

    pub enabled: bool,

    #[validate(length(max = 64))]
    pub id: String,

    /// K8s auth role name.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: String,

    /// A token restriction ID that is used to bind the K8s token to the
    /// Keystone Identity and Authorization mapping.
    #[validate(length(max = 64))]
    pub token_restriction_id: String,
}

/// K8s auth role response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct K8sAuthRoleResponse {
    /// K8s auth role object.
    #[validate(nested)]
    pub role: K8sAuthRole,
}

/// New K8s authentication role.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthRoleCreate {
    // /// ID of the K8s auth instance this role belongs to.
    // #[validate(length(max = 64))]
    // pub auth_configuration_id: String,
    ///  Optional Audience claim to verify in the JWT.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub bound_audience: Option<String>,

    /// List of service account names able to access this role.
    pub bound_service_account_names: Vec<String>,

    /// List of namespaces allowed to access this role.
    pub bound_service_account_namespaces: Vec<String>,

    // /// Domain ID owning the K8s auth role configuration. It must always match
    // /// the `domain_id` of the referred configuration.
    // #[validate(length(max = 64))]
    // pub domain_id: String,
    pub enabled: bool,

    /// K8s auth role name.
    #[validate(length(max = 255))]
    pub name: String,

    /// A token restriction ID that is used to bind the K8s token to the
    /// Keystone Identity and Authorization mapping.
    #[validate(length(max = 64))]
    pub token_restriction_id: String,
}

/// K8s auth role create request.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthRoleCreateRequest {
    /// K8s auth role object.
    #[validate(nested)]
    pub role: K8sAuthRoleCreate,
}

/// Update K8s authentication role.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthRoleUpdate {
    ///  Optional Audience claim to verify in the JWT.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub bound_audience: Option<String>,

    /// List of service account names able to access this role.
    #[builder(default)]
    pub bound_service_account_names: Option<Vec<String>>,

    /// List of namespaces allowed to access this role.
    #[builder(default)]
    pub bound_service_account_namespaces: Option<Vec<String>>,

    #[builder(default)]
    pub enabled: Option<bool>,

    /// K8s auth role name.
    #[builder(default)]
    #[validate(length(max = 255))]
    pub name: Option<String>,

    /// A token restriction ID that is used to bind the K8s token to the
    /// Keystone Identity and Authorization mapping.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub token_restriction_id: Option<String>,
}

/// K8s auth role update request.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthRoleUpdateRequest {
    /// K8s auth role object.
    #[validate(nested)]
    pub role: K8sAuthRoleUpdate,
}

/// List of K8s auth roles.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct K8sAuthRoleList {
    /// Collection of k8s auth role objects.
    #[validate(nested)]
    pub roles: Vec<K8sAuthRole>,

    /// Pagination links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
}

impl IntoResponse for K8sAuthRoleList {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

/// K8s Auth role list parameters (nested).
#[derive(
    Builder, Clone, Debug, Deserialize, IntoParams, PartialEq, Serialize, ToSchema, Validate,
)]
#[builder(build_fn(error = "BuilderError"))]
pub struct K8sAuthRolePathParams {
    /// The ID of the K8s auth instance.
    #[validate(length(max = 64))]
    pub instance_id: String,

    /// The ID of the K8s auth role.
    #[validate(length(max = 64))]
    pub id: String,
}

/// K8s Auth role list parameters (nested).
#[derive(
    Builder,
    Clone,
    Debug,
    Default,
    Deserialize,
    IntoParams,
    PartialEq,
    Serialize,
    ToSchema,
    Validate,
)]
#[builder(build_fn(error = "BuilderError"))]
pub struct K8sAuthRoleListParametersNested {
    /// Name.
    #[validate(length(max = 255))]
    pub name: Option<String>,
}

/// K8s Auth role list parameters.
#[derive(
    Builder,
    Clone,
    Debug,
    Default,
    Deserialize,
    IntoParams,
    PartialEq,
    Serialize,
    ToSchema,
    Validate,
)]
#[builder(build_fn(error = "BuilderError"))]
pub struct K8sAuthRoleListParameters {
    /// K8s auth instance id.
    #[validate(length(max = 64))]
    pub auth_instance_id: Option<String>,

    /// Domain id.
    ///
    /// Bu default only user with corresponding privileges is allowed to list
    /// roles of the domain other than in the current scope.
    #[validate(length(max = 64))]
    pub domain_id: Option<String>,

    /// Name.
    #[validate(length(max = 255))]
    pub name: Option<String>,
}
