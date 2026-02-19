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

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::error::BuilderError;

/// K8s authentication role.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthRole {
    /// ID of the K8s auth configuration this role belongs to.
    pub auth_configuration_id: String,

    ///  Optional Audience claim to verify in the JWT.
    #[builder(default)]
    pub bound_audience: Option<String>,

    /// List of service account names able to access this role.
    pub bound_service_account_names: Vec<String>,

    /// List of namespaces allowed to access this role.
    pub bound_service_account_namespaces: Vec<String>,

    /// Domain ID owning the K8s auth role configuration. It must always match
    /// the `domain_id` of the referred configuration.
    pub domain_id: String,

    pub enabled: bool,

    pub id: String,

    /// K8s auth role name.
    #[builder(default)]
    pub name: String,

    /// A token restriction ID that is used to bind the K8s token to the
    /// Keystone Identity and Authorization mapping.
    pub token_restriction_id: String,
}

/// New K8s authentication role.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthRoleCreate {
    /// ID of the K8s auth configuration this role belongs to.
    pub auth_configuration_id: String,

    ///  Optional Audience claim to verify in the JWT.
    #[builder(default)]
    pub bound_audience: Option<String>,

    /// List of service account names able to access this role.
    pub bound_service_account_names: Vec<String>,

    /// List of namespaces allowed to access this role.
    pub bound_service_account_namespaces: Vec<String>,

    /// Domain ID owning the K8s auth role configuration. It must always match
    /// the `domain_id` of the referred configuration.
    pub domain_id: String,

    pub enabled: bool,

    /// Optional ID.
    #[builder(default)]
    pub id: Option<String>,

    /// K8s auth role name.
    pub name: String,

    /// A token restriction ID that is used to bind the K8s token to the
    /// Keystone Identity and Authorization mapping.
    pub token_restriction_id: String,
}

/// Update K8s authentication role.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthRoleUpdate {
    ///  Optional Audience claim to verify in the JWT.
    #[builder(default)]
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
    pub name: Option<String>,

    /// A token restriction ID that is used to bind the K8s token to the
    /// Keystone Identity and Authorization mapping.
    #[builder(default)]
    pub token_restriction_id: Option<String>,
}

/// K8s Auth role list parameters.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
pub struct K8sAuthRoleListParameters {
    /// K8s auth configuration id.
    pub auth_configuration_id: Option<String>,
    /// Domain id.
    pub domain_id: Option<String>,
    /// Name.
    pub name: Option<String>,
}
