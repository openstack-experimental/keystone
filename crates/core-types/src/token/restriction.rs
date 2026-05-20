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
//! Restricted token types.

use derive_builder::Builder;
use serde::Serialize;
use validator::Validate;

use crate::error::BuilderError;
use crate::role::RoleRef;

/// Token restriction information.
#[derive(Builder, Clone, Debug, Default, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct TokenRestriction {
    /// Whether the restriction allows to rescope the token.
    pub allow_rescope: bool,

    /// Whether it is allowed to renew the token with this restriction.
    pub allow_renew: bool,

    /// Id.
    #[validate(length(min = 1, max = 64))]
    pub id: String,

    /// Domain Id the token restriction belongs to.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: String,

    /// Optional project ID to be used with this restriction.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub project_id: Option<String>,

    /// Roles bound to the restriction.
    pub role_ids: Vec<String>,

    /// Optional list of full Role information.
    #[builder(default)]
    #[validate(nested)]
    pub roles: Option<Vec<RoleRef>>,

    /// User id.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
    pub user_id: Option<String>,
}

/// New token restriction information.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
pub struct TokenRestrictionCreate {
    /// Whether the restriction allows to rescope the token.
    pub allow_rescope: bool,
    /// Whether it is allowed to renew the token with this restriction.
    pub allow_renew: bool,
    /// Id.
    #[validate(length(min = 1, max = 64))]
    pub id: String,
    /// Domain Id the token restriction belongs to.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: String,
    /// Optional project ID to be used with this restriction.
    #[validate(length(min = 1, max = 64))]
    pub project_id: Option<String>,
    /// Roles bound to the restriction.
    pub role_ids: Vec<String>,
    /// User id.
    #[validate(length(min = 1, max = 64))]
    pub user_id: Option<String>,
}

/// Token restriction update information.
#[derive(Builder, Clone, Debug, Default, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
pub struct TokenRestrictionUpdate {
    /// Whether the restriction allows to rescope the token.
    pub allow_rescope: Option<bool>,
    /// Whether it is allowed to renew the token with this restriction.
    pub allow_renew: Option<bool>,
    /// Optional project ID to be used with this restriction.
    pub project_id: Option<Option<String>>,
    /// Roles bound to the restriction.
    pub role_ids: Option<Vec<String>>,
    /// User id.
    pub user_id: Option<Option<String>>,
}

/// Token restriction list filters.
#[derive(Builder, Clone, Debug, Default, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
pub struct TokenRestrictionListParameters {
    /// Domain id.
    #[validate(length(min = 1, max = 64))]
    pub domain_id: Option<String>,
    /// User id.
    #[validate(length(min = 1, max = 64))]
    pub user_id: Option<String>,
    /// Project id.
    #[validate(length(min = 1, max = 64))]
    pub project_id: Option<String>,
}
