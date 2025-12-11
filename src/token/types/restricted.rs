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

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::assignment::types::Role;
use crate::identity::types::UserResponse;
use crate::resource::types::Project;
use crate::token::types::Token;
use crate::token::types::common;

/// Restricted token payload.
#[derive(Builder, Clone, Debug, Default, PartialEq, Serialize, Validate)]
#[builder(setter(into))]
pub struct RestrictedPayload {
    /// User ID.
    #[validate(length(min = 1, max = 64))]
    pub user_id: String,

    /// Authentication methods used to obtain the token.
    #[builder(default, setter(name = _methods))]
    #[validate(length(min = 1))]
    pub methods: Vec<String>,
    /// Token audit IDs.
    #[builder(default, setter(name = _audit_ids))]
    #[validate(custom(function = "common::validate_audit_ids"))]
    pub audit_ids: Vec<String>,
    /// Token expiration datetime in UTC.
    pub expires_at: DateTime<Utc>,
    /// ID of the token restrictions.
    #[validate(length(min = 1, max = 64))]
    pub token_restriction_id: String,
    /// Project ID scope for the token.
    #[validate(length(min = 1, max = 64))]
    pub project_id: String,
    /// Whether the token can be renewed.
    pub allow_renew: bool,
    /// Whether the token can be rescoped.
    pub allow_rescope: bool,

    #[builder(default)]
    pub issued_at: DateTime<Utc>,
    #[builder(default)]
    pub user: Option<UserResponse>,
    #[builder(default)]
    pub roles: Option<Vec<Role>>,
    #[builder(default)]
    pub project: Option<Project>,
}

impl RestrictedPayloadBuilder {
    pub fn methods<I, V>(&mut self, iter: I) -> &mut Self
    where
        I: Iterator<Item = V>,
        V: Into<String>,
    {
        self.methods
            .get_or_insert_with(Vec::new)
            .extend(iter.map(Into::into));
        self
    }

    pub fn audit_ids<I, V>(&mut self, iter: I) -> &mut Self
    where
        I: Iterator<Item = V>,
        V: Into<String>,
    {
        self.audit_ids
            .get_or_insert_with(Vec::new)
            .extend(iter.map(Into::into));
        self
    }
}

impl From<RestrictedPayload> for Token {
    fn from(value: RestrictedPayload) -> Self {
        Self::Restricted(value)
    }
}

/// Token restriction information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct TokenRestriction {
    /// Whether the restriction allows to rescope the token.
    pub allow_rescope: bool,
    /// Whether it is allowed to renew the token with this restriction.
    pub allow_renew: bool,
    /// Id.
    pub id: String,
    /// Domain Id the token restriction belongs to.
    pub domain_id: String,
    /// Optional project ID to be used with this restriction.
    pub project_id: Option<String>,
    /// Roles bound to the restriction.
    pub role_ids: Vec<String>,
    /// Optional list of full Role information.
    pub roles: Option<Vec<crate::assignment::types::Role>>,
    /// User id
    pub user_id: Option<String>,
}

/// New token restriction information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct TokenRestrictionCreate {
    /// Whether the restriction allows to rescope the token.
    pub allow_rescope: bool,
    /// Whether it is allowed to renew the token with this restriction.
    pub allow_renew: bool,
    /// Id.
    pub id: String,
    /// Domain Id the token restriction belongs to.
    pub domain_id: String,
    /// Optional project ID to be used with this restriction.
    pub project_id: Option<String>,
    /// Roles bound to the restriction.
    pub role_ids: Vec<String>,
    /// User id
    pub user_id: Option<String>,
}

/// Token restriction update information.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
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
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct TokenRestrictionListParameters {
    /// Domain id.
    pub domain_id: Option<String>,
    /// User id.
    pub user_id: Option<String>,
    /// Project id.
    pub project_id: Option<String>,
}
