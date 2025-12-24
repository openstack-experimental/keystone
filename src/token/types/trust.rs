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
//! Trust token types.

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::Serialize;
use validator::Validate;

use crate::assignment::types::Role;
use crate::error::BuilderError;
use crate::identity::types::UserResponse;
use crate::resource::types::Project;
use crate::token::types::{Token, common};
use crate::trust::types::Trust;

/// Trust token payload.
#[derive(Builder, Clone, Debug, Default, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into))]
pub struct TrustPayload {
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

    /// ID of the trust.
    #[validate(length(min = 1, max = 64))]
    pub trust_id: String,

    /// Project ID scope for the token.
    #[validate(length(min = 1, max = 64))]
    pub project_id: String,

    #[builder(default)]
    pub issued_at: DateTime<Utc>,
    #[builder(default)]
    pub user: Option<UserResponse>,
    #[builder(default)]
    pub trust: Option<Trust>,
    #[builder(default)]
    pub roles: Option<Vec<Role>>,
    #[builder(default)]
    pub project: Option<Project>,
}

impl TrustPayloadBuilder {
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

impl From<TrustPayload> for Token {
    fn from(value: TrustPayload) -> Self {
        Self::Trust(value)
    }
}
