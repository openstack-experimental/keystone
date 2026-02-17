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

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::Serialize;
use validator::Validate;

use crate::error::BuilderError;
use crate::identity::types::UserResponse;
use crate::resource::types::Domain;
use crate::role::types::Role;
use crate::token::types::Token;
use crate::token::types::common;

/// Federated domain scope token payload.
#[derive(Builder, Clone, Debug, Default, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into))]
pub struct FederationDomainScopePayload {
    #[validate(length(min = 1, max = 64))]
    pub user_id: String,

    #[builder(default, setter(name = _methods))]
    #[validate(length(min = 1))]
    pub methods: Vec<String>,

    #[builder(default, setter(name = _audit_ids))]
    #[validate(custom(function = "common::validate_audit_ids"))]
    pub audit_ids: Vec<String>,
    pub expires_at: DateTime<Utc>,

    #[validate(length(min = 1, max = 64))]
    pub domain_id: String,

    #[validate(length(min = 1, max = 64))]
    pub idp_id: String,

    #[validate(length(min = 1, max = 64))]
    pub protocol_id: String,
    pub group_ids: Vec<String>,

    #[builder(default)]
    pub issued_at: DateTime<Utc>,

    #[builder(default)]
    pub user: Option<UserResponse>,
    #[builder(default)]
    pub roles: Option<Vec<Role>>,
    #[builder(default)]
    pub domain: Option<Domain>,
}

impl FederationDomainScopePayloadBuilder {
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

impl From<FederationDomainScopePayload> for Token {
    fn from(value: FederationDomainScopePayload) -> Self {
        Self::FederationDomainScope(value)
    }
}
