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
//! Token restriction types.
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub use openstack_keystone_api_types::v4::token_restriction::*;

use crate::api::v3::role_assignment::types::Role;
use crate::token::types::{
    self as types, TokenRestriction as ProviderTokenRestriction,
    TokenRestrictionCreate as ProviderTokenRestrictionCreate,
    TokenRestrictionUpdate as ProviderTokenRestrictionUpdate,
};

impl From<TokenRestrictionListParameters> for types::TokenRestrictionListParameters {
    fn from(value: TokenRestrictionListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            user_id: value.user_id,
            project_id: value.project_id,
        }
    }
}

impl From<ProviderTokenRestriction> for TokenRestriction {
    fn from(value: ProviderTokenRestriction) -> Self {
        Self {
            allow_rescope: value.allow_rescope,
            allow_renew: value.allow_renew,
            id: value.id,
            domain_id: value.domain_id,
            project_id: value.project_id,
            user_id: value.user_id,
            roles: value
                .roles
                .map(|roles| roles.into_iter().map(Into::into).collect())
                .unwrap_or_default(),
        }
    }
}

impl From<TokenRestrictionCreateRequest> for ProviderTokenRestrictionCreate {
    fn from(value: TokenRestrictionCreateRequest) -> Self {
        Self {
            allow_rescope: value.restriction.allow_rescope,
            allow_renew: value.restriction.allow_renew,
            id: String::new(),
            domain_id: value.restriction.domain_id,
            project_id: value.restriction.project_id,
            user_id: value.restriction.user_id,
            role_ids: value
                .restriction
                .roles
                .into_iter()
                .map(|role| role.id)
                .collect(),
        }
    }
}

impl From<TokenRestrictionUpdateRequest> for ProviderTokenRestrictionUpdate {
    fn from(value: TokenRestrictionUpdateRequest) -> Self {
        Self {
            allow_rescope: value.restriction.allow_rescope,
            allow_renew: value.restriction.allow_renew,
            project_id: value.restriction.project_id,
            user_id: value.restriction.user_id,
            role_ids: value
                .restriction
                .roles
                .map(|roles| roles.into_iter().map(|role| role.id).collect()),
        }
    }
}

impl From<crate::role::types::Role> for Role {
    fn from(value: crate::role::types::Role) -> Self {
        Self {
            id: value.id,
            name: value.name.into(),
        }
    }
}

impl IntoResponse for ProviderTokenRestriction {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            Json(TokenRestrictionResponse {
                restriction: TokenRestriction::from(self),
            }),
        )
            .into_response()
    }
}
