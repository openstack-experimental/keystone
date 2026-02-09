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
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::api::v3::role_assignment::types::Role;
use crate::token::types::{
    self as types, TokenRestriction as ProviderTokenRestriction,
    TokenRestrictionCreate as ProviderTokenRestrictionCreate,
    TokenRestrictionUpdate as ProviderTokenRestrictionUpdate,
};

/// Token restriction data.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(setter(strip_option, into))]
pub struct TokenRestriction {
    /// Allow token renew.
    pub allow_renew: bool,

    /// Allow token rescope.
    pub allow_rescope: bool,

    /// Domain ID the token restriction belongs to.
    #[validate(length(max = 64))]
    pub domain_id: String,

    /// Token restriction ID.
    #[validate(length(max = 64))]
    pub id: String,

    /// Project ID that the token must be bound to.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub project_id: Option<String>,

    /// User ID that the token must be bound to.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub user_id: Option<String>,

    /// Bound token roles.
    #[builder(default)]
    #[validate(nested)]
    pub roles: Vec<Role>,
}

/// New token restriction data.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(setter(strip_option, into))]
pub struct TokenRestrictionCreate {
    /// Allow token renew.
    pub allow_renew: bool,

    /// Allow token rescope.
    pub allow_rescope: bool,

    /// Domain ID the token restriction belongs to.
    #[validate(length(max = 64))]
    pub domain_id: String,

    /// Project ID that the token must be bound to.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 64))]
    pub project_id: Option<String>,

    /// User ID that the token must be bound to.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// Bound token roles.
    #[builder(default)]
    #[validate(nested)]
    pub roles: Vec<Role>,
}

/// New token restriction data.
#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[builder(setter(strip_option, into))]
pub struct TokenRestrictionUpdate {
    /// Allow token renew.
    pub allow_renew: Option<bool>,

    /// Allow token rescope.
    pub allow_rescope: Option<bool>,

    /// Project ID that the token must be bound to.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub project_id: Option<Option<String>>,

    /// User ID that the token must be bound to.
    #[builder(default)]
    #[validate(length(max = 64))]
    pub user_id: Option<Option<String>>,

    /// Bound token roles.
    #[builder(default)]
    #[validate(nested)]
    pub roles: Option<Vec<Role>>,
}

/// Token restriction data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct TokenRestrictionResponse {
    /// Restriction object.
    #[validate(nested)]
    pub restriction: TokenRestriction,
}

/// Token restriction creation request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct TokenRestrictionCreateRequest {
    /// Restriction object.
    #[validate(nested)]
    pub restriction: TokenRestrictionCreate,
}

/// Token restriction update request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
pub struct TokenRestrictionUpdateRequest {
    /// Restriction object.
    #[validate(nested)]
    pub restriction: TokenRestrictionUpdate,
}

/// Token restriction list filters.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, IntoParams, Validate)]
pub struct TokenRestrictionListParameters {
    /// Domain id.
    #[validate(length(max = 64))]
    pub domain_id: Option<String>,
    /// User id.
    #[validate(length(max = 64))]
    pub user_id: Option<String>,
    /// Project id.
    #[validate(length(max = 64))]
    pub project_id: Option<String>,
}

/// Token restrictions.
#[derive(Builder, Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
#[builder(setter(strip_option, into))]
pub struct TokenRestrictionList {
    /// Token restrictions.
    pub restrictions: Vec<TokenRestriction>,
}

impl IntoResponse for TokenRestrictionList {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

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

impl From<crate::assignment::types::role::Role> for Role {
    fn from(value: crate::assignment::types::role::Role) -> Self {
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
