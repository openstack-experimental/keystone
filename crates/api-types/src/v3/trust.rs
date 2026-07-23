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
//! # Trust REST resource types
//!
//! Distinct from `crate::trust::TokenTrustRepr`, which is the trust
//! representation embedded in a token response body. These types represent
//! `/v3/OS-TRUST/trusts` as its own resource.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "validate")]
use validator::Validate;

/// A role reference as accepted/returned by the trust API.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TrustRoleRef {
    /// Role domain ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: Option<String>,

    /// Role ID. May be omitted if `name` is given instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: Option<String>,

    /// Role name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub name: Option<String>,
}

/// The trust data.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct Trust {
    /// Trust ID.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,

    /// The ID of the user who created the trust, and who's authorization is
    /// being delegated.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub trustor_user_id: String,

    /// The ID of the user who is capable of consuming the trust.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub trustee_user_id: String,

    /// The ID of the project upon which the trustor is delegating
    /// authorization.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub project_id: Option<String>,

    /// Allow the trustee to impersonate the trustor.
    pub impersonation: bool,

    /// Trust expiration time.
    ///
    /// Always present (as `null` when unset) to match python keystone --
    /// tempest indexes `trust['expires_at']` unconditionally.
    pub expires_at: Option<DateTime<Utc>>,

    /// Remaining number of times the trust can be used to obtain a token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_uses: Option<u32>,

    /// The ID of the redelegated trust, if this trust was created by
    /// redelegation.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub redelegated_trust_id: Option<String>,

    /// Maximum remaining depth of the redelegated trust chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redelegation_count: Option<u32>,

    /// Roles delegated by this trust.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub roles: Vec<TrustRoleRef>,

    /// Arbitrary additional attributes stored with the trust.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TrustResponse {
    /// Trust object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub trust: Trust,
}

/// Trusts.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TrustList {
    /// Collection of trust objects.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub trusts: Vec<Trust>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TrustListParameters {
    /// Whether to include soft-deleted trusts.
    #[serde(default)]
    pub include_deleted: Option<bool>,
}

/// Trust create request body.
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
pub struct TrustCreate {
    /// The ID of the trust. A UUID is generated when omitted.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: Option<String>,

    /// The ID of the user who created the trust, and who's authorization is
    /// being delegated.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub trustor_user_id: String,

    /// The ID of the user who is capable of consuming the trust.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub trustee_user_id: String,

    /// The ID of the project upon which the trustor is delegating
    /// authorization. Must be set together with `roles`, or omitted together
    /// with `roles`.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub project_id: Option<String>,

    /// Allow the trustee to impersonate the trustor.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default)]
    pub impersonation: bool,

    /// Trust expiration time.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Limit the number of times the trust can be used to obtain a token.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_uses: Option<u32>,

    /// The ID of the trust to redelegate from.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub redelegated_trust_id: Option<String>,

    /// Maximum remaining depth of the redelegated trust chain.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redelegation_count: Option<u32>,

    /// Roles to delegate. Must be set together with `project_id`, or omitted
    /// together with `project_id`.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "validate", validate(nested))]
    pub roles: Vec<TrustRoleRef>,

    /// Arbitrary additional attributes to store with the trust.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

/// New trust creation request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TrustCreateRequest {
    /// Trust object.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub trust: TrustCreate,
}
