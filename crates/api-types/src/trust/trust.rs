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
use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

/// A trust object returned in the token.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(
    feature = "builder",
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TokenTrustRepr {
    /// Specifies the expiration time of the trust. A trust may be revoked ahead
    /// of expiration. If the value represents a time in the past, the trust is
    /// deactivated. In the redelegation case it must not exceed the value of
    /// the corresponding `expires_at` field of the redelegated trust or it may
    /// be omitted, then the `expires_at` value is copied from the
    /// redelegated trust.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// The ID of the trust.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,

    /// If set to `true`, then the user attribute of tokens generated based on
    /// the trust will represent that of the `trustor` rather than the
    /// `trustee`, thus allowing the `trustee` to impersonate the `trustor`.
    /// If impersonation is set to `false`, then the token's user attribute
    /// will represent that of the `trustee`.
    pub impersonation: bool,

    /// Specifies how many times the trust can be used to obtain a token. This
    /// value is decreased each time a token is issued through the trust. Once
    /// it reaches 0, no further tokens will be issued through the trust. The
    /// default value is null, meaning there is no limit on the number of tokens
    /// issued through the trust. If redelegation is enabled it must not be set.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_uses: Option<u32>,

    /// Returned with redelegated trust provides information about the
    /// predecessor in the trust chain.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub redelegated_trust_id: Option<String>,

    /// Specifies the maximum remaining depth of the redelegated trust chain.
    /// Each subsequent trust has this field decremented by 1 automatically. The
    /// initial trustor issuing new trust that can be redelegated, must set
    /// allow_redelegation to true and may set `redelegation_count` to an
    /// integer value less than or equal to `max_redelegation_count`
    /// configuration parameter in order to limit the possible length of
    /// derived trust chains. The trust issued by the `trustor` using a
    /// project-scoped token (not redelegating), in which
    /// `allow_redelegation` is set to true (the new
    /// trust is redelegatable), will be populated with the value specified in
    /// the `max_redelegation_count` configuration parameter if
    /// `redelegation_count` is not set or set to `null`. If
    /// `allow_redelegation` is set to `false` then `redelegation_count`
    /// will be set to 0 in the trust. If the trust is being issued by the
    /// `trustee` of a redelegatable trust-scoped token (redelegation case)
    /// then `redelegation_count` should not be set, as it
    /// will automatically be set to the value in the redelegatable
    /// trust-scoped token decremented by 1. Note, if the resulting value is
    /// 0, this means that the new trust will not be redelegatable,
    /// regardless of the value of `allow_redelegation`.
    #[cfg_attr(feature = "builder", builder(default))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redelegation_count: Option<u32>,

    /// Represents the user who created the trust, and who's authorization is
    /// being delegated.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub trustor_user: TokenTrustUser,

    /// Represents the user who is capable of consuming the trust.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub trustee_user: TokenTrustUser,
}

/// A trust object returned in the token.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[cfg_attr(feature = "builder", derive(derive_builder::Builder))]
#[cfg_attr(
    feature = "builder",
    builder(
        build_fn(error = "crate::error::BuilderError"),
        setter(strip_option, into)
    )
)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct TokenTrustUser {
    /// The ID of the user.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub id: String,
}
