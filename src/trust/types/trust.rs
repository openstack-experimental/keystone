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

//! # Trust types
use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::Validate;

use crate::assignment::types::Role;
use crate::error::BuilderError;

/// A trust object.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Trust {
    /// The trust deletion date.
    #[builder(default)]
    pub deleted_at: Option<DateTime<Utc>>,

    /// Specifies the expiration time of the trust. A trust may be revoked ahead
    /// of expiration. If the value represents a time in the past, the trust is
    /// deactivated. In the redelegation case it must not exceed the value of
    /// the corresponding `expires_at` field of the redelegated trust or it may
    /// be omitted, then the `expires_at` value is copied from the
    /// redelegated trust.
    #[builder(default)]
    pub expires_at: Option<DateTime<Utc>>,

    #[builder(default)]
    pub extra: Option<Value>,

    /// The ID of the trust.
    #[validate(length(min = 1, max = 64))]
    pub id: String,

    /// If set to `true`, then the user attribute of tokens generated based on
    /// the trust will represent that of the `trustor` rather than the
    /// `trustee`, thus allowing the `trustee` to impersonate the `trustor`.
    /// If impersonation is set to `false`, then the token’s user attribute
    /// will represent that of the `trustee`.
    pub impersonation: bool,

    /// Identifies the project upon which the trustor is delegating
    /// authorization.
    #[builder(default)]
    #[serde(default)]
    #[validate(length(min = 1, max = 64))]
    pub project_id: Option<String>,

    /// Specifies how many times the trust can be used to obtain a token. This
    /// value is decreased each time a token is issued through the trust. Once
    /// it reaches 0, no further tokens will be issued through the trust. The
    /// default value is null, meaning there is no limit on the number of tokens
    /// issued through the trust. If redelegation is enabled it must not be set.
    #[builder(default)]
    pub remaining_uses: Option<u32>,

    /// Returned with redelegated trust provides information about the
    /// predecessor in the trust chain.
    #[builder(default)]
    #[validate(length(min = 1, max = 64))]
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
    #[builder(default)]
    pub redelegation_count: Option<u32>,

    /// Specifies the subset of the trustor's roles on the `project_id` to be
    /// granted to the `trustee` when the token is consumed. The trustor must
    /// already be granted these roles in the project referenced by the
    /// `project_id` attribute. If redelegation is used (when trust-scoped token
    /// is used and consumed trust has `allow_redelegation` set to true) this
    /// parameter should contain redelegated trust's roles only.
    /// Roles are only provided when the trust is created, and are subsequently
    /// available as a separate read-only collection. Each role can be specified
    /// by either id or name.
    #[builder(default)]
    pub roles: Option<Vec<Role>>,

    /// Represents the user who created the trust, and who’s authorization is
    /// being delegated.
    #[validate(length(min = 1, max = 64))]
    pub trustor_user_id: String,

    /// Represents the user who is capable of consuming the trust.
    #[validate(length(min = 1, max = 64))]
    pub trustee_user_id: String,
}

/// A trust list parameters.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq, Validate)]
#[builder(setter(strip_option, into))]
pub struct TrustListParameters {
    /// Whether to include deleted trusts.
    #[builder(default)]
    pub include_deleted: Option<bool>,

    /// Limit number of entries on the single response page.
    #[builder(default)]
    pub limit: Option<u64>,

    /// Page marker (id of the last entry on the previous page.
    #[builder(default)]
    pub marker: Option<String>,
}
