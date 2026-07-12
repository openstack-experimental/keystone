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
//! v4 API types for dynamic auth plugin administration (ADR 0025 §4
//! "Admin-Authorized External Identity Linking").

use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

/// A single `(plugin_name, external_id) -> user_id` identity link, as
/// returned by the admin linking API. `plugin_name` comes from the request
/// path, not the body.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IdentityLink {
    pub plugin_name: String,
    pub external_id: String,
    pub user_id: String,
}

/// Body of a link-create request: pair an existing Keystone `user_id` with
/// the `external_id` a `full_auth` plugin's `find_user` will present (ADR
/// 0025 §4). The plugin never populates this table itself for a pre-existing
/// user - an administrator does, out of band, gated by ordinary RBAC.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityLinkCreate {
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 255)))]
    pub external_id: String,
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub user_id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(validator::Validate))]
pub struct IdentityLinkCreateRequest {
    #[cfg_attr(feature = "validate", validate(nested))]
    pub identity_link: IdentityLinkCreate,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IdentityLinkResponse {
    pub identity_link: IdentityLink,
}

/// Per-category blast-radius counts returned by `revoke_all` (ADR 0025 §4
/// "Bulk Revocation on Plugin Compromise"). An empty run reports all zeros.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeAllSummary {
    pub users_disabled: usize,
    pub links_deleted: usize,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeAllResponse {
    pub revoke_all: RevokeAllSummary,
}
