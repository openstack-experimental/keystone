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
//! Service grant API types (ADR 0036 §4).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "validate")]
use validator::Validate;

/// Who a grant delegates to.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Grantee {
    /// A registered delegatable service client.
    Client {
        /// Grantee client id.
        client_id: String,
        /// Domain of the grantee client.
        client_domain_id: String,
    },
}

/// What a grant lets the grantee act on.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GrantTarget {
    /// One project.
    Project {
        /// Target project id.
        project_id: String,
        /// Domain of the target project.
        project_domain_id: String,
    },
}

/// Why a grant was disabled.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DisabledReason {
    /// The grantor no longer holds any of the delegated roles.
    RoleLost,
    /// The grantor was disabled.
    GrantorDisabled,
    /// The grantee client is gone or no longer delegatable.
    GranteeRemoved,
    /// The target project was disabled.
    TargetDisabled,
    /// The grant was revoked.
    Revoked,
    /// The grant expired.
    Expired,
}

/// A service grant: a user's standing delegation of a subset of their roles
/// on one project to one service client.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ServiceGrant {
    /// Grant id.
    pub id: String,

    /// Grantor's domain.
    pub domain_id: String,

    /// The user whose authority is delegated.
    pub grantor_user_id: String,

    /// Who may redeem the grant.
    pub grantee: Grantee,

    /// What the grant applies to.
    pub target: GrantTarget,

    /// Delegated role ids.
    pub role_ids: Vec<String>,

    /// Expiry, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Free-form description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Whether the grant may be redeemed.
    pub enabled: bool,

    /// Creation time.
    pub created_at: DateTime<Utc>,

    /// Approximate time of the last redemption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_redeemed_at: Option<DateTime<Utc>>,

    /// Why the grant was disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<DisabledReason>,
}

/// Service grant creation payload. The grantor is always the caller.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(Validate))]
pub struct ServiceGrantCreate {
    /// Grantee client id, as listed by `GET /v4/delegatable-services`.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub grantee_client_id: String,

    /// Target project id.
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub project_id: String,

    /// Role ids to delegate; omitted delegates the caller's current
    /// effective roles on the project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub role_ids: Option<Vec<String>>,

    /// Expiry; defaults to the grantee's `max_grant_lifetime`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Free-form description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(max = 255)))]
    pub description: Option<String>,
}

/// Service grant creation request.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "validate", derive(Validate))]
pub struct ServiceGrantCreateRequest {
    /// The grant to create.
    #[cfg_attr(feature = "validate", validate(nested))]
    pub service_grant: ServiceGrantCreate,
}

/// Single service grant response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ServiceGrantResponse {
    /// The grant.
    pub service_grant: ServiceGrant,
}

/// Service grant list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ServiceGrantList {
    /// Grants visible to the caller.
    pub service_grants: Vec<ServiceGrant>,

    /// Pagination links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<crate::Link>>,
}

/// Service grant list filters. A caller without `admin` must name either
/// itself as `user_id`, or the project (`project_id`) or domain
/// (`domain_id`) it manages.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[cfg_attr(feature = "validate", derive(Validate))]
pub struct ServiceGrantListParameters {
    /// Grantor user id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub user_id: Option<String>,

    /// Target project id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub project_id: Option<String>,

    /// Grantor domain id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub domain_id: Option<String>,

    /// Grantee client id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "validate", validate(length(min = 1, max = 64)))]
    pub grantee_client_id: Option<String>,

    /// Restrict to enabled or disabled grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// A service a user may name as a service grant grantee (ADR 0036 §3).
/// Carries the delegation ceilings only; SPIFFE IDs are never returned.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DelegatableService {
    /// Client id to pass as `grantee_client_id`.
    pub client_id: String,

    /// Client display name.
    pub name: String,

    /// Client domain.
    pub domain_id: String,

    /// Users of other domains may delegate to this client.
    pub cross_domain: bool,

    /// Role ids a grant may carry; empty means no ceiling beyond the
    /// grantor's own roles.
    pub max_role_ids: Vec<String>,

    /// Maximum grant lifetime in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_grant_lifetime: Option<u64>,

    /// Maximum live grants per project for this client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_grants_per_project: Option<u32>,
}

/// Delegatable service list response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DelegatableServiceList {
    /// Services the caller may delegate to.
    pub delegatable_services: Vec<DelegatableService>,
}
