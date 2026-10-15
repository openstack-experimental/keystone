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
//! # Service grant resource (ADR 0036 §4.1)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The service a grant delegates to.
///
/// Phase 1 grantees are always registered delegatable service clients
/// (ADR 0036 §3); human grantees are a later phase.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Grantee {
    /// A registered OAuth2 client with `delegation.service_grants`.
    Client {
        /// Public `client_id` of the grantee.
        client_id: String,
        /// Domain the client is registered in.
        client_domain_id: String,
    },
}

impl Grantee {
    /// `client_id` of a client grantee.
    pub fn client_id(&self) -> &str {
        match self {
            Self::Client { client_id, .. } => client_id,
        }
    }

    /// Domain a client grantee is registered in.
    pub fn client_domain_id(&self) -> &str {
        match self {
            Self::Client {
                client_domain_id, ..
            } => client_domain_id,
        }
    }
}

/// What a grant lets the grantee act on.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GrantTarget {
    /// One project.
    Project {
        /// Target project id.
        project_id: String,
        /// Domain of the target project, resolved at creation so domain
        /// managers can be authorized without a project lookup. A
        /// project never changes domain.
        #[serde(default)]
        project_domain_id: String,
    },
}

impl GrantTarget {
    /// Target project id.
    pub fn project_id(&self) -> &str {
        match self {
            Self::Project { project_id, .. } => project_id,
        }
    }

    /// Domain of the target project.
    pub fn project_domain_id(&self) -> &str {
        match self {
            Self::Project {
                project_domain_id, ..
            } => project_domain_id,
        }
    }
}

/// Why a grant was disabled (ADR 0036 §4.1, §8).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DisabledReason {
    /// The grantor no longer holds any of the delegated roles on the
    /// target.
    RoleLost,
    /// The grantor was disabled.
    GrantorDisabled,
    /// The grantee client was deleted, disabled or lost
    /// `delegation.service_grants`.
    GranteeRemoved,
    /// The target project was disabled. Not in the ADR's list, which
    /// disables grants of a disabled project without naming a reason.
    TargetDisabled,
    /// Explicitly revoked.
    Revoked,
    /// `expires_at` passed.
    Expired,
}

/// A service grant (ADR 0036 §4.1).
///
/// Stored under `service_grant:v1:<domain_id>:<id>` as a positional
/// MessagePack array: append new fields at the end with `#[serde(default)]`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ServiceGrant {
    /// Grant id (UUIDv4, simple form).
    pub id: String,
    /// Record version, incremented on every lifecycle update.
    pub version: u64,
    /// Domain of the grantor; the grant lives (and is redeemed) in it.
    pub domain_id: String,
    /// The user whose authority the grant delegates.
    pub grantor_user_id: String,
    /// The service the authority is delegated to.
    pub grantee: Grantee,
    /// What the grantee may act on.
    pub target: GrantTarget,
    /// Delegated role ids; never more than the grantor held at creation,
    /// and intersected with the grantor's live roles at every redemption.
    pub role_ids: Vec<String>,
    /// Expiry; `None` = until revoked.
    pub expires_at: Option<DateTime<Utc>>,
    /// Free-form description.
    pub description: Option<String>,
    /// Whether the grant is redeemable.
    pub enabled: bool,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last redemption time; updated at most once per configured interval.
    pub last_redeemed_at: Option<DateTime<Utc>>,
    /// Why the grant was disabled, when it is.
    pub disabled_reason: Option<DisabledReason>,
}

impl ServiceGrant {
    /// Whether `expires_at` has passed at `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|exp| exp <= now)
    }

    /// Whether the grant may be redeemed at `now`: enabled and not
    /// expired.
    pub fn is_redeemable(&self, now: DateTime<Utc>) -> bool {
        self.enabled && !self.is_expired(now)
    }
}

/// Input to create a service grant (`POST /v4/service-grants`).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ServiceGrantCreate {
    /// `client_id` of the delegatable service.
    pub grantee_client_id: String,
    /// Target project.
    pub project_id: String,
    /// Delegated roles; `None` = the caller's current effective roles on
    /// the project (within the client's ceiling).
    pub role_ids: Option<Vec<String>>,
    /// Expiry; defaults to the client's `max_grant_lifetime` when it has
    /// one.
    pub expires_at: Option<DateTime<Utc>>,
    /// Free-form description.
    pub description: Option<String>,
}

/// Lifecycle change of a grant. Every other field is immutable: a different
/// grant is a new grant.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ServiceGrantUpdate {
    /// `None` = unchanged.
    pub enabled: Option<bool>,
    /// `None` = unchanged; set together with `enabled: Some(false)`.
    pub disabled_reason: Option<DisabledReason>,
    /// `None` = unchanged.
    pub last_redeemed_at: Option<DateTime<Utc>>,
}

impl ServiceGrant {
    /// Apply a lifecycle update, bumping the version.
    pub fn with_update(self, update: ServiceGrantUpdate) -> Self {
        let enabled = update.enabled.unwrap_or(self.enabled);
        Self {
            version: self.version + 1,
            enabled,
            disabled_reason: if enabled {
                None
            } else {
                update.disabled_reason.or(self.disabled_reason)
            },
            last_redeemed_at: update.last_redeemed_at.or(self.last_redeemed_at),
            ..self
        }
    }
}

/// Filters for listing service grants. Every set filter must match.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct ServiceGrantListParameters {
    /// Grantor's domain.
    pub domain_id: Option<String>,
    /// Grantor user id.
    pub grantor_user_id: Option<String>,
    /// Target project id.
    pub project_id: Option<String>,
    /// Grantee `client_id`.
    pub grantee_client_id: Option<String>,
    /// Only enabled (or disabled) grants.
    pub enabled: Option<bool>,
    /// Pagination.
    pub pagination: crate::ListPagination,
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn grant() -> ServiceGrant {
        ServiceGrant {
            id: "g".into(),
            version: 1,
            domain_id: "d".into(),
            grantor_user_id: "u".into(),
            grantee: Grantee::Client {
                client_id: "c".into(),
                client_domain_id: "d".into(),
            },
            target: GrantTarget::Project {
                project_id: "p".into(),
                project_domain_id: "pd".into(),
            },
            role_ids: vec!["r".into()],
            expires_at: None,
            description: None,
            enabled: true,
            created_at: Utc::now(),
            last_redeemed_at: None,
            disabled_reason: None,
        }
    }

    #[test]
    fn test_redeemable() {
        let now = Utc::now();
        let mut g = grant();
        assert!(g.is_redeemable(now));
        g.expires_at = Some(now - Duration::seconds(1));
        assert!(!g.is_redeemable(now));
        g.expires_at = Some(now + Duration::seconds(10));
        assert!(g.is_redeemable(now));
        g.enabled = false;
        assert!(!g.is_redeemable(now));
    }

    #[test]
    fn test_with_update() {
        let g = grant().with_update(ServiceGrantUpdate {
            enabled: Some(false),
            disabled_reason: Some(DisabledReason::RoleLost),
            ..Default::default()
        });
        assert_eq!(g.version, 2);
        assert!(!g.enabled);
        assert_eq!(g.disabled_reason, Some(DisabledReason::RoleLost));
        let g = g.with_update(ServiceGrantUpdate {
            enabled: Some(true),
            ..Default::default()
        });
        assert!(g.enabled);
        assert_eq!(g.disabled_reason, None);
    }
}
