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
//! Service grant conversion implementations.

use openstack_keystone_core_types::oauth2_client::OAuth2ClientResource;
use openstack_keystone_core_types::service_grant as core;

use crate::v4::service_grant as api;

impl From<core::Grantee> for api::Grantee {
    fn from(value: core::Grantee) -> Self {
        match value {
            core::Grantee::Client {
                client_id,
                client_domain_id,
            } => Self::Client {
                client_id,
                client_domain_id,
            },
        }
    }
}

impl From<core::GrantTarget> for api::GrantTarget {
    fn from(value: core::GrantTarget) -> Self {
        match value {
            core::GrantTarget::Project {
                project_id,
                project_domain_id,
            } => Self::Project {
                project_id,
                project_domain_id,
            },
        }
    }
}

impl From<core::DisabledReason> for api::DisabledReason {
    fn from(value: core::DisabledReason) -> Self {
        match value {
            core::DisabledReason::RoleLost => Self::RoleLost,
            core::DisabledReason::GrantorDisabled => Self::GrantorDisabled,
            core::DisabledReason::GranteeRemoved => Self::GranteeRemoved,
            core::DisabledReason::TargetDisabled => Self::TargetDisabled,
            core::DisabledReason::Revoked => Self::Revoked,
            core::DisabledReason::Expired => Self::Expired,
        }
    }
}

impl From<core::ServiceGrant> for api::ServiceGrant {
    fn from(value: core::ServiceGrant) -> Self {
        Self {
            id: value.id,
            domain_id: value.domain_id,
            grantor_user_id: value.grantor_user_id,
            grantee: value.grantee.into(),
            target: value.target.into(),
            role_ids: value.role_ids,
            expires_at: value.expires_at,
            description: value.description,
            enabled: value.enabled,
            created_at: value.created_at,
            last_redeemed_at: value.last_redeemed_at,
            disabled_reason: value.disabled_reason.map(Into::into),
        }
    }
}

impl From<api::ServiceGrantCreate> for core::ServiceGrantCreate {
    fn from(value: api::ServiceGrantCreate) -> Self {
        Self {
            grantee_client_id: value.grantee_client_id,
            project_id: value.project_id,
            role_ids: value.role_ids,
            expires_at: value.expires_at,
            description: value.description,
        }
    }
}

impl From<api::ServiceGrantListParameters> for core::ServiceGrantListParameters {
    fn from(value: api::ServiceGrantListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            grantor_user_id: value.user_id,
            project_id: value.project_id,
            grantee_client_id: value.grantee_client_id,
            enabled: value.enabled,
            pagination: Default::default(),
        }
    }
}

impl api::DelegatableService {
    /// The listing entry of `client`, or `None` for a client that is not a
    /// live service grant grantee.
    pub fn from_client(client: OAuth2ClientResource) -> Option<Self> {
        let policy = client.service_grant_policy()?.clone();
        Some(Self {
            client_id: client.client_id,
            name: client.name,
            domain_id: client.domain_id,
            cross_domain: policy.cross_domain,
            max_role_ids: policy.max_role_ids,
            max_grant_lifetime: policy.max_grant_lifetime,
            max_grants_per_project: policy.max_grants_per_project,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    #[test]
    fn test_service_grant_conversion() {
        let grant = core::ServiceGrant {
            id: "g".into(),
            version: 3,
            domain_id: "d".into(),
            grantor_user_id: "u".into(),
            grantee: core::Grantee::Client {
                client_id: "c".into(),
                client_domain_id: "cd".into(),
            },
            target: core::GrantTarget::Project {
                project_id: "p".into(),
                project_domain_id: "pd".into(),
            },
            role_ids: vec!["r".into()],
            expires_at: None,
            description: Some("x".into()),
            enabled: false,
            created_at: Utc::now(),
            last_redeemed_at: None,
            disabled_reason: Some(core::DisabledReason::RoleLost),
        };
        let api = api::ServiceGrant::from(grant);
        let json = serde_json::to_value(&api).unwrap();
        assert_eq!(json["grantee"]["type"], "client");
        assert_eq!(json["grantee"]["client_id"], "c");
        assert_eq!(json["target"]["type"], "project");
        assert_eq!(json["target"]["project_domain_id"], "pd");
        assert_eq!(json["disabled_reason"], "role_lost");
        assert!(json.get("version").is_none());
    }

    #[test]
    fn test_list_parameters_conversion() {
        let params = core::ServiceGrantListParameters::from(api::ServiceGrantListParameters {
            user_id: Some("u".into()),
            project_id: Some("p".into()),
            domain_id: None,
            grantee_client_id: Some("c".into()),
            enabled: Some(true),
        });
        assert_eq!(params.grantor_user_id.as_deref(), Some("u"));
        assert_eq!(params.project_id.as_deref(), Some("p"));
        assert_eq!(params.grantee_client_id.as_deref(), Some("c"));
        assert_eq!(params.enabled, Some(true));
    }
}
