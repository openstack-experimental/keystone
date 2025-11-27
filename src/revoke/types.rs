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
//! Token revocation types definitions.
//! Revocation provider types.

use async_trait::async_trait;
use chrono::{DateTime, Timelike, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::keystone::ServiceState;
use crate::revoke::RevokeProviderError;
use crate::token::types::Token;

/// Revocation Provider interface.
#[async_trait]
pub trait RevokeApi: Send + Sync + Clone {
    /// Check whether the token has been revoked of not.
    ///
    /// Checks revocation events matching the token parameters and return
    /// `false` if their count is more than `0`.
    async fn is_token_revoked(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<bool, RevokeProviderError>;

    /// Revoke the token.
    ///
    /// Mark the token as revoked to prohibit from being used even while not
    /// expired.
    async fn revoke_token(
        &self,
        state: &ServiceState,
        token: &Token,
    ) -> Result<(), RevokeProviderError>;
}

/// Revocation event.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(strip_option, into))]
pub struct RevocationEvent {
    pub domain_id: Option<String>,
    pub project_id: Option<String>,
    pub user_id: Option<String>,
    pub role_id: Option<String>,
    pub trust_id: Option<String>,
    pub consumer_id: Option<String>,
    pub access_token_id: Option<String>,
    pub issued_before: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: DateTime<Utc>,
    pub audit_id: Option<String>,
    pub audit_chain_id: Option<String>,
}

/// Revocation event creation data.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(strip_option, into))]
pub struct RevocationEventCreate {
    pub domain_id: Option<String>,
    pub project_id: Option<String>,
    pub user_id: Option<String>,
    pub role_id: Option<String>,
    pub trust_id: Option<String>,
    pub consumer_id: Option<String>,
    pub access_token_id: Option<String>,
    pub issued_before: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: DateTime<Utc>,
    pub audit_id: Option<String>,
    pub audit_chain_id: Option<String>,
}

/// Revocation list parameters.
///
/// It may be necessary to list revocation events not related to the certain
/// token.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(strip_option, into))]
pub struct RevocationEventListParameters {
    //pub access_token_id: Option<String>,
    //pub audit_chain_id: Option<String>,
    /// Audit_id to match against.
    #[builder(default)]
    pub audit_id: Option<String>,
    //pub consumer_id: Option<String>,
    /// List revocation events with an empty `domain_id` or matching any of the
    /// given values.
    #[builder(default)]
    pub domain_ids: Option<Vec<String>>,
    /// Expires_at parameter to match against.
    #[builder(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// List revocation events with the `issued_before` value greater or equal
    /// the value (revocating tokens issued before the certain time).
    #[builder(default)]
    pub issued_before: Option<DateTime<Utc>>,
    /// Project_id to match against.
    #[builder(default)]
    pub project_id: Option<String>,
    #[builder(default)]
    /// Revocation timestamp to match against. Currently not respected.
    pub revoked_at: Option<DateTime<Utc>>,
    /// List revocation events with an empty `role_id` or matching any of the
    /// given values.
    #[builder(default)]
    pub role_ids: Option<Vec<String>>,
    //pub trust_id: Option<String>,
    /// User_id to match against.
    #[builder(default)]
    pub user_ids: Option<Vec<String>>,
}

/// Convert Token into the revocation events listing parameters following the
/// <https://openstack-experimental.github.io/keystone/adr/0009-auth-token-revoke.html#revocation-check>
// TODO: It is necessary to also consider list of the token roles against the
// role_id of the entry TODO: domain_id of the database entry should be compared
// against the user_domain_id and the scope_domain_id. That means, however, that
// we must resolve the user first.
impl TryFrom<&Token> for RevocationEventListParameters {
    type Error = RevokeProviderError;
    fn try_from(value: &Token) -> Result<Self, Self::Error> {
        // TODO: for trust token user_id can be trustee_id or trustor_id
        Ok(Self {
            //access_token_id: None,
            //audit_chain_id: None,
            audit_id: Some(
                value
                    .audit_ids()
                    .first()
                    .ok_or_else(|| RevokeProviderError::TokenHasNoAuditId)?,
            )
            .cloned(),
            //consumer_id: None,
            domain_ids: Some(
                value
                    .user()
                    .iter()
                    .map(|user| user.domain_id.clone())
                    .chain(value.domain().map(|domain| domain.id.clone()))
                    .collect::<Vec<String>>(),
            ),
            expires_at: None,
            issued_before: Some(*value.issued_at()),
            project_id: value.project_id().cloned(),
            revoked_at: None,
            role_ids: value
                .roles()
                .map(|roles| roles.iter().map(|role| role.id.clone()).collect()),
            //trust_id: None,
            user_ids: Some(vec![value.user_id().clone()]),
        })
    }
}

/// Convert the Token into the new revocation events revord following the
/// <https://openstack-experimental.github.io/keystone/adr/0009-auth-token-revoke.html#token-revocation>
impl TryFrom<&Token> for RevocationEventCreate {
    type Error = RevokeProviderError;
    fn try_from(value: &Token) -> Result<Self, Self::Error> {
        let now = Utc::now();
        Ok(Self {
            access_token_id: None,
            audit_chain_id: None,
            audit_id: Some(
                value
                    .audit_ids()
                    .first()
                    .ok_or_else(|| RevokeProviderError::TokenHasNoAuditId)?,
            )
            .cloned(),
            consumer_id: None,
            domain_id: None,
            expires_at: value.expires_at().with_nanosecond(0),
            issued_before: now,
            project_id: None,
            revoked_at: now,
            role_id: None,
            trust_id: None,
            user_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::types::UserResponse;
    use crate::token::ProjectScopePayload;
    //use crate::resource::types::Domain;
    use crate::assignment::types::Role;

    #[test]
    fn test_list_for_project_scope_token() {
        let token = Token::ProjectScope(ProjectScopePayload {
            user_id: "user_id".into(),
            user: Some(UserResponse {
                id: "user_id".to_string(),
                domain_id: "user_domain_id".into(),
                ..Default::default()
            }),
            methods: Vec::from(["password".to_string()]),
            project_id: "project_id".into(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: DateTime::parse_from_rfc3339("2025-11-17T19:55:06.123456Z")
                .unwrap()
                .with_timezone(&Utc),
            roles: Some(vec![
                Role {
                    id: "role_id1".to_string(),
                    ..Default::default()
                },
                Role {
                    id: "role_id2".to_string(),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        });
        let revocation: RevocationEventListParameters =
            RevocationEventListParameters::try_from(&token).unwrap();

        //assert!(revocation.audit_chain_id.is_none());
        assert_eq!(
            *token.audit_ids().first().unwrap(),
            revocation.audit_id.unwrap()
        );
        //assert!(revocation.consumer_id.is_none());
        assert_eq!(
            revocation.domain_ids.unwrap(),
            vec!["user_domain_id".to_string()]
        );
        assert!(revocation.expires_at.is_none());
        assert_eq!(revocation.project_id.unwrap(), "project_id".to_string());
        assert_eq!(
            revocation.role_ids.unwrap(),
            vec!["role_id1".to_string(), "role_id2".to_string()]
        );
        //assert!(revocation.trust_id.is_none());
        assert_eq!(revocation.user_ids.unwrap(), vec!["user_id".to_string()]);
    }

    #[test]
    fn test_create_from_token() {
        let token = Token::ProjectScope(ProjectScopePayload {
            user_id: "bar".into(),
            methods: Vec::from(["password".to_string()]),
            project_id: "pid".into(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: DateTime::parse_from_rfc3339("2025-11-17T19:55:06.123456Z")
                .unwrap()
                .with_timezone(&Utc),
            roles: Some(vec![
                Role {
                    id: "role_id1".to_string(),
                    ..Default::default()
                },
                Role {
                    id: "role_id2".to_string(),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        });
        let revocation: RevocationEventCreate = RevocationEventCreate::try_from(&token).unwrap();

        assert!(revocation.access_token_id.is_none());
        assert!(revocation.audit_chain_id.is_none());
        assert_eq!(
            *token.audit_ids().first().unwrap(),
            revocation.audit_id.unwrap()
        );
        assert!(revocation.consumer_id.is_none());
        assert!(revocation.domain_id.is_none());
        assert_eq!(
            DateTime::parse_from_rfc3339("2025-11-17T19:55:06.000000Z")
                .unwrap()
                .with_timezone(&Utc),
            revocation.expires_at.unwrap()
        );
        assert!(revocation.project_id.is_none());
        assert!(revocation.role_id.is_none());
        assert!(revocation.trust_id.is_none());
        assert!(revocation.user_id.is_none());
    }
}
