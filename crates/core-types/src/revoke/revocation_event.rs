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

use chrono::{DateTime, Timelike, Utc};
use derive_builder::Builder;

use crate::error::BuilderError;
use crate::role::RoleRef;
use crate::token::FernetToken;

/// Revocation event.
#[derive(Builder, Clone, Debug, Default, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct RevocationEvent {
    pub access_token_id: Option<String>,

    /// Audit_id to match against.
    pub audit_id: Option<String>,

    pub audit_chain_id: Option<String>,

    pub consumer_id: Option<String>,

    pub domain_id: Option<String>,

    pub expires_at: Option<DateTime<Utc>>,

    pub issued_before: DateTime<Utc>,

    pub project_id: Option<String>,

    pub revoked_at: DateTime<Utc>,

    pub role_id: Option<String>,

    pub trust_id: Option<String>,

    pub user_id: Option<String>,
}

/// Revocation event creation data.
#[derive(Builder, Clone, Debug, Default, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct RevocationEventCreate {
    #[builder(default)]
    pub access_token_id: Option<String>,

    /// Audit_id to match against.
    #[builder(default)]
    pub audit_id: Option<String>,

    #[builder(default)]
    pub audit_chain_id: Option<String>,

    #[builder(default)]
    pub consumer_id: Option<String>,

    #[builder(default)]
    pub domain_id: Option<String>,

    #[builder(default)]
    pub expires_at: Option<DateTime<Utc>>,

    #[builder(default)]
    pub issued_before: DateTime<Utc>,

    #[builder(default)]
    pub project_id: Option<String>,

    pub revoked_at: DateTime<Utc>,

    #[builder(default)]
    pub role_id: Option<String>,

    #[builder(default)]
    pub trust_id: Option<String>,

    #[builder(default)]
    pub user_id: Option<String>,
}

/// Revocation list parameters.
///
/// It may be necessary to list revocation events not related to the certain
/// token.
#[derive(Builder, Clone, Debug, Default, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
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
    /// the value (revoking tokens issued before the certain time).
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

    /// Trust ID to match against.
    #[builder(default)]
    pub trust_id: Option<String>,

    /// User_id to match against.
    #[builder(default)]
    pub user_ids: Option<Vec<String>>,
}

impl RevocationEventListParametersBuilder {
    pub fn role_refs<'a, I>(&mut self, iter: I) -> &mut Self
    where
        I: Iterator<Item = &'a RoleRef>,
    {
        self.role_ids
            .get_or_insert_default()
            .get_or_insert_with(Vec::new)
            .extend(iter.map(|role| role.id.clone()));
        self
    }
}

/// Convert the Token into the new revocation events record following the
/// <https://openstack-experimental.github.io/keystone/adr/0009-auth-token-revoke.html#token-revocation>.
impl TryFrom<&FernetToken> for RevocationEventCreate {
    type Error = crate::error::BuilderError;
    fn try_from(value: &FernetToken) -> Result<Self, Self::Error> {
        let now = Utc::now();
        Ok(Self {
            access_token_id: None,
            audit_chain_id: None,
            audit_id: Some(value.audit_ids().first().ok_or(
                crate::error::BuilderError::Validation("token has no audit_id".to_string()),
            )?)
            .cloned(),
            consumer_id: None,
            domain_id: None,
            expires_at: value.expires_at().with_nanosecond(0),
            issued_before: now,
            project_id: None,
            revoked_at: now,
            role_id: None,
            trust_id: if let FernetToken::Trust(data) = value {
                Some(data.trust_id.clone())
            } else {
                None
            },
            user_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::ProjectScopePayload;

    #[test]
    fn test_create_from_token() {
        let token = FernetToken::ProjectScope(ProjectScopePayload {
            user_id: "bar".into(),
            methods: Vec::from(["password".to_string()]),
            project_id: "pid".into(),
            audit_ids: vec!["Zm9vCg".into()],
            expires_at: DateTime::parse_from_rfc3339("2025-11-17T19:55:06.123456Z")
                .unwrap()
                .with_timezone(&Utc),
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
