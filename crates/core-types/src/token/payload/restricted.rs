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
//! Restricted token types.

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::Serialize;
use validator::Validate;

use super::common;
use crate::auth::{AuthzInfo, IdentityInfo, SecurityContext};
use crate::error::BuilderError;
use crate::identity::UserResponse;
use crate::resource::Project;
use crate::role::RoleRef;
use crate::token::error::TokenProviderError;
use crate::token::{Token, TokenRestriction};

/// Restricted token payload.
#[derive(Builder, Clone, Debug, Default, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into))]
pub struct RestrictedPayload {
    /// User ID.
    #[validate(length(min = 1, max = 64))]
    pub user_id: String,

    /// Authentication methods used to obtain the token.
    #[builder(default, setter(name = _methods))]
    #[validate(length(min = 1))]
    pub methods: Vec<String>,
    /// Token audit IDs.
    #[builder(default, setter(name = _audit_ids))]
    #[validate(custom(function = "common::validate_audit_ids"))]
    pub audit_ids: Vec<String>,
    /// Token expiration datetime in UTC.
    pub expires_at: DateTime<Utc>,
    /// ID of the token restrictions.
    #[validate(length(min = 1, max = 64))]
    pub token_restriction_id: String,
    /// Project ID scope for the token.
    #[validate(length(min = 1, max = 64))]
    pub project_id: String,
    /// Whether the token can be renewed.
    pub allow_renew: bool,
    /// Whether the token can be rescoped.
    pub allow_rescope: bool,

    #[builder(default)]
    pub issued_at: DateTime<Utc>,
    #[builder(default)]
    pub user: Option<UserResponse>,
    #[builder(default)]
    pub roles: Option<Vec<RoleRef>>,
    #[builder(default)]
    pub project: Option<Project>,
}

impl RestrictedPayloadBuilder {
    pub fn methods<I, V>(&mut self, iter: I) -> &mut Self
    where
        I: Iterator<Item = V>,
        V: Into<String>,
    {
        self.methods
            .get_or_insert_with(Vec::new)
            .extend(iter.map(Into::into));
        self
    }

    pub fn audit_ids<I, V>(&mut self, iter: I) -> &mut Self
    where
        I: Iterator<Item = V>,
        V: Into<String>,
    {
        self.audit_ids
            .get_or_insert_with(Vec::new)
            .extend(iter.map(Into::into));
        self
    }
}

impl From<RestrictedPayload> for Token {
    fn from(value: RestrictedPayload) -> Self {
        Self::Restricted(value)
    }
}

impl RestrictedPayload {
    /// Construct a restricted token payload from a [`SecurityContext`].
    ///
    /// Propagates the principal's user ID, authentication methods, and audit
    /// IDs from the context. The user ID is taken from the restriction if
    /// explicitly set, otherwise falls back to the context's principal.
    /// Requires a project scope (either from the restriction or the context);
    /// returns [`TokenProviderError::RestrictedTokenNotProjectScoped`] when no
    /// project is available.
    pub fn from_security_context(
        ctx: &SecurityContext,
        restriction: &TokenRestriction,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, TokenProviderError> {
        match &ctx.principal.identity {
            IdentityInfo::User(user) => Ok(RestrictedPayloadBuilder::default()
                .user_id(
                    restriction
                        .user_id
                        .as_ref()
                        .unwrap_or(&user.user_id.clone()),
                )
                .methods(ctx.auth_methods.iter())
                .audit_ids(ctx.audit_ids.iter())
                .expires_at(expires_at)
                .token_restriction_id(restriction.id.clone())
                .project_id(
                    restriction
                        .project_id
                        .as_ref()
                        .or(match &ctx.authorization {
                            Some(AuthzInfo::Project(project)) => Some(&project.id),
                            _ => None,
                        })
                        .ok_or_else(|| TokenProviderError::RestrictedTokenNotProjectScoped)?,
                )
                .allow_renew(restriction.allow_renew)
                .allow_rescope(restriction.allow_rescope)
                .roles(restriction.roles.clone())
                .build()?),
            _ => {
                todo!();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::auth::*;
    use crate::token::restriction::*;

    #[test]
    fn test_create_from_security_context() {
        let now = Utc::now();
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                domain_id: Some("did".into()),
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();
        let ctx = SecurityContext::try_from(auth).unwrap();

        let tr = TokenRestrictionBuilder::default()
            .id("rid")
            .domain_id("did")
            .project_id("pid")
            .allow_renew(true)
            .allow_rescope(true)
            .role_ids([])
            .build()
            .unwrap();
        let payload = RestrictedPayload::from_security_context(&ctx, &tr, now).unwrap();
        assert_eq!(now, payload.expires_at);
        assert_eq!("uid", payload.user_id);
        assert_eq!(vec!["password"], payload.methods);
        assert_eq!("pid", payload.project_id);
        assert!(payload.allow_renew);
        assert!(payload.allow_rescope);
    }
}
