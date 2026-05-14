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
//! Trust token types.

use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::Serialize;
use validator::Validate;

use super::common;
use crate::auth::SecurityContext;
use crate::error::BuilderError;
use crate::identity::UserResponse;
use crate::resource::Project;
use crate::token::Token;
use crate::token::error::TokenProviderError;
use crate::trust::Trust;

/// Trust token payload.
#[derive(Builder, Clone, Debug, Default, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into))]
pub struct TrustPayload {
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

    /// ID of the trust.
    #[validate(length(min = 1, max = 64))]
    pub trust_id: String,

    /// Project ID scope for the token.
    #[validate(length(min = 1, max = 64))]
    pub project_id: String,

    #[builder(default)]
    pub issued_at: DateTime<Utc>,
    #[builder(default)]
    pub user: Option<UserResponse>,
    #[builder(default)]
    pub trust: Option<Trust>,
    #[builder(default)]
    pub project: Option<Project>,
}

impl TrustPayloadBuilder {
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

impl From<TrustPayload> for Token {
    fn from(value: TrustPayload) -> Self {
        Self::Trust(value)
    }
}

impl TrustPayload {
    /// Construct a trust-scoped token payload from a [`SecurityContext`].
    ///
    /// Propagates the principal's user ID, authentication methods, and audit
    /// IDs from the context, and embeds the trust object and its identifier
    /// into the payload.
    pub fn from_security_context<S: Into<String>>(
        ctx: &SecurityContext,
        trust: &Trust,
        project_id: S,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, TokenProviderError> {
        Ok(TrustPayloadBuilder::default()
            .user_id(ctx.principal.get_user_id())
            .methods(ctx.auth_methods.iter())
            .audit_ids(ctx.audit_ids.iter())
            .expires_at(expires_at)
            .trust_id(trust.id.clone())
            .trust(trust.clone())
            .project_id(project_id)
            .build()?)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::auth::*;
    use crate::trust::*;

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

        let trust = TrustBuilder::default()
            .id("tid")
            .impersonation(false)
            .trustor_user_id("trustor_uid")
            .trustee_user_id("trustor_uid")
            .build()
            .unwrap();
        let payload = TrustPayload::from_security_context(&ctx, &trust, "pid", now).unwrap();
        assert_eq!(now, payload.expires_at);
        assert_eq!("uid", payload.user_id);
        assert_eq!(vec!["password"], payload.methods);
        assert_eq!("tid", payload.trust_id);
    }
}
