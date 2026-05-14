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
use derive_builder::Builder;
use serde::Serialize;
use validator::Validate;

use super::common;
use crate::auth::{IdentityInfo, OidcContext, SecurityContext};
use crate::error::BuilderError;
use crate::identity::UserResponse;
use crate::token::Token;
use crate::token::error::TokenProviderError;

/// Federated unscoped token payload.
#[derive(Builder, Clone, Debug, Default, PartialEq, Serialize, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into))]
pub struct FederationUnscopedPayload {
    #[validate(length(min = 1, max = 64))]
    pub user_id: String,

    #[builder(default, setter(name = _methods))]
    #[validate(length(min = 1))]
    pub methods: Vec<String>,

    #[builder(default, setter(name = _audit_ids))]
    #[validate(custom(function = "common::validate_audit_ids"))]
    pub audit_ids: Vec<String>,
    pub expires_at: DateTime<Utc>,

    #[validate(length(min = 1, max = 64))]
    pub idp_id: String,

    #[validate(length(min = 1, max = 64))]
    pub protocol_id: String,
    #[builder(setter(name = _group_ids))]
    pub group_ids: Vec<String>,

    #[builder(default)]
    pub issued_at: DateTime<Utc>,
    #[builder(default)]
    pub user: Option<UserResponse>,
}

impl FederationUnscopedPayloadBuilder {
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

    /// Set the group IDs for the federated unscoped payload.
    ///
    /// Collects group identifiers from an iterator, allowing the builder to
    /// accept any iterable of values that can be converted into `String`.
    pub fn group_ids<I, V>(&mut self, iter: I) -> &mut Self
    where
        I: Iterator<Item = V>,
        V: Into<String>,
    {
        self.group_ids
            .get_or_insert_with(Vec::new)
            .extend(iter.map(Into::into));
        self
    }
}

impl From<FederationUnscopedPayload> for Token {
    fn from(value: FederationUnscopedPayload) -> Self {
        Self::FederationUnscoped(value)
    }
}

impl FederationUnscopedPayload {
    /// Construct a federated unscoped token payload from a [`SecurityContext`].
    ///
    /// Propagates the principal's user ID, authentication methods, audit IDs,
    /// and user group IDs from the context, and fills in OIDC-specific
    /// fields (IDP ID and protocol ID) from the provided [`OidcContext`].
    /// Returns [`TokenProviderError::UnsupportedPrinciple`] when the
    /// principal is not a traditional user.
    pub fn from_security_context(
        ctx: &SecurityContext,
        oidc: &OidcContext,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, TokenProviderError> {
        match &ctx.principal.identity {
            IdentityInfo::User(user) => Ok(FederationUnscopedPayloadBuilder::default()
                .user_id(ctx.principal.get_user_id())
                .methods(ctx.auth_methods.iter())
                .audit_ids(ctx.audit_ids.iter())
                .expires_at(expires_at)
                .idp_id(oidc.idp_id.clone())
                .protocol_id(oidc.protocol_id.clone())
                .group_ids(user.user_groups.iter().map(|g| g.id.clone()))
                .build()?),
            _ => Err(TokenProviderError::UnsupportedPrinciple),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::auth::*;

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

        let oidc = OidcContextBuilder::default()
            .idp_id("idp")
            .protocol_id("protocol_id")
            .build()
            .unwrap();
        let payload = FederationUnscopedPayload::from_security_context(&ctx, &oidc, now).unwrap();
        assert_eq!(now, payload.expires_at);
        assert_eq!("uid", payload.user_id);
        assert_eq!(vec!["password"], payload.methods);
        assert_eq!("idp", payload.idp_id);
        assert_eq!("protocol_id", payload.protocol_id);
    }
}
