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
//! Token provider types.
use chrono::{DateTime, Utc};
use serde::Serialize;
use validator::Validate;

use crate::auth::*;
use crate::identity::UserResponse;
use crate::resource::{Domain, Project};
use crate::role::RoleRef;

mod error;
pub mod payload;
mod restriction;

pub use error::*;
pub use payload::*;
pub use restriction::*;

/// Fernet Token.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Token {
    /// Application credential.
    ApplicationCredential(ApplicationCredentialPayload),
    /// Domain scoped.
    DomainScope(DomainScopePayload),
    /// Federated domain scoped.
    FederationDomainScope(FederationDomainScopePayload),
    /// Federated project scoped.
    FederationProjectScope(FederationProjectScopePayload),
    /// Federated unscoped.
    FederationUnscoped(FederationUnscopedPayload),
    /// Project scoped.
    ProjectScope(ProjectScopePayload),
    /// Restricted.
    Restricted(RestrictedPayload),
    /// System scoped.
    SystemScope(SystemScopePayload),
    /// Trust.
    Trust(TrustPayload),
    /// Unscoped.
    Unscoped(UnscopedPayload),
}

// TODO: From<Token> for SecurityContext

impl Token {
    /// Construct the [`Token`] for the requested [`AuthzInfo`] with the current
    /// [`SecurityContext`].`
    ///
    /// # Security Note
    /// This is the low-level method with no real validation whether the token
    /// can be issued.
    pub fn from_security_context_with_scope(
        ctx: &SecurityContext,
        scope: &AuthzInfo,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, error::TokenProviderError> {
        if let Some(token_restriction) = &ctx.token_restriction {
            return Ok(Self::Restricted(RestrictedPayload::from_security_context(
                ctx,
                token_restriction,
                expires_at,
            )?));
        }
        match scope {
            AuthzInfo::Domain(domain) => match &ctx.authentication_context {
                AuthenticationContext::Oidc(oidc) => Ok(Self::FederationDomainScope(
                    FederationDomainScopePayload::from_security_context(
                        ctx, domain, oidc, expires_at,
                    )?,
                )),
                AuthenticationContext::Trust(_trust) => todo!(),
                _ => Ok(Self::DomainScope(
                    DomainScopePayload::from_security_context(ctx, domain, expires_at)?,
                )),
            },
            AuthzInfo::Project(project) => match &ctx.authentication_context {
                AuthenticationContext::ApplicationCredential(app_cred) => {
                    Ok(Self::ApplicationCredential(
                        ApplicationCredentialPayload::from_security_context(
                            ctx, app_cred, expires_at,
                        )?,
                    ))
                }
                AuthenticationContext::Oidc(oidc) => Ok(Self::FederationProjectScope(
                    FederationProjectScopePayload::from_security_context(
                        ctx, project, oidc, expires_at,
                    )?,
                )),
                _ => Ok(Self::ProjectScope(
                    ProjectScopePayload::from_security_context(ctx, project, expires_at)?,
                )),
            },
            AuthzInfo::Trust(trust) => Ok(match &trust.project_id {
                Some(project_id) => Self::Trust(TrustPayload::from_security_context(
                    ctx,
                    trust,
                    project_id.clone(),
                    expires_at,
                )?),
                None => todo!(),
            }),
            AuthzInfo::System(system) => Ok(Self::SystemScope(
                SystemScopePayload::from_security_context(ctx, system, expires_at)?,
            )),
            AuthzInfo::Unscoped => match &ctx.authentication_context {
                AuthenticationContext::Oidc(oidc) => Ok(Self::FederationUnscoped(
                    FederationUnscopedPayload::from_security_context(ctx, oidc, expires_at)?,
                )),

                _ => Ok(Self::Unscoped(UnscopedPayload::from_security_context(
                    ctx, expires_at,
                )?)),
            },
        }
    }

    pub const fn user_id(&self) -> &String {
        match self {
            Self::ApplicationCredential(x) => &x.user_id,
            Self::DomainScope(x) => &x.user_id,
            Self::FederationUnscoped(x) => &x.user_id,
            Self::FederationProjectScope(x) => &x.user_id,
            Self::FederationDomainScope(x) => &x.user_id,
            Self::ProjectScope(x) => &x.user_id,
            Self::Restricted(x) => &x.user_id,
            Self::SystemScope(x) => &x.user_id,
            Self::Trust(x) => &x.user_id,
            Self::Unscoped(x) => &x.user_id,
        }
    }

    pub const fn user(&self) -> &Option<UserResponse> {
        match self {
            Self::ApplicationCredential(x) => &x.user,
            Self::DomainScope(x) => &x.user,
            Self::FederationUnscoped(x) => &x.user,
            Self::FederationProjectScope(x) => &x.user,
            Self::FederationDomainScope(x) => &x.user,
            Self::ProjectScope(x) => &x.user,
            Self::Restricted(x) => &x.user,
            Self::SystemScope(x) => &x.user,
            Self::Trust(x) => &x.user,
            Self::Unscoped(x) => &x.user,
        }
    }

    /// Set the `issued_at` property of the token.
    ///
    /// An internal method (available only within the module) to set the
    /// `issued_at` into the token payload.
    pub fn set_issued_at(&mut self, issued_at: DateTime<Utc>) -> &mut Self {
        match self {
            Self::ApplicationCredential(x) => x.issued_at = issued_at,
            Self::DomainScope(x) => x.issued_at = issued_at,
            Self::FederationUnscoped(x) => x.issued_at = issued_at,
            Self::FederationProjectScope(x) => x.issued_at = issued_at,
            Self::FederationDomainScope(x) => x.issued_at = issued_at,
            Self::ProjectScope(x) => x.issued_at = issued_at,
            Self::Restricted(x) => x.issued_at = issued_at,
            Self::SystemScope(x) => x.issued_at = issued_at,
            Self::Trust(x) => x.issued_at = issued_at,
            Self::Unscoped(x) => x.issued_at = issued_at,
        }
        self
    }

    /// Get token `issued_at` timestamp.
    ///
    /// Returns the UTC timestamp when the token was encoded (part of the Fernet
    /// payload and not the token payload).
    pub const fn issued_at(&self) -> &DateTime<Utc> {
        match self {
            Self::ApplicationCredential(x) => &x.issued_at,
            Self::DomainScope(x) => &x.issued_at,
            Self::FederationUnscoped(x) => &x.issued_at,
            Self::FederationProjectScope(x) => &x.issued_at,
            Self::FederationDomainScope(x) => &x.issued_at,
            Self::ProjectScope(x) => &x.issued_at,
            Self::Restricted(x) => &x.issued_at,
            Self::SystemScope(x) => &x.issued_at,
            Self::Trust(x) => &x.issued_at,
            Self::Unscoped(x) => &x.issued_at,
        }
    }

    /// Get token expiration timestamp.
    pub const fn expires_at(&self) -> &DateTime<Utc> {
        match self {
            Self::ApplicationCredential(x) => &x.expires_at,
            Self::DomainScope(x) => &x.expires_at,
            Self::FederationUnscoped(x) => &x.expires_at,
            Self::FederationProjectScope(x) => &x.expires_at,
            Self::FederationDomainScope(x) => &x.expires_at,
            Self::ProjectScope(x) => &x.expires_at,
            Self::Restricted(x) => &x.expires_at,
            Self::SystemScope(x) => &x.expires_at,
            Self::Trust(x) => &x.expires_at,
            Self::Unscoped(x) => &x.expires_at,
        }
    }

    pub const fn methods(&self) -> &Vec<String> {
        match self {
            Self::ApplicationCredential(x) => &x.methods,
            Self::DomainScope(x) => &x.methods,
            Self::FederationUnscoped(x) => &x.methods,
            Self::FederationProjectScope(x) => &x.methods,
            Self::FederationDomainScope(x) => &x.methods,
            Self::ProjectScope(x) => &x.methods,
            Self::Restricted(x) => &x.methods,
            Self::SystemScope(x) => &x.methods,
            Self::Trust(x) => &x.methods,
            Self::Unscoped(x) => &x.methods,
        }
    }

    pub const fn audit_ids(&self) -> &Vec<String> {
        match self {
            Self::ApplicationCredential(x) => &x.audit_ids,
            Self::DomainScope(x) => &x.audit_ids,
            Self::FederationUnscoped(x) => &x.audit_ids,
            Self::FederationProjectScope(x) => &x.audit_ids,
            Self::FederationDomainScope(x) => &x.audit_ids,
            Self::ProjectScope(x) => &x.audit_ids,
            Self::Restricted(x) => &x.audit_ids,
            Self::SystemScope(x) => &x.audit_ids,
            Self::Trust(x) => &x.audit_ids,
            Self::Unscoped(x) => &x.audit_ids,
        }
    }

    pub const fn project(&self) -> Option<&Project> {
        match self {
            Self::ApplicationCredential(x) => x.project.as_ref(),
            Self::ProjectScope(x) => x.project.as_ref(),
            Self::FederationProjectScope(x) => x.project.as_ref(),
            Self::Restricted(x) => x.project.as_ref(),
            Self::Trust(x) => x.project.as_ref(),
            _ => None,
        }
    }

    pub const fn project_id(&self) -> Option<&String> {
        match self {
            Self::ApplicationCredential(x) => Some(&x.project_id),
            Self::FederationProjectScope(x) => Some(&x.project_id),
            Self::ProjectScope(x) => Some(&x.project_id),
            Self::Restricted(x) => Some(&x.project_id),
            Self::Trust(x) => Some(&x.project_id),
            _ => None,
        }
    }

    /// Get the domain ID for domain-scoped tokens.
    ///
    /// Returns the domain identifier when the token is a [`Token::DomainScope`]
    /// or [`Token::FederationDomainScope`]. Returns `None` for all other
    /// token types.
    pub const fn domain_id(&self) -> Option<&String> {
        match self {
            Self::DomainScope(x) => Some(&x.domain_id),
            Self::FederationDomainScope(x) => Some(&x.domain_id),
            _ => None,
        }
    }

    /// Get the resolved [`Domain`] if present in the token. It may be empty for
    /// the DomainScope and FederationDomainScope token when it was not
    /// previously minted.
    pub const fn domain(&self) -> Option<&Domain> {
        match self {
            Self::DomainScope(x) => x.domain.as_ref(),
            Self::FederationDomainScope(x) => x.domain.as_ref(),
            _ => None,
        }
    }

    /// Original roles that were granted to the authn/authz.
    ///
    /// For application credentials original roles represent the roles tied to
    /// the application credential, while the effective roles represent the
    /// subset of the original roles that the user still have on the target
    /// scope. Some logic may need to differentiate between the roles
    /// originally tied to the authz from the effective roles in the moment of
    /// the new authentication.
    pub const fn original_roles(&self) -> Option<&Vec<RoleRef>> {
        match self {
            Self::ApplicationCredential(x) => match &x.application_credential {
                Some(ac) => Some(&ac.roles),
                None => None,
            },
            Self::DomainScope(x) => x.roles.as_ref(),
            Self::FederationProjectScope(x) => x.roles.as_ref(),
            Self::FederationDomainScope(x) => x.roles.as_ref(),
            Self::ProjectScope(x) => x.roles.as_ref(),
            Self::Restricted(x) => x.roles.as_ref(),
            Self::SystemScope(x) => x.roles.as_ref(),
            Self::Trust(x) => match &x.trust {
                Some(trust) => trust.roles.as_ref(),
                None => None,
            },
            _ => None,
        }
    }

    /// Effective roles of the token.
    ///
    /// Application credentials, trusts and other concepts may bind roles for
    /// the use. When some of this roles has been revoked from the user
    /// afterwards the user should not be able to obtain them anymore. Some
    /// concepts are being disabled completely in such case, some are supposed
    /// to have a reduced scope (e.g., application credentials).
    ///
    /// Effective roles represent the roles that the user can currently get on
    /// the target scope.
    pub const fn effective_roles(&self) -> Option<&Vec<RoleRef>> {
        match self {
            Self::ApplicationCredential(x) => x.roles.as_ref(),
            Self::DomainScope(x) => x.roles.as_ref(),
            Self::FederationProjectScope(x) => x.roles.as_ref(),
            Self::FederationDomainScope(x) => x.roles.as_ref(),
            Self::ProjectScope(x) => x.roles.as_ref(),
            Self::Restricted(x) => x.roles.as_ref(),
            Self::SystemScope(x) => x.roles.as_ref(),
            Self::Trust(x) => match &x.trust {
                Some(trust) => trust.roles.as_ref(),
                None => None,
            },
            _ => None,
        }
    }
}

impl Validate for Token {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        match self {
            Self::ApplicationCredential(x) => x.validate(),
            Self::DomainScope(x) => x.validate(),
            Self::FederationUnscoped(x) => x.validate(),
            Self::FederationProjectScope(x) => x.validate(),
            Self::FederationDomainScope(x) => x.validate(),
            Self::ProjectScope(x) => x.validate(),
            Self::Restricted(x) => x.validate(),
            Self::SystemScope(x) => x.validate(),
            Self::Trust(x) => x.validate(),
            Self::Unscoped(x) => x.validate(),
        }
    }
}
