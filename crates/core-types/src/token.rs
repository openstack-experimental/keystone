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

mod error;
pub mod payload;
mod restriction;

pub use error::*;
pub use payload::*;
pub use restriction::*;

/// Fernet Token.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum FernetToken {
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

impl FernetToken {
    /// Construct the [`FernetToken`] for the requested [`ScopeInfo`] with the
    /// current [`SecurityContext`].
    ///
    /// # Security Note
    /// This is the low-level method with no real validation whether the token
    /// can be issued.
    pub fn from_security_context(
        ctx: &SecurityContext,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, error::TokenProviderError> {
        if let Some(token_restriction) = ctx.token_restriction() {
            return Ok(Self::Restricted(RestrictedPayload::from_security_context(
                ctx,
                token_restriction,
                expires_at,
            )?));
        }
        let scope = ctx
            .authorization()
            .map(|authz| &authz.scope)
            .ok_or(TokenProviderError::ScopeMissing)?;
        match scope {
            ScopeInfo::Domain(domain) => match ctx.authentication_context() {
                // Protect domain scope by not implementing default match branch allowing newer
                // AuthenticationContext accidentally grant domain scope token.
                AuthenticationContext::ApplicationCredential { .. } => {
                    Err(AuthenticationError::ScopeNotAllowed.into())
                }
                AuthenticationContext::Oidc { oidc, .. } => Ok(Self::FederationDomainScope(
                    FederationDomainScopePayload::from_security_context(
                        ctx, domain, oidc, expires_at,
                    )?,
                )),
                AuthenticationContext::K8s { .. } => {
                    Err(AuthenticationError::ScopeNotAllowed.into())
                }
                AuthenticationContext::Password => Ok(Self::DomainScope(
                    DomainScopePayload::from_security_context(ctx, domain, expires_at)?,
                )),
                AuthenticationContext::Admin => Ok(Self::DomainScope(
                    DomainScopePayload::from_security_context(ctx, domain, expires_at)?,
                )),
                AuthenticationContext::Token(..) => Ok(Self::DomainScope(
                    DomainScopePayload::from_security_context(ctx, domain, expires_at)?,
                )),
                AuthenticationContext::Trust { .. } => {
                    Err(AuthenticationError::ScopeNotAllowed.into())
                }
                AuthenticationContext::WebauthN => Ok(Self::DomainScope(
                    DomainScopePayload::from_security_context(ctx, domain, expires_at)?,
                )),
                AuthenticationContext::Mapping(_) => Ok(Self::DomainScope(
                    DomainScopePayload::from_security_context(ctx, domain, expires_at)?,
                )),
                // EC2 credentials always resolve to a project scope (ADR 0019
                // §5); a domain-scoped EC2 token has no legitimate use case.
                AuthenticationContext::Ec2Credential => {
                    Err(AuthenticationError::ScopeNotAllowed.into())
                }
                AuthenticationContext::Totp => Ok(Self::DomainScope(
                    DomainScopePayload::from_security_context(ctx, domain, expires_at)?,
                )),
                // Direct, non-delegated authentication (ADR 0025 §4), same
                // as Password/Token - no dedicated payload variant exists
                // yet (Phase 1 PR 1.4, plugin-version-bound token
                // verification, is deferred).
                AuthenticationContext::WasmPlugin { .. } => Ok(Self::DomainScope(
                    DomainScopePayload::from_security_context(ctx, domain, expires_at)?,
                )),
            },
            ScopeInfo::Project { project, .. } => match ctx.authentication_context() {
                AuthenticationContext::ApplicationCredential {
                    application_credential,
                    ..
                } => Ok(Self::ApplicationCredential(
                    ApplicationCredentialPayload::from_security_context(
                        ctx,
                        application_credential,
                        expires_at,
                    )?,
                )),
                AuthenticationContext::Oidc { oidc, .. } => Ok(Self::FederationProjectScope(
                    FederationProjectScopePayload::from_security_context(
                        ctx, project, oidc, expires_at,
                    )?,
                )),
                // A trust presented on a plain Project scope (the EC2-redemption
                // shape, `validate_scope_boundaries` guarantees `project.id ==
                // trust.project_id` here) MUST NOT fall through to a plain
                // `ProjectScope` payload: that payload type carries no trust
                // reference, so decoding it back (`build_authz_info_from_fernet_token`
                // / `validate_to_context_impl`) would reconstruct a generic
                // `AuthenticationContext::Token` with the trustee's own live
                // project role assignments instead of the trust's bounded set —
                // silently dropping the delegation restriction on every reuse of
                // the issued token (OSSA-2026-015). Emit the same `Trust` payload
                // used for the native `TrustProject` scope so the round-trip
                // always re-derives `AuthenticationContext::Trust`.
                AuthenticationContext::Trust { trust, .. } => {
                    Ok(Self::Trust(TrustPayload::from_security_context(
                        ctx,
                        trust.id.clone(),
                        project.id.clone(),
                        expires_at,
                    )?))
                }
                _ => Ok(Self::ProjectScope(
                    ProjectScopePayload::from_security_context(ctx, project, expires_at)?,
                )),
            },
            ScopeInfo::TrustProject(tpi) => Ok(Self::Trust(TrustPayload::from_security_context(
                ctx,
                tpi.trust.id.clone(),
                tpi.project.id.clone(),
                expires_at,
            )?)),
            ScopeInfo::System(system) => Ok(Self::SystemScope(
                SystemScopePayload::from_security_context(ctx, system, expires_at)?,
            )),
            ScopeInfo::Unscoped => match ctx.authentication_context() {
                AuthenticationContext::Oidc { oidc, .. } => Ok(Self::FederationUnscoped(
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
    /// Returns the domain identifier when the token is a
    /// [`FernetToken::DomainScope`]
    /// or [`FernetToken::FederationDomainScope`]. Returns `None` for all other
    /// token types.
    pub const fn domain_id(&self) -> Option<&String> {
        match self {
            Self::DomainScope(x) => Some(&x.domain_id),
            Self::FederationDomainScope(x) => Some(&x.domain_id),
            _ => None,
        }
    }

    pub const fn system_id(&self) -> Option<&String> {
        match self {
            Self::SystemScope(x) => Some(&x.system_id),
            _ => None,
        }
    }
}

/// Opaque wrapper around a `FernetToken` that proves cryptographic verification
/// passed.
///
/// The `_score: NonZeroU32` parameter in `from_verified` is an unforgeable
/// proof: `NonZeroU32` cannot be zero-constructed in safe Rust, so callers
/// must have obtained it from the token-verification path.
pub struct VerifiedFernetToken(FernetToken);

impl VerifiedFernetToken {
    /// Construct a `VerifiedFernetToken`.
    ///
    /// Only callable from within the crate (or by the token provider, which
    /// holds the `_score` from its HMAC/Fernet verification step).
    pub fn from_verified(token: FernetToken, _score: std::num::NonZeroU32) -> Self {
        Self(token)
    }

    pub fn user_id(&self) -> &str {
        self.0.user_id()
    }

    pub fn domain_id(&self) -> Option<&str> {
        self.0.domain_id().map(|s| s.as_str())
    }

    pub fn project_id(&self) -> Option<&str> {
        self.0.project_id().map(|s| s.as_str())
    }
}

impl Validate for FernetToken {
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

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::resource::*;
    use crate::trust::TrustBuilder;

    fn make_project(id: &str) -> Project {
        ProjectBuilder::default()
            .id(id)
            .domain_id("did")
            .name("pname")
            .enabled(true)
            .build()
            .unwrap()
    }

    fn make_domain() -> Domain {
        DomainBuilder::default()
            .id("did")
            .name("dname")
            .enabled(true)
            .build()
            .unwrap()
    }

    fn make_trust_ctx(project_id: &str) -> SecurityContext {
        let trust = TrustBuilder::default()
            .id("trust_id")
            .trustor_user_id("trustor")
            .trustee_user_id("trustee")
            .project_id(project_id)
            .impersonation(false)
            .build()
            .unwrap();
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Trust { trust, token: None })
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("trustee")
                        .build()
                        .unwrap(),
                ),
            })
            .build()
            .unwrap();
        let mut ctx = SecurityContext::try_from(auth).unwrap();
        ctx.set_authorization(
            AuthzInfoBuilder::default()
                .scope(ScopeInfo::Project {
                    project: make_project(project_id),
                    project_domain: make_domain(),
                })
                .build()
                .unwrap(),
        );
        ctx
    }

    /// A trust presented on a plain `Project` scope (the EC2-redemption shape)
    /// MUST still be encoded as a `Trust` payload, never `ProjectScope` --
    /// otherwise decoding the issued token back drops the delegation binding
    /// entirely (OSSA-2026-015, see doc/src/security.md I4).
    #[test]
    fn test_from_security_context_trust_on_project_scope_emits_trust_payload() {
        let ctx = make_trust_ctx("pid");
        let token = FernetToken::from_security_context(&ctx, Utc::now()).unwrap();

        match token {
            FernetToken::Trust(payload) => {
                assert_eq!("trust_id", payload.trust_id);
                assert_eq!("pid", payload.project_id);
            }
            other => panic!("expected FernetToken::Trust, got {other:?}"),
        }
    }
}
