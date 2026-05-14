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

//! # Authorization and authentication information.
//!
//! Authentication and authorization types with corresponding validation.
//! Authentication specific validation may stay in the corresponding provider
//! (i.e. user password is expired), but general validation rules must be
//! present here to be shared across different authentication methods. The
//! same is valid for the authorization validation (project/domain must exist
//! and be enabled).
use std::collections::{HashMap, HashSet};
use std::iter::once;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use derive_builder::Builder;
use thiserror::Error;
use tracing::warn;
use uuid::{Uuid, uuid};
use validator::{Validate, ValidationErrors};

use crate::application_credential::ApplicationCredential;
use crate::error::BuilderError;
use crate::identity::{Group, UserResponse};
use crate::resource::{Domain, Project};
use crate::token::TokenRestriction;
use crate::trust::Trust;

/// Namespace UUID for the virtual ID generation based on the UUIDv5
const NAMESPACE_UUID: Uuid = uuid!("96f0e3b8-0d21-41bc-bd0d-457da94345f9");

#[derive(Error, Debug)]
pub enum AuthenticationError {
    /// Auth principal mismatch.
    #[error("the principal differs in authentication results")]
    AuthPrincipalDiffers,

    /// Domain is disabled.
    #[error("The domain is disabled.")]
    DomainDisabled(String),

    /// Project is disabled.
    #[error("The project is disabled.")]
    ProjectDisabled(String),

    /// Scope is not allowed with the current SecurityContext.
    #[error("target scope is not allowed with the current authentication context")]
    ScopeNotAllowed,

    /// Structures builder error.
    #[error(transparent)]
    StructBuilder {
        /// The source of the error.
        #[from]
        source: BuilderError,
    },

    /// Token renewal is forbidden.
    #[error("Token renewal (getting token from token) is prohibited.")]
    TokenRenewalForbidden,

    /// Unauthorized.
    #[error("The request you have made requires authentication.")]
    Unauthorized,

    /// User is disabled.
    #[error("The account is disabled for user: {0}")]
    UserDisabled(String),

    /// User is locked due to the multiple failed attempts.
    #[error("The account is temporarily disabled for user: {0}")]
    UserLocked(String),

    /// User name password combination is wrong.
    #[error("wrong username or password")]
    UserNameOrPasswordWrong,

    /// User password is expired.
    #[error("The password is expired for user: {0}")]
    UserPasswordExpired(String),

    /// Validation error.
    #[error("context validation error")]
    Validation {
        /// The source of the error.
        #[from]
        source: ValidationErrors,
    },
}

/// Security Context of the operation.
///
/// Authentication and information bound to the operation.
#[derive(Builder, Clone, Debug, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(private, setter(into, strip_option))]
pub struct SecurityContext {
    /// Audit IDs.
    pub audit_ids: Vec<String>,

    /// Authentication context (how the authentication was performed).
    // TODO: It may be a Vec<AuthenticationContext> in the case of MFA
    pub authentication_context: AuthenticationContext,

    /// Authentication methods used to establish the context.
    pub auth_methods: HashSet<String>,

    /// Authorization scope of the context. During the authentication request
    /// this information becomes available at the later phase.
    #[builder(default)]
    pub authorization: Option<AuthzInfo>,

    /// Authentication expiration.
    #[builder(default)]
    pub expires_at: Option<DateTime<Utc>>,

    /// Identity information.
    pub principal: PrincipalInfo,

    /// Token restriction.
    #[builder(default)]
    pub token_restriction: Option<TokenRestriction>,
}

impl SecurityContext {
    /// Validate the authentication information:
    ///
    /// - User attribute must be set
    /// - User must be enabled
    /// - User object id must match user_id
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        self.principal.validate()?;
        Ok(())
    }

    /// SECURITY GATE: Validate whether the scope is accessible with the current
    /// [`SecurityContext`].
    ///
    /// Perform validation whether it is possible to grant authorization for the
    /// scope based on the authentication or whether it violates the bounds
    /// of the current authentication. No check for whether the principal has
    /// any roles on the target scope.
    ///
    /// # Security Notes
    /// No validations of whether the principal has any roles on the target
    /// scope are performed. This is barely AuthN/AuthZ context boundaries
    /// check.
    pub fn validate_scope_boundaries(&self, scope: &AuthzInfo) -> Result<(), AuthenticationError> {
        match scope {
            AuthzInfo::Domain(_domain) => {
                if self.token_restriction.is_some() {
                    return Err(AuthenticationError::ScopeNotAllowed);
                };
                match &self.authentication_context {
                    AuthenticationContext::ApplicationCredential(_) => {
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::Oidc(_) => Ok(()),
                    AuthenticationContext::K8s(_) => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::Password => Ok(()),
                    AuthenticationContext::Token(_) => Ok(()),
                    AuthenticationContext::Trust(_trust) => {
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::WebauthN => Ok(()),
                }
            }
            AuthzInfo::Project(project) => {
                if let Some(token_restriction) = &self.token_restriction
                    && let Some(tr_pid) = &token_restriction.project_id
                    && *tr_pid != project.id
                {
                    return Err(AuthenticationError::ScopeNotAllowed);
                }
                match &self.authentication_context {
                    AuthenticationContext::ApplicationCredential(app_cred) => {
                        if app_cred.project_id != project.id {
                            Err(AuthenticationError::ScopeNotAllowed)
                        } else {
                            Ok(())
                        }
                    }
                    AuthenticationContext::Oidc(_) => Ok(()),
                    AuthenticationContext::K8s(_) => Ok(()),
                    AuthenticationContext::Password => Ok(()),
                    AuthenticationContext::Token(_) => Ok(()),
                    AuthenticationContext::Trust(trust) => {
                        if trust.project_id.as_ref().is_none_or(|x| *x != project.id) {
                            return Err(AuthenticationError::ScopeNotAllowed);
                        }
                        Ok(())
                    }
                    AuthenticationContext::WebauthN => Ok(()),
                }
            }
            AuthzInfo::Trust(_trust) => {
                if self.token_restriction.is_some() {
                    return Err(AuthenticationError::ScopeNotAllowed);
                };
                match &self.authentication_context {
                    AuthenticationContext::ApplicationCredential(_) => {
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::Oidc(_) => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::K8s(_) => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::Password => Ok(()),
                    AuthenticationContext::Token(_) => Ok(()),
                    AuthenticationContext::Trust(_trust) => {
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::WebauthN => Err(AuthenticationError::ScopeNotAllowed),
                }
            }
            AuthzInfo::System(_system) => {
                if self.token_restriction.is_some() {
                    return Err(AuthenticationError::ScopeNotAllowed);
                };
                match &self.authentication_context {
                    // TODO: SPIFFE auth should be included here
                    AuthenticationContext::ApplicationCredential(_) => {
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::Oidc(_) => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::K8s(_) => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::Password => Ok(()),
                    AuthenticationContext::Token(_) => Ok(()),
                    AuthenticationContext::Trust(_) => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::WebauthN => Ok(()),
                }
            }
            AuthzInfo::Unscoped => {
                if self.token_restriction.is_some() {
                    return Err(AuthenticationError::ScopeNotAllowed);
                };
                match &self.authentication_context {
                    AuthenticationContext::ApplicationCredential(_) => {
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::Oidc(_) => Ok(()),
                    AuthenticationContext::K8s(_) => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::Password => Ok(()),
                    AuthenticationContext::Token(_) => Ok(()),
                    AuthenticationContext::Trust(_) => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::WebauthN => Ok(()),
                }
            }
        }
    }
}

impl TryFrom<AuthenticationResult> for SecurityContext {
    type Error = AuthenticationError;
    /// Construct a single-method [`SecurityContext`] from a single
    /// [`AuthenticationResult`].
    ///
    /// Generates a fresh audit ID, propagates any token audit IDs from the
    /// parent token (when authenticated by token), and maps the
    /// authentication result's context and principal into the security
    /// context.
    fn try_from(value: AuthenticationResult) -> Result<Self, Self::Error> {
        let mut builder = SecurityContextBuilder::default();
        builder
            .authentication_context(value.context.clone())
            .principal(value.principal.clone());

        let mut audit_ids = vec![URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())];
        if let AuthenticationContext::Token(token) = &value.context {
            audit_ids.extend(token.audit_ids.clone());
        }
        builder.audit_ids(audit_ids);
        if let Some(token_restriction) = value.token_restriction {
            builder.token_restriction(token_restriction);
        }
        builder.auth_methods(value.context.methods());
        Ok(builder.build()?)
    }
}

impl TryFrom<Vec<AuthenticationResult>> for SecurityContext {
    type Error = AuthenticationError;
    /// Construct a [`SecurityContext`] from multiple [`AuthenticationResult`]'s
    /// (e.g., MFA).
    ///
    /// The first result provides the principal and primary authentication
    /// context. All subsequent results must share the same principal;
    /// otherwise [`AuthenticationError::AuthPrincipalDiffers`] is returned.
    /// Audit IDs and authentication methods are aggregated across all results.
    fn try_from(value: Vec<AuthenticationResult>) -> Result<Self, Self::Error> {
        let mut builder = SecurityContextBuilder::default();
        let mut audit_ids = vec![URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())];
        let mut auth_results = value.into_iter();

        if let Some(auth) = auth_results.next() {
            builder.principal(auth.principal.clone());
            builder.authentication_context(auth.context.clone());
            // TODO: process properly the token restrictions
            if let Some(token_restriction) = auth.token_restriction {
                builder.token_restriction(token_restriction);
            }
            if let AuthenticationContext::Token(token) = &auth.context {
                audit_ids.extend(token.audit_ids.clone());
            };
            builder.audit_ids(audit_ids);
            builder.auth_methods(auth.context.methods());
        }
        let mut ctx = builder.build()?;
        for auth in auth_results {
            if auth.principal != ctx.principal {
                return Err(AuthenticationError::AuthPrincipalDiffers);
            }
            if let AuthenticationContext::Token(token) = &auth.context {
                ctx.audit_ids.extend(token.audit_ids.clone());
            };
            ctx.auth_methods.extend(auth.context.methods());
        }

        Ok(ctx)
    }
}

/// Principal information.
///
/// Represent an entity that is trying to perform an action.
#[derive(Builder, Clone, Debug, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct PrincipalInfo {
    /// Domain ID of the principal.
    ///
    /// The domain the principal belongs to. For the classical user it
    /// represents the user domain_id. For the service accounts and other
    /// remote principals it may be empty (e.g., internal service accounts
    /// like nova, neutron, etc).
    pub domain_id: Option<String>,

    /// Principal identity.
    pub identity: IdentityInfo,
}

impl PrincipalInfo {
    /// Validate the principal information
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        self.identity.validate()?;
        Ok(())
    }
    /// Get the traditional user_id.
    ///
    /// For the regular user principal it is just the user_id. For the service
    /// accounts, spiffe and k8s service accounts it is a virtual ID.
    pub fn get_user_id(&self) -> String {
        match &self.identity {
            IdentityInfo::User(user) => user.user_id.clone(),
            // Virtual ID for the Principal not existing as a regular user.
            IdentityInfo::Principal(principal) => {
                Uuid::new_v5(&NAMESPACE_UUID, principal.id.as_bytes())
                    .simple()
                    .to_string()
            }
        }
    }
}

/// Principal identity information.
#[derive(Clone, Debug, PartialEq)]
pub enum IdentityInfo {
    /// Traditional user.
    User(UserIdentityInfo),
    /// A remote identity (Spiffe, SA, etc).
    Principal(PrincipalIdentityInfo),
}

impl IdentityInfo {
    /// Validate the identity information:
    ///
    /// Dispatches to the appropriate variant's validation logic.
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        match &self {
            Self::User(user) => Ok(user.validate()?),
            Self::Principal(principal) => Ok(principal.validate()?),
        }
    }
}

/// Traditional Keystone User.
#[derive(Builder, Clone, Debug, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct UserIdentityInfo {
    /// Resolved user object.
    #[builder(default)]
    pub user: Option<UserResponse>,

    /// Resolved user domain information.
    #[builder(default)]
    pub user_domain: Option<Domain>,

    /// Resolved user groups object.
    #[builder(default)]
    pub user_groups: Vec<Group>,

    /// User id.
    #[validate(length(min = 1, max = 64))]
    pub user_id: String,
}

impl UserIdentityInfo {
    /// Validate the authentication information:
    ///
    /// - User attribute must be set
    /// - User must be enabled
    /// - User object id must match user_id
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        // TODO: all validations (disabled user, locked, etc) should be placed here
        // since every authentication method goes different way and we risk
        // missing validations
        if let Some(user) = &self.user {
            if user.id != self.user_id {
                warn!(
                    "User data does not match the user_id attribute: {} vs {}",
                    self.user_id, user.id
                );
                return Err(AuthenticationError::Unauthorized);
            }
            if !user.enabled {
                return Err(AuthenticationError::UserDisabled(self.user_id.clone()));
            }
        } else {
            warn!(
                "User data must be resolved in the AuthenticatedInfo before validating: {:?}",
                self
            );
            return Err(AuthenticationError::Unauthorized);
        }

        Ok(())
    }
}

/// Workload principal.
#[derive(Builder, Clone, Debug, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct PrincipalIdentityInfo {
    /// The unique identifier for the workload (e.g., SPIFFE ID or GitHub
    /// Subject).
    pub id: String,

    /// Metadata about the workload environment.
    /// This allows OPA/Keystone to verify specific attributes like
    /// 'repository'.
    #[builder(default)]
    pub attributes: HashMap<String, String>,

    /// The source of the identity (e.g., "https://token.actions.githubusercontent.com").
    pub issuer: String,
}

/// Authentication context.
#[derive(Clone, Debug, PartialEq)]
pub enum AuthenticationContext {
    /// Login using application credentials.
    ApplicationCredential(ApplicationCredential),
    /// Login using OIDC federation
    Oidc(OidcContext),
    /// K8s Auth
    K8s(K8sContext),
    /// Login with password.
    Password,
    /// Login using regular fernet/jwt token.
    Token(TokenContext),
    /// Login consuming the trust.
    Trust(Trust),
    /// Login with WebauthN credentials.
    WebauthN,
}

/// K8s auth context.
#[derive(Builder, Clone, Debug, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct K8sContext {
    /// Token restriction bound to the K8s auth role.
    pub token_restriction_id: String,
}

impl AuthenticationContext {
    /// Get the authentication method names related to the authentication
    /// context.
    ///
    /// When authenticated using the token this is technically just the list of
    /// all methods already present in the token. For everything else it is
    /// a new list of only the method itself.
    pub fn methods(&self) -> HashSet<String> {
        match self {
            Self::ApplicationCredential(_) => once("application_credential".to_string()).collect(),
            Self::Oidc(_) => once("openid".to_string()).collect(),
            Self::Password => once("password".to_string()).collect(),
            Self::K8s(_) => once("mapped".to_string()).collect(),
            Self::Token(token) => token
                .methods
                .iter()
                .cloned()
                .chain(once("token".to_string()))
                .collect(),
            Self::Trust(_) => once("trust".to_string()).collect(),
            Self::WebauthN => once("x509".to_string()).collect(),
        }
    }
}

/// OIDC auth context.
#[derive(Builder, Clone, Debug, Default, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct OidcContext {
    /// Federated IDP id.
    pub idp_id: String,

    /// Federated protocol id.
    pub protocol_id: String,
}

/// Token auth context.
#[derive(Builder, Clone, Debug, Default, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into))]
pub struct TokenContext {
    /// Audit IDs.
    #[builder(default)]
    pub audit_ids: Vec<String>,

    /// Authentication expiration.
    #[builder(default)]
    pub expires_at: DateTime<Utc>,

    /// Authentication methods.
    #[builder(default)]
    pub methods: Vec<String>,
}

/// Result of the single method Authentication
#[derive(Builder, Clone, Debug, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct AuthenticationResult {
    /// The specific context for THIS factor (e.g., method name, audit IDs).
    pub context: AuthenticationContext,

    /// The identity this provider identified/verified.
    pub principal: PrincipalInfo,

    /// Token restriction rules tied to the authentication.
    #[builder(default)]
    pub token_restriction: Option<TokenRestriction>,
}

/// Authorization information.
#[derive(Clone, Debug, PartialEq)]
pub enum AuthzInfo {
    /// Domain scope.
    Domain(Domain),
    /// Project scope.
    Project(Project),
    /// System scope.
    System(String),
    /// Trust scope.
    Trust(Trust),
    /// Unscoped.
    Unscoped,
}

impl AuthzInfo {
    /// Validate the authorization information:
    ///
    /// - Unscoped: always valid
    /// - Project: check if the project is enabled
    /// - Domain: check if the domain is enabled
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        match self {
            AuthzInfo::Domain(domain) => {
                if !domain.enabled {
                    return Err(AuthenticationError::DomainDisabled(domain.id.clone()));
                }
            }
            AuthzInfo::Project(project) => {
                if !project.enabled {
                    return Err(AuthenticationError::ProjectDisabled(project.id.clone()));
                }
            }
            AuthzInfo::System(_) => {}
            AuthzInfo::Trust(_) => {}
            AuthzInfo::Unscoped => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::application_credential::ApplicationCredentialBuilder;
    use crate::identity::{UserOptions, UserResponse};
    use crate::token::TokenRestrictionBuilder;
    use crate::trust::*;

    #[test]
    fn test_authn_validate_no_user() {
        let authn = UserIdentityInfoBuilder::default()
            .user_id("uid")
            .build()
            .unwrap();
        if let Err(AuthenticationError::Unauthorized) = authn.validate() {
        } else {
            panic!("should be unauthorized");
        }
    }

    #[test]
    fn test_authn_validate_user_disabled() {
        let authn = UserIdentityInfoBuilder::default()
            .user_id("uid")
            .user(UserResponse {
                id: "uid".to_string(),
                enabled: false,
                default_project_id: None,
                domain_id: "did".into(),
                extra: HashMap::new(),
                name: "foo".into(),
                options: UserOptions::default(),
                federated: None,
                password_expires_at: None,
            })
            .build()
            .unwrap();
        if let Err(AuthenticationError::UserDisabled(uid)) = authn.validate() {
            assert_eq!("uid", uid);
        } else {
            panic!("should fail for disabled user");
        }
    }

    #[test]
    fn test_authn_validate_user_mismatch() {
        let authn = UserIdentityInfoBuilder::default()
            .user_id("uid1")
            .user(UserResponse {
                id: "uid2".to_string(),
                enabled: false,
                default_project_id: None,
                domain_id: "did".into(),
                extra: HashMap::new(),
                name: "foo".into(),
                options: UserOptions::default(),
                federated: None,
                password_expires_at: None,
            })
            .build()
            .unwrap();
        if let Err(AuthenticationError::Unauthorized) = authn.validate() {
        } else {
            panic!("should fail when user_id != user.id");
        }
    }

    #[test]
    fn test_authz_validate_project() {
        let authz = AuthzInfo::Project(Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        assert!(authz.validate().is_ok());
    }

    #[test]
    fn test_authz_validate_project_disabled() {
        let authz = AuthzInfo::Project(Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: false,
            ..Default::default()
        });
        if let Err(AuthenticationError::ProjectDisabled(..)) = authz.validate() {
        } else {
            panic!("should fail when project is not enabled");
        }
    }

    #[test]
    fn test_authz_validate_domain() {
        let authz = AuthzInfo::Domain(Domain {
            id: "id".into(),
            name: "name".into(),
            enabled: true,
            ..Default::default()
        });
        assert!(authz.validate().is_ok());
    }

    #[test]
    fn test_authz_validate_domain_disabled() {
        let authz = AuthzInfo::Domain(Domain {
            id: "id".into(),
            name: "name".into(),
            enabled: false,
            ..Default::default()
        });
        if let Err(AuthenticationError::DomainDisabled(..)) = authz.validate() {
        } else {
            panic!("should fail when domain is not enabled");
        }
    }

    #[test]
    fn test_authz_validate_system() {
        let authz = AuthzInfo::System("system".into());
        assert!(authz.validate().is_ok());
    }

    #[test]
    fn test_authz_validate_unscoped() {
        let authz = AuthzInfo::Unscoped;
        assert!(authz.validate().is_ok());
    }

    #[test]
    fn test_validate_scope_boundarires_with_token_restriction() {
        let project = AuthzInfo::Project(Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let project2 = AuthzInfo::Project(Project {
            id: "pid2".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let domain = AuthzInfo::Domain(Domain {
            id: "id".into(),
            name: "name".into(),
            enabled: true,
            ..Default::default()
        });
        let trust = AuthzInfo::Trust(
            TrustBuilder::default()
                .id("trust_id")
                .trustor_user_id("trustor")
                .trustee_user_id("trustee")
                .impersonation(false)
                .build()
                .unwrap(),
        );
        let system = AuthzInfo::System("system".into());
        let unscoped = AuthzInfo::Unscoped;
        let tr = TokenRestrictionBuilder::default()
            .allow_rescope(true)
            .allow_renew(true)
            .id("tr_id")
            .domain_id("did")
            .role_ids(vec![])
            .project_id("pid")
            .build()
            .unwrap();
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
            .token_restriction(tr.clone())
            .build()
            .unwrap();
        let ctx = SecurityContext::try_from(auth).unwrap();
        assert!(matches!(
            ctx.validate_scope_boundaries(&domain),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(ctx.validate_scope_boundaries(&project).is_ok());
        assert!(
            matches!(
                ctx.validate_scope_boundaries(&project2),
                Err(AuthenticationError::ScopeNotAllowed),
            ),
            "TR restricted to the other project"
        );
        assert!(matches!(
            ctx.validate_scope_boundaries(&trust),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&system),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&unscoped),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
    }

    #[test]
    fn test_validate_scope_boundaries_app_cred() {
        let project = AuthzInfo::Project(Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let project2 = AuthzInfo::Project(Project {
            id: "pid2".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let domain = AuthzInfo::Domain(Domain {
            id: "id".into(),
            name: "name".into(),
            enabled: true,
            ..Default::default()
        });
        let trust = AuthzInfo::Trust(
            TrustBuilder::default()
                .id("trust_id")
                .trustor_user_id("trustor")
                .trustee_user_id("trustee")
                .impersonation(false)
                .build()
                .unwrap(),
        );
        let system = AuthzInfo::System("system".into());
        let unscoped = AuthzInfo::Unscoped;
        let app_cred = ApplicationCredentialBuilder::default()
            .id("app_cred_id")
            .name("app_cred_name")
            .project_id("pid")
            .roles(vec![])
            .unrestricted(false)
            .user_id("uid")
            .build()
            .unwrap();
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::ApplicationCredential(app_cred))
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
        assert!(matches!(
            ctx.validate_scope_boundaries(&domain),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(ctx.validate_scope_boundaries(&project).is_ok());
        assert!(matches!(
            ctx.validate_scope_boundaries(&project2),
            Err(AuthenticationError::ScopeNotAllowed),
        ),);
        assert!(matches!(
            ctx.validate_scope_boundaries(&trust),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&system),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&unscoped),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
    }

    #[test]
    fn test_validate_scope_boundaries_oidc() {
        let project = AuthzInfo::Project(Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let project2 = AuthzInfo::Project(Project {
            id: "pid2".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let domain = AuthzInfo::Domain(Domain {
            id: "id".into(),
            name: "name".into(),
            enabled: true,
            ..Default::default()
        });
        let trust = AuthzInfo::Trust(
            TrustBuilder::default()
                .id("trust_id")
                .trustor_user_id("trustor")
                .trustee_user_id("trustee")
                .impersonation(false)
                .build()
                .unwrap(),
        );
        let system = AuthzInfo::System("system".into());
        let unscoped = AuthzInfo::Unscoped;
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Oidc(
                OidcContextBuilder::default()
                    .idp_id("idp")
                    .protocol_id("protocol")
                    .build()
                    .unwrap(),
            ))
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
        assert!(ctx.validate_scope_boundaries(&domain).is_ok());
        assert!(ctx.validate_scope_boundaries(&project).is_ok());
        assert!(ctx.validate_scope_boundaries(&project2).is_ok());
        assert!(matches!(
            ctx.validate_scope_boundaries(&trust),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&system),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(ctx.validate_scope_boundaries(&unscoped).is_ok());
    }

    #[test]
    fn test_validate_scope_boundarires_k8s() {
        let project = AuthzInfo::Project(Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let project2 = AuthzInfo::Project(Project {
            id: "pid2".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let domain = AuthzInfo::Domain(Domain {
            id: "id".into(),
            name: "name".into(),
            enabled: true,
            ..Default::default()
        });
        let trust = AuthzInfo::Trust(
            TrustBuilder::default()
                .id("trust_id")
                .trustor_user_id("trustor")
                .trustee_user_id("trustee")
                .impersonation(false)
                .build()
                .unwrap(),
        );
        let system = AuthzInfo::System("system".into());
        let unscoped = AuthzInfo::Unscoped;
        let tr = TokenRestrictionBuilder::default()
            .allow_rescope(true)
            .allow_renew(true)
            .id("tr_id")
            .domain_id("did")
            .role_ids(vec![])
            .project_id("pid")
            .build()
            .unwrap();
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::K8s(
                K8sContextBuilder::default()
                    .token_restriction_id(tr.id.clone())
                    .build()
                    .unwrap(),
            ))
            .principal(PrincipalInfo {
                domain_id: Some("did".into()),
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .build()
                        .unwrap(),
                ),
            })
            .token_restriction(tr.clone())
            .build()
            .unwrap();
        let ctx = SecurityContext::try_from(auth).unwrap();
        assert!(matches!(
            ctx.validate_scope_boundaries(&domain),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(ctx.validate_scope_boundaries(&project).is_ok());
        assert!(matches!(
            ctx.validate_scope_boundaries(&project2),
            Err(AuthenticationError::ScopeNotAllowed),
        ),);
        assert!(matches!(
            ctx.validate_scope_boundaries(&trust),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&system),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&unscoped),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
    }

    #[test]
    fn test_validate_scope_boundaries_password() {
        let project = AuthzInfo::Project(Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let project2 = AuthzInfo::Project(Project {
            id: "pid2".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let domain = AuthzInfo::Domain(Domain {
            id: "id".into(),
            name: "name".into(),
            enabled: true,
            ..Default::default()
        });
        let trust = AuthzInfo::Trust(
            TrustBuilder::default()
                .id("trust_id")
                .trustor_user_id("trustor")
                .trustee_user_id("trustee")
                .impersonation(false)
                .build()
                .unwrap(),
        );
        let system = AuthzInfo::System("system".into());
        let unscoped = AuthzInfo::Unscoped;
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
        assert!(ctx.validate_scope_boundaries(&domain).is_ok());
        assert!(ctx.validate_scope_boundaries(&project).is_ok());
        assert!(ctx.validate_scope_boundaries(&project2).is_ok());
        assert!(ctx.validate_scope_boundaries(&trust).is_ok());
        assert!(ctx.validate_scope_boundaries(&system).is_ok());
        assert!(ctx.validate_scope_boundaries(&unscoped).is_ok());
    }

    #[test]
    fn test_validate_scope_boundarires_trust() {
        let project = AuthzInfo::Project(Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let project2 = AuthzInfo::Project(Project {
            id: "pid2".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let domain = AuthzInfo::Domain(Domain {
            id: "id".into(),
            name: "name".into(),
            enabled: true,
            ..Default::default()
        });
        let trust = TrustBuilder::default()
            .id("trust_id")
            .trustor_user_id("trustor")
            .trustee_user_id("trustee")
            .project_id("pid")
            .impersonation(false)
            .build()
            .unwrap();
        let trust_scope = AuthzInfo::Trust(trust.clone());
        let system = AuthzInfo::System("system".into());
        let unscoped = AuthzInfo::Unscoped;
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Trust(trust.clone()))
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
        assert!(matches!(
            ctx.validate_scope_boundaries(&domain),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(ctx.validate_scope_boundaries(&project).is_ok());
        assert!(matches!(
            ctx.validate_scope_boundaries(&project2),
            Err(AuthenticationError::ScopeNotAllowed),
        ),);
        assert!(matches!(
            ctx.validate_scope_boundaries(&trust_scope),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&system),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&unscoped),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
    }

    #[test]
    fn test_validate_scope_boundaries_webauthn() {
        let project = AuthzInfo::Project(Project {
            id: "pid".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let project2 = AuthzInfo::Project(Project {
            id: "pid2".into(),
            domain_id: "pdid".into(),
            enabled: true,
            ..Default::default()
        });
        let domain = AuthzInfo::Domain(Domain {
            id: "id".into(),
            name: "name".into(),
            enabled: true,
            ..Default::default()
        });
        let trust = AuthzInfo::Trust(
            TrustBuilder::default()
                .id("trust_id")
                .trustor_user_id("trustor")
                .trustee_user_id("trustee")
                .impersonation(false)
                .build()
                .unwrap(),
        );
        let system = AuthzInfo::System("system".into());
        let unscoped = AuthzInfo::Unscoped;
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::WebauthN)
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
        assert!(ctx.validate_scope_boundaries(&domain).is_ok());
        assert!(ctx.validate_scope_boundaries(&project).is_ok());
        assert!(ctx.validate_scope_boundaries(&project2).is_ok());
        assert!(matches!(
            ctx.validate_scope_boundaries(&trust),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(ctx.validate_scope_boundaries(&system).is_ok());
        assert!(ctx.validate_scope_boundaries(&unscoped).is_ok());
    }
}
