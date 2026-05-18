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
use crate::role::RoleRef;
use crate::token::TokenRestriction;
use crate::trust::Trust;

/// Namespace UUID for the virtual ID generation based on the UUIDv5
const NAMESPACE_UUID: Uuid = uuid!("96f0e3b8-0d21-41bc-bd0d-457da94345f9");

#[derive(Error, Debug)]
pub enum AuthenticationError {
    /// Actor has no roles on the target scope.
    #[error("actor has no roles on scope")]
    ActorHasNoRolesOnTarget,

    /// AuthenticationContext is bound to the user not matching the
    /// SecurityContext principal.
    #[error("authorization context bind is not owned by a context principal")]
    AuthzPrincipalMismatch,

    /// Varying principal used in multiple authentication methods.
    #[error("the principal differs between authentication results")]
    AuthnPrincipalMismatch,

    /// Domain is disabled.
    #[error("The domain is disabled.")]
    DomainDisabled(String),

    /// Principal not supported for the request.
    #[error("principal with `domain_id` is required")]
    PrincipalDomainIdMissing,

    /// Project is disabled.
    #[error("The project is disabled.")]
    ProjectDisabled(String),

    /// The security context must be resolved before the use.
    #[error("security context is not resolved")]
    SecurityContextNotResolved,

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

    /// A role assignment failed to convert to a valid RoleRef.
    #[error("role assignment cannot be converted to a role reference")]
    RoleConversionFailed,
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
        match &self.authentication_context {
            AuthenticationContext::ApplicationCredential(application_credential) => {
                if application_credential.user_id != self.principal.get_user_id() {
                    return Err(AuthenticationError::AuthzPrincipalMismatch);
                }
            }
            AuthenticationContext::Trust(trust) => {
                if trust.trustee_user_id != self.principal.get_user_id() {
                    return Err(AuthenticationError::AuthzPrincipalMismatch);
                }
            }
            _ => {}
        }
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
    pub fn validate_scope_boundaries(&self, scope: &ScopeInfo) -> Result<(), AuthenticationError> {
        match scope {
            ScopeInfo::Domain(_domain) => {
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
            ScopeInfo::Project(project) => {
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
            ScopeInfo::Trust(_trust) => {
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
            ScopeInfo::System(_system) => {
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
            ScopeInfo::Unscoped => {
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

    // Verifies all required fields are populated before policy enforcement
    pub fn fully_resolved(&self) -> Result<(), AuthenticationError> {
        self.validate()?;
        let authz = self
            .authorization
            .as_ref()
            .ok_or(AuthenticationError::SecurityContextNotResolved)?;
        // Unscoped with no roles is valid. Scoped with no roles OR empty roles list is
        // not.
        if !matches!(authz.scope, ScopeInfo::Unscoped)
            && authz.roles.as_ref().is_none_or(|r| r.is_empty())
        {
            return Err(AuthenticationError::SecurityContextNotResolved);
        }
        Ok(())
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
        let mut ctx = builder.build()?;
        if value.authorization.is_some() {
            ctx.authorization = value.authorization;
        }
        Ok(ctx)
    }
}

impl TryFrom<Vec<AuthenticationResult>> for SecurityContext {
    type Error = AuthenticationError;
    /// Construct a [`SecurityContext`] from multiple [`AuthenticationResult`]'s
    /// (e.g., MFA).
    ///
    /// The first result provides the principal and primary authentication
    /// context. All subsequent results must share the same principal;
    /// otherwise [`AuthenticationError::AuthPrincipalMismatch`] is returned.
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
            if let Some(authorization) = auth.authorization.clone() {
                builder.authorization(authorization);
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
                return Err(AuthenticationError::AuthnPrincipalMismatch);
            }
            if let AuthenticationContext::Token(token) = &auth.context {
                ctx.audit_ids.extend(token.audit_ids.clone());
            };
            ctx.auth_methods.extend(auth.context.methods());
            if ctx.authorization.is_none() && auth.authorization.is_some() {
                ctx.authorization = auth.authorization;
            }
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
    #[validate(length(min = 1))]
    pub id: String,

    /// Metadata about the workload environment.
    /// This allows OPA/Keystone to verify specific attributes like
    /// 'repository'.
    #[builder(default)]
    pub attributes: HashMap<String, String>,

    /// The source of the identity (e.g., "https://token.actions.githubusercontent.com").
    #[validate(length(min = 1))]
    pub issuer: String,
}

/// Authentication context.
///
/// # Security Note
///
/// Role information in AuthenticationContext represent original information of
/// the resource (application_credential, trust, etc), and **not** the effective
/// roles.
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

    /// Authorization information extracted from the authentication token.
    ///
    /// Populated when the parent token carries scope and role information
    /// that should be propagated to the new security context. Other
    /// authentication methods _(e.g., SPIFFE, K8s)_ may also produce
    /// authorization context here.
    #[builder(default)]
    pub authorization: Option<AuthzInfo>,

    /// Token restriction rules tied to the authentication.
    #[builder(default)]
    pub token_restriction: Option<TokenRestriction>,
}

/// Authorization information.
#[derive(Builder, Clone, Debug, PartialEq, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct AuthzInfo {
    /// Effective roles on the authorization scope.
    #[builder(default)]
    #[validate(required)]
    pub roles: Option<Vec<RoleRef>>,

    /// Scope information.
    pub scope: ScopeInfo,
}

impl AuthzInfo {
    pub fn roles<I, V>(&mut self, iter: I) -> &mut Self
    where
        I: Iterator<Item = V>,
        V: Into<RoleRef>,
    {
        self.roles
            .get_or_insert_with(Vec::new)
            .extend(iter.map(Into::into));
        self
    }

    pub fn try_set_roles<I, V>(&mut self, iter: I) -> Result<(), AuthenticationError>
    where
        I: IntoIterator<Item = V>,
        V: TryInto<RoleRef>,
    {
        for assignment in iter {
            match assignment.try_into() {
                Ok(role) => {
                    self.roles.get_or_insert_with(Vec::new).push(role);
                }
                Err(_) => {
                    return Err(AuthenticationError::RoleConversionFailed)?;
                }
            }
        }
        Ok(())
    }
}

/// Authorization information.
#[derive(Clone, Debug, PartialEq)]
pub enum ScopeInfo {
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

impl ScopeInfo {
    /// Validate the authorization information:
    ///
    /// - Unscoped: always valid
    /// - Project: check if the project is enabled
    /// - Domain: check if the domain is enabled
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        match self {
            ScopeInfo::Domain(domain) => {
                if !domain.enabled {
                    return Err(AuthenticationError::DomainDisabled(domain.id.clone()));
                }
            }
            ScopeInfo::Project(project) => {
                if !project.enabled {
                    return Err(AuthenticationError::ProjectDisabled(project.id.clone()));
                }
            }
            ScopeInfo::System(_) => {}
            ScopeInfo::Trust(_) => {}
            ScopeInfo::Unscoped => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::application_credential::ApplicationCredentialBuilder;
    use crate::assignment::{AssignmentBuilder, AssignmentType};
    use crate::identity::UserOptions;
    use crate::role::RoleRefBuilder;
    use crate::token::TokenRestrictionBuilder;
    use crate::trust::*;

    // --- Fixture builders ---

    fn make_user(uid: &str, enabled: bool) -> UserResponse {
        UserResponse {
            id: uid.to_string(),
            enabled,
            default_project_id: None,
            domain_id: "did".into(),
            extra: HashMap::new(),
            name: "foo".into(),
            options: UserOptions::default(),
            federated: None,
            password_expires_at: None,
        }
    }

    fn make_enabled_user(uid: &str) -> UserIdentityInfo {
        UserIdentityInfoBuilder::default()
            .user_id(uid)
            .user(make_user(uid, true))
            .build()
            .unwrap()
    }

    fn make_disabled_user(uid: &str) -> UserIdentityInfo {
        UserIdentityInfoBuilder::default()
            .user_id(uid)
            .user(make_user(uid, false))
            .build()
            .unwrap()
    }

    fn make_principal(uid: &str) -> PrincipalInfo {
        PrincipalInfo {
            domain_id: Some("did".into()),
            identity: IdentityInfo::User(make_enabled_user(uid)),
        }
    }

    fn make_project() -> Project {
        Project {
            id: "pid".into(),
            domain_id: "did".into(),
            enabled: true,
            name: "proj".into(),
            description: Some("desc".into()),
            is_domain: false,
            parent_id: None,
            extra: HashMap::new(),
            ..Default::default()
        }
    }

    fn make_disabled_project() -> Project {
        Project {
            id: "pid".into(),
            domain_id: "did".into(),
            enabled: false,
            name: "proj".into(),
            ..Default::default()
        }
    }

    fn make_project2() -> Project {
        Project {
            id: "pid2".into(),
            domain_id: "did".into(),
            enabled: true,
            name: "proj2".into(),
            ..Default::default()
        }
    }

    fn make_domain() -> Domain {
        Domain {
            id: "did".into(),
            name: "default".into(),
            enabled: true,
            description: None,
            extra: HashMap::new(),
        }
    }

    fn make_disabled_domain() -> Domain {
        Domain {
            id: "did".into(),
            name: "default".into(),
            enabled: false,
            description: None,
            extra: HashMap::new(),
        }
    }

    fn make_trust_with_project(pid: &str) -> Trust {
        TrustBuilder::default()
            .id("trust_id")
            .trustor_user_id("trustor")
            .trustee_user_id("trustee")
            .project_id(pid)
            .impersonation(false)
            .build()
            .unwrap()
    }

    fn make_token_restriction(pid: &str) -> TokenRestriction {
        TokenRestrictionBuilder::default()
            .allow_rescope(true)
            .allow_renew(true)
            .id("tr_id")
            .domain_id("did")
            .role_ids(vec![])
            .project_id(pid)
            .build()
            .unwrap()
    }

    fn admin_role() -> RoleRef {
        RoleRefBuilder::default()
            .id("admin")
            .name("admin")
            .build()
            .unwrap()
    }

    /// Pre-built scopes used by every scope-boundaries test.
    struct AllScopes {
        project: ScopeInfo,
        project2: ScopeInfo,
        domain: ScopeInfo,
        trust: ScopeInfo,
        system: ScopeInfo,
        unscoped: ScopeInfo,
    }

    impl AllScopes {
        fn new() -> Self {
            // Trust scope without project (generic trust)
            let trust = TrustBuilder::default()
                .id("trust_id")
                .trustor_user_id("trustor")
                .trustee_user_id("trustee")
                .impersonation(false)
                .build()
                .unwrap();
            Self {
                project: ScopeInfo::Project(make_project()),
                project2: ScopeInfo::Project(make_project2()),
                domain: ScopeInfo::Domain(make_domain().clone()),
                trust: ScopeInfo::Trust(trust),
                system: ScopeInfo::System("all".into()),
                unscoped: ScopeInfo::Unscoped,
            }
        }
    }

    // --- Test helpers for AuthenticationResult + SecurityContext ---

    fn make_password_context(principal: PrincipalInfo) -> SecurityContext {
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(principal)
            .build()
            .unwrap();
        SecurityContext::try_from(auth).unwrap()
    }

    fn make_auth_ctx_with_scope(
        ctx: AuthenticationContext,
        principal: PrincipalInfo,
    ) -> SecurityContext {
        let auth = AuthenticationResultBuilder::default()
            .context(ctx)
            .principal(principal)
            .build()
            .unwrap();
        SecurityContext::try_from(auth).unwrap()
    }

    fn make_auth_ctx_with_tr(
        ctx: AuthenticationContext,
        principal: PrincipalInfo,
        tr: TokenRestriction,
    ) -> SecurityContext {
        let auth = AuthenticationResultBuilder::default()
            .context(ctx)
            .principal(principal)
            .token_restriction(tr)
            .build()
            .unwrap();
        SecurityContext::try_from(auth).unwrap()
    }

    fn make_auth_result_unscoped(
        principal: PrincipalInfo,
        roles: Option<Vec<RoleRef>>,
    ) -> SecurityContext {
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(principal)
            .authorization(AuthzInfo {
                scope: ScopeInfo::Unscoped,
                roles,
            })
            .build()
            .unwrap();
        SecurityContext::try_from(auth).unwrap()
    }

    fn make_auth_result_project(
        principal: PrincipalInfo,
        project: Project,
        roles: Option<Vec<RoleRef>>,
    ) -> SecurityContext {
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(principal)
            .authorization(AuthzInfo {
                scope: ScopeInfo::Project(project),
                roles,
            })
            .build()
            .unwrap();
        SecurityContext::try_from(auth).unwrap()
    }

    fn make_auth_result_system(
        principal: PrincipalInfo,
        roles: Option<Vec<RoleRef>>,
    ) -> SecurityContext {
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(principal)
            .authorization(AuthzInfo {
                scope: ScopeInfo::System("all".into()),
                roles,
            })
            .build()
            .unwrap();
        SecurityContext::try_from(auth).unwrap()
    }

    fn make_auth_result_domain(
        principal: PrincipalInfo,
        roles: Option<Vec<RoleRef>>,
    ) -> SecurityContext {
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(principal)
            .authorization(AuthzInfo {
                scope: ScopeInfo::Domain(make_domain()),
                roles,
            })
            .build()
            .unwrap();
        SecurityContext::try_from(auth).unwrap()
    }

    fn make_trust(trustee_uid: &str) -> Trust {
        TrustBuilder::default()
            .id("trust_id")
            .trustor_user_id("trustor")
            .trustee_user_id(trustee_uid)
            .impersonation(false)
            .build()
            .unwrap()
    }

    fn make_trust_no_project() -> Trust {
        TrustBuilder::default()
            .id("trust_id")
            .trustor_user_id("trustor")
            .trustee_user_id("trustee")
            .impersonation(false)
            .build()
            .unwrap()
    }

    fn make_trust_with_roles(roles: Option<Vec<RoleRef>>) -> SecurityContext {
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_principal("uid"))
            .authorization(AuthzInfo {
                scope: ScopeInfo::Trust(make_trust_no_project()),
                roles,
            })
            .build()
            .unwrap();
        SecurityContext::try_from(auth).unwrap()
    }

    fn make_app_cred(user_id: &str) -> ApplicationCredential {
        ApplicationCredentialBuilder::default()
            .id("app_cred_id")
            .name("app_cred_name")
            .project_id("pid")
            .roles(vec![])
            .unrestricted(false)
            .user_id(user_id)
            .build()
            .unwrap()
    }

    fn make_token_ctx(principal: PrincipalInfo) -> SecurityContext {
        let token = TokenContext {
            audit_ids: vec!["parent1".to_string(), "parent2".to_string()],
            methods: vec!["password".to_string()],
            expires_at: Utc::now(),
        };
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Token(token))
            .principal(principal)
            .build()
            .unwrap();
        SecurityContext::try_from(auth).unwrap()
    }

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
        let authn = make_disabled_user("uid");
        if let Err(AuthenticationError::UserDisabled(uid_err)) = authn.validate() {
            assert_eq!("uid", uid_err);
        } else {
            panic!("should fail for disabled user");
        }
    }

    #[test]
    fn test_authn_validate_user_mismatch() {
        let authn = UserIdentityInfoBuilder::default()
            .user_id("uid1")
            .user(make_user("uid2", false))
            .build()
            .unwrap();
        if let Err(AuthenticationError::Unauthorized) = authn.validate() {
        } else {
            panic!("should fail when user_id != user.id");
        }
    }

    #[test]
    fn test_authz_validate_project() {
        assert!(ScopeInfo::Project(make_project()).validate().is_ok());
    }

    #[test]
    fn test_authz_validate_project_disabled() {
        if let Err(AuthenticationError::ProjectDisabled(..)) =
            ScopeInfo::Project(make_disabled_project()).validate()
        {
        } else {
            panic!("should fail when project is not enabled");
        }
    }

    #[test]
    fn test_authz_validate_domain() {
        assert!(ScopeInfo::Domain(make_domain()).validate().is_ok());
    }

    #[test]
    fn test_authz_validate_domain_disabled() {
        if let Err(AuthenticationError::DomainDisabled(..)) =
            ScopeInfo::Domain(make_disabled_domain()).validate()
        {
        } else {
            panic!("should fail when domain is not enabled");
        }
    }

    #[test]
    fn test_authz_validate_system() {
        let authz = ScopeInfo::System("system".into());
        assert!(authz.validate().is_ok());
    }

    #[test]
    fn test_authz_validate_unscoped() {
        let authz = ScopeInfo::Unscoped;
        assert!(authz.validate().is_ok());
    }

    #[test]
    fn test_validate_scope_boundaries_with_token_restriction() {
        let s = AllScopes::new();
        let ctx = make_auth_ctx_with_tr(
            AuthenticationContext::Password,
            make_principal("uid"),
            make_token_restriction("pid"),
        );
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.domain),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.project2),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.trust),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.system),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.unscoped),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
    }

    #[test]
    fn test_validate_scope_boundaries_app_cred() {
        let s = AllScopes::new();
        let ctx = make_auth_ctx_with_scope(
            AuthenticationContext::ApplicationCredential(
                ApplicationCredentialBuilder::default()
                    .id("app_cred_id")
                    .name("app_cred_name")
                    .project_id("pid")
                    .roles(vec![])
                    .unrestricted(false)
                    .user_id("uid")
                    .build()
                    .unwrap(),
            ),
            make_principal("uid"),
        );
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.domain),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.project2),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.trust),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.system),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.unscoped),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
    }

    #[test]
    fn test_validate_scope_boundaries_oidc() {
        let s = AllScopes::new();
        let ctx = make_auth_ctx_with_scope(
            AuthenticationContext::Oidc(
                OidcContextBuilder::default()
                    .idp_id("idp")
                    .protocol_id("protocol")
                    .build()
                    .unwrap(),
            ),
            make_principal("uid"),
        );
        assert!(ctx.validate_scope_boundaries(&s.domain).is_ok());
        assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
        assert!(ctx.validate_scope_boundaries(&s.project2).is_ok());
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.trust),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.system),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(ctx.validate_scope_boundaries(&s.unscoped).is_ok());
    }

    #[test]
    fn test_validate_scope_boundarires_k8s() {
        let s = AllScopes::new();
        let tr = make_token_restriction("pid");
        let ctx = make_auth_ctx_with_tr(
            AuthenticationContext::K8s(
                K8sContextBuilder::default()
                    .token_restriction_id(tr.id.clone())
                    .build()
                    .unwrap(),
            ),
            make_principal("uid"),
            tr,
        );
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.domain),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.project2),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.trust),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.system),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.unscoped),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
    }

    #[test]
    fn test_validate_scope_boundaries_password() {
        let s = AllScopes::new();
        let ctx = make_password_context(make_principal("uid"));
        assert!(ctx.validate_scope_boundaries(&s.domain).is_ok());
        assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
        assert!(ctx.validate_scope_boundaries(&s.project2).is_ok());
        assert!(ctx.validate_scope_boundaries(&s.trust).is_ok());
        assert!(ctx.validate_scope_boundaries(&s.system).is_ok());
        assert!(ctx.validate_scope_boundaries(&s.unscoped).is_ok());
    }

    #[test]
    fn test_validate_scope_boundarires_trust() {
        let p = make_project();
        let p2 = make_project2();
        let d = make_domain();
        let trust = make_trust_with_project(&p.id);
        let trust_scope = ScopeInfo::Trust(trust.clone());
        let system = ScopeInfo::System("all".into());
        let unscoped = ScopeInfo::Unscoped;
        let ctx =
            make_auth_ctx_with_scope(AuthenticationContext::Trust(trust), make_principal("uid"));
        assert!(matches!(
            ctx.validate_scope_boundaries(&ScopeInfo::Domain(d)),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(
            ctx.validate_scope_boundaries(&ScopeInfo::Project(p))
                .is_ok()
        );
        assert!(matches!(
            ctx.validate_scope_boundaries(&ScopeInfo::Project(p2)),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
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
        let s = AllScopes::new();
        let ctx = make_auth_ctx_with_scope(AuthenticationContext::WebauthN, make_principal("uid"));
        assert!(ctx.validate_scope_boundaries(&s.domain).is_ok());
        assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
        assert!(ctx.validate_scope_boundaries(&s.project2).is_ok());
        assert!(matches!(
            ctx.validate_scope_boundaries(&s.trust),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(ctx.validate_scope_boundaries(&s.system).is_ok());
        assert!(ctx.validate_scope_boundaries(&s.unscoped).is_ok());
    }

    #[test]
    fn test_fully_resolved_none_authorization() {
        let ctx = make_password_context(make_principal("uid"));
        assert!(matches!(
            ctx.fully_resolved(),
            Err(AuthenticationError::SecurityContextNotResolved)
        ));
    }

    #[test]
    fn test_fully_resolved_unscoped_none_roles() {
        let ctx = make_auth_result_unscoped(make_principal("uid"), None);
        assert!(ctx.fully_resolved().is_ok());
    }

    #[test]
    fn test_fully_resolved_unscoped_empty_roles() {
        let ctx = make_auth_result_unscoped(make_principal("uid"), Some(vec![]));
        assert!(ctx.fully_resolved().is_ok());
    }

    #[test]
    fn test_fully_resolved_scoped_none_roles() {
        let ctx = make_auth_result_project(make_principal("uid"), make_project(), None);
        assert!(matches!(
            ctx.fully_resolved(),
            Err(AuthenticationError::SecurityContextNotResolved)
        ));
    }

    #[test]
    fn test_fully_resolved_scoped_empty_roles() {
        let ctx = make_auth_result_project(make_principal("uid"), make_project(), Some(vec![]));
        assert!(matches!(
            ctx.fully_resolved(),
            Err(AuthenticationError::SecurityContextNotResolved)
        ));
    }

    #[test]
    fn test_fully_resolved_scoped_with_roles() {
        let ctx = make_auth_result_project(
            make_principal("uid"),
            make_project(),
            Some(vec![admin_role()]),
        );
        assert!(ctx.fully_resolved().is_ok());
    }

    #[test]
    fn test_fully_resolved_system_with_roles() {
        let ctx = make_auth_result_system(make_principal("uid"), Some(vec![admin_role()]));
        assert!(ctx.fully_resolved().is_ok());
    }

    #[test]
    fn test_fully_resolved_system_none_roles() {
        let ctx = make_auth_result_system(make_principal("uid"), None);
        assert!(matches!(
            ctx.fully_resolved(),
            Err(AuthenticationError::SecurityContextNotResolved)
        ));
    }

    #[test]
    fn test_fully_resolved_domain_with_roles() {
        let ctx = make_auth_result_domain(make_principal("uid"), Some(vec![admin_role()]));
        assert!(ctx.fully_resolved().is_ok());
    }

    #[test]
    fn test_fully_resolved_domain_none_roles() {
        let ctx = make_auth_result_domain(make_principal("uid"), None);
        assert!(matches!(
            ctx.fully_resolved(),
            Err(AuthenticationError::SecurityContextNotResolved)
        ));
    }

    #[test]
    fn test_try_from_auth_to_security_context() {
        let ctx = make_auth_result_project(
            make_principal("uid"),
            make_project(),
            Some(vec![admin_role()]),
        );
        assert!(matches!(
            ctx.authentication_context,
            AuthenticationContext::Password
        ));
        assert!(matches!(ctx.principal.identity, IdentityInfo::User(_)));
        assert!(matches!(
            ctx.authorization,
            Some(AuthzInfo {
                scope: ScopeInfo::Project(_),
                ..
            })
        ));
    }

    #[test]
    fn test_try_from_auth_unscoped_to_security_context() {
        let ctx = make_auth_result_unscoped(make_principal("uid"), None);
        assert!(matches!(
            ctx.authorization,
            Some(AuthzInfo {
                scope: ScopeInfo::Unscoped,
                ..
            })
        ));
    }

    #[test]
    fn test_validate_scope_boundaries_system() {
        let s = AllScopes::new();
        let ctx = make_auth_result_system(make_principal("uid"), Some(vec![admin_role()]));
        // Password auth can request any scope
        assert!(ctx.validate_scope_boundaries(&s.project).is_ok());
        assert!(ctx.validate_scope_boundaries(&s.domain).is_ok());
        assert!(ctx.validate_scope_boundaries(&s.system).is_ok());
        assert!(ctx.validate_scope_boundaries(&s.unscoped).is_ok());
    }

    #[test]
    fn test_identity_validate_user() {
        let user = IdentityInfo::User(make_enabled_user("uid"));
        assert!(user.validate().is_ok());
    }

    #[test]
    fn test_identity_validate_user_disabled() {
        let user = IdentityInfo::User(make_disabled_user("uid"));
        assert!(matches!(
            user.validate(),
            Err(AuthenticationError::UserDisabled(_))
        ));
    }

    #[test]
    fn test_identity_validate_principal() {
        let principal = IdentityInfo::Principal(
            PrincipalIdentityInfoBuilder::default()
                .id("p1")
                .issuer("https://my.spiffe.id")
                .build()
                .unwrap(),
        );
        assert!(principal.validate().is_ok());
    }

    #[test]
    fn test_authz_validation_disabled_project() {
        let scope = ScopeInfo::Project(make_disabled_project());
        assert!(matches!(
            scope.validate(),
            Err(AuthenticationError::ProjectDisabled(id)) if id == "pid"
        ));
    }

    #[test]
    fn test_authz_validation_disabled_domain() {
        let scope = ScopeInfo::Domain(make_disabled_domain());
        assert!(matches!(
            scope.validate(),
            Err(AuthenticationError::DomainDisabled(id)) if id == "did"
        ));
    }

    // --- MFA: TryFrom<Vec<AuthenticationResult>> ---

    #[test]
    fn test_mfa_principal_mismatch() {
        let auth1 = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_principal("uid1"))
            .build()
            .unwrap();
        let auth2 = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_principal("uid2"))
            .build()
            .unwrap();
        assert!(matches!(
            SecurityContext::try_from(vec![auth1, auth2]),
            Err(AuthenticationError::AuthnPrincipalMismatch)
        ));
    }

    #[test]
    fn test_mfa_authz_propagated_from_second() {
        let auth1 = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_principal("uid"))
            .build()
            .unwrap();
        let auth2 = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_principal("uid"))
            .authorization(AuthzInfo {
                scope: ScopeInfo::Unscoped,
                roles: Some(vec![admin_role()]),
            })
            .build()
            .unwrap();
        let ctx = SecurityContext::try_from(vec![auth1, auth2]).unwrap();
        assert!(matches!(
            ctx.authorization,
            Some(AuthzInfo {
                scope: ScopeInfo::Unscoped,
                ..
            })
        ));
        assert!(ctx.authorization.as_ref().unwrap().roles.is_some());
    }

    #[test]
    fn test_mfa_token_audit_ids_extended() {
        let token1 = TokenContext {
            audit_ids: vec!["parent1".to_string()],
            methods: vec!["token".to_string()],
            expires_at: Utc::now(),
        };
        let auth1 = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Token(token1))
            .principal(make_principal("uid"))
            .build()
            .unwrap();
        let token2 = TokenContext {
            audit_ids: vec!["parent2".to_string(), "parent3".to_string()],
            methods: vec!["token".to_string()],
            expires_at: Utc::now(),
        };
        let auth2 = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Token(token2))
            .principal(make_principal("uid"))
            .authorization(AuthzInfo {
                scope: ScopeInfo::Unscoped,
                roles: None,
            })
            .build()
            .unwrap();
        let ctx = SecurityContext::try_from(vec![auth1, auth2]).unwrap();
        assert!(ctx.audit_ids.iter().any(|s| s == "parent1"));
        assert!(ctx.audit_ids.iter().any(|s| s == "parent2"));
        assert!(ctx.audit_ids.iter().any(|s| s == "parent3"));
    }

    #[test]
    fn test_mfa_auth_methods_aggregated() {
        let auth1 = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_principal("uid"))
            .build()
            .unwrap();
        let oidc = OidcContextBuilder::default()
            .idp_id("idp")
            .protocol_id("protocol")
            .build()
            .unwrap();
        let auth2 = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Oidc(oidc))
            .principal(make_principal("uid"))
            .build()
            .unwrap();
        let ctx = SecurityContext::try_from(vec![auth1, auth2]).unwrap();
        assert!(ctx.auth_methods.contains("password"));
        assert!(ctx.auth_methods.contains("openid"));
    }

    // --- SecurityContext::validate() principal mismatch arms ---

    #[test]
    fn test_validate_appcred_principal_mismatch() {
        let appcred = make_app_cred("other_user");
        let ctx = make_auth_ctx_with_scope(
            AuthenticationContext::ApplicationCredential(appcred),
            make_principal("uid"),
        );
        assert!(matches!(
            ctx.validate(),
            Err(AuthenticationError::AuthzPrincipalMismatch)
        ));
    }

    #[test]
    fn test_validate_appcred_principal_match() {
        let appcred = make_app_cred("uid");
        let ctx = make_auth_ctx_with_scope(
            AuthenticationContext::ApplicationCredential(appcred),
            make_principal("uid"),
        );
        assert!(ctx.validate().is_ok());
    }

    #[test]
    fn test_validate_trust_principal_mismatch() {
        let trust = make_trust("other_user");
        let ctx =
            make_auth_ctx_with_scope(AuthenticationContext::Trust(trust), make_principal("uid"));
        assert!(matches!(
            ctx.validate(),
            Err(AuthenticationError::AuthzPrincipalMismatch)
        ));
    }

    #[test]
    fn test_validate_trust_principal_match() {
        let trust = make_trust("uid");
        let ctx =
            make_auth_ctx_with_scope(AuthenticationContext::Trust(trust), make_principal("uid"));
        assert!(ctx.validate().is_ok());
    }

    // --- AuthzInfo::try_set_roles failure path ---

    #[test]
    fn test_try_set_roles_success() {
        let mut authz = AuthzInfo {
            scope: ScopeInfo::Project(make_project()),
            roles: None,
        };
        let assignment = AssignmentBuilder::default()
            .actor_id("uid")
            .role_id("admin")
            .role_name("admin")
            .target_id("pid")
            .r#type(AssignmentType::UserProject)
            .inherited(false)
            .build()
            .unwrap();
        assert!(authz.try_set_roles(vec![assignment]).is_ok());
        assert_eq!(authz.roles.as_ref().unwrap().len(), 1);
        assert_eq!(authz.roles.as_ref().unwrap()[0].id, "admin");
    }

    #[test]
    fn test_try_set_roles_mixed_success_failure() {
        let mut authz = AuthzInfo {
            scope: ScopeInfo::Project(make_project()),
            roles: None,
        };
        let good = AssignmentBuilder::default()
            .actor_id("uid")
            .role_id("admin")
            .target_id("pid")
            .r#type(AssignmentType::UserProject)
            .inherited(false)
            .build()
            .unwrap();
        let bad = AssignmentBuilder::default()
            .actor_id("uid")
            .role_id("")
            .target_id("pid")
            .r#type(AssignmentType::UserProject)
            .inherited(false)
            .build()
            .unwrap();
        assert!(authz.try_set_roles(vec![good, bad]).is_err());
    }

    // --- HV-08: PrincipalIdentityInfo empty id/issuer ---

    #[test]
    fn test_principal_empty_id_fails_validate() {
        let principal = PrincipalIdentityInfoBuilder::default()
            .id("")
            .issuer("https://my.spiffe.id")
            .build()
            .unwrap();
        assert!(principal.validate().is_err());
    }

    #[test]
    fn test_principal_empty_issuer_fails_validate() {
        let principal = PrincipalIdentityInfoBuilder::default()
            .id("p1")
            .issuer("")
            .build()
            .unwrap();
        assert!(principal.validate().is_err());
    }

    // --- Trust scope in fully_resolved() ---

    #[test]
    fn test_fully_resolved_trust_with_roles() {
        let ctx = make_trust_with_roles(Some(vec![admin_role()]));
        assert!(ctx.fully_resolved().is_ok());
    }

    #[test]
    fn test_fully_resolved_trust_none_roles() {
        let ctx = make_trust_with_roles(None);
        assert!(matches!(
            ctx.fully_resolved(),
            Err(AuthenticationError::SecurityContextNotResolved)
        ));
    }

    #[test]
    fn test_fully_resolved_trust_empty_roles() {
        let ctx = make_trust_with_roles(Some(vec![]));
        assert!(matches!(
            ctx.fully_resolved(),
            Err(AuthenticationError::SecurityContextNotResolved)
        ));
    }

    // --- TokenContext audit_ids propagation ---

    #[test]
    fn test_token_ctx_audit_ids_propagated() {
        let ctx = make_token_ctx(make_principal("uid"));
        assert!(ctx.audit_ids.len() >= 3);
        assert!(ctx.audit_ids.iter().any(|s| s == "parent1"));
        assert!(ctx.audit_ids.iter().any(|s| s == "parent2"));
    }

    #[test]
    fn test_token_ctx_methods_include_token() {
        let ctx = make_token_ctx(make_principal("uid"));
        assert!(ctx.auth_methods.contains("password"));
        assert!(ctx.auth_methods.contains("token"));
    }

    // --- Trust scope validate() ---

    #[test]
    fn test_authz_validate_trust() {
        let trust = make_trust_no_project();
        assert!(ScopeInfo::Trust(trust).validate().is_ok());
    }
}
