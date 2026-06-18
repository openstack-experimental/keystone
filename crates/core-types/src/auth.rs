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
//! Authentication-specific validation may stay in the corresponding provider
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

use openstack_keystone_config::Interface;

use crate::application_credential::ApplicationCredential;
use crate::assignment::AssignmentProviderError;
use crate::error::BuilderError;
use crate::identity::{Group, UserResponse};
use crate::resource::{Domain, Project};
use crate::role::RoleRef;
use crate::token::{FernetToken, TokenRestriction};
use crate::trust::Trust;

/// Namespace UUID for the virtual ID generation based on the UUIDv5
const NAMESPACE_UUID: Uuid = uuid!("96f0e3b8-0d21-41bc-bd0d-457da94345f9");

#[derive(Error, Debug)]
pub enum AuthenticationError {
    /// Actor has no roles on the target scope.
    #[error("actor has no roles on scope")]
    ActorHasNoRolesOnTarget,

    /// Application Credential has expired.
    #[error("application credential has expired")]
    AuthApplicationCredentialExpired,

    /// Token has expired.
    #[error("token has expired")]
    AuthTokenExpired,

    /// Varying principal used in multiple authentication methods.
    #[error("the principal differs between authentication results")]
    AuthnPrincipalMismatch,

    /// AuthenticationContext is bound to the user not matching the
    /// SecurityContext principal.
    #[error("authorization context bind is not owned by a context principal")]
    AuthzPrincipalMismatch,

    /// Domain is disabled.
    #[error("The domain is disabled.")]
    DomainDisabled(String),

    /// Authorization is forbidden.
    #[error("this action is forbidden")]
    Forbidden,

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

    /// Token missing in the context.
    #[error("validated security context is missing token")]
    TokenNotInContext,

    /// Token renewal is forbidden.
    #[error("Token renewal (getting token from token) is prohibited.")]
    TokenRenewalForbidden,

    /// Trusts can only be consumed by regular users.
    #[error("use of trusts by not a regular user is not supported")]
    TrustorPrincipalUseNotSupported,

    /// The trustor domain is disabled.
    #[error("trustor domain disabled")]
    TrustorDomainDisabled,

    /// The trustor user is disabled.
    #[error("trustor user disabled")]
    TrustorUserDisabled(String),

    /// Unauthorized.
    #[error("The request you have made requires authentication.")]
    Unauthorized,

    /// User is disabled.
    #[error("The account is disabled for user: {0}")]
    UserDisabled(String),

    /// The user domain is disabled.
    #[error("user domain disabled")]
    UserDomainDisabled,

    /// User is locked due to the multiple failed attempts.
    #[error("The account is temporarily disabled for user: {0}")]
    UserLocked(String),

    /// User name password combination is wrong.
    #[error("wrong username or password")]
    UserNameOrPasswordWrong,

    /// User password is expired.
    #[error("The password is expired for user: {0}")]
    UserPasswordExpired(String),

    /// A role assignment failed to convert to a valid RoleRef.
    #[error("role assignment cannot be converted to a role reference")]
    RoleConversionFailed,

    /// A provider error that occurred during authentication validation.
    ///
    /// The `context` field provides a descriptive label for debugging,
    /// indicating which operation failed (e.g., `"get_user_domain"`,
    /// `"list_project_roles"`).
    #[error("provider error: {source}")]
    Provider {
        /// Source error.
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
        /// Context hint for debugging.
        context: Option<String>,
    },

    /// A validation error from the validator crate.
    #[error("validation error: {0}")]
    Validation(#[from] validator::ValidationError),
}

impl From<AssignmentProviderError> for AuthenticationError {
    fn from(e: AssignmentProviderError) -> Self {
        AuthenticationError::Provider {
            source: Box::new(e),
            context: None,
        }
    }
}

/// Security Context of the operation.
///
/// Authentication and information bound to the operation.
#[derive(Builder, Clone, Debug, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(private, setter(into, strip_option))]
pub struct SecurityContext {
    /// Audit IDs.
    #[builder(default)]
    audit_ids: Vec<String>,

    /// Authentication context (how the authentication was performed).
    // TODO: It may be a Vec<AuthenticationContext> in the case of MFA
    authentication_context: AuthenticationContext,

    /// Authentication methods used to establish the context.
    #[builder(default)]
    auth_methods: HashSet<String>,

    /// Authorization scope of the context. During the authentication request
    /// this information becomes available at the later phase.
    #[builder(default)]
    authorization: Option<AuthzInfo>,

    /// Authentication expiration.
    #[builder(default)]
    expires_at: Option<DateTime<Utc>>,

    /// Interface the connection was established on.
    #[builder(default = "Interface::Public")]
    interface: Interface,

    /// Whether context is established for the admin.
    #[builder(default)]
    is_admin: bool,

    /// Identity information.
    principal: PrincipalInfo,

    /// Token restriction.
    #[builder(default)]
    token_restriction: Option<TokenRestriction>,

    /// Original token used for authentication.
    #[builder(default)]
    token: Option<FernetToken>,
}

/// Builder for constructing [`SecurityContext`] in test code.
///
/// Provides named setters for the fields that are private on the real
/// struct, so test fixtures are self-documenting and compile-only under
/// `#[cfg(any(test, feature = "mock"))]`.
#[cfg(any(test, feature = "mock"))]
#[derive(Default)]
pub struct SecurityContextTestingBuilder {
    authentication_context: Option<AuthenticationContext>,
    principal: Option<PrincipalInfo>,
    token: Option<FernetToken>,
    authorization: Option<AuthzInfo>,
    expires_at: Option<DateTime<Utc>>,
    token_restriction: Option<TokenRestriction>,
}

#[cfg(any(test, feature = "mock"))]
impl SecurityContextTestingBuilder {
    #[must_use]
    pub fn authentication_context(mut self, ctx: AuthenticationContext) -> Self {
        self.authentication_context = Some(ctx);
        self
    }

    #[must_use]
    pub fn principal(mut self, principal: PrincipalInfo) -> Self {
        self.principal = Some(principal);
        self
    }

    #[must_use]
    pub fn token(mut self, token: FernetToken) -> Self {
        self.token = Some(token);
        self
    }

    #[must_use]
    pub fn authorization(mut self, authz: AuthzInfo) -> Self {
        self.authorization = Some(authz);
        self
    }

    #[must_use]
    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    #[must_use]
    pub fn token_restriction(mut self, tr: TokenRestriction) -> Self {
        self.token_restriction = Some(tr);
        self
    }

    pub fn build(self) -> SecurityContext {
        let authentication_context = self
            .authentication_context
            .expect("SecurityContextTestingBuilder: authentication_context is required");
        SecurityContext {
            audit_ids: vec![],
            authentication_context: authentication_context.clone(),
            auth_methods: authentication_context.methods(),
            principal: self
                .principal
                .expect("SecurityContextTestingBuilder: principal is required"),
            authorization: self.authorization,
            expires_at: self.expires_at,
            is_admin: false,
            interface: Interface::Public,
            token_restriction: self.token_restriction,
            token: self.token,
        }
    }
}

impl SecurityContext {
    /// Returns the audit IDs associated with this security context.
    ///
    /// The returned slice always contains at least one element — the fresh
    /// audit ID generated when the context was constructed. When the context
    /// was authenticated by a parent token, the parent's audit IDs are carried
    /// forward.
    #[must_use]
    pub fn audit_ids(&self) -> &[String] {
        &self.audit_ids
    }

    /// Appends audit IDs from an additional [`AuthenticationResult`].
    ///
    /// Used internally during multi-auth result aggregation to push the
    /// new result's own audit ID and any parent token audit IDs.
    fn extend_audit_ids_from_auth_result(&mut self, auth: &AuthenticationResult) {
        self.audit_ids.push(auth.audit_id.clone());
        if let AuthenticationContext::Token(token) = &auth.context {
            self.audit_ids.extend(token.audit_ids().clone());
        }
    }

    /// Returns the authentication context that produced this security context.
    ///
    /// The authentication context describes *how* the principal was verified
    /// — e.g., password, token, trust, OIDC federation, or application
    /// credential  .  The returned [`AuthenticationContext`] variant determines
    /// which scope transitions are permitted.
    #[must_use]
    pub fn authentication_context(&self) -> &AuthenticationContext {
        &self.authentication_context
    }

    /// Returns the authentication methods used to establish this context.
    ///
    /// Each entry is a method name string such as `"password"`,
    /// `"token"`, `"oidc"`, or `"webauthn"`.  When multiple authentication
    /// methods were chained (MFA), the set contains all of them.
    #[must_use]
    pub fn auth_methods(&self) -> &HashSet<String> {
        &self.auth_methods
    }

    /// Extends the authentication methods set from an additional context.
    fn extend_auth_methods<I>(&mut self, methods: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.auth_methods.extend(methods);
    }

    /// Returns the identity of the authenticated principal.
    ///
    /// The principal carries the user ID, domain ID, and identity type
    /// (`UserIdentityInfo` for traditional users, `PrincipalIdentityInfo` for
    /// workload identities such as SPIFFE or Kubernetes service accounts).
    #[must_use]
    pub fn principal(&self) -> &PrincipalInfo {
        &self.principal
    }

    /// Populates the user's domain on the principal's identity.
    ///
    /// This is a write-once operation: if `user_domain` is already `Some`, the
    /// call is a no-op.  The domain is fetched from the resource provider
    /// and written here before `validate()` runs, because domain enabled-ness
    /// is a validation requirement.
    ///
    /// # Arguments
    ///
    /// * `domain` - The [`Domain`] object resolved from the database for the
    ///   user's domain ID.
    pub fn populate_user_domain(&mut self, domain: crate::resource::Domain) {
        if let IdentityInfo::User(ref mut user_info) = self.principal.identity
            && user_info.user_domain.is_none()
        {
            user_info.user_domain = Some(domain);
        }
    }

    /// Returns the `FernetToken` for this context, if one was set.
    ///
    /// For password-authenticated contexts the token is not populated until
    /// the token service creates it.  For token-authenticated contexts it is
    /// set during construction.
    #[must_use]
    pub fn token(&self) -> Option<&FernetToken> {
        self.token.as_ref()
    }

    /// Sets the `FernetToken` on this context.
    ///
    /// Populates the `token` field that was absent during initial
    /// `SecurityContext` construction (e.g., for password-authenticated
    /// sessions).  Once set, the token can be queried via
    /// [`SecurityContext::token`].
    ///
    /// # Arguments
    ///
    /// * `token` - The freshly minted [`FernetToken`] for the session.
    pub fn set_token(&mut self, token: FernetToken) {
        self.token = Some(token);
    }

    /// Returns the authorization information, if a scope and roles have been
    /// bound.
    ///
    /// For unscoped authentication the authorization may still be present with
    /// `scope` set to [`ScopeInfo::Unscoped`] and `roles` set to `None`.
    /// For scoped tokens, `roles` carries the effective role assignments
    /// resolved from the assignment backend.
    #[must_use]
    pub fn authorization(&self) -> Option<&AuthzInfo> {
        self.authorization.as_ref()
    }

    /// Sets the effective roles on the authorization scope.
    ///
    /// Overwrites any existing role list with the newly resolved assignments.
    /// If no authorization scope is bound on this context, the call is a no-op.
    ///
    /// # Arguments
    ///
    /// * `roles` - The complete list of effective [`RoleRef`]s resolved from
    ///   the assignment backend for the principal on the bound scope.
    pub fn set_effective_roles(&mut self, roles: Vec<crate::role::RoleRef>) {
        if let Some(authz) = self.authorization.as_mut() {
            authz.set_roles(roles);
        }
    }

    /// Sets the authorization information with scope and pre-populated roles.
    ///
    /// Replaces whatever authorization was previously bound, including the
    /// scope.  This is intended for test fixtures where roles are known ahead
    /// of time; production paths use
    /// [`SecurityContext::set_authorization_scope`] (which validates
    /// boundaries) followed by `set_effective_roles`.
    ///
    /// # Arguments
    ///
    /// * `authz` - An [`AuthzInfo`] containing the target scope and
    ///   (optionally) resolved roles.
    pub fn set_authorization(&mut self, authz: AuthzInfo) {
        self.authorization = Some(authz);
    }

    /// Returns the authentication expiration time, if set.
    ///
    /// A token or credential is expired when `expires_at < Utc::now()`.
    #[must_use]
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    /// Returns information whether the user is considered an admin.
    ///
    /// # Returns
    ///
    /// A boolean set to true when the authenticated Principal is an admin.
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }

    /// Set the context to represent the administrative user.
    pub fn set_is_admin(&mut self) {
        self.is_admin = true;
    }

    /// Updates the expiration datetime, respecting the policy that the latest
    /// expiry wins.  Used during multi-auth result aggregation.
    ///
    /// # Arguments
    ///
    /// * `expires` - The candidate expiration datetime from an auth result. If
    ///   the context has no expiry yet, or this value expires later than or at
    ///   the same time as the current expiry, the context is updated.
    fn update_expires_at(&mut self, expires: DateTime<Utc>) {
        if self
            .expires_at
            .is_none_or(|global_expires| expires >= global_expires)
        {
            self.expires_at = Some(expires);
        }
    }

    /// Returns the token restriction, if one was applied during authentication.
    ///
    /// A token restriction narrows the roles and/or project scope compared to
    /// the parent token.  When a restriction is present the context can only
    /// produce a restricted (sub-scoped) token.
    #[must_use]
    pub fn token_restriction(&self) -> Option<&TokenRestriction> {
        self.token_restriction.as_ref()
    }

    /// Sets the token restriction on this context.
    ///
    /// Attaches a [`TokenRestriction`] that was resolved from the database.
    /// The restriction limits which scopes are reachable and may narrow the
    /// effective role set.
    ///
    /// # Arguments
    ///
    /// * `tr` - The [`TokenRestriction`] resolved for the requested restriction
    ///   ID.
    pub fn set_token_restriction(&mut self, tr: TokenRestriction) {
        self.token_restriction = Some(tr);
    }

    /// Construct a [`SecurityContext`] for testing and mocks via a builder.
    ///
    /// Bypasses builder constraints to set private fields (`token`,
    /// `authorization`, `expires_at`, `token_restriction`) that are
    /// normally populated by the validation pipeline.  The returned
    /// [`SecurityContextTestingBuilder`] has named setters for each field;
    /// `authentication_context` and `principal` are required.
    ///
    /// # Returns
    ///
    /// A [`SecurityContextTestingBuilder`] pre-populated with defaults.  Call
    /// `.build()` to obtain a fully constructed [`SecurityContext`].
    #[cfg(any(test, feature = "mock"))]
    #[must_use]
    pub fn test_build() -> SecurityContextTestingBuilder {
        SecurityContextTestingBuilder::default()
    }

    /// Validate the authentication information:
    ///
    /// - User attribute must be set and enabled
    /// - User object id must match user_id
    /// - When authenticated with AppCred, the principal must match the bound
    ///   user
    /// - When authenticated with Trust, the principal must match the trustee
    ///   user_id
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the context is valid.
    /// * `Err(AuthenticationError)` if validation fails.
    ///
    /// # Errors
    ///
    /// - [`AuthenticationError::AuthzPrincipalMismatch`] if the authentication
    ///   context is bound to a different user than the principal.
    #[must_use = "SecurityContext must be always validated"]
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        self.principal.validate()?;
        match &self.authentication_context {
            // Trust and ApplicationCredential are bounded objects that carry their own
            // user_id. If it differs from the principal's user_id, the context is
            // misconstructed or malicious. Other authentication methods derive the
            // principal directly at authentication time and do not have a separate
            // bounded object restriction, so no check is needed.
            AuthenticationContext::ApplicationCredential {
                application_credential,
                ..
            } if application_credential.user_id != self.principal.get_user_id() => {
                return Err(AuthenticationError::AuthzPrincipalMismatch);
            }
            AuthenticationContext::Trust { trust, .. }
                if trust.trustee_user_id != self.principal.get_user_id() =>
            {
                return Err(AuthenticationError::AuthzPrincipalMismatch);
            }
            _ => {}
        }
        Ok(())
    }

    /// Returns `true` if the session has expired.
    ///
    /// A session is expired when `expires_at < Utc::now()`.  When no expiry
    /// was set, the session is considered valid.
    ///
    /// # Returns
    ///
    /// * `true` if the session has expired.
    /// * `false` if the session is still valid or has no expiry.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|expiry| expiry < Utc::now())
    }

    /// SECURITY GATE: Validate whether the scope is accessible with the current
    /// [`SecurityContext`].
    ///
    /// Perform validation whether it is possible to grant authorization for the
    /// scope based on the authentication or whether it violates the bounds
    /// of the current authentication. No check for whether the principal has
    /// any roles on the target scope.
    ///
    /// # Arguments
    ///
    /// * `scope` - The target [`ScopeInfo`] to validate against this context's
    ///   authentication method and token restrictions.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the scope transition is permitted.
    /// * `Err(AuthenticationError::ScopeNotAllowed)` if the authentication
    ///   method or token restriction prohibits the scope.
    ///
    /// # Security Notes
    ///
    /// No validations of whether the principal has any roles on the target
    /// scope are performed. This is an AuthN/AuthZ context boundaries check.
    #[must_use = "A new scope must always be checked against authentication constraints"]
    pub fn validate_scope_boundaries(&self, scope: &ScopeInfo) -> Result<(), AuthenticationError> {
        match scope {
            ScopeInfo::Domain(_domain) => {
                if self.token_restriction.is_some() {
                    return Err(AuthenticationError::ScopeNotAllowed);
                };
                match &self.authentication_context {
                    AuthenticationContext::ApplicationCredential { .. } => {
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::Oidc { .. } => Ok(()),
                    AuthenticationContext::K8s(_) => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::Password => Ok(()),
                    AuthenticationContext::Admin => Ok(()),
                    AuthenticationContext::Token(_) => Ok(()),
                    AuthenticationContext::Trust { .. } => {
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::WebauthN => Ok(()),
                    AuthenticationContext::Mapping(_) => Ok(()),
                }
            }
            ScopeInfo::Project { project, .. } => {
                if let Some(token_restriction) = &self.token_restriction
                    && let Some(tr_pid) = &token_restriction.project_id
                    && *tr_pid != project.id
                {
                    return Err(AuthenticationError::ScopeNotAllowed);
                }
                match &self.authentication_context {
                    AuthenticationContext::ApplicationCredential {
                        application_credential,
                        ..
                    } => {
                        if application_credential.project_id != project.id {
                            Err(AuthenticationError::ScopeNotAllowed)
                        } else {
                            Ok(())
                        }
                    }
                    AuthenticationContext::Oidc { .. } => Ok(()),
                    AuthenticationContext::K8s(_) => Ok(()),
                    AuthenticationContext::Password => Ok(()),
                    AuthenticationContext::Admin => Ok(()),
                    AuthenticationContext::Token(_) => Ok(()),
                    AuthenticationContext::Trust { .. } => {
                        // Trust authentication must use TrustProject scope. Rescoping to a plain
                        // Project scope would bypass the trust's role and project constraints.
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::WebauthN => Ok(()),
                    AuthenticationContext::Mapping(_) => Ok(()),
                }
            }
            ScopeInfo::TrustProject(_) => {
                if self.token_restriction.is_some() {
                    return Err(AuthenticationError::ScopeNotAllowed);
                };
                match &self.authentication_context {
                    AuthenticationContext::ApplicationCredential { .. } => {
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::Oidc { .. } => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::K8s(_) => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::Password => Ok(()),
                    AuthenticationContext::Admin => Ok(()),
                    AuthenticationContext::Token(_) => Ok(()),
                    AuthenticationContext::Trust { .. } => Err(AuthenticationError::Forbidden),
                    AuthenticationContext::WebauthN => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::Mapping(_) => Err(AuthenticationError::ScopeNotAllowed),
                }
            }
            ScopeInfo::System(_system) => {
                if self.token_restriction.is_some() {
                    return Err(AuthenticationError::ScopeNotAllowed);
                };
                match &self.authentication_context {
                    AuthenticationContext::ApplicationCredential { .. } => {
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::Oidc { .. } => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::K8s(_) => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::Password => Ok(()),
                    AuthenticationContext::Admin => Ok(()),
                    AuthenticationContext::Token(_) => Ok(()),
                    AuthenticationContext::Trust { .. } => {
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::WebauthN => Ok(()),
                    AuthenticationContext::Mapping(_) => Ok(()),
                }
            }
            ScopeInfo::Unscoped => {
                if self.token_restriction.is_some() {
                    return Err(AuthenticationError::ScopeNotAllowed);
                };
                match &self.authentication_context {
                    AuthenticationContext::ApplicationCredential { .. } => {
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::Oidc { .. } => Ok(()),
                    AuthenticationContext::K8s(_) => Err(AuthenticationError::ScopeNotAllowed),
                    AuthenticationContext::Password => Ok(()),
                    AuthenticationContext::Admin => Ok(()),
                    AuthenticationContext::Token(_) => Ok(()),
                    AuthenticationContext::Trust { .. } => {
                        Err(AuthenticationError::ScopeNotAllowed)
                    }
                    AuthenticationContext::WebauthN => Ok(()),
                    AuthenticationContext::Mapping(_) => Ok(()),
                }
            }
        }
    }

    /// Set the authorization scope, validating that it is permissible for this
    /// context.
    ///
    /// This enforces [`SecurityContext::validate_scope_boundaries`] before
    /// allowing the scope to be assigned, guaranteeing the invariant that a
    /// [`SecurityContext`]'s authorization is always consistent with its
    /// authentication context.  The resulting `AuthzInfo` has `roles: None`;
    /// roles are populated later by
    /// [`SecurityContext::set_effective_roles`].
    ///
    /// # Arguments
    ///
    /// * `scope` - The target [`ScopeInfo`] (domain, project, system, trust, or
    ///   unscoped) to bind on this context.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the scope boundaries check passed and the authorization
    ///   was set.
    /// * `Err(AuthenticationError::ScopeNotAllowed)` if the authentication
    ///   method or token restriction prohibits the scope.
    #[must_use = "discarding the result ignores scope assignment errors"]
    pub fn set_authorization_scope(&mut self, scope: ScopeInfo) -> Result<(), AuthenticationError> {
        self.validate_scope_boundaries(&scope)?;
        let authorization = AuthzInfo {
            roles: None,
            scope: scope.clone(),
        };
        self.authorization = Some(authorization);
        Ok(())
    }

    /// Verifies that all required fields are populated before policy
    /// enforcement.
    ///
    /// This is the final gate that prevents an incomplete context from reaching
    /// an endpoint handler.  It performs two checks:
    ///
    /// 1. Calls [`SecurityContext::validate`] to verify principal integrity.
    /// 2. Ensures that if `authorization` is scoped (project, domain, system,
    ///    trust), `roles` is non-empty.  Unscoped authorization with `roles:
    ///    None` is considered valid.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the context is fully resolved.
    /// * `Err(AuthenticationError::SecurityContextNotResolved)` if
    ///   authorization is absent, or if a scoped authorization has no roles.
    #[must_use = "discarding the result allows incomplete contexts to pass through"]
    pub fn fully_resolved(&self) -> Result<(), AuthenticationError> {
        self.validate()?;
        let _authz = self
            .authorization
            .as_ref()
            .ok_or(AuthenticationError::SecurityContextNotResolved)?;

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

        let mut audit_ids = vec![value.audit_id];
        if let AuthenticationContext::Token(token) = &value.context {
            audit_ids.extend(token.audit_ids().clone());
        }
        if let Some(expires) = &value.expires_at {
            builder.expires_at(*expires);
        }
        builder.audit_ids(audit_ids);
        if let Some(token_restriction) = value.token_restriction {
            builder.token_restriction(token_restriction);
        }
        builder.auth_methods(value.context.methods());
        let mut ctx = builder.build()?;
        if let Some(authz) = value.authorization {
            ctx.set_authorization(authz);
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
        let mut audit_ids: Vec<String> = vec![];
        let mut auth_results = value.into_iter();

        if let Some(auth) = auth_results.next() {
            builder.principal(auth.principal.clone());
            builder.authentication_context(auth.context.clone());
            audit_ids.push(auth.audit_id.clone());
            if let Some(expires) = &auth.expires_at {
                builder.expires_at(*expires);
            }
            // TODO: process properly the token restrictions
            if let Some(token_restriction) = auth.token_restriction {
                builder.token_restriction(token_restriction);
            }
            if let Some(authorization) = auth.authorization.clone() {
                builder.authorization(authorization);
            }
            if let AuthenticationContext::Token(token) = &auth.context {
                audit_ids.extend(token.audit_ids().clone());
            };
            builder.auth_methods(auth.context.methods());
        }
        builder.audit_ids(audit_ids);
        let mut ctx = builder.build()?;
        for auth in auth_results {
            if auth.principal != *ctx.principal() {
                return Err(AuthenticationError::AuthnPrincipalMismatch);
            }
            ctx.extend_audit_ids_from_auth_result(&auth);

            if let Some(expires) = &auth.expires_at {
                ctx.update_expires_at(*expires);
            }
            ctx.extend_auth_methods(auth.context.methods());
            if ctx.authorization().is_none()
                && let Some(authz) = &auth.authorization
            {
                ctx.set_authorization(authz.clone());
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
    /// Principal identity.
    pub identity: IdentityInfo,
}

impl PrincipalInfo {
    /// Returns the domain ID of the principal.
    ///
    /// Extracted from the underlying identity variant:
    /// - For `User` identity: returns the user's domain ID.
    /// - For workload `Principal` identity: returns the principal's domain ID
    ///   if the domain has been resolved.
    #[must_use]
    pub fn domain_id(&self) -> Option<String> {
        match &self.identity {
            IdentityInfo::User(user) => {
                if let Some(domain) = &user.user_domain {
                    Some(domain.id.clone())
                } else {
                    user.user
                        .as_ref()
                        .map(|user_resp| user_resp.domain_id.clone())
                }
            }
            IdentityInfo::Principal(principal) => {
                principal.domain.as_ref().map(|domain| domain.id.clone())
            }
        }
    }

    /// Validates the principal's identity data.
    ///
    /// Checks the domain ID length constraint, then delegates to
    /// [`IdentityInfo::validate`] to verify the underlying identity variant
    /// is well-formed (user enabled, domain enabled, etc.).
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the principal is valid.
    /// * `Err(AuthenticationError)` if the identity data is missing,
    ///   mismatched, or disabled.
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        self.identity.validate()
    }

    /// Returns the user identifier for the principal.
    ///
    /// For a traditional user the result is the raw `user_id`.  For a workload
    /// principal (SPIFFE, K8s, etc.) the result is a deterministic UUIDv5
    /// derived from the principal's ID.
    ///
    /// # Returns
    ///
    /// A `String` suitable for use in assignment queries and policy evaluation.
    #[must_use]
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
    /// Validates the identity data against business rules.
    ///
    /// For a user identity this verifies that the resolved user matches the
    /// `user_id`, is enabled, and the user domain is enabled.  For a workload
    /// principal it verifies that the domain is resolved and enabled.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the identity is valid.
    /// * `Err(AuthenticationError::Unauthorized)` if the resolved data is
    ///   missing, mismatched, or the user/domain is disabled.
    /// * `Err(AuthenticationError::DomainDisabled)` if the principal's domain
    ///   is disabled.
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        match &self {
            Self::User(user) => user.validate(),
            Self::Principal(principal) => {
                principal.validate()?;
                if let Some(domain) = &principal.domain
                    && !domain.enabled
                {
                    return Err(AuthenticationError::DomainDisabled(domain.id.clone()));
                }
                Ok(())
            }
        }
    }
}

/// Traditional Keystone User.
#[derive(Builder, Clone, Debug, PartialEq)]
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
    pub user_id: String,
}

impl UserIdentityInfo {
    /// Validates the user identity data against business rules.
    ///
    /// Checks:
    /// 1. The resolved [`UserResponse`] must be present and its `id` must match
    ///    the `user_id` attribute.
    /// 2. The user must be enabled.
    /// 3. The user domain must be present and enabled.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if all checks pass.
    /// * `Err(AuthenticationError::Unauthorized)` if the user data is missing,
    ///   the domain data is missing, or the IDs don't match.
    /// * `Err(AuthenticationError::UserDisabled)` if the user is disabled.
    /// * `Err(AuthenticationError::UserDomainDisabled)` if the user domain is
    ///   disabled.
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        // TODO: all validations (disabled user, locked, etc) should be placed here
        // since every authentication method goes different way and we risk
        // missing validations
        if self.user_id.is_empty() || self.user_id.len() > 64 {
            return Err(validator::ValidationError::new(
                "user id must be >1 and <64 characters long",
            )
            .into());
        }
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
        if let Some(user_domain) = &self.user_domain {
            if !user_domain.enabled {
                return Err(AuthenticationError::UserDomainDisabled);
            }
        } else {
            warn!(
                "User domain data must be resolved in the AuthenticatedInfo before validating: {:?}",
                self
            );
            return Err(AuthenticationError::Unauthorized);
        }

        Ok(())
    }
}

/// Workload principal.
#[derive(Builder, Clone, Debug, PartialEq)]
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

    /// Domain the principal belongs to.
    #[builder(default)]
    pub domain: Option<crate::resource::Domain>,

    /// Human-readable name resolved by the mapping engine (e.g., mapping rule's
    /// user_name). Set when authentication goes through a mapping-based provider
    /// (mapping, k8s_auth, etc.) and the matched rule specifies a user identity.
    #[builder(default)]
    pub resolved_user_name: Option<String>,
}

impl PrincipalIdentityInfo {
    /// Validates the workload principal identity data.
    ///
    /// Checks that the `id` and `issuer` fields are non-empty.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the identity is valid.
    /// * `Err(AuthenticationError::Unauthorized)` if `id` or `issuer` is empty.
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        if self.id.is_empty() {
            return Err(AuthenticationError::Unauthorized);
        }
        if self.issuer.is_empty() {
            return Err(AuthenticationError::Unauthorized);
        }
        Ok(())
    }
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
    ApplicationCredential {
        /// Application credential.
        application_credential: ApplicationCredential,
        /// Original token with the ApplicationCredential payload type.
        token: Option<FernetToken>,
    },
    /// Login using OIDC federation
    Oidc {
        oidc: OidcContext,
        /// Original token with the Federated payload type.
        token: Option<FernetToken>,
    },
    /// K8s Auth
    K8s(K8sContext),
    /// Login with password.
    Password,
    /// Admin SVID authenticated via admin interface.
    Admin,
    /// Login using regular fernet/jwt token.
    Token(FernetToken),
    /// Login consuming the trust.
    Trust {
        trust: Trust,
        /// Original token with the Trust payload type.
        token: Option<FernetToken>,
    },
    /// Login with WebauthN credentials.
    WebauthN,
    /// Login via the unified mapping engine (virtual user).
    Mapping(crate::mapping::MappingContext),
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
    /// Returns the authentication method names associated with this context.
    ///
    /// Each method name corresponds to a Keystone authentication mechanism
    /// (e.g., `"password"`, `"token"`, `"application_credential"`, `"openid"`,
    /// `"trust"`, `"webauthn"`, `"mapped"`).  When a token is used as the
    /// parent, the methods from the parent token are carried forward and
    /// `"token"` is added.
    ///
    /// # Returns
    ///
    /// A [`HashSet<String>`] of method name strings.
    #[must_use]
    pub fn methods(&self) -> HashSet<String> {
        match self {
            Self::ApplicationCredential { .. } => {
                once("application_credential".to_string()).collect()
            }
            Self::Oidc { .. } => once("openid".to_string()).collect(),
            Self::K8s(_) => once("mapped".to_string()).collect(),
            Self::Password => once("password".to_string()).collect(),
            Self::Admin => once("admin".to_string()).collect(),
            Self::Token(token) => token
                .methods()
                .iter()
                .cloned()
                .chain(once("token".to_string()))
                .collect(),
            Self::Trust { .. } => once("trust".to_string()).collect(),
            Self::WebauthN => once("x509".to_string()).collect(),
            Self::Mapping(_) => once("mapped".to_string()).collect(),
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

/// Result of the single method Authentication.
#[derive(Builder, Clone, Debug, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct AuthenticationResult {
    /// Audit IDs already associated with Authentication.
    #[builder(default = "new_audit_id()")]
    pub audit_id: String,

    /// The specific context for THIS factor (e.g., method name, audit IDs).
    pub context: AuthenticationContext,

    /// Authentication expiration.
    #[builder(default)]
    pub expires_at: Option<DateTime<Utc>>,

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

fn new_audit_id() -> String {
    URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes())
}

/// Authorization information.
#[derive(Builder, Clone, Debug, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(into, strip_option))]
pub struct AuthzInfo {
    /// Effective roles on the authorization scope.
    #[builder(default)]
    pub(crate) roles: Option<Vec<RoleRef>>,

    /// Scope information.
    pub scope: ScopeInfo,
}

impl AuthzInfo {
    /// Returns the effective roles resolved for this authorization scope.
    ///
    /// For a scoped context this is expected to be `Some` with a non-empty
    /// list after role resolution in
    /// `core::auth::ValidatedSecurityContext::new_for_scope`. An unscoped
    /// context may legitimately return `None`.
    ///
    /// # Returns
    ///
    /// * `Some(&[RoleRef])` with the resolved roles, if populated.
    /// * `None` if roles have not been resolved or the scope is unscoped.
    #[must_use]
    pub fn effective_roles(&self) -> Option<&[RoleRef]> {
        self.roles.as_deref()
    }

    /// Sets the effective roles, replacing any existing value.
    ///
    /// # Arguments
    ///
    /// * `roles` - The complete role list resolved from the assignment backend.
    pub fn set_roles(&mut self, roles: Vec<RoleRef>) {
        self.roles = Some(roles);
    }

    /// Appends roles to the authorization, converting each item via
    /// `Into<RoleRef>`.
    ///
    /// If `roles` is not yet set, a new vector is allocated first.  The method
    /// returns `&mut Self` to allow chaining with the builder pattern.
    ///
    /// # Arguments
    ///
    /// * `iter` - An iterator over items convertible into [`RoleRef`].
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

    /// Appends roles to the authorization, converting each item via
    /// `TryInto<RoleRef>`.
    ///
    /// If any item fails to convert, the original `roles` is preserved and an
    /// error is returned.
    ///
    /// # Arguments
    ///
    /// * `iter` - An iterator over items convertible into [`RoleRef`] via
    ///   fallible conversion.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if all items converted successfully and were appended.
    /// * `Err(AuthenticationError::RoleConversionFailed)` if any item could not
    ///   be converted.
    pub fn try_set_roles<I, V>(&mut self, iter: I) -> Result<(), AuthenticationError>
    where
        I: IntoIterator<Item = V>,
        V: TryInto<RoleRef>,
    {
        let roles: Vec<RoleRef> = iter
            .into_iter()
            .map(|assignment| {
                assignment
                    .try_into()
                    .map_err(|_| AuthenticationError::RoleConversionFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.roles.get_or_insert_with(Vec::new).extend(roles);
        Ok(())
    }
}

/// Trust-project scope information.
///
/// Stored behind a `Box` in [`ScopeInfo::TrustProject`] to avoid inflating
/// the enum size for the smaller variants (Domain, System, Unscoped).
#[derive(Clone, Debug)]
pub struct TrustProjectInfo {
    /// Trust information.
    pub trust: Trust,
    /// Project information for the trust scope.
    pub project: Project,
    /// Domain information for the trust scope.
    pub project_domain: Domain,
}

/// Authorization information.
#[derive(Clone, Debug)]
pub enum ScopeInfo {
    /// Domain scope.
    Domain(Domain),
    /// Project scope.
    Project {
        /// Project information.
        project: Project,
        /// Domain information for the project scope.
        project_domain: Domain,
    },
    /// System scope.
    System(String),
    /// Trust scope.
    TrustProject(Box<TrustProjectInfo>),
    /// Unscoped.
    Unscoped,
}

impl PartialEq for ScopeInfo {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Domain(a), Self::Domain(b)) => a.id == b.id && a.enabled == b.enabled,
            (
                Self::Project {
                    project: a,
                    project_domain: domain_a,
                },
                Self::Project {
                    project: b,
                    project_domain: domain_b,
                },
            ) => {
                a.id == b.id
                    && a.domain_id == b.domain_id
                    && a.enabled == b.enabled
                    && domain_a.enabled == domain_b.enabled
            }
            (Self::System(a), Self::System(b)) => a == b,
            (Self::TrustProject(a), Self::TrustProject(b)) => a.trust == b.trust,
            (Self::Unscoped, Self::Unscoped) => true,
            _ => false,
        }
    }
}

impl PartialEq for TrustProjectInfo {
    fn eq(&self, other: &Self) -> bool {
        self.trust.id == other.trust.id && self.project.id == other.project.id
    }
}

impl ScopeInfo {
    /// Validates that the scope-targeted resources exist and are enabled.
    ///
    /// - `Domain`: checks that `domain.enabled` is `true`.
    /// - `Project`: checks that `project.enabled` is `true` and that the
    ///   project's owning domain is enabled.
    /// - `System`: always valid (system scope cannot be disabled).
    /// - `TrustProject`: checks that the trust's project and project domain are
    ///   enabled.
    /// - `Unscoped`: always valid.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the scope is valid.
    /// * `Err(AuthenticationError::DomainDisabled)` if the target domain is
    ///   disabled.
    /// * `Err(AuthenticationError::ProjectDisabled)` if the target project is
    ///   disabled.
    pub fn validate(&self) -> Result<(), AuthenticationError> {
        match self {
            ScopeInfo::Domain(domain) => {
                if !domain.enabled {
                    return Err(AuthenticationError::DomainDisabled(domain.id.clone()));
                }
            }
            ScopeInfo::Project {
                project,
                project_domain,
            } => {
                if !project.enabled {
                    return Err(AuthenticationError::ProjectDisabled(project.id.clone()));
                }
                if !project_domain.enabled {
                    return Err(AuthenticationError::DomainDisabled(
                        project_domain.id.clone(),
                    ));
                }
            }
            ScopeInfo::System(_) => {}
            ScopeInfo::TrustProject(tpi) => {
                if !tpi.project.enabled {
                    return Err(AuthenticationError::ProjectDisabled(tpi.project.id.clone()));
                }
                if !tpi.project_domain.enabled {
                    return Err(AuthenticationError::DomainDisabled(
                        tpi.project_domain.id.clone(),
                    ));
                }
            }
            ScopeInfo::Unscoped => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::collections::HashMap;

    use crate::application_credential::ApplicationCredentialBuilder;
    use crate::assignment::{AssignmentBuilder, AssignmentType};
    use crate::identity::UserOptions;
    use crate::role::RoleRefBuilder;
    use crate::token::FernetToken;
    use crate::token::TokenRestrictionBuilder;
    use crate::token::payload::UnscopedPayloadBuilder;
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
            .user_domain(make_domain())
            .build()
            .unwrap()
    }

    fn make_disabled_user(uid: &str) -> UserIdentityInfo {
        UserIdentityInfoBuilder::default()
            .user_id(uid)
            .user(make_user(uid, false))
            .user_domain(make_domain())
            .build()
            .unwrap()
    }

    fn make_principal(uid: &str) -> PrincipalInfo {
        PrincipalInfo {
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
                project: ScopeInfo::Project {
                    project: make_project(),
                    project_domain: make_domain(),
                },
                project2: ScopeInfo::Project {
                    project: make_project2(),
                    project_domain: make_domain(),
                },
                domain: ScopeInfo::Domain(make_domain().clone()),
                trust: ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
                    trust: trust.clone(),
                    project: make_project(),
                    project_domain: make_domain(),
                })),
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
                scope: ScopeInfo::Project {
                    project,
                    project_domain: make_domain(),
                },
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
                scope: ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
                    trust: make_trust("uid"),
                    project: Project {
                        id: "project_id".into(),
                        domain_id: "domain_id".into(),
                        enabled: true,
                        name: "project_name".into(),
                        description: None,
                        is_domain: false,
                        parent_id: None,
                        extra: HashMap::new(),
                    },
                    project_domain: make_domain(),
                })),
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
        let payload = UnscopedPayloadBuilder::default()
            .user_id(principal.get_user_id())
            .audit_ids(vec!["parent1".to_string(), "parent2".to_string()].into_iter())
            .methods(vec!["password".to_string()].into_iter())
            .expires_at(Utc::now())
            .build()
            .unwrap();
        let token = FernetToken::Unscoped(payload);
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
        assert!(authn.validate().is_err());
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
        assert!(
            ScopeInfo::Project {
                project: make_project(),
                project_domain: make_domain(),
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn test_authz_validate_project_disabled() {
        if let Err(AuthenticationError::ProjectDisabled(..)) = (ScopeInfo::Project {
            project: make_disabled_project(),
            project_domain: make_domain(),
        })
        .validate()
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
            AuthenticationContext::ApplicationCredential {
                application_credential: ApplicationCredentialBuilder::default()
                    .id("app_cred_id")
                    .name("app_cred_name")
                    .project_id("pid")
                    .roles(vec![])
                    .unrestricted(false)
                    .user_id("uid")
                    .build()
                    .unwrap(),
                token: None,
            },
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
            AuthenticationContext::Oidc {
                oidc: OidcContextBuilder::default()
                    .idp_id("idp")
                    .protocol_id("protocol")
                    .build()
                    .unwrap(),
                token: None,
            },
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
        let trust_scope = ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
            trust: trust.clone(),
            project: p.clone(),
            project_domain: make_domain(),
        }));
        let system = ScopeInfo::System("all".into());
        let unscoped = ScopeInfo::Unscoped;
        let ctx = make_auth_ctx_with_scope(
            AuthenticationContext::Trust { trust, token: None },
            make_principal("uid"),
        );
        assert!(matches!(
            ctx.validate_scope_boundaries(&ScopeInfo::Domain(d)),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&ScopeInfo::Project {
                project: p,
                project_domain: make_domain(),
            }),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&ScopeInfo::Project {
                project: p2,
                project_domain: make_domain(),
            }),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(matches!(
            ctx.validate_scope_boundaries(&trust_scope),
            Err(AuthenticationError::Forbidden)
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
    fn test_fully_resolved_domain_with_roles() {
        let ctx = make_auth_result_domain(make_principal("uid"), Some(vec![admin_role()]));
        assert!(ctx.fully_resolved().is_ok());
    }

    #[test]
    fn test_try_from_auth_to_security_context() {
        let ctx = make_auth_result_project(
            make_principal("uid"),
            make_project(),
            Some(vec![admin_role()]),
        );
        assert!(matches!(
            ctx.authentication_context(),
            AuthenticationContext::Password
        ));
        assert!(matches!(ctx.principal().identity, IdentityInfo::User(_)));
        let authz_scope_match = if let Some(AuthzInfo { scope, .. }) = ctx.authorization()
            && let ScopeInfo::Project { project, .. } = scope
        {
            project.id == "pid"
        } else {
            false
        };
        assert!(authz_scope_match);
    }

    #[test]
    fn test_try_from_auth_unscoped_to_security_context() {
        let ctx = make_auth_result_unscoped(make_principal("uid"), None);
        assert!(matches!(
            ctx.authorization(),
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
        if let Err(AuthenticationError::UserDisabled(_)) = user.validate() {
        } else {
            panic!("should fail for disabled user");
        }
    }

    #[test]
    fn test_identity_validate_principal() {
        let principal = IdentityInfo::Principal(
            PrincipalIdentityInfoBuilder::default()
                .id("p1")
                .issuer("https://my.spiffe.id")
                .domain(make_domain())
                .build()
                .unwrap(),
        );
        assert!(principal.validate().is_ok());
    }

    #[test]
    fn test_identity_validate_principal_missing_domain() {
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
    fn test_identity_validate_principal_disabled_domain() {
        let principal = IdentityInfo::Principal(
            PrincipalIdentityInfoBuilder::default()
                .id("p1")
                .issuer("https://my.spiffe.id")
                .domain(make_disabled_domain())
                .build()
                .unwrap(),
        );
        assert!(matches!(
            principal.validate(),
            Err(AuthenticationError::DomainDisabled(_))
        ));
    }

    #[test]
    fn test_authz_validation_disabled_project() {
        let scope = ScopeInfo::Project {
            project: make_disabled_project(),
            project_domain: make_domain(),
        };
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
            ctx.authorization(),
            Some(AuthzInfo {
                scope: ScopeInfo::Unscoped,
                ..
            })
        ));
        assert!(ctx.authorization().unwrap().roles.is_some());
    }

    #[test]
    fn test_mfa_token_audit_ids_extended() {
        use crate::token::FernetToken;

        let payload1 = UnscopedPayloadBuilder::default()
            .user_id("uid")
            .audit_ids(vec!["parent1".to_string()].into_iter())
            .methods(vec!["token".to_string()].into_iter())
            .expires_at(Utc::now())
            .build()
            .unwrap();
        let token1 = FernetToken::Unscoped(payload1);
        let auth1 = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Token(token1))
            .principal(make_principal("uid"))
            .build()
            .unwrap();

        let payload2 = UnscopedPayloadBuilder::default()
            .user_id("uid")
            .audit_ids(vec!["parent2".to_string(), "parent3".to_string()].into_iter())
            .methods(vec!["token".to_string()].into_iter())
            .expires_at(Utc::now())
            .build()
            .unwrap();
        let token2 = FernetToken::Unscoped(payload2);
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
        assert!(ctx.audit_ids().iter().any(|s| s == "parent1"));
        assert!(ctx.audit_ids().iter().any(|s| s == "parent2"));
        assert!(ctx.audit_ids().iter().any(|s| s == "parent3"));
    }

    #[test]
    fn test_mfa_auth_methods_aggregated() {
        let auth1 = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_principal("uid"))
            .build()
            .unwrap();
        let _oidc = OidcContextBuilder::default()
            .idp_id("idp")
            .protocol_id("protocol")
            .build()
            .unwrap();
        let auth2 = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Oidc {
                oidc: OidcContextBuilder::default()
                    .idp_id("idp")
                    .protocol_id("protocol")
                    .build()
                    .unwrap(),
                token: None,
            })
            .principal(make_principal("uid"))
            .build()
            .unwrap();
        let ctx = SecurityContext::try_from(vec![auth1, auth2]).unwrap();
        assert!(ctx.auth_methods().contains("password"));
        assert!(ctx.auth_methods().contains("openid"));
    }

    #[test]
    fn test_mfa_expiry_latest_wins() {
        let base = Utc::now();
        let earlier = base + Duration::hours(1);
        let later = base + Duration::hours(2);
        let auth1 = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_principal("uid"))
            .expires_at(earlier)
            .build()
            .unwrap();
        let auth2 = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_principal("uid"))
            .expires_at(later)
            .build()
            .unwrap();
        let ctx = SecurityContext::try_from(vec![auth1, auth2]).unwrap();
        assert_eq!(ctx.expires_at, Some(later));
    }

    // --- SecurityContext::validate() principal mismatch arms ---

    #[test]
    fn test_validate_appcred_principal_mismatch() {
        let appcred = make_app_cred("other_user");
        let ctx = make_auth_ctx_with_scope(
            AuthenticationContext::ApplicationCredential {
                application_credential: appcred,
                token: None,
            },
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
            AuthenticationContext::ApplicationCredential {
                application_credential: appcred,
                token: None,
            },
            make_principal("uid"),
        );
        assert!(ctx.validate().is_ok());
    }

    #[test]
    fn test_validate_trust_principal_mismatch() {
        let trust = make_trust("other_user");
        let ctx = make_auth_ctx_with_scope(
            AuthenticationContext::Trust { trust, token: None },
            make_principal("uid"),
        );
        assert!(matches!(
            ctx.validate(),
            Err(AuthenticationError::AuthzPrincipalMismatch)
        ));
    }

    #[test]
    fn test_validate_trust_principal_match() {
        let trust = make_trust("uid");
        let ctx = make_auth_ctx_with_scope(
            AuthenticationContext::Trust { trust, token: None },
            make_principal("uid"),
        );
        assert!(ctx.validate().is_ok());
    }

    // --- AuthzInfo::try_set_roles failure path ---

    #[test]
    fn test_try_set_roles_success() {
        let mut authz = AuthzInfo {
            scope: ScopeInfo::Project {
                project: make_project(),
                project_domain: make_domain(),
            },
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

    // --- FernetToken audit_ids propagation ---

    #[test]
    fn test_token_ctx_audit_ids_propagated() {
        let ctx = make_token_ctx(make_principal("uid"));
        assert!(ctx.audit_ids().len() >= 3);
        assert!(ctx.audit_ids().iter().any(|s| s == "parent1"));
        assert!(ctx.audit_ids().iter().any(|s| s == "parent2"));
    }

    #[test]
    fn test_token_ctx_methods_include_token() {
        let ctx = make_token_ctx(make_principal("uid"));
        assert!(ctx.auth_methods().contains("password"));
        assert!(ctx.auth_methods().contains("token"));
    }

    // --- Trust scope ---

    #[test]
    fn test_trust_no_project_created() {
        let trust = make_trust_no_project();
        assert_eq!(trust.id, "trust_id");
        assert_eq!(trust.trustor_user_id, "trustor");
        assert_eq!(trust.trustee_user_id, "trustee");
    }

    // --- SecurityContext::is_expired() ---

    #[test]
    fn test_is_expired_expiry_propagated_from_result() {
        let expires = Utc::now() + Duration::hours(1);
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_principal("uid"))
            .expires_at(expires)
            .build()
            .unwrap();
        let ctx = SecurityContext::try_from(auth).unwrap();
        assert_eq!(ctx.expires_at, Some(expires));
        assert!(!ctx.is_expired());
    }

    #[test]
    fn test_is_expired_set_after_build() {
        let ctx = SecurityContext::try_from(
            AuthenticationResultBuilder::default()
                .context(AuthenticationContext::Password)
                .principal(make_principal("uid"))
                .build()
                .unwrap(),
        )
        .unwrap();
        let mut ctx = ctx;
        ctx.expires_at = Some(Utc::now() - Duration::hours(1));
        assert!(ctx.is_expired());
    }

    #[test]
    fn test_is_expired_no_expiry() {
        let ctx = make_password_context(make_principal("uid"));
        assert_eq!(ctx.expires_at, None);
        assert!(!ctx.is_expired());
    }

    // --- SecurityContext::set_authorization_scope() ---

    #[test]
    fn test_set_authorization_scope_success() {
        let mut ctx = make_password_context(make_principal("uid"));
        let scope = ScopeInfo::Project {
            project: make_project(),
            project_domain: make_domain(),
        };
        assert!(ctx.set_authorization_scope(scope.clone()).is_ok());
        assert!(matches!(
            ctx.authorization(),
            Some(AuthzInfo {
                scope: ScopeInfo::Project { .. },
                ..
            })
        ));
        assert!(ctx.authorization().unwrap().roles.is_none());
    }

    #[test]
    fn test_set_authorization_scope_fails_restricted_token() {
        let mut ctx = make_auth_ctx_with_tr(
            AuthenticationContext::Password,
            make_principal("uid"),
            make_token_restriction("pid"),
        );
        let scope = ScopeInfo::Domain(make_domain());
        assert!(matches!(
            ctx.set_authorization_scope(scope),
            Err(AuthenticationError::ScopeNotAllowed)
        ));
        assert!(ctx.authorization().is_none());
    }

    // --- AuthenticationContext::methods() ---

    #[test]
    fn test_methods_application_credential() {
        let m = AuthenticationContext::ApplicationCredential {
            application_credential: make_app_cred("uid"),
            token: None,
        }
        .methods();
        assert_eq!(
            m,
            HashSet::from_iter(vec!["application_credential".to_string()])
        );
    }

    #[test]
    fn test_methods_oidc() {
        let oidc = OidcContextBuilder::default()
            .idp_id("idp")
            .protocol_id("protocol")
            .build()
            .unwrap();
        let m = AuthenticationContext::Oidc { oidc, token: None }.methods();
        assert_eq!(m, HashSet::from_iter(vec!["openid".to_string()]));
    }

    #[test]
    fn test_methods_k8s() {
        let k8s = K8sContextBuilder::default()
            .token_restriction_id("tr")
            .build()
            .unwrap();
        let m = AuthenticationContext::K8s(k8s).methods();
        assert_eq!(m, HashSet::from_iter(vec!["mapped".to_string()]));
    }

    #[test]
    fn test_methods_password() {
        let m = AuthenticationContext::Password.methods();
        assert_eq!(m, HashSet::from_iter(vec!["password".to_string()]));
    }

    #[test]
    fn test_methods_trust() {
        let trust = make_trust_no_project();
        let m = AuthenticationContext::Trust { trust, token: None }.methods();
        assert_eq!(m, HashSet::from_iter(vec!["trust".to_string()]));
    }

    #[test]
    fn test_methods_webauthn() {
        let m = AuthenticationContext::WebauthN.methods();
        assert_eq!(m, HashSet::from_iter(vec!["x509".to_string()]));
    }

    #[test]
    fn test_methods_token_chain() {
        let payload = UnscopedPayloadBuilder::default()
            .user_id("uid")
            .audit_ids(vec!["parent".to_string()].into_iter())
            .methods(vec!["password".to_string()].into_iter())
            .expires_at(Utc::now())
            .build()
            .unwrap();
        let token = FernetToken::Unscoped(payload);
        let m = AuthenticationContext::Token(token).methods();
        assert!(m.contains("password"));
        assert!(m.contains("token"));
    }

    // --- PrincipalInfo::get_user_id() Principal variant (UUIDv5) ---

    #[test]
    fn test_get_user_id_regular_user() {
        let principal = make_principal("uid");
        assert_eq!(principal.get_user_id(), "uid");
    }

    #[test]
    fn test_get_user_id_principal_uuid_v5() {
        let identity = IdentityInfo::Principal(
            PrincipalIdentityInfoBuilder::default()
                .id("spiffe://trust_domain/ns/sa")
                .issuer("https://my.spiffe.id")
                .build()
                .unwrap(),
        );
        let principal = PrincipalInfo { identity };
        let uid = principal.get_user_id();
        let expected = Uuid::new_v5(&NAMESPACE_UUID, b"spiffe://trust_domain/ns/sa")
            .simple()
            .to_string();
        assert_eq!(uid, expected);
    }

    // --- AuthzInfo::roles() ---

    #[test]
    fn test_authz_roles_empty() {
        let mut authz = AuthzInfo {
            scope: ScopeInfo::Unscoped,
            roles: None,
        };
        authz.roles(std::iter::empty::<RoleRef>());
        assert!(authz.roles.is_some());
        assert!(authz.roles.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_authz_roles_multiple() {
        let mut authz = AuthzInfo {
            scope: ScopeInfo::Unscoped,
            roles: None,
        };
        let r1 = RoleRefBuilder::default()
            .id("r1")
            .name("reader")
            .build()
            .unwrap();
        let r2 = RoleRefBuilder::default()
            .id("r2")
            .name("writer")
            .build()
            .unwrap();
        authz.roles(vec![r1, r2].into_iter());
        assert_eq!(authz.roles.as_ref().unwrap().len(), 2);
    }

    // --- ScopeInfo::validate() for TrustProject ---

    #[test]
    fn test_authz_validate_trust_project() {
        let scope = ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
            trust: make_trust_no_project(),
            project: make_project(),
            project_domain: make_domain(),
        }));
        assert!(scope.validate().is_ok());
    }

    #[test]
    fn test_authz_validate_trust_project_disabled_project() {
        let scope = ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
            trust: make_trust_no_project(),
            project: make_disabled_project(),
            project_domain: make_domain(),
        }));
        assert!(matches!(
            scope.validate(),
            Err(AuthenticationError::ProjectDisabled(_))
        ));
    }

    #[test]
    fn test_authz_validate_trust_project_disabled_domain() {
        let scope = ScopeInfo::TrustProject(Box::new(TrustProjectInfo {
            trust: make_trust_no_project(),
            project: make_project(),
            project_domain: make_disabled_domain(),
        }));
        assert!(matches!(
            scope.validate(),
            Err(AuthenticationError::DomainDisabled(_))
        ));
    }

    // --- TryFrom<AuthenticationResult> single conversion ---

    #[test]
    fn test_try_from_single_auth_result_audit_id() {
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(make_principal("uid"))
            .build()
            .unwrap();
        let ctx = SecurityContext::try_from(auth).unwrap();
        assert_eq!(ctx.audit_ids().len(), 1);
        assert!(ctx.auth_methods().contains("password"));
        assert!(matches!(
            ctx.authentication_context(),
            AuthenticationContext::Password
        ));
    }

    #[test]
    fn test_try_from_single_auth_result_token_audit_ids() {
        let payload = UnscopedPayloadBuilder::default()
            .user_id("uid")
            .audit_ids(vec!["parent1".to_string(), "parent2".to_string()].into_iter())
            .methods(vec!["password".to_string()].into_iter())
            .expires_at(Utc::now())
            .build()
            .unwrap();
        let token = FernetToken::Unscoped(payload);
        let auth = AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Token(token))
            .principal(make_principal("uid"))
            .build()
            .unwrap();
        let ctx = SecurityContext::try_from(auth).unwrap();
        let has_audit = ctx.audit_ids().iter().any(|s| s == "parent1");
        assert!(has_audit);
        let has_auth = ctx.audit_ids().iter().any(|s| s == "parent2");
        assert!(has_auth);
    }
}
