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
use std::borrow::Cow;
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

    /// A dynamic auth plugin token was minted before the currently
    /// configured `valid_since` cutoff for that plugin (ADR 0025 §4).
    #[error("dynamic plugin `{0}` was updated since this token was issued")]
    PluginVersionMismatch(String),

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

    /// An API Key's Unified Mapping Engine (ADR 0020) evaluation resolved
    /// zero authorizations. Per ADR 0021 Invariant 1, this MUST fail
    /// authentication rather than produce an unscoped, role-less context
    /// that would push the access decision onto downstream OPA coverage.
    #[error("API key resolved no authorizations")]
    NoAuthorizationsFound,

    /// An API Key's mapping resolved to more than one authorization entry.
    /// Per ADR 0021 Invariant 2, an Ephemeral Security Context must operate
    /// under exactly one scope.
    #[error("API key resolved multiple authorizations; only a single scope is permitted")]
    MultipleScopesForbidden,

    /// An API Key's mapping resolved to `Authorization::System`. Per ADR
    /// 0021 Invariant 3, system scope is prohibited at API-Key ingress; the
    /// write-time prohibition (ADR 0021 §6.C) is defense-in-depth, not a
    /// substitute for this runtime check.
    #[error("system scope is forbidden for API-Key ingress")]
    SystemScopeForbiddenForApiKey,

    /// An API Key's mapping resolved to an authorization other than
    /// `Authorization::Domain`. API Keys are domain-owned machine identities
    /// (ADR 0021 §2), so only a domain-scoped authorization is accepted at
    /// ingress; the write-time prohibition (ADR 0021 §6.C) is
    /// defense-in-depth, not a substitute for this runtime check.
    #[error("only domain scope is accepted for API-Key ingress")]
    NonDomainScopeForbiddenForApiKey,

    /// A role assignment failed to convert to a valid RoleRef.
    #[error("role assignment cannot be converted to a role reference")]
    RoleConversionFailed,

    /// `POST /v3/ec2tokens`: no EC2 credential matches the supplied access
    /// key (ADR 0019 §5).
    #[error("EC2 access key not found")]
    Ec2AccessKeyNotFound,

    /// `POST /v3/ec2tokens`: the `credentials` object did not carry a
    /// `signature` to compare against.
    #[error("EC2 signature not supplied")]
    Ec2SignatureMissing,

    /// `POST /v3/ec2tokens`: the supplied signature did not match the
    /// server-generated one (including the boto port-stripping retry).
    #[error("invalid EC2 signature")]
    Ec2SignatureInvalid,

    /// `POST /v3/ec2tokens`: `SignatureVersion` was not one of `0`/`1`/`2`,
    /// and the request could not be recognised as a v4 (SigV4) request via
    /// the `Authorization` header or `X-Amz-Algorithm` param.
    #[error("unknown EC2 signature version")]
    Ec2UnknownSignatureVersion,

    /// `POST /v3/ec2tokens`: the replay-prevention timestamp was absent from
    /// the location mandated for the detected signature version.
    #[error("EC2 request timestamp not supplied")]
    Ec2TimestampMissing,

    /// `POST /v3/ec2tokens`: the replay-prevention timestamp could not be
    /// parsed in the expected format for the detected signature version.
    #[error("EC2 request timestamp is not a valid timestamp: {0}")]
    Ec2TimestampInvalid(String),

    /// `POST /v3/ec2tokens`: the replay-prevention timestamp fell outside the
    /// `[ec2] auth_ttl` window (CVE-2020-12692).
    #[error("EC2 request timestamp is outside the permitted window")]
    Ec2TimestampExpired,

    /// `POST /v3/ec2tokens` (SigV4 only): the date embedded in the
    /// `X-Amz-Date` header/param does not match the date embedded in the
    /// `Credential` scope.
    #[error("EC2 SigV4 credential scope date does not match the request date")]
    Ec2CredentialScopeDateMismatch,

    /// TOTP authentication (ADR 0019 §3): the submitted passcode did not
    /// match any `type='totp'` credential registered for the resolved user
    /// (including the case where no user or no TOTP credential could be
    /// resolved at all). Deliberately generic, mirroring
    /// `UserNameOrPasswordWrong`, to avoid leaking which lookup failed.
    #[error("invalid TOTP passcode")]
    TotpPasscodeInvalid,

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

    /// Request correlation ID for linking perimeter and provider audit events.
    ///
    /// Set by the API handler from the `x-openstack-request-id` header
    /// (always server-generated — see ADR 0023 §2.1). Defaults to `None`
    /// for contexts created outside an HTTP request (e.g. tests, CLI).
    #[builder(default)]
    correlation_id: Option<String>,
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
            correlation_id: None,
        }
    }
}

impl SecurityContext {
    /// Construct a security context with an exact authentication-method set.
    ///
    /// This is intended for authentication mechanisms whose authorization
    /// bounds are represented by a delegation-carrying
    /// [`AuthenticationContext`], while the immutable mechanism that verified
    /// the request is different. Callers must provide the non-empty set of
    /// methods they have already verified.
    pub fn try_from_authentication_result_with_auth_methods(
        value: AuthenticationResult,
        auth_methods: HashSet<String>,
    ) -> Result<Self, AuthenticationError> {
        let mut context = Self::try_from(value)?;
        context.auth_methods = auth_methods;
        Ok(context)
    }

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

    /// Returns the request correlation ID, if set.
    ///
    /// Populated by the HTTP handler from the server-generated
    /// `x-openstack-request-id` value (ADR 0023 §2.1). Absent for
    /// contexts constructed outside an HTTP request.
    pub fn correlation_id(&self) -> Option<&str> {
        self.correlation_id.as_deref()
    }

    /// Attach a correlation ID to this context.
    ///
    /// Called by the auth handler immediately after the VSC is constructed.
    pub fn set_correlation_id(&mut self, id: impl Into<String>) {
        self.correlation_id = Some(id.into());
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
        // A restricted token may only be used to obtain a token for its own
        // project; every other scope is prohibited outright. Checked once,
        // up front, instead of duplicating the `token_restriction.is_some()`
        // guard in every non-Project branch below.
        if let Some(token_restriction) = &self.token_restriction {
            match scope {
                ScopeInfo::Project { project, .. } => {
                    if let Some(tr_pid) = &token_restriction.project_id
                        && *tr_pid != project.id
                    {
                        return Err(AuthenticationError::ScopeNotAllowed);
                    }
                }
                _ => return Err(AuthenticationError::ScopeNotAllowed),
            }
        }
        match scope {
            ScopeInfo::Domain(_domain) => match &self.authentication_context {
                AuthenticationContext::ApplicationCredential { .. } => {
                    Err(AuthenticationError::ScopeNotAllowed)
                }
                AuthenticationContext::Oidc { .. } => Ok(()),
                AuthenticationContext::K8s(_) => Err(AuthenticationError::ScopeNotAllowed),
                AuthenticationContext::Password => Ok(()),
                AuthenticationContext::Ec2Credential => Ok(()),
                AuthenticationContext::Totp => Ok(()),
                AuthenticationContext::Admin => Ok(()),
                AuthenticationContext::Token(_) => Ok(()),
                AuthenticationContext::Trust { .. } => Err(AuthenticationError::ScopeNotAllowed),
                AuthenticationContext::WebauthN => Ok(()),
                AuthenticationContext::Mapping(_) => Ok(()),
                // Direct, non-delegated authentication (ADR 0025 §4), same
                // as Password/Token.
                AuthenticationContext::WasmPlugin { .. } => Ok(()),
            },
            ScopeInfo::Project { project, .. } => {
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
                    AuthenticationContext::Ec2Credential => Ok(()),
                    AuthenticationContext::Totp => Ok(()),
                    AuthenticationContext::Admin => Ok(()),
                    AuthenticationContext::Token(_) => Ok(()),
                    AuthenticationContext::Trust { trust, token } => {
                        // A plain Project scope is legal for a trust ONLY when
                        // (a) it is the trust's own bound project, mirroring the
                        // ApplicationCredential arm above, AND (b) the context was
                        // freshly reconstructed rather than decoded from a bearer
                        // trust token (`token.is_none()`). A real OS-Trust auth
                        // request can only ever request `OS-TRUST:trust` scope --
                        // there is no client-facing way to present a trust
                        // identity and ask for a plain project scope. The one
                        // legitimate producer of this exact shape is `/v3/ec2tokens`
                        // redemption of an EC2 credential minted under a trust: it
                        // reconstructs `AuthenticationContext::Trust` directly from
                        // the credential's stored `trust_id` blob field (`token:
                        // None`, see `create_inner` in
                        // `crates/keystone/src/api/v3/ec2tokens/create.rs`) because
                        // the credential carries a bare `project_id`, not a
                        // `TrustProject` scope -- see
                        // `calculate_effective_roles()`'s Trust-on-Project handling,
                        // which bounds the resulting roles to the trust's delegated
                        // set exactly as the native `TrustProject` path does
                        // (OSSA-2026-015). A caller reauthenticating with method
                        // "token" against an actual trust-scoped bearer token
                        // (`token: Some(_)`, see `validate_to_context_impl` in
                        // `crates/core/src/token/service.rs`) and requesting a
                        // project scope must be rejected here: trust tokens can
                        // never be used to mint another token ("token renewal ...
                        // is prohibited"), and the `TrustProject` arm below already
                        // blocks the same caller from renewing via its native
                        // scope -- this closes the equivalent Project-scope escape
                        // hatch.
                        if token.is_some()
                            || trust.project_id.as_deref() != Some(project.id.as_str())
                        {
                            Err(AuthenticationError::ScopeNotAllowed)
                        } else {
                            Ok(())
                        }
                    }
                    AuthenticationContext::WebauthN => Ok(()),
                    AuthenticationContext::Mapping(_) => Ok(()),
                    AuthenticationContext::WasmPlugin { .. } => Ok(()),
                }
            }
            ScopeInfo::TrustProject(_) => match &self.authentication_context {
                AuthenticationContext::ApplicationCredential { .. } => {
                    Err(AuthenticationError::ScopeNotAllowed)
                }
                AuthenticationContext::Oidc { .. } => Err(AuthenticationError::ScopeNotAllowed),
                AuthenticationContext::K8s(_) => Err(AuthenticationError::ScopeNotAllowed),
                AuthenticationContext::Password => Ok(()),
                AuthenticationContext::Ec2Credential => Ok(()),
                AuthenticationContext::Totp => Ok(()),
                AuthenticationContext::Admin => Ok(()),
                AuthenticationContext::Token(_) => Ok(()),
                AuthenticationContext::Trust { .. } => Err(AuthenticationError::Forbidden),
                AuthenticationContext::WebauthN => Err(AuthenticationError::ScopeNotAllowed),
                AuthenticationContext::Mapping(_) => Err(AuthenticationError::ScopeNotAllowed),
                AuthenticationContext::WasmPlugin { .. } => Ok(()),
            },
            ScopeInfo::System(_system) => match &self.authentication_context {
                AuthenticationContext::ApplicationCredential { .. } => {
                    Err(AuthenticationError::ScopeNotAllowed)
                }
                AuthenticationContext::Oidc { .. } => Err(AuthenticationError::ScopeNotAllowed),
                AuthenticationContext::K8s(_) => Err(AuthenticationError::ScopeNotAllowed),
                AuthenticationContext::Password => Ok(()),
                AuthenticationContext::Ec2Credential => Ok(()),
                AuthenticationContext::Totp => Ok(()),
                AuthenticationContext::Admin => Ok(()),
                AuthenticationContext::Token(_) => Ok(()),
                AuthenticationContext::Trust { .. } => Err(AuthenticationError::ScopeNotAllowed),
                AuthenticationContext::WebauthN => Ok(()),
                AuthenticationContext::Mapping(_) => Ok(()),
                AuthenticationContext::WasmPlugin { .. } => Ok(()),
            },
            ScopeInfo::Unscoped => match &self.authentication_context {
                AuthenticationContext::ApplicationCredential { .. } => {
                    Err(AuthenticationError::ScopeNotAllowed)
                }
                AuthenticationContext::Oidc { .. } => Ok(()),
                AuthenticationContext::K8s(_) => Err(AuthenticationError::ScopeNotAllowed),
                AuthenticationContext::Password => Ok(()),
                AuthenticationContext::Ec2Credential => Ok(()),
                AuthenticationContext::Totp => Ok(()),
                AuthenticationContext::Admin => Ok(()),
                AuthenticationContext::Token(_) => Ok(()),
                AuthenticationContext::Trust { .. } => Err(AuthenticationError::ScopeNotAllowed),
                AuthenticationContext::WebauthN => Ok(()),
                AuthenticationContext::Mapping(_) => Ok(()),
                AuthenticationContext::WasmPlugin { .. } => Ok(()),
            },
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
        // Preserve existing roles if available, otherwise fall back to None.
        let roles = self.authorization.as_ref().and_then(|a| a.roles.clone());
        let authorization = AuthzInfo { roles, scope };
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
    /// user_name). Set when authentication goes through a mapping-based
    /// provider (mapping, k8s_auth, etc.) and the matched rule specifies a
    /// user identity.
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
    /// Login using a signed EC2 request (`POST /v3/ec2tokens`, ADR 0019 §5),
    /// where the EC2 credential carries no delegation metadata. When the
    /// credential *was* created via a trust or application credential
    /// (`trust_id`/`app_cred_id` in its blob), the delegation metadata is
    /// passed through by using [`AuthenticationContext::Trust`] or
    /// [`AuthenticationContext::ApplicationCredential`] instead of this
    /// variant, so the existing bounded-object validation in
    /// `ValidatedSecurityContext::new_for_scope` applies unchanged.
    Ec2Credential,
    /// Login using a TOTP passcode verified against a `type='totp'`
    /// credential (ADR 0019 §3).
    Totp,
    /// Login authenticated by a `mode = full_auth` dynamic auth plugin (ADR
    /// 0025 §4). The handle a plugin presented back via
    /// `Allow.resolved_identity` is deliberately not carried here - it's
    /// verified once, at dispatch time
    /// (`openstack_keystone_core::auth_plugin_auth::authenticate_via_wasm_plugin`),
    /// and expires with that invocation; by the time an
    /// `AuthenticationContext` exists, the real user is already resolved
    /// and there is nothing left to verify a handle against.
    WasmPlugin {
        /// The plugin's configured `[auth] methods` name. This is the only
        /// plugin-version-binding anchor carried here: the `FernetToken`
        /// payload cannot be extended with a per-plugin SHA-256 (its variant
        /// set is fixed and a `WasmPlugin` login mints an ordinary
        /// `DomainScope` token), so version binding is enforced at
        /// verification time by comparing the token's own `issued_at`
        /// against the plugin's configured `valid_since` (ADR 0025 §4
        /// "Plugin Version Binding"), keyed on this `plugin_name` - not by
        /// embedding and re-comparing a module hash.
        plugin_name: String,
        /// Extra claims the plugin's `authenticate` response attached,
        /// surfaced to policy as `plugin_claims.<plugin_name>.*`
        /// (`Credentials::plugin_claims`) - never a top-level,
        /// privilege-relevant field (ADR §7 "Response Payload Bounds").
        claims: HashMap<String, serde_json::Value>,
        /// Always `None` in Phase 1 PR 1.2 - no code path mints a
        /// `FernetToken::WasmPlugin` payload yet; that's PR 1.4's job. The
        /// field exists now so this variant already has its ADR-final
        /// shape and doesn't need a second breaking change later.
        token: Option<FernetToken>,
    },
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
    /// `"trust"`, `"webauthn"`, `"mapped"`). When a token is used as the
    /// parent, including one whose delegated context is restored as a trust
    /// or application credential, the methods from the parent token are
    /// carried forward and `"token"` is added.
    ///
    /// # Returns
    ///
    /// A [`HashSet<String>`] of method name strings.
    #[must_use]
    pub fn methods(&self) -> HashSet<String> {
        match self {
            Self::ApplicationCredential { token, .. } => token.as_ref().map_or_else(
                || once("application_credential".to_string()).collect(),
                |token| {
                    token
                        .methods()
                        .iter()
                        .cloned()
                        .chain(once("token".to_string()))
                        .collect()
                },
            ),
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
            Self::Trust { token, .. } => token.as_ref().map_or_else(
                || once("trust".to_string()).collect(),
                |token| {
                    token
                        .methods()
                        .iter()
                        .cloned()
                        .chain(once("token".to_string()))
                        .collect()
                },
            ),
            Self::WebauthN => once("x509".to_string()).collect(),
            Self::Mapping(_) => once("mapped".to_string()).collect(),
            Self::Ec2Credential => once("ec2credential".to_string()).collect(),
            Self::Totp => once("totp".to_string()).collect(),
            Self::WasmPlugin { plugin_name, .. } => once(plugin_name.clone()).collect(),
        }
    }

    /// Returns the canonical auth-method string for *this* authentication
    /// context (top-level variant only).
    ///
    /// Passed to the policy engine as `input.credentials.auth_type` so
    /// `.rego` rules can distinguish delegated authentication (trust,
    /// application credential) from direct authentication (password,
    /// token, TOTP, ...). Use [`Self::is_delegated`] rather than comparing
    /// this string directly, since a re-scoped [`Self::Token`] reports
    /// `"token"` here even when its underlying payload originated from a
    /// trust or application credential.
    #[must_use]
    pub fn auth_type(&self) -> Cow<'_, str> {
        match self {
            Self::ApplicationCredential { .. } => Cow::Borrowed("application_credential"),
            Self::Oidc { .. } => Cow::Borrowed("openid"),
            Self::K8s(_) => Cow::Borrowed("k8s"),
            Self::Password => Cow::Borrowed("password"),
            Self::Admin => Cow::Borrowed("admin"),
            Self::Token(_) => Cow::Borrowed("token"),
            Self::Trust { .. } => Cow::Borrowed("trust"),
            Self::WebauthN => Cow::Borrowed("webauthn"),
            Self::Mapping(_) => Cow::Borrowed("mapped"),
            Self::Ec2Credential => Cow::Borrowed("ec2credential"),
            Self::Totp => Cow::Borrowed("totp"),
            Self::WasmPlugin { plugin_name, .. } => Cow::Owned(plugin_name.clone()),
        }
    }

    /// Returns `true` if this authentication is bound to a delegation
    /// (a trust or an application credential), either directly or carried
    /// forward through a re-scoped [`Self::Token`].
    ///
    /// # Security Note
    ///
    /// Delegated tokens are scoped to a single project at delegation time
    /// (OSSA-2026-015 / ADR 0019 §2). Resource authorization must check
    /// this flag alongside `project_id` so a delegated token cannot reach
    /// resources outside its delegation project just because a re-scope
    /// (`Self::Token`) hides the original delegated method behind
    /// `auth_type() == "token"`.
    #[must_use]
    pub fn is_delegated(&self) -> bool {
        matches!(
            self,
            Self::ApplicationCredential { .. } | Self::Trust { .. }
        ) || self
            .methods()
            .iter()
            .any(|m| m == "trust" || m == "application_credential")
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
#[path = "auth/tests.rs"]
mod tests;
