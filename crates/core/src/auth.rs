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
use std::collections::HashSet;
use std::ops::Deref;

use chrono::Utc;
use tracing::{debug, warn};

use openstack_keystone_core_types::assignment::{
    AssignmentProviderError, RoleAssignmentListParametersBuilder,
};
use openstack_keystone_core_types::identity::IdentityProviderError;
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::resource::ResourceProviderError;
use openstack_keystone_core_types::role::*;
use openstack_keystone_core_types::token::FernetToken;

use crate::keystone::ServiceState;

pub use openstack_keystone_core_types::auth::*;

/// Conversion trait that forces the caller to provide context information when
/// converting a provider error into [`AuthenticationError::Provider`]. Similar
/// to [`crate::error::DbContextExt`] but for authentication validation errors.
pub trait IntoAuthContext<T> {
    /// Converts the result error into `AuthenticationError::Provider` with the
    /// given context label.
    ///
    /// # Parameters
    /// - `ctx`: The context message to add to the error.
    ///
    /// # Returns
    /// - `Result<T, AuthenticationError>` - The original result or a wrapped
    ///   `AuthenticationError::Provider`.
    fn auth_context(self, ctx: impl Into<String>) -> Result<T, AuthenticationError>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> IntoAuthContext<T> for Result<T, E> {
    fn auth_context(self, ctx: impl Into<String>) -> Result<T, AuthenticationError> {
        self.map_err(|e| AuthenticationError::Provider {
            source: Box::new(e),
            context: Some(ctx.into()),
        })
    }
}

// Validated security context.
//
// Prevent use of unvalidated context
#[derive(Clone, Debug)]
pub struct ValidatedSecurityContext(SecurityContext);

impl ValidatedSecurityContext {
    /// The validated security context.
    #[must_use]
    pub fn inner(&self) -> &SecurityContext {
        &self.0
    }

    /// Validate the SecurityContext for the given scope, resolving effective
    /// roles and returning a locked context.
    ///
    /// When a scope is requested that differs from any scope already set on
    /// the context, [`SecurityContext::validate_scope_boundaries`] is
    /// enforced to guard the override. When it is unset, it is always
    /// enforced via [`SecurityContext::set_authorization_scope`] (every
    /// fresh scope assignment is validated; see I5 in `doc/src/security.md`
    /// -- there is no "first scope is trusted" carve-out).
    ///
    /// Re-presenting an *already-validated* token with its stored scope
    /// unchanged (e.g. token/trust re-authentication, which reconstructs
    /// `authorization` directly from the decoded Fernet token via
    /// `SecurityContext::set_authorization` rather than through this
    /// constructor) intentionally skips re-validation here: the scope was
    /// checked once at issuance, and a Fernet token is authenticated
    /// encryption, so the stored scope cannot have been tampered with
    /// between issuance and reuse. This is *not* the same case as a caller
    /// pre-setting an arbitrary, never-validated scope and then requesting
    /// that exact scope to dodge the gate -- every `authorization`-setting
    /// path in this codebase either runs through `set_authorization_scope`
    /// (validated) or reconstructs a value that was already validated when
    /// its token was minted. Scope-setting, validation, and role resolution
    /// happen as a single atomic step.
    #[tracing::instrument(skip(state), err(Debug))]
    pub async fn new_for_scope(
        mut ctx: SecurityContext,
        scope: ScopeInfo,
        state: &ServiceState,
    ) -> Result<Self, AuthenticationError> {
        if let Some(existing_authz) = ctx.authorization() {
            if existing_authz.scope != scope {
                ctx.validate_scope_boundaries(&scope)?;
            }
        } else {
            ctx.set_authorization_scope(scope.clone())?;
        }
        let scope_clone = scope;

        // Populate user_domain before validation, since validate() requires it
        if let IdentityInfo::User(user_info) = &ctx.principal().identity
            && user_info.user_domain.is_none()
            && let Some(domain) = &user_info.user
        {
            let domain_id = &domain.domain_id;
            let user_domain = state
                .provider
                .get_resource_provider()
                .get_domain(&ExecutionContext::internal(state), domain_id)
                .await
                .auth_context("fetching user domain")?
                .ok_or(ResourceProviderError::DomainNotFound(domain_id.clone()))
                .auth_context("fetching user domain")?;
            ctx.populate_user_domain(user_domain);
        }
        ctx.validate()?;
        let now = Utc::now();
        if ctx.expires_at().is_some_and(|expiry| expiry < now) {
            return Err(AuthenticationError::AuthTokenExpired);
        }
        // Not all of the checks can be done synchronously inside the SecurityContext.
        // Do whatever else is required.
        match &ctx.authentication_context() {
            AuthenticationContext::ApplicationCredential {
                application_credential,
                ..
            } => {
                if application_credential.user_id != ctx.principal().get_user_id() {
                    return Err(AuthenticationError::AuthzPrincipalMismatch);
                }

                if application_credential
                    .expires_at
                    .is_some_and(|expiry| expiry < Utc::now())
                {
                    return Err(AuthenticationError::AuthApplicationCredentialExpired);
                }
            }
            AuthenticationContext::Oidc { .. } => {}
            AuthenticationContext::K8s(..) => {}
            AuthenticationContext::Password => {}
            AuthenticationContext::Admin => {}
            AuthenticationContext::Ec2Credential => {}
            AuthenticationContext::Totp => {}
            // The `resolved_identity` handle a dynamic auth plugin
            // presented is already verified once, at dispatch time, in
            // `crate::auth_plugin_auth::authenticate_via_wasm_plugin`
            // (ADR 0025 §4 "Identity Binding") - by the time an
            // `AuthenticationContext::WasmPlugin` exists here, the real
            // user is already resolved and the handle itself was never
            // carried into this context (it expires with that invocation).
            //
            // What *is* re-checked here is plugin version binding (ADR
            // 0025 §4 "Plugin Version Binding"): `ctx.token()` is only
            // `Some` when re-verifying an already-minted token (it is
            // `None` during a fresh mint, per `SecurityContext::token`'s
            // doc comment), so this never rejects a brand-new login. On
            // reuse, if the operator has since bumped `valid_since` for
            // this plugin (normally alongside a `sha256` bump) past the
            // token's `issued_at`, the token is stale and rejected -
            // forcing re-authentication against the current plugin logic.
            //
            // Defense-in-depth only: the real, always-reachable enforcement
            // point for an already-minted `WasmPlugin` token is
            // `TokenService::validate_to_context_impl`
            // (`crates/core/src/token/service.rs`), which checks the
            // token's `methods` against configured plugins directly - the
            // context re-verification path there reconstructs an ordinary
            // `AuthenticationContext::Token`, not `WasmPlugin`, so this arm
            // is never actually exercised by token re-verification today.
            // It stays in place in case a future change threads `WasmPlugin`
            // back through re-verification.
            AuthenticationContext::WasmPlugin { plugin_name, .. } => {
                if let Some(token) = ctx.token() {
                    let cfg = state.config_manager.config.read().await;
                    if let Some(valid_since) =
                        cfg.auth_plugin.get(plugin_name).and_then(|p| p.valid_since)
                        && *token.issued_at() < valid_since
                    {
                        return Err(AuthenticationError::PluginVersionMismatch(
                            plugin_name.clone(),
                        ));
                    }
                }
            }
            AuthenticationContext::Trust { trust, .. } => {
                // Validate the trust chain
                state
                    .provider
                    .get_trust_provider()
                    .validate_trust_delegation_chain(&ExecutionContext::internal(state), trust)
                    .await
                    .auth_context("validating trust delegation chain")?;

                if trust.trustee_user_id != ctx.principal().get_user_id() {
                    return Err(AuthenticationError::AuthzPrincipalMismatch);
                }

                // Resolve and verify trustor user is enabled and resolves to a
                // domain that is also enabled
                let trustor = state
                    .provider
                    .get_identity_provider()
                    .get_user(&ExecutionContext::internal(state), &trust.trustor_user_id)
                    .await
                    .auth_context("fetching trustor user")?
                    .ok_or(IdentityProviderError::UserNotFound(
                        trust.trustor_user_id.clone(),
                    ))
                    .auth_context("fetching trustor user")?;
                if !trustor.enabled {
                    return Err(AuthenticationError::TrustorUserDisabled(
                        trust.trustor_user_id.clone(),
                    ));
                }

                // TODO: this hints to eventual necessity to include trustor information in the
                // Context statically.
                if let IdentityInfo::User(user) = &ctx.principal().identity {
                    if let Some(user) = &user.user
                        && user.domain_id != trustor.domain_id
                    {
                        let trustor_domain_enabled = state
                            .provider
                            .get_resource_provider()
                            .get_domain_enabled(
                                &ExecutionContext::internal(state),
                                &trustor.domain_id,
                            )
                            .await
                            .auth_context("get_trustor_domain_enabled")?;
                        if !trustor_domain_enabled {
                            return Err(AuthenticationError::TrustorDomainDisabled);
                        }
                    }
                } else {
                    return Err(AuthenticationError::TrustorPrincipalUseNotSupported);
                }
            }
            AuthenticationContext::Token(..) => {}
            AuthenticationContext::WebauthN => {}
            AuthenticationContext::Mapping(mc) => {
                // Plugin version binding for a `mapping`-mode dynamic auth
                // plugin (ADR 0025 §4 "Plugin-version binding for mapping
                // mode"), mirroring the `full_auth` `valid_since` check
                // above. On token re-verification (`ctx.token()` is `Some`;
                // `None` during a fresh mint), if the ruleset that produced
                // this mapping is sourced from a WASM plugin whose
                // `valid_since` was bumped past the token's `issued_at`, the
                // token is stale and rejected exactly like a `full_auth`
                // plugin patch invalidates its outstanding tokens. The
                // plugin name is recovered from the ruleset's own
                // `IdentitySource::WasmPlugin`, so no per-plugin hash has to
                // be embedded in the (unextendable) `FernetToken` payload.
                //
                // Not reachable in production today (ADR §4/§8 amendment):
                // a `mapping`-mode token carries only `methods = ["mapped"]`
                // with no `mapping_id`, and `TokenService::
                // validate_to_context_impl` reconstructs re-verified,
                // non-ApplicationCredential/Trust tokens as
                // `AuthenticationContext::Token`, never `Mapping` - so
                // `ctx.token()` and a `Mapping` context are never both
                // present outside a hand-built test `SecurityContext`. Kept
                // as the documented, correct-if-ever-reachable behavior
                // rather than removed, since the underlying design intent
                // (recover the plugin from the matched ruleset) is still
                // right if a future change threads a mapping identifier
                // through re-verification.
                if let Some(token) = ctx.token() {
                    let ruleset = state
                        .provider
                        .get_mapping_provider()
                        .get_ruleset(&ExecutionContext::internal(state), &mc.mapping_id)
                        .await
                        .auth_context("loading mapping ruleset for plugin version binding")?;
                    if let Some(
                        openstack_keystone_core_types::mapping::resolution::IdentitySource::WasmPlugin {
                            plugin_name,
                        },
                    ) = ruleset.as_ref().map(|r| &r.source)
                    {
                        let cfg = state.config_manager.config.read().await;
                        if let Some(valid_since) = cfg
                            .auth_plugin
                            .get(plugin_name)
                            .and_then(|p| p.valid_since)
                            && *token.issued_at() < valid_since
                        {
                            return Err(AuthenticationError::PluginVersionMismatch(
                                plugin_name.clone(),
                            ));
                        }
                    }
                }

                // Extract data from mc before modifying ctx (mc borrows ctx).
                let virtual_user_id = mc.virtual_user_id.clone();
                let is_system = mc.is_system;

                // Fast path: if authorization was already derived during
                // authenticate_ephemeral (from match_result.authorizations),
                // use it directly to avoid a second storage read that could
                // race with Raft replication on follower nodes.
                let roles_prepopulated = ctx
                    .authorization()
                    .and_then(|a| a.effective_roles())
                    .map(|r| r.to_vec());

                debug!(
                    virtual_user_id = &virtual_user_id,
                    is_system,
                    scope = ?scope_clone,
                    roles_prepopulated = roles_prepopulated.as_ref().map(|r| r.len()),
                    "Mapping: validate_security_context — checking prepopulated roles"
                );

                if let Some(roles) = roles_prepopulated {
                    let resolved_scope = if is_system && matches!(scope_clone, ScopeInfo::Unscoped)
                    {
                        ctx.set_authorization_scope(ScopeInfo::System("all".into()))?;
                        ScopeInfo::System("all".into())
                    } else {
                        scope_clone.clone()
                    };

                    debug!(
                        virtual_user_id = &virtual_user_id,
                        scope = ?resolved_scope,
                        role_count = roles.len(),
                        "Mapping: fast path — prepopulated roles, skipping storage read"
                    );

                    let authz_for_scope =
                        openstack_keystone_core_types::auth::AuthzInfoBuilder::default()
                            .scope(resolved_scope.clone())
                            .roles(roles)
                            .build()
                            .map_err(
                                openstack_keystone_core_types::auth::AuthenticationError::from,
                            )?;
                    ctx.set_authorization(authz_for_scope);
                } else if is_system && matches!(scope_clone, ScopeInfo::Unscoped) {
                    // Even with no pre-set roles, a system principal requesting
                    // unscoped should be upgraded to system scope.
                    debug!(
                        virtual_user_id = &virtual_user_id,
                        "Mapping: is_system=true with Unscoped, upgrading to System, slow path"
                    );
                    ctx.set_authorization_scope(ScopeInfo::System("all".into()))?;

                    // Slow path: read virtual user to obtain authorizations.
                    // The scope was just overridden to System("all") above, so
                    // only a System authorization can ever match here -- no
                    // Domain/Project match arm is reachable in this branch.
                    let vu = get_virtual_user_or_error(state, &virtual_user_id).await?;

                    let roles = vu.authorizations.iter().find_map(|a| {
                        if let Authorization::System { system_id, roles } = a
                            && system_id == "all"
                        {
                            Some(roles.clone())
                        } else {
                            None
                        }
                    });

                    if let Some(roles) = roles {
                        let authz =
                            openstack_keystone_core_types::auth::AuthzInfoBuilder::default()
                                .scope(ScopeInfo::System("all".into()))
                                .roles(roles)
                                .build()
                                .map_err(
                                    openstack_keystone_core_types::auth::AuthenticationError::from,
                                )?;
                        ctx.set_authorization(authz);
                    }
                } else if matches!(scope_clone, ScopeInfo::Unscoped) {
                    // Unscoped with no pre-populated roles: skip storage read.
                    // There's nothing to derive from the virtual user, and a read
                    // would race with Raft replication during auth.
                    debug!(
                        virtual_user_id = &virtual_user_id,
                        "Mapping: Unscoped with no prepopulated roles, skipping storage read"
                    );
                    let _ = ctx.set_authorization_scope(scope_clone);
                } else {
                    // Slow path: read virtual user to obtain authorizations.
                    debug!(
                        virtual_user_id = &virtual_user_id,
                        scope = ?scope_clone,
                        "Mapping: slow path — reading virtual user for role resolution"
                    );
                    let vu = get_virtual_user_or_error(state, &virtual_user_id).await?;

                    let resolved_scope = scope_clone.clone();

                    if vu.authorizations.is_empty() {
                        // No authorizations - fall through with no scope
                    } else {
                        let roles = match &resolved_scope {
                            ScopeInfo::Domain(domain) => vu.authorizations.iter().find_map(|a| {
                                if let Authorization::Domain { domain_id, roles } = a
                                    && *domain_id == domain.id
                                {
                                    Some(roles.clone())
                                } else {
                                    None
                                }
                            }),
                            ScopeInfo::Project {
                                project,
                                project_domain,
                            } => vu.authorizations.iter().find_map(|a| {
                                if let Authorization::Project {
                                    project_id,
                                    project_domain_id,
                                    roles,
                                } = a
                                    && *project_id == project.id
                                    && *project_domain_id == project_domain.id
                                {
                                    Some(roles.clone())
                                } else {
                                    None
                                }
                            }),
                            ScopeInfo::System(system_id) => {
                                vu.authorizations.iter().find_map(|a| {
                                    if let Authorization::System {
                                        system_id: s,
                                        roles,
                                    } = a
                                        && s.as_str() == system_id.as_str()
                                    {
                                        Some(roles.clone())
                                    } else {
                                        None
                                    }
                                })
                            }
                            ScopeInfo::Unscoped | ScopeInfo::TrustProject(_) => None,
                        };

                        if let Some(roles) = roles {
                            let authz =
                                openstack_keystone_core_types::auth::AuthzInfoBuilder::default()
                                    .scope(resolved_scope)
                                    .roles(roles)
                                    .build()
                                    .map_err(
                                        openstack_keystone_core_types::auth::AuthenticationError::from,
                                    )?;
                            ctx.set_authorization(authz);
                        }
                    }
                }
            }
        }
        // TODO: Evaluate whether token revocation check should be done here - it is a
        // part of the authentication validation
        // Populate roles before locking
        if let Some(authz) = ctx.authorization() {
            let role_vec = calculate_effective_roles(state, &ctx, &authz.scope).await?;
            debug!(
                scope = ?authz.scope,
                role_count = role_vec.len(),
                "calculated effective_roles"
            );
            ctx.set_effective_roles(role_vec);
        }

        if let Some(authz) = ctx.authorization()
            && !matches!(authz.scope, ScopeInfo::Unscoped)
            && authz.effective_roles().is_none_or(|r| r.is_empty())
            && !ctx.is_admin()
        {
            let virtual_user_id = match ctx.authentication_context() {
                AuthenticationContext::Mapping(mc) => Some(mc.virtual_user_id.as_str()),
                _ => None,
            };
            warn!(
                virtual_user_id,
                scope = ?authz.scope,
                "ActorHasNoRolesOnTarget — returning 401"
            );
            return Err(AuthenticationError::ActorHasNoRolesOnTarget);
        }
        Ok(ValidatedSecurityContext(ctx))
    }

    /// Returns the token associated with the security context.
    ///
    /// The token is guaranteed to be present for any validated context that
    /// was produced by token-based authentication flows (`issue_token_context`
    /// or `authorize_by_token`). If `None`, it indicates a programming error
    /// where a token was expected but a password-auth or similar context was
    /// passed to a token handler.
    #[must_use = "FernetToken must be read from the context"]
    pub fn token(&self) -> Result<&FernetToken, AuthenticationError> {
        self.0.token().ok_or(AuthenticationError::TokenNotInContext)
    }

    /// Returns the request correlation ID, falling back to `"unknown"`.
    ///
    /// Used by `audited_op!` to stamp the compensating local log when the
    /// post-audit critical channel is full.
    pub fn correlation_id(&self) -> &str {
        self.0.correlation_id().unwrap_or("unknown")
    }

    /// Construct without validation. ONLY for tests and mocks.
    #[cfg(any(test, feature = "mock"))]
    pub fn test_new(ctx: SecurityContext) -> Self {
        ValidatedSecurityContext(ctx)
    }
}

impl Deref for ValidatedSecurityContext {
    type Target = SecurityContext;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// ExecutionContext bundles service state and optional security context.
///
/// Passed to all provider methods instead of separate `state` and `ctx`
/// parameters. For authenticated HTTP requests, constructed with
/// `from_auth(state, user_auth)`. For internal auth-flow code (e.g.
/// fernet token validation) where no security context exists yet,
/// constructed with `internal(state)`.
///
/// This eliminates the need for `stub()` patterns and makes the distinction
/// between authenticated and internal calls explicit.
#[derive(Clone)]
pub struct ExecutionContext<'a> {
    /// The current service state, providing access to providers, configuration,
    /// and other shared resources.
    state: &'a ServiceState,

    /// Optional validated security context from the authenticated request.
    /// `None` when called from internal code paths that have no auth context
    /// yet (e.g., token validation, internal provider delegation).
    ctx: Option<&'a ValidatedSecurityContext>,
}

impl<'a> ExecutionContext<'a> {
    /// Construct from an authenticated request context.
    #[must_use]
    pub fn from_auth(state: &'a ServiceState, ctx: &'a ValidatedSecurityContext) -> Self {
        Self {
            state,
            ctx: Some(ctx),
        }
    }

    /// Construct for internal calls where no security context exists yet
    /// (e.g. token validation, trust chain resolution).
    #[must_use]
    pub fn internal(state: &'a ServiceState) -> Self {
        Self { state, ctx: None }
    }

    /// The service state.
    #[must_use]
    pub fn state(&self) -> &ServiceState {
        self.state
    }

    /// The security context, if available.
    #[must_use]
    pub fn ctx(&self) -> Option<&ValidatedSecurityContext> {
        self.ctx
    }

    /// Returns whether a security context is present (i.e., not an internal
    /// call).
    #[must_use]
    pub fn has_auth(&self) -> bool {
        self.ctx.is_some()
    }
}

impl<'a> Deref for ExecutionContext<'a> {
    type Target = ServiceState;

    fn deref(&self) -> &Self::Target {
        self.state
    }
}

// Expand scope role information.
// Fetch the virtual user shadow record from storage.
async fn get_virtual_user_or_error(
    state: &ServiceState,
    virtual_user_id: &str,
) -> Result<openstack_keystone_core_types::mapping::VirtualUser, AuthenticationError> {
    let exec = ExecutionContext::internal(state);
    state
        .provider
        .get_mapping_provider()
        .get_virtual_user(&exec, virtual_user_id)
        .await
        .auth_context("fetching virtual user for scope resolution")?
        .ok_or(AuthenticationError::ActorHasNoRolesOnTarget)
        .auth_context("virtual user not found")
}

// Expand scope role information.
//
// Compute the effective roles that the principal has on the scope taking into
// consideration the authentication method.
//
// * For application_credential this returns roles frozen on the application
//   credential removing the ones the principal is not having access to anymore.
// * For trusts it returns all roles the trustor has or the ones explicitly
//   declared on the [`Trust`].
// * For project scope and token restrictions present in the context with the
//   roles attached - such roles are returned without verifying whether they are
//   directly assigned to the user. Otherwise a regular user roles on the
//   project resolving is applied.
// * For the domain scope a roles that the user is having on the domain are
//   evaluated.
// * For unscoped context an empty list is returned.
// * For system scope a lookup of all roles the user has access to on the system
//   are returned.
async fn calculate_effective_roles(
    state: &ServiceState,
    ctx: &SecurityContext,
    scope: &ScopeInfo,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    scope.validate()?;

    // Mapping engine pre-populates roles from the matched authorization.
    // Skip assignment lookup since virtual users have no role assignments.
    if matches!(
        ctx.authentication_context(),
        AuthenticationContext::Mapping(_)
    ) && let Some(authz) = ctx.authorization()
        && let Some(roles) = authz.effective_roles()
        && !ctx.is_admin()
    {
        return Ok(roles.to_vec());
    }

    // A trust presented on a plain Project scope — e.g. an EC2 credential
    // created under a trust and redeemed at `/v3/ec2tokens`, where the scope
    // is rebuilt from the credential's project rather than the trust's own
    // `TrustProject` scope — must still have its effective roles bounded by
    // the trust's delegated role set, never the trustee's own project
    // assignments (OSSA-2026-015 defense-in-depth; mirrors the
    // application-credential handling in `resolve_project_default_roles`).
    if let AuthenticationContext::Trust { trust, .. } = ctx.authentication_context()
        && let ScopeInfo::Project {
            project,
            project_domain,
        } = scope
    {
        let tpi = TrustProjectInfo {
            trust: trust.clone(),
            project: project.clone(),
            project_domain: project_domain.clone(),
        };
        return resolve_trust_roles(state, &tpi).await;
    }

    let roles = match scope {
        ScopeInfo::Domain(domain) => resolve_domain_roles(state, ctx, &domain.id).await?,
        ScopeInfo::Project { project, .. } => {
            resolve_project_roles(state, ctx, &project.id).await?
        }
        ScopeInfo::System(system_id) => resolve_system_roles(state, ctx, system_id).await?,
        ScopeInfo::TrustProject(tpi) => resolve_trust_roles(state, tpi).await?,
        ScopeInfo::Unscoped => Vec::new(),
    };

    if !matches!(scope, ScopeInfo::Unscoped) && roles.is_empty() && !ctx.is_admin() {
        return Err(AuthenticationError::ActorHasNoRolesOnTarget);
    }

    Ok(roles)
}

// Resolve effective roles for a domain scope.
async fn resolve_domain_roles(
    state: &ServiceState,
    ctx: &SecurityContext,
    domain_id: &str,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    let user_id = ctx.principal().get_user_id();
    let assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            &ExecutionContext::internal(state),
            &RoleAssignmentListParametersBuilder::default()
                .user_id(&user_id)
                .domain_id(domain_id)
                .include_names(true)
                .effective(true)
                .resolve_implied_roles(true)
                .build()
                .map_err(AssignmentProviderError::from)?,
        )
        .await
        .auth_context("resolving role assignments")?;
    assignments_to_roles(assignments)
}

// Resolve effective roles for a project scope.
async fn resolve_project_roles(
    state: &ServiceState,
    ctx: &SecurityContext,
    project_id: &str,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    if let Some(restriction) = ctx.token_restriction()
        && !restriction.role_ids.is_empty()
    {
        return resolve_project_token_restriction_roles(state, restriction).await;
    }

    resolve_project_default_roles(state, ctx, project_id).await
}

// Resolve roles from a token restriction on a project scope.
async fn resolve_project_token_restriction_roles(
    state: &ServiceState,
    restriction: &openstack_keystone_core_types::token::TokenRestriction,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    if let Some(roles) = &restriction.roles {
        return Ok(roles.clone());
    }

    let mut roles = restriction
        .role_ids
        .iter()
        .map(|rid| RoleRef {
            id: rid.clone(),
            name: None,
            domain_id: None,
        })
        .collect();
    state
        .provider
        .get_role_provider()
        .expand_implied_roles(&ExecutionContext::internal(state), &mut roles)
        .await
        .auth_context("expanding token restriction roles")?;
    Ok(roles)
}

// Resolve project-scoped roles using the default assignment-based logic.
async fn resolve_project_default_roles(
    state: &ServiceState,
    ctx: &SecurityContext,
    project_id: &str,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    let user_id = ctx.principal().get_user_id();
    let assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            &ExecutionContext::internal(state),
            &RoleAssignmentListParametersBuilder::default()
                .user_id(&user_id)
                .project_id(project_id)
                .include_names(true)
                .effective(true)
                .resolve_implied_roles(true)
                .build()
                .map_err(AssignmentProviderError::from)?,
        )
        .await
        .auth_context("resolving role assignments")?;

    match ctx.authentication_context() {
        AuthenticationContext::ApplicationCredential {
            application_credential,
            ..
        } => {
            let user_role_ids: HashSet<String> =
                assignments.iter().map(|a| a.role_id.clone()).collect();
            let restricted = application_credential
                .roles
                .iter()
                .filter(|role| user_role_ids.contains(&role.id))
                .cloned()
                .collect();
            Ok(restricted)
        }
        _ => assignments_to_roles(assignments),
    }
}

// Resolve effective roles for a system scope.
async fn resolve_system_roles(
    state: &ServiceState,
    ctx: &SecurityContext,
    system_id: &str,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    if matches!(ctx.authentication_context(), AuthenticationContext::Admin) {
        let roles = state
            .provider
            .get_role_provider()
            .list_roles(
                &ExecutionContext::internal(state),
                &RoleListParameters {
                    name: Some("reader".into()),
                    ..Default::default()
                },
            )
            .await
            .auth_context("searching reader role")?
            .into_iter()
            .map(|role| role.into())
            .collect();
        return Ok(roles);
    }

    let user_id = ctx.principal().get_user_id();
    let assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            &ExecutionContext::internal(state),
            &RoleAssignmentListParametersBuilder::default()
                .user_id(&user_id)
                .system_id(system_id)
                .include_names(true)
                .effective(true)
                .resolve_implied_roles(true)
                .build()
                .map_err(AssignmentProviderError::from)?,
        )
        .await
        .auth_context("resolving role assignments")?;
    assignments_to_roles(assignments)
}

// Resolve effective roles for a trust scope.
async fn resolve_trust_roles(
    state: &ServiceState,
    tpi: &TrustProjectInfo,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    let trustor_assignments = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            &ExecutionContext::internal(state),
            &RoleAssignmentListParametersBuilder::default()
                .user_id(tpi.trust.trustor_user_id.clone())
                .project_id(tpi.project.id.clone())
                .include_names(true)
                .effective(true)
                .resolve_implied_roles(true)
                .build()
                .map_err(AssignmentProviderError::from)?,
        )
        .await
        .auth_context("resolving trust role assignments")?;

    if let Some(trust_roles) = &tpi.trust.roles {
        let trustor_role_ids: HashSet<String> = trustor_assignments
            .iter()
            .map(|a| a.role_id.clone())
            .collect();
        let mut trust_roles = trust_roles.clone();
        state
            .provider
            .get_role_provider()
            .expand_implied_roles(&ExecutionContext::internal(state), &mut trust_roles)
            .await
            .auth_context("expanding implied roles for trust")?;

        if !trust_roles
            .iter()
            .all(|role| trustor_role_ids.contains(&role.id))
        {
            debug!(
                "Trust roles {:?} are missing for the trustor {:?}",
                trust_roles, trustor_role_ids
            );
            return Err(AuthenticationError::ActorHasNoRolesOnTarget);
        }
        trust_roles.retain_mut(|role| role.domain_id.is_none());
        Ok(trust_roles)
    } else {
        assignments_to_roles(trustor_assignments)
    }
}

// Convert a list of role assignments into [`RoleRef`] values.
fn assignments_to_roles(
    assignments: Vec<openstack_keystone_core_types::assignment::Assignment>,
) -> Result<Vec<RoleRef>, AuthenticationError> {
    assignments
        .into_iter()
        .map(|a| {
            a.try_into()
                .map_err(|_| AuthenticationError::RoleConversionFailed)
        })
        .collect::<Result<Vec<_>, _>>()
}

#[cfg(test)]
#[path = "auth/tests.rs"]
mod tests;
