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

//! # Identity provider

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrecy::SecretString;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::domain_config::DomainConfigGroupName;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::identity::*;

use crate::auth::{
    AuthenticationContext, AuthenticationError, AuthenticationResult, AuthenticationResultBuilder,
    ExecutionContext, IdentityInfo, PrincipalInfo, UserIdentityInfoBuilder, scope_domain_id,
};
use crate::domain_config::DomainConfigResolver;
use crate::events::AuditDispatchError;
use crate::identity::{IdentityApi, IdentityProviderError, backend::IdentityBackend};
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::request_cache::{cache_get, cache_remove, cache_set};
use crate::resource::error::ResourceProviderError;

/// Request-cache namespace for [`UserResponse`] lookups by `user_id`.
const USER_CACHE_NS: &str = "identity.user";
/// Request-cache namespace for [`Group`] lookups by `group_id`.
const GROUP_CACHE_NS: &str = "identity.group";

/// Identity provider.
pub struct IdentityService {
    /// The global identity driver, used for every domain unless per-domain
    /// drivers are enabled and a domain's stored config selects another one.
    backend_driver: Arc<dyn IdentityBackend>,
    /// Name of [`Self::backend_driver`] in [`Self::backends`] (the global
    /// `[identity] driver`). Empty for [`Self::from_driver`], which has no
    /// named registry.
    default_driver_name: String,
    /// `[identity] default_domain_id`. A non-domain-aware global driver is
    /// allowed to serve this one domain even without its own stored config.
    default_domain_id: String,
    /// Every registered identity backend by name. Holds just the global driver
    /// unless `[identity] domain_specific_drivers_enabled`, in which case it
    /// also holds the backends a domain config may select (`sql` + `ldap`).
    backends: HashMap<String, Arc<dyn IdentityBackend>>,
    /// Resolves a domain's effective stored configuration. `Some` only when
    /// `[identity] domain_specific_drivers_enabled`; `None` disables all
    /// per-domain dispatch and every operation uses [`Self::backend_driver`].
    domain_config_resolver: Option<Arc<DomainConfigResolver>>,
    /// Cache of `domain_id` to resolved identity driver name. An empty value
    /// means "no per-domain override, use the global driver". No invalidation:
    /// a change to a domain's `identity/driver` through the config API is
    /// picked up only after a restart (issue #960 follow-up).
    resolved_driver_cache: RwLock<HashMap<String, String>>,
    /// Caching flag. When enabled certain data can be cached (i.e. `domain_id`
    /// by `user_id`).
    caching: bool,
    /// Internal cache of `user_id` to `domain_id` mappings. This information if
    /// fully static and can never change (well, except with a direct SQL
    /// update).
    user_id_domain_id_cache: RwLock<HashMap<String, String>>,
}

impl IdentityService {
    /// Create a new IdentityService.
    ///
    /// # Parameters
    /// - `config`: The service configuration.
    /// - `plugin_manager`: The plugin manager.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, IdentityProviderError> {
        let backend_driver = plugin_manager
            .get_identity_backend(config.identity.driver.clone())?
            .clone();
        let domain_config_resolver = if config.identity.domain_specific_drivers_enabled {
            Some(Arc::new(
                DomainConfigResolver::new(config, plugin_manager)
                    .map_err(|e| IdentityProviderError::Driver(e.to_string()))?,
            ))
        } else {
            None
        };
        Ok(Self {
            backend_driver,
            default_driver_name: config.identity.driver.clone(),
            default_domain_id: config.identity.default_domain_id.clone(),
            backends: plugin_manager.identity_backends().clone(),
            domain_config_resolver,
            resolved_driver_cache: HashMap::new().into(),
            caching: config.identity.caching,
            user_id_domain_id_cache: HashMap::new().into(),
        })
    }

    /// Create an IdentityService from a backend driver.
    ///
    /// Per-domain dispatch is off (`domain_config_resolver` is `None`), so
    /// every operation goes to `driver`; this keeps the unit tests that build a
    /// service from a single mock backend working unchanged.
    ///
    /// # Parameters
    /// - `driver`: The backend driver.
    pub fn from_driver<I: IdentityBackend + 'static>(driver: I) -> Self {
        Self {
            backend_driver: Arc::new(driver),
            default_driver_name: String::new(),
            default_domain_id: String::new(),
            backends: HashMap::new(),
            domain_config_resolver: None,
            resolved_driver_cache: HashMap::new().into(),
            caching: false,
            user_id_domain_id_cache: HashMap::new().into(),
        }
    }

    /// Build a service with an explicit backend registry and resolver.
    /// Test-only; production code goes through [`Self::new`].
    #[cfg(test)]
    pub(crate) fn from_backends(
        default_driver_name: impl Into<String>,
        backend_driver: Arc<dyn IdentityBackend>,
        backends: HashMap<String, Arc<dyn IdentityBackend>>,
        domain_config_resolver: Option<Arc<DomainConfigResolver>>,
    ) -> Self {
        Self {
            backend_driver,
            default_driver_name: default_driver_name.into(),
            default_domain_id: "default".to_string(),
            backends,
            domain_config_resolver,
            resolved_driver_cache: HashMap::new().into(),
            caching: false,
            user_id_domain_id_cache: HashMap::new().into(),
        }
    }

    /// Test-only override for `[identity] default_domain_id`, so a test can
    /// prove the non-domain-aware guard keys on the configured value rather
    /// than a literal `"default"`.
    #[cfg(test)]
    pub(crate) fn with_default_domain_id(mut self, domain_id: impl Into<String>) -> Self {
        self.default_domain_id = domain_id.into();
        self
    }

    /// The identity backend that serves `domain_id`.
    ///
    /// The global driver when per-domain drivers are off, `domain_id` is
    /// `None`, the domain's stored config names no `identity/driver`, or it
    /// names one with no registered backend. Otherwise the backend the
    /// resolved `identity/driver` selects. The resolution is cached per domain.
    ///
    /// Errors with `DomainNotFound` (404) when the request would fall back to
    /// a global driver that is not domain aware (e.g. `[identity] driver =
    /// ldap`) for a domain other than `[identity] default_domain_id` — a
    /// single LDAP directory cannot represent multiple domains. Mirrors
    /// python-keystone's `Manager._select_identity_driver`.
    async fn driver_for(
        &self,
        state: &ServiceState,
        domain_id: Option<&str>,
    ) -> Result<Arc<dyn IdentityBackend>, IdentityProviderError> {
        let (Some(resolver), Some(domain_id)) = (&self.domain_config_resolver, domain_id) else {
            return Ok(self.backend_driver.clone());
        };

        let name = if let Some(name) = self
            .resolved_driver_cache
            .read()
            .await
            .get(domain_id)
            .cloned()
        {
            name
        } else {
            let name = match resolver.effective_config(state, domain_id).await {
                Ok(config) => config
                    .into_group(DomainConfigGroupName::Identity)
                    .and_then(|group| {
                        group
                            .get("driver")
                            .and_then(|value| value.as_str())
                            .map(str::to_owned)
                    })
                    .unwrap_or_default(),
                Err(error) => {
                    tracing::warn!(
                        %domain_id,
                        %error,
                        "domain config resolution failed; using the global identity driver"
                    );
                    String::new()
                }
            };
            self.resolved_driver_cache
                .write()
                .await
                .insert(domain_id.to_owned(), name.clone());
            name
        };

        let backend = self.backend_by_name(&name);
        if Arc::ptr_eq(&backend, &self.backend_driver)
            && !backend.is_domain_aware()
            && domain_id != self.default_domain_id
        {
            tracing::warn!(
                %domain_id,
                "the global identity driver is not domain aware; a non-default \
                 domain cannot be mapped onto it"
            );
            return Err(ResourceProviderError::DomainNotFound(domain_id.to_owned()).into());
        }
        Ok(backend)
    }

    /// The registered backend called `name`, or the global driver when `name`
    /// is empty (no per-domain override) or unknown.
    fn backend_by_name(&self, name: &str) -> Arc<dyn IdentityBackend> {
        if name.is_empty() || name == self.default_driver_name {
            return self.backend_driver.clone();
        }
        self.backends
            .get(name)
            .cloned()
            .unwrap_or_else(|| self.backend_driver.clone())
    }

    /// The identity backend that serves the user `user_id`.
    ///
    /// Mirrors python-keystone's `_get_domain_driver_and_entity_id`: the id
    /// mapping is the authoritative record of which backend owns an entity.
    async fn driver_for_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &str,
    ) -> Result<Arc<dyn IdentityBackend>, IdentityProviderError> {
        self.driver_for_public_id(ctx, user_id).await
    }

    /// The identity backend that serves the group `group_id`. Same id-mapping
    /// lookup as [`Self::driver_for_user`].
    async fn driver_for_group<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        group_id: &str,
    ) -> Result<Arc<dyn IdentityBackend>, IdentityProviderError> {
        self.driver_for_public_id(ctx, group_id).await
    }

    /// Resolve the backend for a user or group public id.
    ///
    /// python-keystone (`_get_domain_driver_and_entity_id`): while per-domain
    /// drivers are enabled, look the public id up in the id mapping first. A
    /// mapping row exists for every entity a non-default backend owns; a hit
    /// dispatches to that domain's driver. A miss means the default driver
    /// owns the id (default-SQL entities carry no mapping row), so fall back
    /// to the global driver rather than re-deriving a domain that would
    /// mis-route the entity.
    async fn driver_for_public_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        public_id: &str,
    ) -> Result<Arc<dyn IdentityBackend>, IdentityProviderError> {
        if self.domain_config_resolver.is_none() {
            return Ok(self.backend_driver.clone());
        }
        let domain_id = match ctx
            .state()
            .provider
            .get_idmapping_provider()
            .get_by_public_id(ctx, public_id)
            .await
        {
            Ok(Some(mapping)) => mapping.domain_id,
            _ => return Ok(self.backend_driver.clone()),
        };
        self.driver_for(ctx.state(), Some(&domain_id)).await
    }

    /// Resolve the user's and the group's backends and require them to be the
    /// same instance before a group-membership mutation.
    ///
    /// Mirrors python-keystone's
    /// `Manager._assert_user_and_group_in_same_backend`: a membership that
    /// spans two identity backends is rejected with `CrossBackendNotAllowed`
    /// (403), after confirming both entities actually exist (a bogus id
    /// surfaces as its own `UserNotFound`/`GroupNotFound` 404 first).
    async fn membership_backend<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &str,
        group_id: &str,
    ) -> Result<Arc<dyn IdentityBackend>, IdentityProviderError> {
        let user_backend = self.driver_for_user(ctx, user_id).await?;
        if self.domain_config_resolver.is_none() {
            return Ok(user_backend);
        }
        let group_backend = self.driver_for_group(ctx, group_id).await?;
        if Arc::ptr_eq(&user_backend, &group_backend) {
            return Ok(user_backend);
        }
        if user_backend.get_user(ctx.state(), user_id).await?.is_none() {
            return Err(IdentityProviderError::UserNotFound(user_id.to_owned()));
        }
        if group_backend
            .get_group(ctx.state(), group_id)
            .await?
            .is_none()
        {
            return Err(IdentityProviderError::GroupNotFound(group_id.to_owned()));
        }
        Err(IdentityProviderError::CrossBackendNotAllowed {
            user_id: user_id.to_owned(),
            group_id: group_id.to_owned(),
        })
    }

    /// The actual password-authentication implementation, split out of the
    /// `IdentityApi::authenticate_by_password` trait method so the latter
    /// can wrap it with `keystone_auth_attempts_total`/
    /// `keystone_auth_duration_seconds`/`keystone_auth_failures_total`
    /// (ADR 0031 "Authentication", `method = "password"`) around every
    /// return path (including the early `UserIdOrNameWithDomain`/rate-limit
    /// returns) without duplicating the timing/recording logic at each one.
    async fn authenticate_by_password_inner<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        auth: &UserPasswordAuthRequest,
    ) -> Result<AuthenticationResult, IdentityProviderError> {
        let state = ctx.state();
        let mut auth = auth.clone();
        if auth.id.is_none() {
            if auth.name.is_none() {
                return Err(IdentityProviderError::UserIdOrNameWithDomain);
            }

            if let Some(ref mut domain) = auth.domain {
                if let Some(dname) = &domain.name {
                    let d = state
                        .provider
                        .get_resource_provider()
                        .find_domain_by_name(ctx, dname)
                        .await?
                        .ok_or(ResourceProviderError::DomainNotFound(dname.clone()))?;
                    domain.id = Some(d.id);
                } else if domain.id.is_none() {
                    return Err(IdentityProviderError::UserIdOrNameWithDomain);
                }
            } else {
                return Err(IdentityProviderError::UserIdOrNameWithDomain);
            }
        }

        // Per-user rate limit (ADR-0022): when the bucket is enabled, resolve
        // the caller-supplied reference to the canonical user ID with a cheap
        // existence probe and key the limiter on that ID, before the backend
        // performs any password verification (Invariants 4 and 8). The
        // throttle lives here at the provider level so every backend driver
        // shares a single implementation.
        let driver = self
            .driver_for(state, auth.domain.as_ref().and_then(|d| d.id.as_deref()))
            .await?;
        if state.rate_limiters.user_auth_enabled() {
            match driver
                .check_user_exist(
                    state,
                    auth.id.as_deref(),
                    auth.name.as_deref(),
                    auth.domain.as_ref().and_then(|d| d.id.as_deref()),
                )
                .await
            {
                Ok(user_id) => {
                    if let Err(retry_after) = state.rate_limiters.check_user(&user_id) {
                        return Err(IdentityProviderError::TooManyRequests {
                            retry_after_secs: retry_after.as_secs(),
                        });
                    }
                }
                // Unknown users never touch the limiter store (Invariant 8):
                // fall through to the backend, which burns a dummy hash and
                // returns the uniform credentials error, preserving the
                // timing parity of the "user not found" path.
                Err(IdentityProviderError::UserNotFound(_)) => {}
                Err(other) => return Err(other),
            }
        }

        driver.authenticate_by_password(state, &auth).await
    }
}

#[async_trait]
impl IdentityApi for IdentityService {
    /// Add the user to the group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_id`: The ID of the group.
    async fn add_user_to_group<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        let backend_driver = self.membership_backend(ctx, user_id, group_id).await?;
        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::GroupMembership {
                        user_id: user_id.to_string(),
                        group_ids: vec![group_id.to_string()],
                    },
                ),
                operation: async {
                    backend_driver
                        .add_user_to_group(ctx.state(), user_id, group_id)
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            backend_driver
                .add_user_to_group(ctx.state(), user_id, group_id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::GroupMembership {
                        user_id: user_id.to_string(),
                        group_ids: vec![group_id.to_string()],
                    },
                ))
                .await;
        }
        Ok(())
    }

    /// Add the user to the group with expiration.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_id`: The ID of the group.
    /// - `idp_id`: The ID of the identity provider.
    async fn add_user_to_group_expiring<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        group_id: &'a str,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        let backend_driver = self.membership_backend(ctx, user_id, group_id).await?;
        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::GroupMembership {
                        user_id: user_id.to_string(),
                        group_ids: vec![group_id.to_string()],
                    },
                ),
                operation: async {
                    backend_driver
                        .add_user_to_group_expiring(ctx.state(), user_id, group_id, idp_id)
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            backend_driver
                .add_user_to_group_expiring(ctx.state(), user_id, group_id, idp_id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::GroupMembership {
                        user_id: user_id.to_string(),
                        group_ids: vec![group_id.to_string()],
                    },
                ))
                .await;
        }
        Ok(())
    }

    /// Add user group membership relations.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `memberships`: A list of (user ID, group ID) tuples.
    async fn add_users_to_groups<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        memberships: Vec<(&'a str, &'a str)>,
    ) -> Result<(), IdentityProviderError> {
        let (first_user_id, group_ids): (String, Vec<String>) = if memberships.is_empty() {
            (String::new(), Vec::new())
        } else {
            (
                memberships[0].0.to_string(),
                memberships.iter().map(|(_, g)| g.to_string()).collect(),
            )
        };
        let backend_driver = match memberships.first() {
            Some((user_id, _)) => self.driver_for_user(ctx, user_id).await?,
            None => self.backend_driver.clone(),
        };
        if let Some(vsc) = ctx.ctx() {
            let memberships_clone = memberships
                .iter()
                .map(|(u, g)| (u.to_string(), g.to_string()))
                .collect::<Vec<_>>();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::GroupMembership {
                        user_id: first_user_id.clone(),
                        group_ids: group_ids.clone(),
                    },
                ),
                operation: async {
                    backend_driver
                        .add_users_to_groups(
                            ctx.state(),
                            memberships_clone
                                .iter()
                                .map(|(u, g)| (u.as_str(), g.as_str()))
                                .collect(),
                        )
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            backend_driver
                .add_users_to_groups(ctx.state(), memberships)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::GroupMembership {
                        user_id: first_user_id,
                        group_ids,
                    },
                ))
                .await;
        }
        Ok(())
    }

    /// Add expiring user group membership relations.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `memberships`: A list of (user ID, group ID) tuples.
    /// - `idp_id`: The ID of the identity provider.
    async fn add_users_to_groups_expiring<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        memberships: Vec<(&'a str, &'a str)>,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        let (first_user_id, group_ids): (String, Vec<String>) = if memberships.is_empty() {
            (String::new(), Vec::new())
        } else {
            (
                memberships[0].0.to_string(),
                memberships.iter().map(|(_, g)| g.to_string()).collect(),
            )
        };
        let backend_driver = match memberships.first() {
            Some((user_id, _)) => self.driver_for_user(ctx, user_id).await?,
            None => self.backend_driver.clone(),
        };
        if let Some(vsc) = ctx.ctx() {
            let memberships_clone = memberships
                .iter()
                .map(|(u, g)| (u.to_string(), g.to_string()))
                .collect::<Vec<_>>();
            let idp_id = idp_id.to_string();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::GroupMembership {
                        user_id: first_user_id.clone(),
                        group_ids: group_ids.clone(),
                    },
                ),
                operation: async {
                    backend_driver
                        .add_users_to_groups_expiring(
                            ctx.state(),
                            memberships_clone
                                .iter()
                                .map(|(u, g)| (u.as_str(), g.as_str()))
                                .collect(),
                            &idp_id,
                        )
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            backend_driver
                .add_users_to_groups_expiring(ctx.state(), memberships, idp_id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::GroupMembership {
                        user_id: first_user_id,
                        group_ids,
                    },
                ))
                .await;
        }
        Ok(())
    }

    /// Authenticate user with the password auth method.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `auth`: The password authentication request.
    async fn authenticate_by_password<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        auth: &UserPasswordAuthRequest,
    ) -> Result<AuthenticationResult, IdentityProviderError> {
        let start = std::time::Instant::now();
        let result = self.authenticate_by_password_inner(ctx, auth).await;
        let reason = result
            .as_ref()
            .err()
            .map(crate::auth_metrics::identity_failure_reason);
        crate::auth_metrics::AUTH_METRICS.record_attempt(
            "password",
            start.elapsed().as_secs_f64(),
            reason,
        );
        result
    }

    /// Authenticate user with a TOTP passcode (ADR 0019 §3).
    ///
    /// Resolves the user (by ID, or by name + domain, mirroring
    /// [`Self::authenticate_by_password`]'s resolution), then verifies the
    /// passcode against every `type='totp'` credential registered for that
    /// user, accepting a match against the current or immediately preceding
    /// time-step.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `auth`: The TOTP authentication request.
    async fn authenticate_by_totp<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        auth: &UserTotpAuthRequest,
    ) -> Result<AuthenticationResult, IdentityProviderError> {
        let state = ctx.state();
        let mut auth = auth.clone();
        if auth.id.is_none() {
            if auth.name.is_none() {
                return Err(IdentityProviderError::UserIdOrNameWithDomain);
            }

            if let Some(ref mut domain) = auth.domain {
                if let Some(dname) = &domain.name {
                    let d = state
                        .provider
                        .get_resource_provider()
                        .find_domain_by_name(ctx, dname)
                        .await?
                        .ok_or(ResourceProviderError::DomainNotFound(dname.clone()))?;
                    domain.id = Some(d.id);
                } else if domain.id.is_none() {
                    return Err(IdentityProviderError::UserIdOrNameWithDomain);
                }
            } else {
                return Err(IdentityProviderError::UserIdOrNameWithDomain);
            }
        }

        // The resolution above guarantees either `auth.id`, or `auth.name` +
        // `auth.domain.id`, is populated at this point. The cheap existence
        // probe shared with password authentication resolves the reference to
        // the canonical user ID and rejects disabled accounts.
        let user_id = match self
            .driver_for(state, auth.domain.as_ref().and_then(|d| d.id.as_deref()))
            .await?
            .check_user_exist(
                state,
                auth.id.as_deref(),
                auth.name.as_deref(),
                auth.domain.as_ref().and_then(|d| d.id.as_deref()),
            )
            .await
        {
            Ok(user_id) => user_id,
            // Do not disclose account existence through the TOTP flow.
            Err(IdentityProviderError::UserNotFound(_)) => {
                return Err(AuthenticationError::TotpPasscodeInvalid.into());
            }
            Err(other) => return Err(other),
        };

        // Per-user rate limit (ADR-0022): keyed on the canonical user ID,
        // checked only after the user is confirmed to exist (Invariant 8) and
        // before any passcode verification. TOTP passcodes are 6-digit values
        // with no lockout counter on this path, so throttling is the only
        // brute-force control. Shares the `[rate_limit_user_auth]` bucket with
        // password authentication so alternating methods cannot double the
        // per-user quota.
        if let Err(retry_after) = state.rate_limiters.check_user(&user_id) {
            return Err(IdentityProviderError::TooManyRequests {
                retry_after_secs: retry_after.as_secs(),
            });
        }

        let user = self
            .get_user(ctx, &user_id)
            .await?
            .ok_or(AuthenticationError::TotpPasscodeInvalid)?;

        let credentials = state
            .provider
            .get_credential_provider()
            .list_credentials_for_user(ctx, &user.id, Some("totp"))
            .await?;

        let now = Utc::now().timestamp();
        let matched = credentials.iter().any(|credential| {
            let Ok(blob) = serde_json::from_str::<serde_json::Value>(&credential.blob) else {
                return false;
            };
            let Some(seed) = blob.get("seed").and_then(serde_json::Value::as_str) else {
                return false;
            };
            let digits = blob
                .get("digits")
                .and_then(serde_json::Value::as_u64)
                .map(|d| d as u32)
                .unwrap_or(6);
            let period = blob
                .get("period")
                .and_then(serde_json::Value::as_u64)
                .map(|d| d as u32)
                .unwrap_or(30);
            crate::credential::totp::verify_totp(seed, &auth.passcode, digits, period, now)
        });

        if !matched {
            return Err(AuthenticationError::TotpPasscodeInvalid.into());
        }

        Ok(AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Totp)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id(user.id.clone())
                        .user(user)
                        .build()?,
                ),
            })
            .build()?)
    }

    /// Create group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group`: The group details to create.
    async fn create_group<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError> {
        let mut res = group;
        let group_id = if let Some(gid) = &res.id {
            gid.clone()
        } else {
            let gid = Uuid::new_v4().simple().to_string();
            res.id = Some(gid.clone());
            gid
        };
        let backend_driver = self.driver_for(ctx.state(), Some(&res.domain_id)).await?;
        let group = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &backend_driver;
            let state = ctx.state();
            let res_clone = res.clone();
            let dispatch = crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::Group { id: group_id },
                ),
                operation: async {
                    backend_driver.create_group(state, res_clone).await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            };
            dispatch?
        } else {
            let group = backend_driver.create_group(ctx.state(), res).await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Group {
                        id: group.id.clone(),
                    },
                ))
                .await;
            group
        };

        Ok(group)
    }

    /// Create user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user`: The user details to create.
    async fn create_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user: UserCreate,
    ) -> Result<UserResponse, IdentityProviderError> {
        let mut mod_user = user;
        let user_id = if let Some(uid) = &mod_user.id {
            uid.clone()
        } else {
            let uid = Uuid::new_v4().simple().to_string();
            mod_user.id = Some(uid.clone());
            uid
        };
        if mod_user.enabled.is_none() {
            mod_user.enabled = Some(true);
        }
        if mod_user.domain_id.is_none() {
            mod_user.domain_id = scope_domain_id(ctx);
        }
        mod_user.validate()?;
        // Validate password against configured regex pattern.
        if let Some(ref password) = mod_user.password {
            let cfg = ctx.state().config_manager.config.read().await;
            cfg.security_compliance.validate_password(password)?;
        }
        let backend_driver = self
            .driver_for(ctx.state(), mod_user.domain_id.as_deref())
            .await?;
        let user = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &backend_driver;
            let state = ctx.state();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::User { id: user_id.clone() },
                ),
                operation: async {
                    backend_driver.create_user(state, mod_user).await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let user = backend_driver.create_user(ctx.state(), mod_user).await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::User {
                        id: user.id.clone(),
                    },
                ))
                .await;
            user
        };

        Ok(user)
    }

    /// Delete group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group_id`: The ID of the group to delete.
    async fn delete_group<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        let backend_driver = self.driver_for_group(ctx, group_id).await?;
        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::Group { id: group_id.to_string() },
                ),
                operation: async {
                    backend_driver.delete_group(ctx.state(), group_id).await?;
                    Ok::<(), IdentityProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            backend_driver.delete_group(ctx.state(), group_id).await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::Group {
                        id: group_id.to_string(),
                    },
                ))
                .await;
        }

        cache_remove(GROUP_CACHE_NS, group_id);
        Ok(())
    }

    /// Delete user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user to delete.
    async fn delete_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        let backend_driver = self.driver_for_user(ctx, user_id).await?;
        if let Some(vsc) = ctx.ctx() {
            // Audited delete – fail‐closed on pre‐audit failure.
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::User { id: user_id.to_string() },
                ),
                operation: async {
                    backend_driver.delete_user(ctx.state(), user_id).await?;
                    if self.caching {
                        self.user_id_domain_id_cache
                            .write()
                            .await
                            .remove(user_id);
                    }
                    ctx.state()
                        .provider
                        .get_credential_provider()
                        .delete_credentials_for_user(ctx, user_id)
                        .await?;
                    Ok::<(), IdentityProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            // No validated context – perform operation and emit on perimeter.
            backend_driver.delete_user(ctx.state(), user_id).await?;
            if self.caching {
                self.user_id_domain_id_cache.write().await.remove(user_id);
            }
            ctx.state()
                .provider
                .get_credential_provider()
                .delete_credentials_for_user(ctx, user_id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::User {
                        id: user_id.to_string(),
                    },
                ))
                .await;
        }

        cache_remove(USER_CACHE_NS, user_id);
        Ok(())
    }

    /// Get single user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<UserResponse>, IdentityProviderError>` - A `Result`
    ///   containing an `Option` with the user if found, or an `Error`.
    async fn get_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        if let Some(user) = cache_get::<UserResponse>(USER_CACHE_NS, user_id) {
            return Ok(Some(user));
        }
        let user = self
            .driver_for_user(ctx, user_id)
            .await?
            .get_user(ctx.state(), user_id)
            .await?;
        if let Some(user) = &user {
            if self.caching {
                self.user_id_domain_id_cache
                    .write()
                    .await
                    .insert(user_id.to_string(), user.domain_id.clone());
            }
            cache_set(USER_CACHE_NS, user_id, user.clone());
        }
        Ok(user)
    }

    /// Get `domain_id` of a user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    ///
    /// When the caching is enabled check for the cached value there. When no
    /// data is present for the key - invoke the backend driver and place
    /// the new value into the cache. Other operations (`get_user`,
    /// `delete_user`) update the cache with `delete_user` purging the value
    /// from the cache.
    async fn get_user_domain_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<String, IdentityProviderError> {
        if self.caching {
            if let Some(domain_id) = self.user_id_domain_id_cache.read().await.get(user_id) {
                return Ok(domain_id.clone());
            } else {
                let domain_id = self
                    .driver_for_user(ctx, user_id)
                    .await?
                    .get_user_domain_id(ctx.state(), user_id)
                    .await?;
                self.user_id_domain_id_cache
                    .write()
                    .await
                    .insert(user_id.to_string(), domain_id.clone());
                return Ok(domain_id);
            }
        } else {
            Ok(self
                .driver_for_user(ctx, user_id)
                .await?
                .get_user_domain_id(ctx.state(), user_id)
                .await?)
        }
    }

    async fn find_user_by_name_ci<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        name: &'a str,
    ) -> Result<Option<String>, IdentityProviderError> {
        self.driver_for(ctx.state(), Some(domain_id))
            .await?
            .find_user_by_name_ci(ctx.state(), domain_id, name)
            .await
    }

    /// Find federated user by `idp_id` and `unique_id`.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `idp_id`: The ID of the identity provider.
    /// - `unique_id`: The unique ID of the federated user.
    ///
    /// # Returns
    /// - `Result<Option<UserResponse>, IdentityProviderError>` - A `Result`
    ///   containing an `Option` with the user if found, or an `Error`.
    async fn find_federated_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        idp_id: &'a str,
        unique_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        self.backend_driver
            .find_federated_user(ctx.state(), idp_id, unique_id)
            .await
    }

    /// List users.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The parameters for listing users.
    async fn list_users<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &UserListParameters,
    ) -> Result<Vec<UserResponse>, IdentityProviderError> {
        self.driver_for(ctx.state(), params.domain_id.as_deref())
            .await?
            .list_users(ctx.state(), params)
            .await
    }

    /// List groups.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The parameters for listing groups.
    async fn list_groups<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &GroupListParameters,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        self.driver_for(ctx.state(), params.domain_id.as_deref())
            .await?
            .list_groups(ctx.state(), params)
            .await
    }

    /// Get single group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group_id`: The ID of the group to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<Group>, IdentityProviderError>` - A `Result` containing
    ///   an `Option` with the group if found, or an `Error`.
    async fn get_group<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        group_id: &'a str,
    ) -> Result<Option<Group>, IdentityProviderError> {
        if let Some(group) = cache_get::<Group>(GROUP_CACHE_NS, group_id) {
            return Ok(Some(group));
        }
        let group = self
            .driver_for_group(ctx, group_id)
            .await?
            .get_group(ctx.state(), group_id)
            .await?;
        if let Some(group) = &group {
            cache_set(GROUP_CACHE_NS, group_id, group.clone());
        }
        Ok(group)
    }

    /// List groups a user is a member of.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    async fn list_groups_of_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        self.driver_for_user(ctx, user_id)
            .await?
            .list_groups_of_user(ctx.state(), user_id)
            .await
    }

    /// List the IDs of users that are members of a group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group_id`: The ID of the group.
    async fn list_users_of_group<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        group_id: &'a str,
    ) -> Result<Vec<String>, IdentityProviderError> {
        self.driver_for_group(ctx, group_id)
            .await?
            .list_users_of_group(ctx.state(), group_id)
            .await
    }

    /// Find any group in `domain_id` whose name matches `name`,
    /// case-insensitively, regardless of which realm (or nothing) created it.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `domain_id`: The domain to search within.
    /// - `name`: The name to match, case-insensitively.
    async fn find_group_by_name_ci<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        name: &'a str,
    ) -> Result<Option<String>, IdentityProviderError> {
        self.driver_for(ctx.state(), Some(domain_id))
            .await?
            .find_group_by_name_ci(ctx.state(), domain_id, name)
            .await
    }

    /// Update group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `group_id`: The ID of the group to update.
    /// - `group`: The group update request.
    async fn update_group<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        group_id: &'a str,
        group: GroupUpdate,
    ) -> Result<Group, IdentityProviderError> {
        let backend_driver = self.driver_for_group(ctx, group_id).await?;
        let group = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &backend_driver;
            let state = ctx.state();
            let group_id_clone = group_id.to_string();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::Group { id: group_id_clone },
                ),
                operation: async {
                    backend_driver.update_group(state, group_id, group).await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let group = backend_driver
                .update_group(ctx.state(), group_id, group)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::Group {
                        id: group.id.clone(),
                    },
                ))
                .await;
            group
        };

        cache_set(GROUP_CACHE_NS, group_id, group.clone());
        Ok(group)
    }

    /// Remove the user from the group.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_id`: The ID of the group.
    async fn remove_user_from_group<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        let backend_driver = self.membership_backend(ctx, user_id, group_id).await?;
        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::GroupMembership {
                        user_id: user_id.to_string(),
                        group_ids: vec![group_id.to_string()],
                    },
                ),
                operation: async {
                    backend_driver
                        .remove_user_from_group(ctx.state(), user_id, group_id)
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            backend_driver
                .remove_user_from_group(ctx.state(), user_id, group_id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::GroupMembership {
                        user_id: user_id.to_string(),
                        group_ids: vec![group_id.to_string()],
                    },
                ))
                .await;
        }
        Ok(())
    }

    /// Remove the user from the group with expiration.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_id`: The ID of the group.
    /// - `idp_id`: The ID of the identity provider.
    async fn remove_user_from_group_expiring<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        group_id: &'a str,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        let backend_driver = self.membership_backend(ctx, user_id, group_id).await?;
        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::GroupMembership {
                        user_id: user_id.to_string(),
                        group_ids: vec![group_id.to_string()],
                    },
                ),
                operation: async {
                    backend_driver
                        .remove_user_from_group_expiring(ctx.state(), user_id, group_id, idp_id)
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            backend_driver
                .remove_user_from_group_expiring(ctx.state(), user_id, group_id, idp_id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::GroupMembership {
                        user_id: user_id.to_string(),
                        group_ids: vec![group_id.to_string()],
                    },
                ))
                .await;
        }
        Ok(())
    }

    /// Remove the user from multiple groups.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_ids`: A set of group IDs.
    async fn remove_user_from_groups<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        let group_ids_vec: Vec<String> = group_ids.iter().copied().map(|s| s.to_string()).collect();
        let backend_driver = self.driver_for_user(ctx, user_id).await?;
        if let Some(vsc) = ctx.ctx() {
            let group_ids_clone = group_ids_vec.clone();
            let user_id_str = user_id.to_string();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::GroupMembership {
                        user_id: user_id_str.clone(),
                        group_ids: group_ids_clone,
                    },
                ),
                operation: async {
                    backend_driver
                        .remove_user_from_groups(ctx.state(), &user_id_str, group_ids.iter().copied().collect())
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            backend_driver
                .remove_user_from_groups(ctx.state(), user_id, group_ids)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::GroupMembership {
                        user_id: user_id.to_string(),
                        group_ids: group_ids_vec,
                    },
                ))
                .await;
        }
        Ok(())
    }

    /// Remove the user from multiple expiring groups.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_ids`: A set of group IDs.
    /// - `idp_id`: The ID of the identity provider.
    async fn remove_user_from_groups_expiring<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
        idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        let group_ids_vec: Vec<String> = group_ids.iter().copied().map(|s| s.to_string()).collect();
        let backend_driver = self.driver_for_user(ctx, user_id).await?;
        if let Some(vsc) = ctx.ctx() {
            let group_ids_clone = group_ids_vec.clone();
            let user_id_str = user_id.to_string();
            let idp_id_str = idp_id.to_string();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::GroupMembership {
                        user_id: user_id_str.clone(),
                        group_ids: group_ids_clone,
                    },
                ),
                operation: async {
                    backend_driver
                        .remove_user_from_groups_expiring(ctx.state(), &user_id_str, group_ids.iter().copied().collect(), &idp_id_str)
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            backend_driver
                .remove_user_from_groups_expiring(ctx.state(), user_id, group_ids, idp_id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::GroupMembership {
                        user_id: user_id.to_string(),
                        group_ids: group_ids_vec,
                    },
                ))
                .await;
        }
        Ok(())
    }

    /// Set group memberships for the user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_ids`: A set of group IDs.
    async fn set_user_groups<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        let group_ids_vec: Vec<String> = group_ids.iter().copied().map(|s| s.to_string()).collect();
        let backend_driver = self.driver_for_user(ctx, user_id).await?;
        if let Some(vsc) = ctx.ctx() {
            let group_ids_clone = group_ids_vec.clone();
            let user_id_str = user_id.to_string();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::GroupMembership {
                        user_id: user_id_str.clone(),
                        group_ids: group_ids_clone,
                    },
                ),
                operation: async {
                    backend_driver
                        .set_user_groups(ctx.state(), &user_id_str, group_ids.iter().copied().collect())
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            backend_driver
                .set_user_groups(ctx.state(), user_id, group_ids)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::GroupMembership {
                        user_id: user_id.to_string(),
                        group_ids: group_ids_vec,
                    },
                ))
                .await;
        }
        Ok(())
    }

    /// Update user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user to update.
    /// - `user`: The user details to update.
    async fn update_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        user: UserUpdate,
    ) -> Result<UserResponse, IdentityProviderError> {
        user.validate()?;
        // Validate password against configured regex pattern.
        if let Some(ref password) = user.password {
            let cfg = ctx.state().config_manager.config.read().await;
            cfg.security_compliance.validate_password(password)?;
        }
        let backend_driver = self.driver_for_user(ctx, user_id).await?;
        let user = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &backend_driver;
            let state = ctx.state();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::User { id: user_id.to_string() },
                ),
                operation: async {
                    backend_driver.update_user(state, user_id, user).await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let user = backend_driver
                .update_user(ctx.state(), user_id, user)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::User {
                        id: user_id.to_string(),
                    },
                ))
                .await;
            user
        };

        cache_set(USER_CACHE_NS, user_id, user.clone());
        Ok(user)
    }

    /// Update user password.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user to update.
    /// - `original_password`: The current password for verification.
    /// - `new_password`: The new password to set.
    async fn update_user_password<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        original_password: SecretString,
        new_password: SecretString,
    ) -> Result<(), IdentityProviderError> {
        let cfg = ctx.state().config_manager.config.read().await;
        cfg.security_compliance.validate_password(&new_password)?;
        let backend_driver = self.driver_for_user(ctx, user_id).await?;
        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &backend_driver;
            let state = ctx.state();
            let user_id = user_id.to_string();
            let orig_pwd = original_password.clone();
            let new_pwd = new_password.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::User { id: user_id.clone() },
                ),
                operation: async {
                    backend_driver.update_user_password(state, &user_id, orig_pwd, new_pwd).await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            backend_driver
                .update_user_password(ctx.state(), user_id, original_password, new_password)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::User {
                        id: user_id.to_string(),
                    },
                ))
                .await;
        }
        cache_remove(USER_CACHE_NS, user_id);
        Ok(())
    }

    /// Set expiring group memberships for the user.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the user.
    /// - `group_ids`: A set of group IDs.
    /// - `idp_id`: The ID of the identity provider.
    /// - `last_verified`: The last verified date, if any.
    async fn set_user_groups_expiring<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
        idp_id: &'a str,
        last_verified: Option<&'a DateTime<Utc>>,
    ) -> Result<(), IdentityProviderError> {
        let group_ids_vec: Vec<String> = group_ids.iter().copied().map(|s| s.to_string()).collect();
        let backend_driver = self.driver_for_user(ctx, user_id).await?;
        if let Some(vsc) = ctx.ctx() {
            let group_ids_clone = group_ids_vec.clone();
            let user_id_str = user_id.to_string();
            let idp_id_str = idp_id.to_string();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::GroupMembership {
                        user_id: user_id_str.clone(),
                        group_ids: group_ids_clone,
                    },
                ),
                operation: async {
                    backend_driver
                        .set_user_groups_expiring(ctx.state(), &user_id_str, group_ids.iter().copied().collect(), &idp_id_str, last_verified)
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            backend_driver
                .set_user_groups_expiring(ctx.state(), user_id, group_ids, idp_id, last_verified)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::GroupMembership {
                        user_id: user_id.to_string(),
                        group_ids: group_ids_vec,
                    },
                ))
                .await;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "service/tests.rs"]
mod tests;
