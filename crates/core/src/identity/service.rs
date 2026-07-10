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
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::identity::*;

use crate::auth::{
    AuthenticationContext, AuthenticationError, AuthenticationResult, AuthenticationResultBuilder,
    ExecutionContext, IdentityInfo, PrincipalInfo, UserIdentityInfoBuilder,
};
use crate::events::AuditDispatchError;
use crate::identity::{IdentityApi, IdentityProviderError, backend::IdentityBackend};
use crate::plugin_manager::PluginManagerApi;
use crate::resource::error::ResourceProviderError;

/// Identity provider.
pub struct IdentityService {
    backend_driver: Arc<dyn IdentityBackend>,
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
        Ok(Self {
            backend_driver,
            caching: config.identity.caching,
            user_id_domain_id_cache: HashMap::new().into(),
        })
    }

    /// Create an IdentityService from a backend driver.
    ///
    /// # Parameters
    /// - `driver`: The backend driver.
    pub fn from_driver<I: IdentityBackend + 'static>(driver: I) -> Self {
        Self {
            backend_driver: Arc::new(driver),
            caching: false,
            user_id_domain_id_cache: HashMap::new().into(),
        }
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
                    self.backend_driver
                        .add_user_to_group(ctx.state(), user_id, group_id)
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
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
                    self.backend_driver
                        .add_user_to_group_expiring(ctx.state(), user_id, group_id, idp_id)
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
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
                    self.backend_driver
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
            self.backend_driver
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
                    self.backend_driver
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
            self.backend_driver
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
        if state.rate_limiters.user_auth_enabled() {
            match self
                .backend_driver
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

        self.backend_driver
            .authenticate_by_password(state, &auth)
            .await
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
            .backend_driver
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
        let group = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
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
            let group = self.backend_driver.create_group(ctx.state(), res).await?;
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

    /// Create service account.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `sa`: The service account details to create.
    async fn create_service_account<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        sa: ServiceAccountCreate,
    ) -> Result<ServiceAccount, IdentityProviderError> {
        let mut mod_sa = sa;
        if mod_sa.id.is_none() {
            mod_sa.id = Some(Uuid::new_v4().simple().to_string());
        }
        if mod_sa.enabled.is_none() {
            mod_sa.enabled = Some(true);
        }
        mod_sa.validate()?;
        let service_account = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let state = ctx.state();
            let sa_clone = mod_sa.clone();
            let sa_id = sa_clone.id.clone();
            let dispatch = crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::ServiceAccount { id: sa_id.unwrap_or_default() },
                ),
                operation: async {
                    backend_driver.create_service_account(state, sa_clone).await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            };
            dispatch?
        } else {
            let sa = self
                .backend_driver
                .create_service_account(ctx.state(), mod_sa)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::ServiceAccount { id: sa.id.clone() },
                ))
                .await;
            sa
        };

        Ok(service_account)
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
        mod_user.validate()?;
        // Validate password against configured regex pattern.
        if let Some(ref password) = mod_user.password {
            let cfg = ctx.state().config_manager.config.read().await;
            cfg.security_compliance.validate_password(password)?;
        }
        let user = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
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
            let user = self
                .backend_driver
                .create_user(ctx.state(), mod_user)
                .await?;
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
        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::Group { id: group_id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_group(ctx.state(), group_id).await?;
                    Ok::<(), IdentityProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
                .delete_group(ctx.state(), group_id)
                .await?;
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
        if let Some(vsc) = ctx.ctx() {
            // Audited delete – fail‑closed on pre‑audit failure.
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::User { id: user_id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_user(ctx.state(), user_id).await?;
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
            self.backend_driver
                .delete_user(ctx.state(), user_id)
                .await?;
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

        Ok(())
    }

    /// Get a service account by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `user_id`: The ID of the service account to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<ServiceAccount>, IdentityProviderError>` - A `Result`
    ///   containing an `Option` with the service account if found, or an
    ///   `Error`.
    async fn get_service_account<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<Option<ServiceAccount>, IdentityProviderError> {
        self.backend_driver
            .get_service_account(ctx.state(), user_id)
            .await
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
        let user = self.backend_driver.get_user(ctx.state(), user_id).await?;
        if self.caching
            && let Some(user) = &user
        {
            self.user_id_domain_id_cache
                .write()
                .await
                .insert(user_id.to_string(), user.domain_id.clone());
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
                    .backend_driver
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
                .backend_driver
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
        self.backend_driver
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
        self.backend_driver.list_users(ctx.state(), params).await
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
        self.backend_driver.list_groups(ctx.state(), params).await
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
        self.backend_driver.get_group(ctx.state(), group_id).await
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
        self.backend_driver
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
        self.backend_driver
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
        self.backend_driver
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
        let group = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
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
            let group = self
                .backend_driver
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
                    self.backend_driver
                        .remove_user_from_group(ctx.state(), user_id, group_id)
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
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
                    self.backend_driver
                        .remove_user_from_group_expiring(ctx.state(), user_id, group_id, idp_id)
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
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
                    self.backend_driver
                        .remove_user_from_groups(ctx.state(), &user_id_str, group_ids.iter().copied().collect())
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
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
                    self.backend_driver
                        .remove_user_from_groups_expiring(ctx.state(), &user_id_str, group_ids.iter().copied().collect(), &idp_id_str)
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
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
                    self.backend_driver
                        .set_user_groups(ctx.state(), &user_id_str, group_ids.iter().copied().collect())
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
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
        let user = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
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
            let user = self
                .backend_driver
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
        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
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
            self.backend_driver
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
                    self.backend_driver
                        .set_user_groups_expiring(ctx.state(), &user_id_str, group_ids.iter().copied().collect(), &idp_id_str, last_verified)
                        .await
                },
                on_audit_error: |_: AuditDispatchError| IdentityProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
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
mod tests {
    use serde_json::json;

    use openstack_keystone_config::Config;
    use openstack_keystone_core_types::credential::{Credential, CredentialBuilder};
    use openstack_keystone_core_types::identity::{
        UserCreateBuilder, UserResponseBuilder, UserUpdateBuilder,
    };

    use super::*;
    use crate::credential::MockCredentialProvider;
    use crate::identity::backend::MockIdentityBackend;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::tests::get_mocked_state;

    fn get_config_with_password_regex(regex_str: &str) -> Config {
        let mut config = Config::default();
        config.security_compliance.password_regex = Some(regex_str.to_string());
        // Compile the regex as Config::load_all would do.
        config.security_compliance.compile_regex().unwrap();
        config
    }

    #[tokio::test]
    async fn test_create_user() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockIdentityBackend::default();
        backend.expect_create_user().returning(|_, _| {
            Ok(UserResponseBuilder::default()
                .id("id")
                .domain_id("domain_id")
                .enabled(true)
                .name("name")
                .build()
                .unwrap())
        });
        let provider = IdentityService::from_driver(backend);

        assert_eq!(
            provider
                .create_user(
                    &ExecutionContext::internal(&state),
                    UserCreateBuilder::default()
                        .name("uname")
                        .domain_id("did")
                        .build()
                        .unwrap()
                )
                .await
                .unwrap(),
            UserResponseBuilder::default()
                .domain_id("domain_id")
                .enabled(true)
                .id("id")
                .name("name")
                .build()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_user() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_get_user()
            .withf(|_, uid: &'_ str| uid == "uid")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .id("id")
                        .domain_id("domain_id")
                        .enabled(true)
                        .name("name")
                        .build()
                        .unwrap(),
                ))
            });
        let provider = IdentityService::from_driver(backend);

        assert_eq!(
            provider
                .get_user(&ExecutionContext::internal(&state), "uid")
                .await
                .unwrap()
                .expect("user should be there"),
            UserResponseBuilder::default()
                .domain_id("domain_id")
                .enabled(true)
                .id("id")
                .name("name")
                .build()
                .unwrap(),
        );
    }

    #[tokio::test]
    async fn test_get_user_domain_id() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_get_user_domain_id()
            .withf(|_, uid: &'_ str| uid == "uid")
            .times(2) // only 2 times
            .returning(|_, _| Ok("did".into()));
        backend
            .expect_get_user_domain_id()
            .withf(|_, uid: &'_ str| uid == "missing")
            .returning(|_, _| Err(IdentityProviderError::UserNotFound("missing".into())));
        let mut provider = IdentityService::from_driver(backend);
        provider.caching = true;

        assert_eq!(
            provider
                .get_user_domain_id(&ExecutionContext::internal(&state), "uid")
                .await
                .unwrap(),
            "did"
        );
        assert_eq!(
            provider
                .get_user_domain_id(&ExecutionContext::internal(&state), "uid")
                .await
                .unwrap(),
            "did",
            "second time data extracted from cache"
        );
        assert!(
            provider
                .get_user_domain_id(&ExecutionContext::internal(&state), "missing")
                .await
                .is_err()
        );
        provider.caching = false;
        assert_eq!(
            provider
                .get_user_domain_id(&ExecutionContext::internal(&state), "uid")
                .await
                .unwrap(),
            "did",
            "third time backend is again triggered causing total of 2 invocations"
        );
    }

    #[tokio::test]
    async fn test_delete_user() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_delete_credentials_for_user()
            .withf(|_, uid: &'_ str| uid == "uid")
            .returning(|_, _| Ok(()));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_credential(credential_mock)),
        )
        .await;
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_delete_user()
            .withf(|_, uid: &'_ str| uid == "uid")
            .returning(|_, _| Ok(()));
        let provider = IdentityService::from_driver(backend);

        assert!(
            provider
                .delete_user(&ExecutionContext::internal(&state), "uid")
                .await
                .is_ok()
        );
    }

    /// RFC 6238 Appendix B seed/passcode used across the TOTP tests below,
    /// with an oversized `period` so the resulting HOTP counter (`now /
    /// period`) stays `0` for the foreseeable future regardless of the
    /// wall-clock time the test actually runs at.
    fn totp_credential(user_id: &str) -> Credential {
        CredentialBuilder::default()
            .id("cred_id")
            .blob(
                json!({
                    "seed": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                    "digits": 8,
                    "period": 10_000_000_000u64,
                })
                .to_string(),
            )
            .r#type("totp")
            .user_id(user_id)
            .build()
            .unwrap()
    }

    const TOTP_PASSCODE_COUNTER_0: &str = "84755224";

    fn totp_user(user_id: &str, domain_id: &str, enabled: bool) -> UserResponse {
        UserResponseBuilder::default()
            .id(user_id)
            .domain_id(domain_id)
            .enabled(enabled)
            .name("uname")
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_authenticate_by_totp_success_by_id() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_list_credentials_for_user()
            .withf(|_, uid: &'_ str, r#type: &Option<&str>| uid == "uid" && *r#type == Some("totp"))
            .returning(|_, _, _| Ok(vec![totp_credential("uid")]));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_credential(credential_mock)),
        )
        .await;
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_check_user_exist()
            .withf(|_, id, name, domain| *id == Some("uid") && name.is_none() && domain.is_none())
            .returning(|_, _, _, _| Ok("uid".to_string()));
        backend
            .expect_get_user()
            .withf(|_, uid: &'_ str| uid == "uid")
            .returning(|_, _| Ok(Some(totp_user("uid", "did", true))));
        let provider = IdentityService::from_driver(backend);

        let result = provider
            .authenticate_by_totp(
                &ExecutionContext::internal(&state),
                &UserTotpAuthRequestBuilder::default()
                    .id("uid")
                    .passcode(TOTP_PASSCODE_COUNTER_0)
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(result.context, AuthenticationContext::Totp);
        assert_eq!(result.principal.get_user_id(), "uid");
    }

    /// ADR-0022 Invariants 4 and 8 on the TOTP path: the per-user bucket is
    /// keyed on the confirmed user ID and fires before any credential is
    /// listed or passcode verified. The bucket is exhausted directly through
    /// `check_user` (simulating a prior authentication attempt) so timing
    /// cannot replenish it mid-test.
    #[tokio::test]
    async fn test_authenticate_by_totp_rate_limited() {
        let mut credential_mock = MockCredentialProvider::default();
        // Rejected before verification: credentials must never be listed.
        credential_mock.expect_list_credentials_for_user().times(0);
        let mut config = openstack_keystone_config::Config::default();
        config.rate_limit_user_auth = openstack_keystone_config::RateLimitSection {
            enabled: true,
            burst_size: 1,
            replenish_rate_per_second: 1,
        };
        let state = get_mocked_state(
            Some(config),
            Some(Provider::mocked_builder().mock_credential(credential_mock)),
        )
        .await;
        assert!(state.rate_limiters.check_user("uid").is_ok());

        let mut backend = MockIdentityBackend::default();
        backend
            .expect_check_user_exist()
            .returning(|_, _, _, _| Ok("uid".to_string()));
        // Rejected before the full user is ever loaded.
        backend.expect_get_user().times(0);
        let provider = IdentityService::from_driver(backend);

        let result = provider
            .authenticate_by_totp(
                &ExecutionContext::internal(&state),
                &UserTotpAuthRequestBuilder::default()
                    .id("uid")
                    .passcode(TOTP_PASSCODE_COUNTER_0)
                    .build()
                    .unwrap(),
            )
            .await;

        assert!(matches!(
            result,
            Err(IdentityProviderError::TooManyRequests { retry_after_secs }) if retry_after_secs >= 1
        ));
    }

    #[tokio::test]
    async fn test_authenticate_by_totp_wrong_passcode() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_list_credentials_for_user()
            .returning(|_, _, _| Ok(vec![totp_credential("uid")]));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_credential(credential_mock)),
        )
        .await;
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_check_user_exist()
            .returning(|_, _, _, _| Ok("uid".to_string()));
        backend
            .expect_get_user()
            .returning(|_, _| Ok(Some(totp_user("uid", "did", true))));
        let provider = IdentityService::from_driver(backend);

        let result = provider
            .authenticate_by_totp(
                &ExecutionContext::internal(&state),
                &UserTotpAuthRequestBuilder::default()
                    .id("uid")
                    .passcode("00000000")
                    .build()
                    .unwrap(),
            )
            .await;

        assert!(matches!(
            result,
            Err(IdentityProviderError::Authentication {
                source: AuthenticationError::TotpPasscodeInvalid
            })
        ));
    }

    #[tokio::test]
    async fn test_authenticate_by_totp_no_credentials() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_list_credentials_for_user()
            .returning(|_, _, _| Ok(vec![]));
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_credential(credential_mock)),
        )
        .await;
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_check_user_exist()
            .returning(|_, _, _, _| Ok("uid".to_string()));
        backend
            .expect_get_user()
            .returning(|_, _| Ok(Some(totp_user("uid", "did", true))));
        let provider = IdentityService::from_driver(backend);

        let result = provider
            .authenticate_by_totp(
                &ExecutionContext::internal(&state),
                &UserTotpAuthRequestBuilder::default()
                    .id("uid")
                    .passcode(TOTP_PASSCODE_COUNTER_0)
                    .build()
                    .unwrap(),
            )
            .await;

        assert!(matches!(
            result,
            Err(IdentityProviderError::Authentication {
                source: AuthenticationError::TotpPasscodeInvalid
            })
        ));
    }

    #[tokio::test]
    async fn test_authenticate_by_totp_user_disabled() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock.expect_list_credentials_for_user().times(0);
        let state = get_mocked_state(
            None,
            Some(Provider::mocked_builder().mock_credential(credential_mock)),
        )
        .await;
        let mut backend = MockIdentityBackend::default();
        // The cheap probe rejects the disabled account before any credential
        // work; the full user is never loaded.
        backend
            .expect_check_user_exist()
            .returning(|_, _, _, _| Err(AuthenticationError::UserDisabled("uid".into()).into()));
        backend.expect_get_user().times(0);
        let provider = IdentityService::from_driver(backend);

        let result = provider
            .authenticate_by_totp(
                &ExecutionContext::internal(&state),
                &UserTotpAuthRequestBuilder::default()
                    .id("uid")
                    .passcode(TOTP_PASSCODE_COUNTER_0)
                    .build()
                    .unwrap(),
            )
            .await;

        assert!(matches!(
            result,
            Err(IdentityProviderError::Authentication {
                source: AuthenticationError::UserDisabled(id)
            }) if id == "uid"
        ));
    }

    #[tokio::test]
    async fn test_authenticate_by_totp_user_not_found() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_check_user_exist()
            .returning(|_, _, _, _| Err(IdentityProviderError::UserNotFound("uid".into())));
        let provider = IdentityService::from_driver(backend);

        let result = provider
            .authenticate_by_totp(
                &ExecutionContext::internal(&state),
                &UserTotpAuthRequestBuilder::default()
                    .id("uid")
                    .passcode(TOTP_PASSCODE_COUNTER_0)
                    .build()
                    .unwrap(),
            )
            .await;

        assert!(matches!(
            result,
            Err(IdentityProviderError::Authentication {
                source: AuthenticationError::TotpPasscodeInvalid
            })
        ));
    }

    #[tokio::test]
    async fn test_authenticate_by_totp_success_by_name_and_domain() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_list_credentials_for_user()
            .withf(|_, uid: &'_ str, r#type: &Option<&str>| uid == "uid" && *r#type == Some("totp"))
            .returning(|_, _, _| Ok(vec![totp_credential("uid")]));
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_find_domain_by_name()
            .withf(|_, name: &'_ str| name == "dname")
            .returning(|_, _| {
                Ok(Some(openstack_keystone_core_types::resource::Domain {
                    id: "did".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_credential(credential_mock)
                    .mock_resource(resource_mock),
            ),
        )
        .await;
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_check_user_exist()
            .withf(|_, id, name, domain| {
                id.is_none() && *name == Some("uname_lookup") && *domain == Some("did")
            })
            .returning(|_, _, _, _| Ok("uid".to_string()));
        backend
            .expect_get_user()
            .withf(|_, uid: &'_ str| uid == "uid")
            .returning(|_, _| Ok(Some(totp_user("uid", "did", true))));
        let provider = IdentityService::from_driver(backend);

        let result = provider
            .authenticate_by_totp(
                &ExecutionContext::internal(&state),
                &UserTotpAuthRequestBuilder::default()
                    .name("uname_lookup")
                    .domain(DomainBuilder::default().name("dname").build().unwrap())
                    .passcode(TOTP_PASSCODE_COUNTER_0)
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(result.context, AuthenticationContext::Totp);
        assert_eq!(result.principal.get_user_id(), "uid");
    }

    /// ADR-0022 Invariants 4 and 8 at the provider level: the enabled
    /// per-user bucket is keyed on the ID resolved by the cheap probe and
    /// fires before the backend performs any password verification. The
    /// bucket is exhausted directly through `check_user` (simulating a prior
    /// attempt) so timing cannot replenish it mid-test.
    #[tokio::test]
    async fn test_authenticate_by_password_rate_limited() {
        let mut config = openstack_keystone_config::Config::default();
        config.rate_limit_user_auth = openstack_keystone_config::RateLimitSection {
            enabled: true,
            burst_size: 1,
            replenish_rate_per_second: 1,
        };
        let state = get_mocked_state(Some(config), None).await;
        assert!(state.rate_limiters.check_user("uid").is_ok());

        let mut backend = MockIdentityBackend::default();
        backend
            .expect_check_user_exist()
            .withf(|_, id, name, domain| *id == Some("uid") && name.is_none() && domain.is_none())
            .returning(|_, _, _, _| Ok("uid".to_string()));
        // The expensive backend authentication must never be reached.
        backend.expect_authenticate_by_password().times(0);
        let provider = IdentityService::from_driver(backend);

        let result = provider
            .authenticate_by_password(
                &ExecutionContext::internal(&state),
                &UserPasswordAuthRequest {
                    id: Some("uid".into()),
                    password: "pass".into(),
                    ..Default::default()
                },
            )
            .await;

        assert!(matches!(
            result,
            Err(IdentityProviderError::TooManyRequests { retry_after_secs }) if retry_after_secs >= 1
        ));
    }

    /// ADR-0022 Invariant 8: unknown users never touch the limiter store.
    /// The probe misses and the request falls through to the backend, which
    /// keeps the uniform dummy-hash credentials error — never a 429 — no
    /// matter how often it is retried.
    #[tokio::test]
    async fn test_authenticate_by_password_unknown_user_uniform_error() {
        let mut config = openstack_keystone_config::Config::default();
        config.rate_limit_user_auth = openstack_keystone_config::RateLimitSection {
            enabled: true,
            burst_size: 1,
            replenish_rate_per_second: 1,
        };
        let state = get_mocked_state(Some(config), None).await;

        let mut backend = MockIdentityBackend::default();
        backend
            .expect_check_user_exist()
            .returning(|_, _, _, _| Err(IdentityProviderError::UserNotFound("ghost".into())));
        backend
            .expect_authenticate_by_password()
            .times(2)
            .returning(|_, _| Err(AuthenticationError::UserNameOrPasswordWrong.into()));
        let provider = IdentityService::from_driver(backend);

        for _ in 0..2 {
            let result = provider
                .authenticate_by_password(
                    &ExecutionContext::internal(&state),
                    &UserPasswordAuthRequest {
                        id: Some("ghost".into()),
                        password: "pass".into(),
                        ..Default::default()
                    },
                )
                .await;
            assert!(matches!(
                result,
                Err(IdentityProviderError::Authentication {
                    source: AuthenticationError::UserNameOrPasswordWrong
                })
            ));
        }
    }

    /// With the bucket disabled (the default), the probe is skipped
    /// entirely: rate limiting adds no extra query to the authentication
    /// hot path.
    #[tokio::test]
    async fn test_authenticate_by_password_probe_skipped_when_disabled() {
        let state = get_mocked_state(None, None).await;

        let mut backend = MockIdentityBackend::default();
        backend.expect_check_user_exist().times(0);
        backend
            .expect_authenticate_by_password()
            .once()
            .returning(|_, _| Err(AuthenticationError::UserNameOrPasswordWrong.into()));
        let provider = IdentityService::from_driver(backend);

        let result = provider
            .authenticate_by_password(
                &ExecutionContext::internal(&state),
                &UserPasswordAuthRequest {
                    id: Some("uid".into()),
                    password: "pass".into(),
                    ..Default::default()
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(IdentityProviderError::Authentication {
                source: AuthenticationError::UserNameOrPasswordWrong
            })
        ));
    }

    /// Within quota the request proceeds to the backend normally.
    #[tokio::test]
    async fn test_authenticate_by_password_within_quota_reaches_backend() {
        let mut config = openstack_keystone_config::Config::default();
        config.rate_limit_user_auth = openstack_keystone_config::RateLimitSection {
            enabled: true,
            burst_size: 100,
            replenish_rate_per_second: 10,
        };
        let state = get_mocked_state(Some(config), None).await;

        let mut backend = MockIdentityBackend::default();
        backend
            .expect_check_user_exist()
            .returning(|_, _, _, _| Ok("uid".to_string()));
        backend
            .expect_authenticate_by_password()
            .once()
            .returning(|_, _| Err(AuthenticationError::UserNameOrPasswordWrong.into()));
        let provider = IdentityService::from_driver(backend);

        let result = provider
            .authenticate_by_password(
                &ExecutionContext::internal(&state),
                &UserPasswordAuthRequest {
                    id: Some("uid".into()),
                    password: "pass".into(),
                    ..Default::default()
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(IdentityProviderError::Authentication {
                source: AuthenticationError::UserNameOrPasswordWrong
            })
        ));
    }

    /// Password regex rejects invalid password on user creation.
    #[tokio::test]
    async fn test_create_user_password_regex_rejected() {
        let config = get_config_with_password_regex(r"^.{7,}$");
        let state = get_mocked_state(Some(config), None).await;
        let provider = IdentityService::from_driver(MockIdentityBackend::default());

        let result = provider
            .create_user(
                &ExecutionContext::internal(&state),
                UserCreateBuilder::default()
                    .name("uname")
                    .domain_id("did")
                    .password("short")
                    .build()
                    .unwrap(),
            )
            .await;

        assert!(
            matches!(result, Err(IdentityProviderError::SecurityCompliance(..))),
            "expected SecurityCompliance error for invalid password"
        );
    }

    /// Password regex accepts valid password on user creation and backend is
    /// invoked.
    #[tokio::test]
    async fn test_create_user_password_regex_accepted() {
        let config = get_config_with_password_regex(r"^.{3,}$");
        let state = get_mocked_state(Some(config), None).await;
        let mut backend = MockIdentityBackend::default();
        backend.expect_create_user().returning(|_, _| {
            Ok(UserResponseBuilder::default()
                .id("id")
                .domain_id("domain_id")
                .enabled(true)
                .name("name")
                .build()
                .unwrap())
        });
        let provider = IdentityService::from_driver(backend);

        assert!(
            provider
                .create_user(
                    &ExecutionContext::internal(&state),
                    UserCreateBuilder::default()
                        .name("uname")
                        .domain_id("did")
                        .password("Abc1")
                        .build()
                        .unwrap(),
                )
                .await
                .is_ok(),
            "password matching regex should reach backend"
        );
    }

    /// No password on user creation skips validation and backend is invoked.
    #[tokio::test]
    async fn test_create_user_no_password() {
        let config = get_config_with_password_regex(r"^.{7,}$");
        let state = get_mocked_state(Some(config), None).await;
        let mut backend = MockIdentityBackend::default();
        backend.expect_create_user().returning(|_, _| {
            Ok(UserResponseBuilder::default()
                .id("id")
                .domain_id("domain_id")
                .enabled(true)
                .name("name")
                .build()
                .unwrap())
        });
        let provider = IdentityService::from_driver(backend);

        assert!(
            provider
                .create_user(
                    &ExecutionContext::internal(&state),
                    UserCreateBuilder::default()
                        .name("uname")
                        .domain_id("did")
                        .build()
                        .unwrap(),
                )
                .await
                .is_ok(),
            "no password should skip validation"
        );
    }

    /// Password regex rejects invalid password on user update.
    #[tokio::test]
    async fn test_update_user_password_regex_rejected() {
        let config = get_config_with_password_regex(r"^.{7,}$");
        let state = get_mocked_state(Some(config), None).await;
        let provider = IdentityService::from_driver(MockIdentityBackend::default());

        let result = provider
            .update_user(
                &ExecutionContext::internal(&state),
                "uid",
                UserUpdateBuilder::default()
                    .password("short")
                    .build()
                    .unwrap(),
            )
            .await;

        assert!(
            matches!(result, Err(IdentityProviderError::SecurityCompliance(..))),
            "expected SecurityCompliance error for invalid password on update"
        );
    }

    /// Password regex accepts valid password on user update and backend is
    /// invoked.
    #[tokio::test]
    async fn test_update_user_password_regex_accepted() {
        let config = get_config_with_password_regex(r"^.{3,}$");
        let state = get_mocked_state(Some(config), None).await;
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_update_user()
            .returning(|_, _: &'_ str, _: UserUpdate| {
                Ok(UserResponseBuilder::default()
                    .id("id")
                    .domain_id("domain_id")
                    .enabled(true)
                    .name("name")
                    .build()
                    .unwrap())
            });
        let provider = IdentityService::from_driver(backend);

        assert!(
            provider
                .update_user(
                    &ExecutionContext::internal(&state),
                    "uid",
                    UserUpdateBuilder::default()
                        .password("Abc1")
                        .build()
                        .unwrap(),
                )
                .await
                .is_ok(),
            "password matching regex on update should reach backend"
        );
    }

    /// No password on user update skips validation and backend is invoked.
    #[tokio::test]
    async fn test_update_user_no_password() {
        let config = get_config_with_password_regex(r"^.{7,}$");
        let state = get_mocked_state(Some(config), None).await;
        let mut backend = MockIdentityBackend::default();
        backend
            .expect_update_user()
            .returning(|_, _: &'_ str, _: UserUpdate| {
                Ok(UserResponseBuilder::default()
                    .id("id")
                    .domain_id("domain_id")
                    .enabled(true)
                    .name("name")
                    .build()
                    .unwrap())
            });
        let provider = IdentityService::from_driver(backend);

        assert!(
            provider
                .update_user(
                    &ExecutionContext::internal(&state),
                    "uid",
                    UserUpdateBuilder::default()
                        .name("new_name")
                        .build()
                        .unwrap(),
                )
                .await
                .is_ok(),
            "no password on update should skip validation"
        );
    }
}
