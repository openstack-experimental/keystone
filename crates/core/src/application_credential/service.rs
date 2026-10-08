// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! # Application credentials provider
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use rand::{RngExt, rng};
use secrecy::SecretString;
use tracing::warn;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::application_credential::*;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::role::{Role, RoleListParameters};

use crate::application_credential::{
    ApplicationCredentialApi, ApplicationCredentialProviderError,
    backend::ApplicationCredentialBackend,
};
use crate::auth::{
    AuthenticationContext, AuthenticationResult, AuthenticationResultBuilder, ExecutionContext,
    IdentityInfo, PrincipalInfo, UserIdentityInfoBuilder,
};

use crate::events::AuditDispatchError;
use crate::identity::user_ref::user_matches_ref;
use crate::plugin_manager::PluginManagerApi;
/// Application Credential Provider.
pub struct ApplicationCredentialService {
    backend_driver: Arc<dyn ApplicationCredentialBackend>,
}

impl ApplicationCredentialService {
    /// Create a new application credential service.
    ///
    /// # Parameters
    /// - `config`: The service configuration.
    /// - `plugin_manager`: The plugin manager to retrieve the backend driver.
    ///
    /// # Returns
    /// - `Result<Self, ApplicationCredentialProviderError>` - The created
    ///   service or an error.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, ApplicationCredentialProviderError> {
        let backend_driver = plugin_manager
            .get_application_credential_backend(config.application_credential.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

impl ApplicationCredentialService {
    /// Resolve the user reference into the user ID.
    ///
    /// Returns `None` when the referenced user (or its domain) does not
    /// exist.
    async fn resolve_user_ref<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user: &UserAuthRef,
    ) -> Result<Option<String>, ApplicationCredentialProviderError> {
        let state = ctx.state();
        if let Some(id) = &user.id {
            // The ID takes precedence for the lookup; name and domain, when
            // given as well, must match the user (same as password/TOTP).
            let Some(found) = state
                .provider
                .get_identity_provider()
                .get_user(ctx, id)
                .await
                .map_err(|e| ApplicationCredentialProviderError::Driver(e.to_string()))?
            else {
                return Ok(None);
            };
            return Ok(
                user_matches_ref(ctx, &found, user.name.as_deref(), user.domain.as_ref())
                    .await
                    .map_err(|e| ApplicationCredentialProviderError::Driver(e.to_string()))?
                    .then_some(found.id),
            );
        }
        let (Some(name), Some(domain)) = (&user.name, &user.domain) else {
            return Ok(None);
        };
        let domain_id = if let Some(did) = &domain.id {
            did.clone()
        } else if let Some(dname) = &domain.name {
            match state
                .provider
                .get_resource_provider()
                .find_domain_by_name(ctx, dname)
                .await
                .map_err(|e| ApplicationCredentialProviderError::Driver(e.to_string()))?
            {
                Some(d) => d.id,
                None => return Ok(None),
            }
        } else {
            return Ok(None);
        };
        state
            .provider
            .get_identity_provider()
            .find_user_by_name_ci(ctx, &domain_id, name)
            .await
            .map_err(|e| ApplicationCredentialProviderError::Driver(e.to_string()))
    }

    /// Find the credential addressed by the authentication request.
    ///
    /// Returns `None` when no credential matches, including when the
    /// supplied user reference does not point to the credential owner.
    async fn resolve_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        data: &ApplicationCredentialAuthData,
    ) -> Result<Option<ApplicationCredential>, ApplicationCredentialProviderError> {
        match data {
            ApplicationCredentialAuthData::Id(by_id) => {
                let Some(app_cred) = self.get_application_credential(ctx, &by_id.id).await? else {
                    return Ok(None);
                };
                if let Some(user) = &by_id.user
                    && self.resolve_user_ref(ctx, user).await?.as_deref()
                        != Some(app_cred.user_id.as_str())
                {
                    return Ok(None);
                }
                Ok(Some(app_cred))
            }
            ApplicationCredentialAuthData::Name(by_name) => {
                let Some(user_id) = self.resolve_user_ref(ctx, &by_name.user).await? else {
                    return Ok(None);
                };
                let params = ApplicationCredentialListParameters {
                    name: Some(by_name.name.clone()),
                    user_id,
                    ..Default::default()
                };
                Ok(self
                    .list_application_credentials(ctx, &params)
                    .await?
                    .into_iter()
                    .next())
            }
        }
    }
}

#[async_trait]
impl ApplicationCredentialApi for ApplicationCredentialService {
    /// Authenticate using an application credential.
    ///
    /// Resolves the credential (by ID, or by name + owning user), verifies
    /// that an optionally supplied user reference matches the credential
    /// owner, applies the per-user rate limit, verifies the secret against
    /// the stored hash and checks that the credential has not expired.
    ///
    /// This only authenticates the credential. Whether the owning user,
    /// bound project and project domain are enabled, and whether the
    /// credential may be used for a given scope, is validated centrally
    /// by [`SecurityContext`](crate::auth::SecurityContext) and
    /// `ValidatedSecurityContext`, which also resolves the user domain.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `auth`: The application credential authentication request.
    ///
    /// # Returns
    /// - `Result<AuthenticationResult, ApplicationCredentialProviderError>` -
    ///   The authentication result populated with
    ///   [`AuthenticationContext::ApplicationCredential`] on success, or an
    ///   error.
    #[tracing::instrument(
        name = "provider.application_credential.authenticate_by_application_credential",
        level = "debug",
        skip_all
    )]
    async fn authenticate_by_application_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        auth: &ApplicationCredentialAuthRequest,
    ) -> Result<AuthenticationResult, ApplicationCredentialProviderError> {
        let state = ctx.state();

        // --- 1. Resolve the credential ---
        let app_cred = match self.resolve_credential(ctx, &auth.credential).await? {
            Some(app_cred) => app_cred,
            None => {
                // Unknown credentials never touch the rate limiter store
                // (ADR-0022 Invariant 8). Burn a dummy hash verification
                // instead so the not-found path is indistinguishable from a
                // wrong secret by timing.
                let _ = self
                    .backend_driver
                    .verify_application_credential_secret(state, "", &auth.secret)
                    .await;
                return Err(ApplicationCredentialProviderError::AuthenticationFailed);
            }
        };

        // --- 2. Rate limit (ADR-0022) ---
        if state.rate_limiters.user_auth_enabled()
            && let Err(retry_after) = state.rate_limiters.check_user(&app_cred.user_id)
        {
            return Err(ApplicationCredentialProviderError::TooManyRequests {
                retry_after_secs: retry_after.as_secs(),
            });
        }

        // --- 3. Verify the secret ---
        self.backend_driver
            .verify_application_credential_secret(state, &app_cred.id, &auth.secret)
            .await?;

        // --- 4. Check credential expiration ---
        if let Some(expires_at) = app_cred.expires_at
            && expires_at < Utc::now()
        {
            return Err(ApplicationCredentialProviderError::ApplicationCredentialExpired);
        }

        // --- 5. Fetch user for identity info ---
        let user = state
            .provider
            .get_identity_provider()
            .get_user(ctx, &app_cred.user_id)
            .await
            .map_err(|_| ApplicationCredentialProviderError::AuthenticationFailed)?
            .ok_or(ApplicationCredentialProviderError::AuthenticationFailed)?;

        // --- 6. Build the authentication result ---
        //
        // The user domain is intentionally not resolved here: like for the
        // other methods it is resolved (and verified) centrally by
        // `ValidatedSecurityContext::new_for_scope`.
        Ok(AuthenticationResultBuilder::default()
            .context(AuthenticationContext::ApplicationCredential {
                application_credential: app_cred,
                token: None,
            })
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

    /// Create a standalone access rule owned by a user.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `rule`: The access rule to create (its `user_id` identifies the
    ///   owner).
    ///
    /// # Returns
    /// - `Result<AccessRule, ApplicationCredentialProviderError>` - The created
    ///   access rule or an error.
    #[tracing::instrument(
        name = "provider.application_credential.create_access_rule",
        level = "debug",
        skip_all
    )]
    async fn create_access_rule<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        rule: AccessRuleCreate,
    ) -> Result<AccessRule, ApplicationCredentialProviderError> {
        let mut rule = rule;
        rule.validate()?;
        if rule.id.is_none() {
            rule.id = Some(Uuid::new_v4().simple().to_string());
        }
        let user_id = rule.user_id.clone();
        let access_rule = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let rule_clone = rule.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::AccessRule {
                        id: rule_clone.id.clone().unwrap_or_default(),
                        user_id: user_id.clone(),
                    },
                ),
                operation: async {
                    backend_driver.create_access_rule(ctx.state(), rule_clone).await
                },
                on_audit_error: |_: AuditDispatchError| ApplicationCredentialProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let access_rule = self
                .backend_driver
                .create_access_rule(ctx.state(), rule)
                .await?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::AccessRule {
                        id: access_rule.id.clone(),
                        user_id,
                    },
                ))
                .await;

            access_rule
        };

        Ok(access_rule)
    }

    /// Create a new application credential.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `rec`: The application credential creation request.
    ///
    /// # Returns
    /// - `Result<ApplicationCredentialCreateResponse,
    ///   ApplicationCredentialProviderError>` - The creation response or an
    ///   error.
    #[tracing::instrument(
        name = "provider.application_credential.create_application_credential",
        level = "debug",
        skip_all
    )]
    async fn create_application_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        rec: ApplicationCredentialCreate,
    ) -> Result<ApplicationCredentialCreateResponse, ApplicationCredentialProviderError> {
        let mut rec = rec;
        // The API payload carries no owner for inline access rules; stamp the
        // credential's owner onto each rule before validation, which
        // enforces a min-length on `user_id`.
        if let Some(rules) = rec.access_rules.as_mut() {
            for rule in rules {
                rule.user_id = rec.user_id.clone();
            }
        }
        rec.validate()?;
        let roles: HashSet<String> = ctx
            .state()
            .provider
            .get_role_provider()
            .list_roles(ctx, &RoleListParameters::default())
            .await?
            .iter()
            .map(|role| role.id.clone())
            .collect();
        for role in rec.roles.iter() {
            if !roles.contains(&role.id) {
                return Err(ApplicationCredentialProviderError::RoleNotFound(
                    role.id.clone(),
                ));
            }
        }
        // V5 (security review, `doc/src/contributor/security-model.md` §9):
        // `access_rules` are stored and CRUD'd but not enforced at request time
        // yet -- no middleware matches the incoming (service, method, path)
        // against them. Warn unconditionally so the gap is visible in logs, and
        // fail loud instead when the operator has opted in, rather than
        // silently accepting a restriction the server cannot honor.
        if rec
            .access_rules
            .as_ref()
            .is_some_and(|rules| !rules.is_empty())
        {
            let cfg = ctx.state().config_manager.config.read().await;
            if cfg.application_credential.reject_unenforced_access_rules {
                return Err(ApplicationCredentialProviderError::AccessRulesUnenforced);
            }
            warn!(
                "creating application credential with a non-empty access_rules list; \
                 access_rules are NOT enforced at request time yet (see doc/src/contributor/security-model.md §9) \
                 -- the restriction is currently a no-op"
            );
        }
        let mut new_rec = rec;
        if new_rec.id.is_none() {
            new_rec.id = Some(Uuid::new_v4().simple().to_string());
        }
        if let Some(ref mut rules) = new_rec.access_rules {
            for rule in rules {
                if rule.id.is_none() {
                    rule.id = Some(Uuid::new_v4().simple().to_string());
                }
            }
        }
        if new_rec.secret.is_none() {
            new_rec.secret = Some(generate_secret());
        }
        let cred_id = new_rec.id.clone().unwrap_or_default();
        let project_id = new_rec.project_id.clone();
        let response = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let new_rec_clone = new_rec.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::ApplicationCredential {
                        id: cred_id.clone(),
                        project_id: project_id.clone(),
                    },
                ),
                operation: async {
                    backend_driver.create_application_credential(ctx.state(), new_rec_clone).await
                },
                on_audit_error: |_: AuditDispatchError| ApplicationCredentialProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let response = self
                .backend_driver
                .create_application_credential(ctx.state(), new_rec)
                .await?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::ApplicationCredential {
                        id: cred_id,
                        project_id,
                    },
                ))
                .await;

            response
        };

        Ok(response)
    }

    /// Delete a user's access rule by its ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `user_id`: The ID of the user owning the access rule.
    /// - `id`: The ID of the access rule.
    ///
    /// # Returns
    /// - `Result<(), ApplicationCredentialProviderError>` - Unit on success, or
    ///   an error.
    #[tracing::instrument(name = "provider.application_credential.delete_access_rule", level = "debug", skip_all, fields(user_id = %user_id, id = %id))]
    async fn delete_access_rule<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        id: &'a str,
    ) -> Result<(), ApplicationCredentialProviderError> {
        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::AccessRule {
                        id: id.to_string(),
                        user_id: user_id.to_string(),
                    },
                ),
                operation: async {
                    self.backend_driver.delete_access_rule(ctx.state(), user_id, id).await?;
                    Ok::<(), ApplicationCredentialProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| ApplicationCredentialProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
                .delete_access_rule(ctx.state(), user_id, id)
                .await?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::AccessRule {
                        id: id.to_string(),
                        user_id: user_id.to_string(),
                    },
                ))
                .await;
        }

        Ok(())
    }

    /// Delete an application credential by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `rec`: The application credential deletion request.
    ///
    /// # Returns
    /// - `Result<(), ApplicationCredentialProviderError>` - Unit on success, or
    ///   an error.
    #[tracing::instrument(
        name = "provider.application_credential.delete_application_credential",
        level = "debug",
        skip_all
    )]
    async fn delete_application_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        rec: ApplicationCredential,
    ) -> Result<(), ApplicationCredentialProviderError> {
        if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::ApplicationCredential { id: rec.id.to_string(), project_id: rec.project_id.to_string() } ,
                ),
                operation: async {
                    backend_driver.delete_application_credential(ctx.state(), &rec.id).await
                },
                on_audit_error: |_: AuditDispatchError| {
                    ApplicationCredentialProviderError::Driver("audit dispatch failed".into())
                },
            }?;
        } else {
            self.backend_driver
                .delete_application_credential(ctx.state(), &rec.id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::ApplicationCredential {
                        id: rec.id.to_string(),
                        project_id: rec.project_id.to_string(),
                    },
                ))
                .await;
        }

        Ok(())
    }
    /// Get a user's access rule by its ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `user_id`: The ID of the user owning the access rule.
    /// - `id`: The ID of the access rule.
    ///
    /// # Returns
    /// - `Result<Option<AccessRule>, ApplicationCredentialProviderError>` - The
    ///   access rule if found, or an error.
    #[tracing::instrument(name = "provider.application_credential.get_access_rule", level = "debug", skip_all, fields(user_id = %user_id, id = %id))]
    async fn get_access_rule<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        id: &'a str,
    ) -> Result<Option<AccessRule>, ApplicationCredentialProviderError> {
        self.backend_driver
            .get_access_rule(ctx.state(), user_id, id)
            .await
    }

    /// Get a single application credential by ID.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `id`: The ID of the application credential.
    ///
    /// # Returns
    /// - `Result<Option<ApplicationCredential>,
    ///   ApplicationCredentialProviderError>` - The credential if found, or an
    ///   error.
    #[tracing::instrument(name = "provider.application_credential.get_application_credential", level = "debug", skip_all, fields(id = %id))]
    async fn get_application_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<ApplicationCredential>, ApplicationCredentialProviderError> {
        if let Some(mut app_cred) = self
            .backend_driver
            .get_application_credential(ctx.state(), id)
            .await?
        {
            let roles: BTreeMap<String, Role> = ctx
                .state()
                .provider
                .get_role_provider()
                .list_roles(ctx, &RoleListParameters::default())
                .await?
                .into_iter()
                .map(|x| (x.id.clone(), x))
                .collect();
            for cred_role in app_cred.roles.iter_mut() {
                if let Some(role) = roles.get(&cred_role.id) {
                    cred_role.name = Some(role.name.clone());
                    cred_role.domain_id = role.domain_id.clone();
                }
            }
            Ok(Some(app_cred))
        } else {
            Ok(None)
        }
    }

    /// List all access rules owned by a user.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `user_id`: The ID of the user owning the access rules.
    ///
    /// # Returns
    /// - `Result<Vec<AccessRule>, ApplicationCredentialProviderError>` - A list
    ///   of access rules or an error.
    #[tracing::instrument(name = "provider.application_credential.list_access_rules", level = "debug", skip_all, fields(user_id = %user_id))]
    async fn list_access_rules<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<Vec<AccessRule>, ApplicationCredentialProviderError> {
        self.backend_driver
            .list_access_rules(ctx.state(), user_id)
            .await
    }

    /// List application credentials.
    ///
    /// # Parameters
    /// - `state`: The current service state.
    /// - `params`: Parameters for filtering the list of credentials.
    ///
    /// # Returns
    /// - `Result<Vec<ApplicationCredential>,
    ///   ApplicationCredentialProviderError>` - A list of application
    ///   credentials or an error.
    #[tracing::instrument(name = "provider.application_credential.list_application_credentials", level = "debug", skip_all, fields(params = ?params))]
    async fn list_application_credentials<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &ApplicationCredentialListParameters,
    ) -> Result<Vec<ApplicationCredential>, ApplicationCredentialProviderError> {
        params.validate()?;
        let mut creds = self
            .backend_driver
            .list_application_credentials(ctx.state(), params)
            .await?;

        let roles: BTreeMap<String, Role> = ctx
            .state()
            .provider
            .get_role_provider()
            .list_roles(ctx, &RoleListParameters::default())
            .await?
            .into_iter()
            .map(|x| (x.id.clone(), x))
            .collect();
        for cred in creds.iter_mut() {
            for cred_role in cred.roles.iter_mut() {
                if let Some(role) = roles.get(&cred_role.id) {
                    cred_role.name = Some(role.name.clone());
                    cred_role.domain_id = role.domain_id.clone();
                }
            }
        }
        Ok(creds)
    }
}

/// Generate application credential secret.
///
/// Use the same algorithm as the python Keystone uses:
///
///  - use random 64 bytes
///  - apply base64 encoding with no padding
///
/// # Returns
/// - `SecretString` - The generated secret.
pub fn generate_secret() -> SecretString {
    const LENGTH: usize = 64;

    // 1. Generate 64 cryptographically secure random bytes (Analogous to
    //    `secrets.token_bytes(length)`)
    let mut secret_bytes = [0u8; LENGTH];
    rng().fill(&mut secret_bytes[..]);

    // 2. Base64 URL-safe encoding (Analogous to
    //    `base64.urlsafe_b64encode(secret)`) with stripping padding handled
    //    automatically by `URL_SAFE_NO_PAD` engine.
    let encoded_secret = general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes);

    SecretString::new(encoded_secret.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::application_credential::backend::MockApplicationCredentialBackend;
    use crate::provider::Provider;
    use crate::role::MockRoleProvider;
    use crate::tests::get_mocked_state;

    fn make_service(
        mock_backend: MockApplicationCredentialBackend,
    ) -> ApplicationCredentialService {
        ApplicationCredentialService {
            backend_driver: Arc::new(mock_backend),
        }
    }

    fn no_op_role_mock() -> MockRoleProvider {
        let mut role_mock = MockRoleProvider::default();
        role_mock.expect_list_roles().returning(|_, _| Ok(vec![]));
        role_mock
    }

    fn rule() -> AccessRuleCreate {
        AccessRuleCreateBuilder::default()
            .user_id("uid")
            .service("compute")
            .method("GET")
            .path("/v2.1/servers")
            .build()
            .unwrap()
    }

    /// V5 (security review, issue #980): a non-empty `access_rules` list is
    /// accepted by default (existing behavior preserved) -- the warning is
    /// only observable via logs, not the return value.
    #[tokio::test]
    async fn test_create_with_access_rules_warns_by_default() {
        let mut mock_backend = MockApplicationCredentialBackend::new();
        mock_backend
            .expect_create_application_credential()
            .returning(|_, rec| {
                Ok(ApplicationCredentialCreateResponseBuilder::default()
                    .id(rec.id.clone().unwrap_or_default())
                    .name(rec.name.clone())
                    .project_id(rec.project_id.clone())
                    .roles(rec.roles.clone())
                    .secret(SecretString::from("s3cr3t"))
                    .unrestricted(false)
                    .user_id(rec.user_id.clone())
                    .build()
                    .unwrap())
            });

        let state = get_mocked_state(
            Some(Config::default()),
            Some(Provider::mocked_builder().mock_role(no_op_role_mock())),
        )
        .await;

        let rec = ApplicationCredentialCreateBuilder::default()
            .name("cred")
            .project_id("pid")
            .user_id("uid")
            .roles(vec![])
            .access_rules(vec![rule()])
            .build()
            .unwrap();

        let result = make_service(mock_backend)
            .create_application_credential(&ExecutionContext::internal(&state), rec)
            .await;

        assert!(result.is_ok());
    }

    /// V5: with `reject_unenforced_access_rules` enabled, creation with a
    /// non-empty `access_rules` list fails loud -- and never reaches the
    /// backend driver at all (no `expect_create_application_credential` is
    /// configured on the mock, so a call would panic the test).
    #[tokio::test]
    async fn test_create_with_access_rules_rejected_when_configured() {
        let mock_backend = MockApplicationCredentialBackend::new();

        let mut cfg = Config::default();
        cfg.application_credential.reject_unenforced_access_rules = true;

        let state = get_mocked_state(
            Some(cfg),
            Some(Provider::mocked_builder().mock_role(no_op_role_mock())),
        )
        .await;

        let rec = ApplicationCredentialCreateBuilder::default()
            .name("cred")
            .project_id("pid")
            .user_id("uid")
            .roles(vec![])
            .access_rules(vec![rule()])
            .build()
            .unwrap();

        let result = make_service(mock_backend)
            .create_application_credential(&ExecutionContext::internal(&state), rec)
            .await;

        assert!(matches!(
            result,
            Err(ApplicationCredentialProviderError::AccessRulesUnenforced)
        ));
    }

    /// V5: an empty/absent `access_rules` list is never rejected, even with
    /// `reject_unenforced_access_rules` enabled -- there is nothing
    /// unenforceable to fail loud about.
    #[tokio::test]
    async fn test_create_without_access_rules_never_rejected() {
        let mut mock_backend = MockApplicationCredentialBackend::new();
        mock_backend
            .expect_create_application_credential()
            .returning(|_, rec| {
                Ok(ApplicationCredentialCreateResponseBuilder::default()
                    .id(rec.id.clone().unwrap_or_default())
                    .name(rec.name.clone())
                    .project_id(rec.project_id.clone())
                    .roles(rec.roles.clone())
                    .secret(SecretString::from("s3cr3t"))
                    .unrestricted(false)
                    .user_id(rec.user_id.clone())
                    .build()
                    .unwrap())
            });

        let mut cfg = Config::default();
        cfg.application_credential.reject_unenforced_access_rules = true;

        let state = get_mocked_state(
            Some(cfg),
            Some(Provider::mocked_builder().mock_role(no_op_role_mock())),
        )
        .await;

        let rec = ApplicationCredentialCreateBuilder::default()
            .name("cred")
            .project_id("pid")
            .user_id("uid")
            .roles(vec![])
            .build()
            .unwrap();

        let result = make_service(mock_backend)
            .create_application_credential(&ExecutionContext::internal(&state), rec)
            .await;

        assert!(result.is_ok());
    }

    fn stored_cred() -> ApplicationCredential {
        ApplicationCredentialBuilder::default()
            .id("cid")
            .name("cname")
            .project_id("pid")
            .user_id("uid")
            .unrestricted(false)
            .roles(vec![])
            .build()
            .unwrap()
    }

    fn user(id: &str) -> openstack_keystone_core_types::identity::UserResponse {
        openstack_keystone_core_types::identity::UserResponseBuilder::default()
            .id(id)
            .name("uname")
            .domain_id("udid")
            .enabled(true)
            .build()
            .unwrap()
    }

    fn by_id(user: Option<UserAuthRef>) -> ApplicationCredentialAuthRequest {
        ApplicationCredentialAuthRequest {
            secret: "s3cr3t".into(),
            credential: ApplicationCredentialAuthData::Id(ApplicationCredentialAuthById {
                id: "cid".into(),
                user,
            }),
        }
    }

    /// Backend returning the credential `cid`. The secret verification
    /// expects exactly `verify_calls` calls.
    fn backend(verify_calls: usize) -> MockApplicationCredentialBackend {
        let mut backend = MockApplicationCredentialBackend::new();
        backend
            .expect_get_application_credential()
            .returning(|_, id| Ok((id == "cid").then(stored_cred)));
        backend
            .expect_list_application_credentials()
            .returning(|_, _| Ok(vec![stored_cred()]));
        backend
            .expect_verify_application_credential_secret()
            .times(verify_calls)
            .returning(|_, id, _| {
                if id == "cid" {
                    Ok(())
                } else {
                    Err(ApplicationCredentialProviderError::AuthenticationFailed)
                }
            });
        backend
    }

    /// A credential that does not exist burns the dummy hash verification
    /// (called with an ID that cannot match) and never touches the rate
    /// limiter store (ADR-0022 Invariant 8).
    #[tokio::test]
    async fn test_authenticate_not_found_burns_dummy_hash() {
        let mut backend = MockApplicationCredentialBackend::new();
        backend
            .expect_get_application_credential()
            .returning(|_, _| Ok(None));
        backend
            .expect_verify_application_credential_secret()
            .withf(|_, id: &str, _| id.is_empty())
            .times(3)
            .returning(|_, _, _| Err(ApplicationCredentialProviderError::AuthenticationFailed));
        let state = get_mocked_state(
            Some(Config {
                rate_limit_user_auth: openstack_keystone_config::RateLimitSection {
                    enabled: true,
                    burst_size: 1,
                    replenish_rate_per_second: 1,
                },
                ..Default::default()
            }),
            Some(Provider::mocked_builder().mock_role(no_op_role_mock())),
        )
        .await;
        let svc = make_service(backend);
        // Repeated attempts are never rate limited for unknown credentials.
        for _ in 0..3 {
            backend_call_not_found(&svc, &state).await;
        }
    }

    async fn backend_call_not_found(
        svc: &ApplicationCredentialService,
        state: &crate::keystone::ServiceState,
    ) {
        assert!(matches!(
            svc.authenticate_by_application_credential(
                &ExecutionContext::internal(state),
                &by_id(None)
            )
            .await,
            Err(ApplicationCredentialProviderError::AuthenticationFailed)
        ));
    }

    /// The user reference naming another user than the owner is rejected and
    /// indistinguishable from an unknown credential (dummy hash burned).
    #[tokio::test]
    async fn test_authenticate_foreign_user_ref_rejected() {
        let mut identity_mock = crate::identity::MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .returning(|_, id| Ok(Some(user(id))));
        let backend = {
            let mut b = MockApplicationCredentialBackend::new();
            b.expect_get_application_credential()
                .returning(|_, _| Ok(Some(stored_cred())));
            b.expect_verify_application_credential_secret()
                .withf(|_, id: &str, _| id.is_empty())
                .times(1)
                .returning(|_, _, _| Err(ApplicationCredentialProviderError::AuthenticationFailed));
            b
        };
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_role(no_op_role_mock())
                    .mock_identity(identity_mock),
            ),
        )
        .await;
        let result = make_service(backend)
            .authenticate_by_application_credential(
                &ExecutionContext::internal(&state),
                &by_id(Some(UserAuthRef {
                    id: Some("other".into()),
                    name: None,
                    domain: None,
                })),
            )
            .await;
        assert!(matches!(
            result,
            Err(ApplicationCredentialProviderError::AuthenticationFailed)
        ));
    }

    /// A user ID together with a mismatching domain name is rejected.
    #[tokio::test]
    async fn test_authenticate_user_ref_domain_name_mismatch_rejected() {
        let mut identity_mock = crate::identity::MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .returning(|_, id| Ok(Some(user(id))));
        let mut resource_mock = crate::resource::MockResourceProvider::default();
        resource_mock.expect_get_domain().returning(|_, _| {
            Ok(Some(
                openstack_keystone_core_types::resource::DomainBuilder::default()
                    .id("udid")
                    .name("real")
                    .enabled(true)
                    .build()
                    .unwrap(),
            ))
        });
        let state = get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_role(no_op_role_mock())
                    .mock_identity(identity_mock)
                    .mock_resource(resource_mock),
            ),
        )
        .await;
        let result = make_service(backend_burning())
            .authenticate_by_application_credential(
                &ExecutionContext::internal(&state),
                &by_id(Some(UserAuthRef {
                    id: Some("uid".into()),
                    name: None,
                    domain: Some(openstack_keystone_core_types::identity::Domain {
                        id: None,
                        name: Some("fake".into()),
                    }),
                })),
            )
            .await;
        assert!(matches!(
            result,
            Err(ApplicationCredentialProviderError::AuthenticationFailed)
        ));
    }

    fn backend_burning() -> MockApplicationCredentialBackend {
        let mut b = MockApplicationCredentialBackend::new();
        b.expect_get_application_credential()
            .returning(|_, _| Ok(Some(stored_cred())));
        b.expect_verify_application_credential_secret()
            .withf(|_, id: &str, _| id.is_empty())
            .times(1)
            .returning(|_, _, _| Err(ApplicationCredentialProviderError::AuthenticationFailed));
        b
    }

    /// The per-user limiter is keyed on the credential owner and fires before
    /// the secret is verified.
    #[tokio::test]
    async fn test_authenticate_rate_limited() {
        let state = get_mocked_state(
            Some(Config {
                rate_limit_user_auth: openstack_keystone_config::RateLimitSection {
                    enabled: true,
                    burst_size: 1,
                    replenish_rate_per_second: 1,
                },
                ..Default::default()
            }),
            Some(Provider::mocked_builder().mock_role(no_op_role_mock())),
        )
        .await;
        // Exhaust the bucket of the credential owner.
        assert!(state.rate_limiters.check_user("uid").is_ok());
        let result = make_service(backend(0))
            .authenticate_by_application_credential(
                &ExecutionContext::internal(&state),
                &by_id(None),
            )
            .await;
        assert!(matches!(
            result,
            Err(ApplicationCredentialProviderError::TooManyRequests { retry_after_secs })
                if retry_after_secs >= 1
        ));
    }
}
