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
use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
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

#[async_trait]
impl ApplicationCredentialApi for ApplicationCredentialService {
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
    async fn create_application_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        rec: ApplicationCredentialCreate,
    ) -> Result<ApplicationCredentialCreateResponse, ApplicationCredentialProviderError> {
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
        // V5 (security review, `doc/src/security.md` §9): `access_rules`
        // are stored and CRUD'd but not enforced at request time yet -- no
        // middleware matches the incoming (service, method, path) against
        // them. Warn unconditionally so the gap is visible in logs, and
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
                 access_rules are NOT enforced at request time yet (see doc/src/security.md §9) \
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
                rule.user_id = new_rec.user_id.clone();
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

    // 2. Base64 URL-safe encoding (Analogous to `base64.urlsafe_b64encode(secret)`)
    //    with stripping padding handled automatically by `URL_SAFE_NO_PAD` engine.
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
}
