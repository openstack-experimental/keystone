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
//! # Service grant provider (ADR 0036 §4)

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};

use openstack_keystone_config::Config;
use openstack_keystone_core_types::assignment::RoleAssignmentListParametersBuilder;
use openstack_keystone_core_types::auth::{AuthenticationContext, IdentityInfo, SecurityContext};
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::service_grant::*;

use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;
use crate::service_grant::backend::ServiceGrantBackend;
use crate::service_grant::{ServiceGrantApi, ServiceGrantProviderError};

/// The only backend registered for the service grant provider.
const BACKEND_NAME: &str = "raft";

/// Maximum length of a grant description.
const MAX_DESCRIPTION_LEN: usize = 255;

/// Audit and hook event of an operation on one grant. IDs only.
pub fn service_grant_event(operation: Operation, domain_id: &str, id: &str) -> Event {
    Event::new(
        operation,
        EventPayload::ServiceGrant {
            domain_id: domain_id.to_string(),
            id: id.to_string(),
        },
    )
}

/// Whether the caller's authentication chain may create a grant (ADR 0036
/// §4.2): only a user's own, non-delegated authority can be delegated
/// further. An unrestricted application credential is the one delegated
/// chain allowed (its roles still bound the grant, see
/// [`effective_role_ids`]); trusts, restricted application credentials,
/// service grants and every other delegated chain are rejected. Keyed on
/// the authentication chain, never on the token scope.
fn ensure_chain_may_delegate(sc: &SecurityContext) -> Result<(), ServiceGrantProviderError> {
    let forbidden = |msg: &str| Err(ServiceGrantProviderError::Forbidden(msg.to_string()));
    if !matches!(sc.principal().identity, IdentityInfo::User(_)) {
        return forbidden("service grants can only be created by users");
    }
    if sc.token_restriction().is_some() {
        return forbidden("a restricted token cannot create service grants");
    }
    match sc.authentication_context() {
        AuthenticationContext::ApplicationCredential {
            application_credential,
            ..
        } if application_credential.unrestricted => Ok(()),
        auth if auth.is_delegated() => {
            forbidden("a delegated authentication cannot create service grants")
        }
        _ => Ok(()),
    }
}

/// Role ids `user_id` holds on `project_id` from role assignments (group
/// membership and implied roles included), never from a token's scoped
/// roles. Also used by the lifecycle hook to re-check grants after an
/// assignment or membership change.
pub(crate) async fn assigned_role_ids(
    state: &ServiceState,
    user_id: &str,
    project_id: &str,
) -> Result<BTreeSet<String>, ServiceGrantProviderError> {
    let params = RoleAssignmentListParametersBuilder::default()
        .user_id(user_id)
        .project_id(project_id)
        .effective(true)
        .resolve_implied_roles(true)
        .build()
        .map_err(ServiceGrantProviderError::provider)?;
    Ok(state
        .provider
        .get_assignment_provider()
        .list_role_assignments(&ExecutionContext::internal(state), &params)
        .await
        .map_err(ServiceGrantProviderError::provider)?
        .into_iter()
        .map(|a| a.role_id)
        .collect())
}

/// Effective role ids of `user_id` on `project_id` ([`assigned_role_ids`]).
/// An application credential caller is further bounded by the
/// credential's own roles.
async fn effective_role_ids(
    state: &ServiceState,
    sc: &SecurityContext,
    user_id: &str,
    project_id: &str,
) -> Result<BTreeSet<String>, ServiceGrantProviderError> {
    let mut roles = assigned_role_ids(state, user_id, project_id).await?;
    if let AuthenticationContext::ApplicationCredential {
        application_credential,
        ..
    } = sc.authentication_context()
    {
        let bound: BTreeSet<&str> = application_credential
            .roles
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        roles.retain(|r| bound.contains(r.as_str()));
    }
    Ok(roles)
}

/// Resolve the delegated role set (ADR 0036 §4.2): the requested roles must
/// be a non-empty subset of the caller's effective roles and of the
/// client's ceiling; no request means all effective roles within the
/// ceiling.
fn resolve_role_ids(
    requested: Option<Vec<String>>,
    effective: &BTreeSet<String>,
    ceiling: &[String],
) -> Result<Vec<String>, ServiceGrantProviderError> {
    let validation = |msg: String| Err(ServiceGrantProviderError::Validation(msg));
    let in_ceiling = |role: &str| ceiling.is_empty() || ceiling.iter().any(|c| c == role);
    let roles: BTreeSet<String> = match requested {
        Some(requested) => {
            let requested: BTreeSet<String> = requested.into_iter().collect();
            for role in &requested {
                if !effective.contains(role) {
                    return validation(format!(
                        "role {role} is not an effective role of the caller on the project"
                    ));
                }
                if !in_ceiling(role) {
                    return validation(format!(
                        "role {role} is above the delegation ceiling of the service"
                    ));
                }
            }
            requested
        }
        None => effective
            .iter()
            .filter(|r| in_ceiling(r))
            .cloned()
            .collect(),
    };
    if roles.is_empty() {
        return validation("a service grant needs at least one delegable role".to_string());
    }
    Ok(roles.into_iter().collect())
}

/// Attempts at disabling a grant that is concurrently being updated.
const DISABLE_ATTEMPTS: usize = 3;

/// Disable `grant` for `reason`.
///
/// The update is versioned, and a redemption refreshing `last_redeemed_at`
/// bumps the version too, so a conflict is retried against the stored
/// grant. A grant that is gone or already disabled is done: it is not
/// written again, so a retry loop against a dead grant causes no writes
/// (ADR 0036 §4.3).
pub(crate) async fn disable_grant(
    state: &ServiceState,
    grant: &ServiceGrant,
    reason: DisabledReason,
) -> Result<(), ServiceGrantProviderError> {
    let ctx = ExecutionContext::internal(state);
    let provider = state.provider.get_service_grant_provider();
    let mut version = grant.version;
    for attempt in 1..=DISABLE_ATTEMPTS {
        if attempt > 1 {
            match provider
                .get_service_grant(&ctx, &grant.domain_id, &grant.id)
                .await?
            {
                Some(current) if current.enabled => version = current.version,
                _ => return Ok(()),
            }
        }
        match provider
            .update_service_grant(
                &ctx,
                &grant.domain_id,
                &grant.id,
                ServiceGrantUpdate {
                    enabled: Some(false),
                    disabled_reason: Some(reason),
                    last_redeemed_at: None,
                },
                version,
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(ServiceGrantProviderError::Conflict(_)) if attempt < DISABLE_ATTEMPTS => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Service grant provider.
pub struct ServiceGrantService {
    /// Backend driver.
    backend_driver: Arc<dyn ServiceGrantBackend>,
}

impl ServiceGrantService {
    /// Create a new `ServiceGrantService`.
    pub fn new<P: PluginManagerApi>(
        _config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, ServiceGrantProviderError> {
        let backend_driver = plugin_manager
            .get_service_grant_backend(BACKEND_NAME)?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl ServiceGrantApi for ServiceGrantService {
    #[tracing::instrument(name = "provider.service_grant.create", level = "debug", skip_all)]
    async fn create_service_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        data: ServiceGrantCreate,
    ) -> Result<ServiceGrant, ServiceGrantProviderError> {
        let state = ctx.state();
        let internal = ExecutionContext::internal(state);
        let sc = ctx.ctx().ok_or_else(|| {
            ServiceGrantProviderError::Forbidden(
                "service grants are created by an authenticated user".to_string(),
            )
        })?;
        ensure_chain_may_delegate(sc)?;
        let grantor_user_id = sc.principal().get_user_id();
        let grantor_domain_id = sc.principal().domain_id().ok_or_else(|| {
            ServiceGrantProviderError::Forbidden("the caller's domain is not resolved".to_string())
        })?;
        if data
            .description
            .as_ref()
            .is_some_and(|d| d.chars().count() > MAX_DESCRIPTION_LEN)
        {
            return Err(ServiceGrantProviderError::Validation(format!(
                "description must be at most {MAX_DESCRIPTION_LEN} characters"
            )));
        }

        // The grantee: an enabled delegatable service accepting grants.
        let client = state
            .provider
            .get_oauth2_client_provider()
            .get_by_client_id(&internal, &data.grantee_client_id)
            .await
            .map_err(ServiceGrantProviderError::provider)?;
        let not_delegatable = || {
            ServiceGrantProviderError::Validation(format!(
                "client {} is not a delegatable service accepting service grants",
                data.grantee_client_id
            ))
        };
        let client = client.ok_or_else(not_delegatable)?;
        let policy = client
            .service_grant_policy()
            .ok_or_else(not_delegatable)?
            .clone();
        let project = state
            .provider
            .get_resource_provider()
            .get_project(&internal, &data.project_id)
            .await
            .map_err(ServiceGrantProviderError::provider)?
            .filter(|p| p.enabled)
            .ok_or_else(|| {
                ServiceGrantProviderError::Validation(format!(
                    "project {} does not exist or is disabled",
                    data.project_id
                ))
            })?;

        // A service only acts in another domain, for the grantor's or the
        // project's, when it accepts cross-domain grants.
        if (client.domain_id != grantor_domain_id || client.domain_id != project.domain_id)
            && !policy.cross_domain
        {
            return Err(not_delegatable());
        }

        let effective = effective_role_ids(state, sc, &grantor_user_id, &project.id).await?;
        let role_ids = resolve_role_ids(data.role_ids, &effective, &policy.max_role_ids)?;

        let now = Utc::now();
        let max_lifetime = policy
            .max_grant_lifetime
            .map(|secs| Duration::seconds(i64::try_from(secs).unwrap_or(i64::MAX)));
        let expires_at = match (data.expires_at, max_lifetime) {
            (Some(exp), _) if exp <= now => {
                return Err(ServiceGrantProviderError::Validation(
                    "expires_at must be in the future".to_string(),
                ));
            }
            (Some(exp), Some(max)) if exp > now + max => {
                return Err(ServiceGrantProviderError::Validation(
                    "expires_at is beyond the service's max_grant_lifetime".to_string(),
                ));
            }
            (None, Some(max)) => Some(now + max),
            (exp, _) => exp,
        };

        // Count caps (ADR 0036 §4.2). Best effort: two concurrent creations
        // can both pass; this bounds storage growth, it is not a security
        // control.
        if let Some(max) = policy.max_grants_per_project {
            let count = self
                .backend_driver
                .count_service_grants(state, &project.id, Some(&client.client_id))
                .await?;
            if count >= max as usize {
                return Err(ServiceGrantProviderError::Validation(format!(
                    "the service accepts at most {max} grants per project"
                )));
            }
        }
        let backstop = state
            .config_manager
            .config
            .read()
            .await
            .delegation
            .max_grants_per_project;
        let count = self
            .backend_driver
            .count_service_grants(state, &project.id, None)
            .await?;
        if count as u64 >= backstop {
            return Err(ServiceGrantProviderError::QuotaExceeded(format!(
                "the project reached the limit of {backstop} service grants"
            )));
        }

        let grant = ServiceGrant {
            id: uuid::Uuid::new_v4().simple().to_string(),
            version: 1,
            // The grant lives in, and is redeemed at, the project's domain:
            // its token asserts authority over that project, so only that
            // domain's issuer may sign it (ADR 0026 §5 domain key
            // isolation). The grantor may belong to another domain.
            domain_id: project.domain_id.clone(),
            grantor_user_id,
            grantee: Grantee::Client {
                client_id: client.client_id.clone(),
                client_domain_id: client.domain_id.clone(),
            },
            target: GrantTarget::Project {
                project_id: project.id.clone(),
                project_domain_id: project.domain_id.clone(),
            },
            role_ids,
            expires_at,
            description: data.description,
            enabled: true,
            created_at: now,
            last_redeemed_at: None,
            disabled_reason: None,
        };
        let event = service_grant_event(Operation::Create, &grant.domain_id, &grant.id);
        let op = async { self.backend_driver.create_service_grant(state, grant).await };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: event,
            operation: op,
            on_audit_error: |_: AuditDispatchError| ServiceGrantProviderError::AuditUnavailable,
        }
    }

    #[tracing::instrument(name = "provider.service_grant.delete", level = "debug", skip_all, fields(domain_id = %domain_id, id = %id))]
    async fn delete_service_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        id: &'a str,
    ) -> Result<(), ServiceGrantProviderError> {
        let op = async {
            self.backend_driver
                .delete_service_grant(ctx.state(), domain_id, id)
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: service_grant_event(Operation::Revoke, domain_id, id),
            operation: op,
            on_audit_error: |_: AuditDispatchError| ServiceGrantProviderError::AuditUnavailable,
        }
    }

    #[tracing::instrument(name = "provider.service_grant.get", level = "debug", skip_all, fields(domain_id = %domain_id, id = %id))]
    async fn get_service_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        id: &'a str,
    ) -> Result<Option<ServiceGrant>, ServiceGrantProviderError> {
        self.backend_driver
            .get_service_grant(ctx.state(), domain_id, id)
            .await
    }

    #[tracing::instrument(name = "provider.service_grant.get_by_id", level = "debug", skip_all, fields(id = %id))]
    async fn get_service_grant_by_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<ServiceGrant>, ServiceGrantProviderError> {
        self.backend_driver
            .get_service_grant_by_id(ctx.state(), id)
            .await
    }

    #[tracing::instrument(name = "provider.service_grant.list", level = "debug", skip_all, fields(params = ?params))]
    async fn list_service_grants<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &ServiceGrantListParameters,
    ) -> Result<Vec<ServiceGrant>, ServiceGrantProviderError> {
        self.backend_driver
            .list_service_grants(ctx.state(), params)
            .await
    }

    #[tracing::instrument(name = "provider.service_grant.update", level = "debug", skip_all, fields(domain_id = %domain_id, id = %id))]
    async fn update_service_grant<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
        id: &'a str,
        update: ServiceGrantUpdate,
        expected_version: u64,
    ) -> Result<ServiceGrant, ServiceGrantProviderError> {
        let operation = match update.enabled {
            Some(false) => Operation::Disable,
            Some(true) => Operation::Enable,
            None => Operation::Update,
        };
        let op = async {
            self.backend_driver
                .update_service_grant(ctx.state(), domain_id, id, update, expected_version)
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: service_grant_event(operation, domain_id, id),
            operation: op,
            on_audit_error: |_: AuditDispatchError| ServiceGrantProviderError::AuditUnavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use openstack_keystone_core_types::application_credential::ApplicationCredential;
    use openstack_keystone_core_types::assignment::{Assignment, AssignmentType};
    use openstack_keystone_core_types::auth::{
        PrincipalInfo, SecurityContextTestingBuilder, UserIdentityInfo,
    };
    use openstack_keystone_core_types::oauth2_client::{DelegationPolicy, OAuth2ClientResource};
    use openstack_keystone_core_types::resource::{Domain, Project};
    use openstack_keystone_core_types::role::RoleRefBuilder;
    use openstack_keystone_core_types::trust::Trust;

    use super::*;
    use crate::assignment::MockAssignmentProvider;
    use crate::auth::ValidatedSecurityContext;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::service_grant::backend::MockServiceGrantBackend;
    use crate::tests::get_mocked_state;

    fn principal(uid: &str) -> PrincipalInfo {
        PrincipalInfo {
            identity: IdentityInfo::User(UserIdentityInfo {
                user_id: uid.to_string(),
                user: None,
                user_domain: Some(Domain {
                    id: "d1".into(),
                    enabled: true,
                    name: "d1".into(),
                    ..Default::default()
                }),
                user_groups: Vec::new(),
            }),
        }
    }

    fn vsc(auth: AuthenticationContext) -> ValidatedSecurityContext {
        ValidatedSecurityContext::test_new(
            SecurityContextTestingBuilder::default()
                .authentication_context(auth)
                .principal(principal("u1"))
                .build(),
        )
    }

    fn client(domain_id: &str, policy: DelegationPolicy) -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_id: "c1".into(),
            provider_id: "backup".into(),
            domain_id: domain_id.into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: "tls_client_auth".into(),
            grant_types: vec![],
            require_pkce: false,
            allowed_scopes: vec![],
            pre_authorized: false,
            enabled: true,
            claims_template: HashMap::new(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
            name: "Backup".into(),
            description: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
            contacts: vec![],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            spiffe_ids: vec!["spiffe://cloud.example/ns/backup/sa/agent".into()],
            delegation: Some(policy),
            dpop_bound_access_tokens: false,
        }
    }

    fn grants_policy() -> DelegationPolicy {
        DelegationPolicy {
            service_grants: true,
            ..Default::default()
        }
    }

    fn assignment(role_id: &str) -> Assignment {
        Assignment {
            actor_id: "u1".into(),
            role_id: role_id.into(),
            role_name: None,
            target_id: "p1".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: None,
        }
    }

    /// A state whose client lookup returns `client`, whose project `p1` is
    /// enabled, and where the caller holds `roles` on it.
    async fn state(client: Option<OAuth2ClientResource>, roles: &[&str]) -> ServiceState {
        state_in(client, roles, "d1").await
    }

    /// Like [`state`], with project `p1` in `project_domain`.
    async fn state_in(
        client: Option<OAuth2ClientResource>,
        roles: &[&str],
        project_domain: &'static str,
    ) -> ServiceState {
        let mut oauth2 = MockOauth2ClientProvider::default();
        oauth2
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(client.clone()));
        let mut resource = MockResourceProvider::default();
        resource.expect_get_project().returning(move |_, id| {
            Ok(Some(Project {
                id: id.to_string(),
                domain_id: project_domain.into(),
                enabled: true,
                name: "p".into(),
                ..Default::default()
            }))
        });
        let roles: Vec<Assignment> = roles.iter().map(|r| assignment(r)).collect();
        let mut assignment = MockAssignmentProvider::default();
        assignment
            .expect_list_role_assignments()
            .withf(|_, q| {
                q.user_id.as_deref() == Some("u1")
                    && q.project_id.as_deref() == Some("p1")
                    && q.effective == Some(true)
            })
            .returning(move |_, _| Ok(roles.clone()));
        get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_oauth2_client(oauth2)
                    .mock_resource(resource)
                    .mock_assignment(assignment),
            ),
        )
        .await
    }

    fn service(counts: usize) -> ServiceGrantService {
        let mut backend = MockServiceGrantBackend::new();
        backend
            .expect_count_service_grants()
            .returning(move |_, _, _| Ok(counts));
        backend
            .expect_create_service_grant()
            .returning(|_, g| Ok(g));
        ServiceGrantService {
            backend_driver: Arc::new(backend),
        }
    }

    fn create(roles: Option<Vec<&str>>) -> ServiceGrantCreate {
        ServiceGrantCreate {
            grantee_client_id: "c1".into(),
            project_id: "p1".into(),
            role_ids: roles.map(|r| r.into_iter().map(String::from).collect()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_create_defaults_to_effective_roles_within_ceiling() {
        let policy = DelegationPolicy {
            max_role_ids: vec!["member".into(), "reader".into()],
            max_grant_lifetime: Some(3600),
            ..grants_policy()
        };
        let state = state(Some(client("d1", policy)), &["admin", "member", "reader"]).await;
        let auth = vsc(AuthenticationContext::Password);
        let ctx = ExecutionContext::from_auth(&state, &auth);
        let grant = service(0)
            .create_service_grant(&ctx, create(None))
            .await
            .unwrap();
        assert_eq!(grant.role_ids, ["member", "reader"]);
        assert_eq!(grant.grantor_user_id, "u1");
        assert_eq!(grant.domain_id, "d1");
        assert_eq!(grant.grantee.client_id(), "c1");
        assert_eq!(grant.target.project_id(), "p1");
        assert!(grant.enabled);
        // The lifetime ceiling becomes the default expiry.
        assert!(grant.expires_at.is_some());
    }

    /// A grant on a project of another domain lives in the project's
    /// domain, whose issuer signs its tokens.
    #[tokio::test]
    async fn test_create_on_project_of_other_domain_anchors_on_project_domain() {
        let policy = DelegationPolicy {
            cross_domain: true,
            ..grants_policy()
        };
        let state = state_in(Some(client("d1", policy)), &["member"], "d2").await;
        let auth = vsc(AuthenticationContext::Password);
        let ctx = ExecutionContext::from_auth(&state, &auth);
        let grant = service(0)
            .create_service_grant(&ctx, create(None))
            .await
            .unwrap();
        assert_eq!(grant.domain_id, "d2");
        assert_eq!(grant.target.project_domain_id(), "d2");
        assert_eq!(grant.grantor_user_id, "u1");
    }

    /// A service without the cross-domain opt-in acts neither for users of
    /// other domains nor on projects of other domains.
    #[tokio::test]
    async fn test_create_cross_domain_requires_opt_in() {
        // Project in another domain than the grantor and the client.
        let state = state_in(Some(client("d1", grants_policy())), &["member"], "d2").await;
        let auth = vsc(AuthenticationContext::Password);
        let ctx = ExecutionContext::from_auth(&state, &auth);
        assert!(matches!(
            service(0).create_service_grant(&ctx, create(None)).await,
            Err(ServiceGrantProviderError::Validation(_))
        ));
        // Client in another domain than the grantor and the project.
        let state = state_in(Some(client("d2", grants_policy())), &["member"], "d1").await;
        let ctx = ExecutionContext::from_auth(&state, &auth);
        assert!(matches!(
            service(0).create_service_grant(&ctx, create(None)).await,
            Err(ServiceGrantProviderError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn test_create_rejects_roles_beyond_caller_or_ceiling() {
        let policy = DelegationPolicy {
            max_role_ids: vec!["member".into()],
            ..grants_policy()
        };
        let state = state(Some(client("d1", policy)), &["admin", "member"]).await;
        let auth = vsc(AuthenticationContext::Password);
        let ctx = ExecutionContext::from_auth(&state, &auth);
        for roles in [vec!["admin"], vec!["owner"], vec![]] {
            assert!(
                matches!(
                    service(0)
                        .create_service_grant(&ctx, create(Some(roles.clone())))
                        .await,
                    Err(ServiceGrantProviderError::Validation(_))
                ),
                "{roles:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_create_rejects_ineligible_client() {
        let auth = vsc(AuthenticationContext::Password);
        let disabled = OAuth2ClientResource {
            enabled: false,
            ..client("d1", grants_policy())
        };
        let no_grants = client(
            "d1",
            DelegationPolicy {
                service_grants: false,
                ..Default::default()
            },
        );
        let foreign = client("d2", grants_policy());
        for c in [None, Some(disabled), Some(no_grants), Some(foreign)] {
            let state = state(c, &["member"]).await;
            let ctx = ExecutionContext::from_auth(&state, &auth);
            assert!(matches!(
                service(0).create_service_grant(&ctx, create(None)).await,
                Err(ServiceGrantProviderError::Validation(_))
            ));
        }
        // A cross-domain service accepts grants from other domains.
        let cross = client(
            "d2",
            DelegationPolicy {
                cross_domain: true,
                ..grants_policy()
            },
        );
        let state = state(Some(cross), &["member"]).await;
        let ctx = ExecutionContext::from_auth(&state, &auth);
        assert!(
            service(0)
                .create_service_grant(&ctx, create(None))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_create_rejects_delegated_chains() {
        let state = state(Some(client("d1", grants_policy())), &["member"]).await;
        let trust = Trust {
            id: "t".into(),
            trustor_user_id: "u0".into(),
            trustee_user_id: "u1".into(),
            ..Default::default()
        };
        let auth = vsc(AuthenticationContext::Trust { trust, token: None });
        let ctx = ExecutionContext::from_auth(&state, &auth);
        assert!(matches!(
            service(0).create_service_grant(&ctx, create(None)).await,
            Err(ServiceGrantProviderError::Forbidden(_))
        ));

        let restricted = ApplicationCredential {
            id: "ac".into(),
            user_id: "u1".into(),
            project_id: "p1".into(),
            name: "ac".into(),
            description: None,
            roles: vec![RoleRefBuilder::default().id("member").build().unwrap()],
            unrestricted: false,
            expires_at: None,
            access_rules: None,
        };
        let auth = vsc(AuthenticationContext::ApplicationCredential {
            application_credential: restricted.clone(),
            token: None,
        });
        let ctx = ExecutionContext::from_auth(&state, &auth);
        assert!(matches!(
            service(0).create_service_grant(&ctx, create(None)).await,
            Err(ServiceGrantProviderError::Forbidden(_))
        ));

        // No security context at all.
        let ctx = ExecutionContext::internal(&state);
        assert!(matches!(
            service(0).create_service_grant(&ctx, create(None)).await,
            Err(ServiceGrantProviderError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn test_create_by_unrestricted_appcred_is_bounded_by_its_roles() {
        let state = state(Some(client("d1", grants_policy())), &["admin", "member"]).await;
        let appcred = ApplicationCredential {
            id: "ac".into(),
            user_id: "u1".into(),
            project_id: "p1".into(),
            name: "ac".into(),
            description: None,
            roles: vec![RoleRefBuilder::default().id("member").build().unwrap()],
            unrestricted: true,
            expires_at: None,
            access_rules: None,
        };
        let auth = vsc(AuthenticationContext::ApplicationCredential {
            application_credential: appcred,
            token: None,
        });
        let ctx = ExecutionContext::from_auth(&state, &auth);
        let grant = service(0)
            .create_service_grant(&ctx, create(None))
            .await
            .unwrap();
        assert_eq!(grant.role_ids, ["member"]);
        assert!(matches!(
            service(0)
                .create_service_grant(&ctx, create(Some(vec!["admin"])))
                .await,
            Err(ServiceGrantProviderError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn test_create_enforces_lifetime_and_caps() {
        let policy = DelegationPolicy {
            max_grant_lifetime: Some(60),
            max_grants_per_project: Some(2),
            ..grants_policy()
        };
        let state = state(Some(client("d1", policy)), &["member"]).await;
        let auth = vsc(AuthenticationContext::Password);
        let ctx = ExecutionContext::from_auth(&state, &auth);

        let too_long = ServiceGrantCreate {
            expires_at: Some(Utc::now() + Duration::seconds(3600)),
            ..create(None)
        };
        assert!(matches!(
            service(0).create_service_grant(&ctx, too_long).await,
            Err(ServiceGrantProviderError::Validation(_))
        ));
        let past = ServiceGrantCreate {
            expires_at: Some(Utc::now() - Duration::seconds(1)),
            ..create(None)
        };
        assert!(matches!(
            service(0).create_service_grant(&ctx, past).await,
            Err(ServiceGrantProviderError::Validation(_))
        ));
        assert!(matches!(
            service(2).create_service_grant(&ctx, create(None)).await,
            Err(ServiceGrantProviderError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn test_create_enforces_deployment_backstop() {
        let state = state(Some(client("d1", grants_policy())), &["member"]).await;
        let auth = vsc(AuthenticationContext::Password);
        let ctx = ExecutionContext::from_auth(&state, &auth);
        assert!(matches!(
            service(10_000)
                .create_service_grant(&ctx, create(None))
                .await,
            Err(ServiceGrantProviderError::QuotaExceeded(_))
        ));
    }

    #[test]
    fn test_resolve_role_ids() {
        let effective: BTreeSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        assert_eq!(
            resolve_role_ids(None, &effective, &[]).unwrap(),
            ["a", "b", "c"]
        );
        assert_eq!(
            resolve_role_ids(Some(vec!["b".into(), "b".into()]), &effective, &[]).unwrap(),
            ["b"]
        );
        assert!(resolve_role_ids(None, &effective, &["z".into()]).is_err());
        assert!(resolve_role_ids(Some(vec!["z".into()]), &effective, &[]).is_err());
    }
}
