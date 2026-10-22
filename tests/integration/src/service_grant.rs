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
//! # Service grant integration tests (ADR 0036 phase 1)
//!
//! Raft-only backend -- these tests only run under the `raft` nextest
//! profile (the `service_grant` filter in `.config/nextest.toml`). They drive
//! the real providers end to end: a user creates a grant for a registered
//! `tls_client_auth` service, the service redeems it with its SVID, and the
//! lifecycle hook and janitor keep it in step with its dependencies. Grants
//! that need a past `expires_at` are written through the backend directly,
//! as the service refuses them.

use std::sync::Arc;

use chrono::{Duration, Utc};
use eyre::{OptionExt, Result};
use serde_json::json;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone::auth::*;
use openstack_keystone::keystone::{Service, ServiceState};
use openstack_keystone_config::InternalInterface;
use openstack_keystone_core::auth::{ExecutionContext, ValidatedSecurityContext};
use openstack_keystone_core::common::SpiffeId;
use openstack_keystone_core::oauth2_client::bound_bearer::{
    BoundBearerError, authenticate_bound_bearer,
};
use openstack_keystone_core::service_grant::backend::ServiceGrantBackend;
use openstack_keystone_core::service_grant::redeem::{
    ServiceGrantRedeemError, build_service_grant_claims, redeem_service_grant,
};
use openstack_keystone_core::service_grant::{ServiceGrantHook, janitor};
use openstack_keystone_core_types::assignment::{Assignment, AssignmentType};
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::oauth2_client::{
    Audience, DelegationPolicy, OAuth2ClientResource, OAuth2ClientResourceCreateBuilder,
};
use openstack_keystone_core_types::resource::{DomainBuilder, ProjectBuilder};
use openstack_keystone_core_types::service_grant::*;
use openstack_keystone_service_grant_driver_raft::RaftServiceGrantBackend;

use crate::assignment::grant_role_to_user_on_project;
use crate::common::{AsyncResourceGuard, get_state_with_config};
use crate::{create_domain, create_project, create_role, create_user};

pub(crate) const TRUST_DOMAIN: &str = "example.org";

pub(crate) async fn get_grant_state() -> Result<(Arc<Service>, tempfile::TempDir)> {
    get_state_with_config(|cfg| {
        cfg.default.public_endpoint = "https://ks.example".parse().ok();
        cfg.interface_internal = serde_json::from_value::<InternalInterface>(json!({
            "type": "spiffe",
            "trust_domains": TRUST_DOMAIN,
        }))
        .ok();
    })
    .await
}

pub(crate) fn svid(client: &OAuth2ClientResource) -> SpiffeId {
    SpiffeId::new(&format!(
        "spiffe://{TRUST_DOMAIN}/service/{}/host/h1",
        client.provider_id
    ))
    .expect("valid test SVID")
}

/// Register a delegatable `tls_client_auth` service in `domain_id`.
async fn register_service(
    state: &ServiceState,
    domain_id: &str,
    cross_domain: bool,
    max_role_ids: Vec<String>,
) -> Result<OAuth2ClientResource> {
    let provider_id = format!("svc-{}", Uuid::new_v4().simple());
    let (client, _) = state
        .provider
        .get_oauth2_client_provider()
        .create(
            &ExecutionContext::internal(state),
            OAuth2ClientResourceCreateBuilder::default()
                .client_id("")
                .provider_id(provider_id.clone())
                .domain_id(domain_id)
                .name("Integration service")
                .token_endpoint_auth_method("tls_client_auth")
                .grant_types(vec![])
                .require_pkce(false)
                .spiffe_ids(vec![format!(
                    "spiffe://{TRUST_DOMAIN}/service/{provider_id}/host/*"
                )])
                .delegation(DelegationPolicy {
                    service_grants: true,
                    cross_domain,
                    max_role_ids,
                    ..Default::default()
                })
                .build()?,
            false,
        )
        .await?;
    Ok(client)
}

type UserGuard =
    AsyncResourceGuard<openstack_keystone_core_types::identity::UserResponse, ServiceState>;
type RoleGuard = AsyncResourceGuard<openstack_keystone_core_types::role::Role, ServiceState>;
type ProjectGuard =
    AsyncResourceGuard<openstack_keystone_core_types::resource::Project, ServiceState>;

/// A password-authenticated security context of `user`, scoped to
/// `project`, as a grant creator holds it.
pub(crate) async fn user_context(
    state: &ServiceState,
    user: &openstack_keystone_core_types::identity::UserResponse,
    project: &openstack_keystone_core_types::resource::Project,
) -> Result<ValidatedSecurityContext> {
    let auth = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::Password)
        .principal(PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id(user.id.clone())
                    .user(user.clone())
                    .build()?,
            ),
        })
        .build()?;
    let ctx = SecurityContext::try_from(auth)?;
    Ok(state
        .provider
        .get_token_provider()
        .issue_token_context(
            &ExecutionContext::internal(state),
            &ctx,
            &ScopeInfo::Project {
                project: ProjectBuilder::default()
                    .id(project.id.clone())
                    .name(project.name.clone())
                    .domain_id(project.domain_id.clone())
                    .enabled(true)
                    .build()?,
                project_domain: DomainBuilder::default()
                    .id(project.domain_id.clone())
                    .name(project.domain_id.clone())
                    .enabled(true)
                    .build()?,
            },
        )
        .await?)
}

async fn create_grant(
    state: &ServiceState,
    vsc: &ValidatedSecurityContext,
    client: &OAuth2ClientResource,
    project_id: &str,
) -> Result<ServiceGrant> {
    Ok(state
        .provider
        .get_service_grant_provider()
        .create_service_grant(
            &ExecutionContext::from_auth(state, vsc),
            ServiceGrantCreate {
                description: None,
                expires_at: None,
                grantee_client_id: client.client_id.clone(),
                project_id: project_id.to_string(),
                role_ids: None,
            },
        )
        .await?)
}

async fn stored(state: &ServiceState, grant: &ServiceGrant) -> Result<Option<ServiceGrant>> {
    Ok(state
        .provider
        .get_service_grant_provider()
        .get_service_grant(
            &ExecutionContext::internal(state),
            &grant.domain_id,
            &grant.id,
        )
        .await?)
}

struct Fixture {
    state: ServiceState,
    _tmp: tempfile::TempDir,
    client: OAuth2ClientResource,
    user: UserGuard,
    project: ProjectGuard,
    role: RoleGuard,
    grant: ServiceGrant,
}

/// One user with `role` on one project, one same-domain service, and a
/// grant from the user to the service.
async fn fixture() -> Result<Fixture> {
    let (state, tmp) = get_grant_state().await?;
    let domain = create_domain!(state)?;
    let project = create_project!(state, domain.id.clone())?;
    let user = create_user!(state, domain.id.clone())?;
    let role = create_role!(state)?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role.id).await?;
    let client = register_service(&state, &domain.id, false, vec![role.id.clone()]).await?;
    let vsc = user_context(&state, &user, &project).await?;
    let grant = create_grant(&state, &vsc, &client, &project.id).await?;
    Ok(Fixture {
        state,
        _tmp: tmp,
        client,
        user,
        project,
        role,
        grant,
    })
}

fn claims_of(
    redeemed: &openstack_keystone_core::service_grant::redeem::RedeemedServiceGrant,
    issuer_domain: &str,
) -> Result<openstack_keystone_core_types::oauth2_client::OpenStackAccessTokenClaims> {
    let now = Utc::now().timestamp();
    Ok(build_service_grant_claims(
        redeemed,
        issuer_domain,
        &format!("https://ks.example/v4/oauth2/{issuer_domain}"),
        Uuid::new_v4().to_string(),
        now,
        now + 300,
        Audience::control_plane(),
    )?)
}

#[tokio::test]
#[traced_test]
async fn test_create_redeem_and_revoke() -> Result<()> {
    let f = fixture().await?;
    assert_eq!(f.grant.domain_id, f.project.domain_id);
    assert_eq!(f.grant.role_ids, std::slice::from_ref(&f.role.id));

    let redeemed = redeem_service_grant(
        &f.state,
        &f.grant.domain_id,
        &svid(&f.client),
        Some(&f.client.client_id),
        &f.grant.id,
        None,
    )
    .await?;
    let claims = claims_of(&redeemed, &f.grant.domain_id)?;
    assert_eq!(claims.sub, f.user.id);
    assert_eq!(claims.amr, ["service_grant"]);
    assert_eq!(
        claims.act.as_ref().map(|a| a.client_id.as_str()),
        Some(f.client.client_id.as_str())
    );

    // Another service's SVID cannot redeem the grant.
    let other = register_service(&f.state, &f.grant.domain_id, false, vec![]).await?;
    assert!(matches!(
        redeem_service_grant(
            &f.state,
            &f.grant.domain_id,
            &svid(&other),
            None,
            &f.grant.id,
            None
        )
        .await,
        Err(ServiceGrantRedeemError::InvalidClient)
    ));

    // Revoking removes it for good.
    f.state
        .provider
        .get_service_grant_provider()
        .delete_service_grant(
            &ExecutionContext::internal(&f.state),
            &f.grant.domain_id,
            &f.grant.id,
        )
        .await?;
    assert!(matches!(
        redeem_service_grant(
            &f.state,
            &f.grant.domain_id,
            &svid(&f.client),
            None,
            &f.grant.id,
            None
        )
        .await,
        Err(ServiceGrantRedeemError::UnknownGrant)
    ));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_redeem_marks_role_lost_when_assignment_is_gone() -> Result<()> {
    let f = fixture().await?;
    f.state
        .provider
        .get_assignment_provider()
        .revoke_grant(
            &ExecutionContext::internal(&f.state),
            Assignment {
                actor_id: f.user.id.clone(),
                role_id: f.role.id.clone(),
                role_name: None,
                target_id: f.project.id.clone(),
                r#type: AssignmentType::UserProject,
                inherited: false,
                implied_via: None,
            },
        )
        .await?;

    assert!(matches!(
        redeem_service_grant(
            &f.state,
            &f.grant.domain_id,
            &svid(&f.client),
            None,
            &f.grant.id,
            None
        )
        .await,
        Err(ServiceGrantRedeemError::RoleLost)
    ));
    let after = stored(&f.state, &f.grant)
        .await?
        .ok_or_eyre("grant is kept")?;
    assert!(!after.enabled);
    assert_eq!(after.disabled_reason, Some(DisabledReason::RoleLost));
    Ok(())
}

/// A user of one domain delegates on a project of another: the grant lives
/// in the project's domain, which issues the token, and the service needs
/// the cross-domain opt-in.
#[tokio::test]
#[traced_test]
async fn test_cross_domain_grant_is_anchored_on_the_project_domain() -> Result<()> {
    let (state, _tmp) = get_grant_state().await?;
    let users_domain = create_domain!(state)?;
    let project_domain = create_domain!(state)?;
    let project = create_project!(state, project_domain.id.clone())?;
    let user = create_user!(state, users_domain.id.clone())?;
    let role = create_role!(state)?;
    grant_role_to_user_on_project(&state, &user.id, &project.id, &role.id).await?;
    let vsc = user_context(&state, &user, &project).await?;

    // Without the opt-in the grant is refused.
    let local = register_service(&state, &project_domain.id, false, vec![]).await?;
    assert!(
        create_grant(&state, &vsc, &local, &project.id)
            .await
            .is_err()
    );

    let shared = register_service(&state, &project_domain.id, true, vec![]).await?;
    let grant = create_grant(&state, &vsc, &shared, &project.id).await?;
    assert_eq!(grant.domain_id, project_domain.id);

    let redeemed = redeem_service_grant(
        &state,
        &project_domain.id,
        &svid(&shared),
        None,
        &grant.id,
        None,
    )
    .await?;
    let claims = claims_of(&redeemed, &project_domain.id)?;
    assert_eq!(claims.sub, user.id);
    assert_eq!(
        claims.iss,
        format!("https://ks.example/v4/oauth2/{}", project_domain.id)
    );
    // It is not redeemable at the grantor's domain.
    assert!(matches!(
        redeem_service_grant(
            &state,
            &users_domain.id,
            &svid(&shared),
            None,
            &grant.id,
            None
        )
        .await,
        Err(ServiceGrantRedeemError::UnknownGrant)
    ));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_registration_rejects_unknown_ceiling_role() -> Result<()> {
    let (state, _tmp) = get_grant_state().await?;
    let domain = create_domain!(state)?;
    assert!(
        register_service(
            &state,
            &domain.id,
            false,
            vec![Uuid::new_v4().simple().to_string()]
        )
        .await
        .is_err()
    );
    Ok(())
}

async fn on_event(f: &Fixture, operation: Operation, payload: EventPayload) {
    use openstack_keystone_core::events::ProviderHooks;
    ServiceGrantHook::new(f.state.clone())
        .on_event(&Event::new(operation, payload))
        .await;
}

#[tokio::test]
#[traced_test]
async fn test_hook_disables_grants_of_a_disabled_grantor_or_project() -> Result<()> {
    let f = fixture().await?;
    on_event(
        &f,
        Operation::Disable,
        EventPayload::User {
            id: f.user.id.clone(),
        },
    )
    .await;
    let after = stored(&f.state, &f.grant)
        .await?
        .ok_or_eyre("grant is kept")?;
    assert!(!after.enabled);
    assert_eq!(after.disabled_reason, Some(DisabledReason::GrantorDisabled));

    let g = fixture().await?;
    on_event(
        &g,
        Operation::Disable,
        EventPayload::Project {
            id: g.project.id.clone(),
        },
    )
    .await;
    let after = stored(&g.state, &g.grant)
        .await?
        .ok_or_eyre("grant is kept")?;
    assert_eq!(after.disabled_reason, Some(DisabledReason::TargetDisabled));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_hook_deletes_grants_of_a_deleted_grantor() -> Result<()> {
    let f = fixture().await?;
    on_event(
        &f,
        Operation::Delete,
        EventPayload::User {
            id: f.user.id.clone(),
        },
    )
    .await;
    assert!(stored(&f.state, &f.grant).await?.is_none());
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_hook_disables_grants_of_a_removed_grantee() -> Result<()> {
    let f = fixture().await?;
    f.state
        .provider
        .get_oauth2_client_provider()
        .delete(
            &ExecutionContext::internal(&f.state),
            &f.client.domain_id,
            &f.client.provider_id,
        )
        .await?;
    on_event(
        &f,
        Operation::Delete,
        EventPayload::Oauth2Client {
            domain_id: f.client.domain_id.clone(),
            provider_id: f.client.provider_id.clone(),
        },
    )
    .await;
    let after = stored(&f.state, &f.grant)
        .await?
        .ok_or_eyre("grant is kept")?;
    assert_eq!(after.disabled_reason, Some(DisabledReason::GranteeRemoved));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_hook_disables_grants_after_role_assignment_removal() -> Result<()> {
    let f = fixture().await?;
    f.state
        .provider
        .get_assignment_provider()
        .revoke_grant(
            &ExecutionContext::internal(&f.state),
            Assignment {
                actor_id: f.user.id.clone(),
                role_id: f.role.id.clone(),
                role_name: None,
                target_id: f.project.id.clone(),
                r#type: AssignmentType::UserProject,
                inherited: false,
                implied_via: None,
            },
        )
        .await?;
    on_event(
        &f,
        Operation::Delete,
        EventPayload::RoleAssignment {
            role_id: f.role.id.clone(),
            user_id: Some(f.user.id.clone()),
            group_id: None,
            project_id: Some(f.project.id.clone()),
            domain_id: None,
            system_id: None,
        },
    )
    .await;
    let after = stored(&f.state, &f.grant)
        .await?
        .ok_or_eyre("grant is kept")?;
    assert_eq!(after.disabled_reason, Some(DisabledReason::RoleLost));
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_janitor_disables_expired_and_purges_after_retention() -> Result<()> {
    let f = fixture().await?;
    let backend = RaftServiceGrantBackend::default();
    let now = Utc::now();
    let make = |expires_in: Duration| ServiceGrant {
        id: Uuid::new_v4().simple().to_string(),
        expires_at: Some(now + expires_in),
        ..f.grant.clone()
    };
    let live = make(Duration::days(1));
    let expired = make(Duration::minutes(-5));
    let old = make(Duration::days(-31));
    for grant in [&live, &expired, &old] {
        backend
            .create_service_grant(&f.state, grant.clone())
            .await?;
    }

    let report = janitor::sweep_if_leader(&f.state)
        .await
        .ok_or_eyre("single-node raft cluster must be its own leader")??;
    assert_eq!(report.errors, 0, "{report:?}");
    // The grant past retention is deleted outright, not disabled first.
    assert!(report.disabled >= 1 && report.deleted >= 1, "{report:?}");

    assert!(
        stored(&f.state, &live)
            .await?
            .ok_or_eyre("live grant")?
            .enabled
    );
    let expired_after = stored(&f.state, &expired)
        .await?
        .ok_or_eyre("expired grant is kept")?;
    assert!(!expired_after.enabled);
    assert_eq!(expired_after.disabled_reason, Some(DisabledReason::Expired));
    assert!(stored(&f.state, &old).await?.is_none(), "past retention");
    Ok(())
}

/// Sign `claims` with the domain's real active key.
pub(crate) async fn sign_claims(
    state: &ServiceState,
    domain_id: &str,
    claims: &openstack_keystone_core_types::oauth2_client::OpenStackAccessTokenClaims,
) -> Result<String> {
    use openstack_keystone_key_repository::asymmetric::{
        derive_kid, jwt_algorithm, to_encoding_key,
    };
    let key = state
        .provider
        .get_oauth2_key_provider()
        .active_signing_key(state, domain_id)
        .await?;
    let mut header = jsonwebtoken::Header::new(jwt_algorithm(key.algorithm));
    header.kid = Some(derive_kid(&key.public_key_der));
    Ok(jsonwebtoken::encode(
        &header,
        claims,
        &to_encoding_key(&key)?,
    )?)
}

#[tokio::test]
#[traced_test]
async fn test_bound_bearer_is_accepted_only_with_the_actors_svid() -> Result<()> {
    let f = fixture().await?;
    let domain = f.grant.domain_id.clone();
    f.state
        .provider
        .get_oauth2_key_provider()
        .ensure_domain_keys(&f.state, &domain)
        .await?;
    let redeemed = redeem_service_grant(
        &f.state,
        &domain,
        &svid(&f.client),
        Some(&f.client.client_id),
        &f.grant.id,
        None,
    )
    .await?;
    let token = sign_claims(&f.state, &domain, &claims_of(&redeemed, &domain)?).await?;

    // The actor's own SVID turns the token into the grant's context.
    let vsc = authenticate_bound_bearer(&f.state, &svid(&f.client), &token).await?;
    assert!(vsc.authentication_context().is_delegated());
    assert!(matches!(
        vsc.authentication_context(),
        AuthenticationContext::ServiceGrant { .. }
    ));

    // Another service's SVID is no proof for this token.
    let other = register_service(&f.state, &domain, false, vec![]).await?;
    assert!(matches!(
        authenticate_bound_bearer(&f.state, &svid(&other), &token).await,
        Err(BoundBearerError::NotBound(_))
    ));

    // A foreign or unsigned token never reaches the grant.
    assert!(matches!(
        authenticate_bound_bearer(&f.state, &svid(&f.client), "a.b.c").await,
        Err(BoundBearerError::InvalidToken(_))
    ));

    // The live grant is re-checked on every request.
    f.state
        .provider
        .get_service_grant_provider()
        .delete_service_grant(&ExecutionContext::internal(&f.state), &domain, &f.grant.id)
        .await?;
    assert!(matches!(
        authenticate_bound_bearer(&f.state, &svid(&f.client), &token).await,
        Err(BoundBearerError::NotBound(_))
    ));
    Ok(())
}
