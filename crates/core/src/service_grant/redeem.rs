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
//! Redeeming a service grant at the OAuth2 token endpoint (ADR 0036 §5.1).

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;
use tracing::warn;

use openstack_keystone_core_types::auth::*;
use openstack_keystone_core_types::oauth2_client::{
    ActClaim, ActSubType, Audience, DelegationContext, OAuth2ClientResource,
    OpenStackAccessTokenClaims, OpenStackContext, OpenStackScope, spiffe_id_matches_any,
};
use openstack_keystone_core_types::service_grant::*;

use crate::auth::{ExecutionContext, ValidatedSecurityContext};
use crate::common::SpiffeId;
use crate::keystone::ServiceState;
use crate::oauth2_client::service::TLS_CLIENT_AUTH;
use crate::service_grant::service::disable_grant;

/// Why a redemption was refused. Each maps to one token endpoint error.
#[derive(Debug, Error)]
pub enum ServiceGrantRedeemError {
    /// No such grant in the token endpoint's domain, or it may not be
    /// redeemed by its grantee here (`invalid_grant`).
    #[error("unknown service grant")]
    UnknownGrant,
    /// The presented SVID does not authenticate the grant's grantee client
    /// (`invalid_client`).
    #[error("the client is not authenticated for this grant")]
    InvalidClient,
    /// The grant is disabled or expired (`403`).
    #[error("service grant {0} is disabled or expired")]
    Disabled(String),
    /// The requested `roles` are not a subset of the grant's
    /// (`invalid_request`).
    #[error("requested roles are not part of the grant")]
    InvalidRoles,
    /// None of the requested roles is still held by the grantor (`403`).
    #[error("the grantor holds none of the delegated roles")]
    RoleLost,
    /// The grantor, its domain or the target project is not usable
    /// (`invalid_grant`).
    #[error(transparent)]
    Authentication(#[from] AuthenticationError),
    /// A storage or provider failure (`server_error`).
    #[error("{0}")]
    Provider(String),
}

impl ServiceGrantRedeemError {
    fn provider(e: impl std::fmt::Display) -> Self {
        Self::Provider(e.to_string())
    }
}

/// A successful redemption: the grantor's security context bounded by the
/// grant, the grant as stored, and the authenticated grantee client.
#[derive(Debug)]
pub struct RedeemedServiceGrant {
    /// The grantor acting under the grant, scoped to its project with the
    /// intersected roles.
    pub vsc: ValidatedSecurityContext,
    /// The grant as stored (before any `roles` narrowing).
    pub grant: ServiceGrant,
    /// The grantee client.
    pub client: OAuth2ClientResource,
    /// When the grant stops being redeemable: the earlier of its
    /// `expires_at` and `created_at` plus the client's current
    /// `max_grant_lifetime`. Tokens must not outlive it.
    pub valid_until: Option<DateTime<Utc>>,
}

/// Redeem grant `grant_id` at the token endpoint of `domain_id`, for a
/// caller presenting `svid` on the internal interface (ADR 0036 §5.1 checks
/// 2-6).
///
/// `client_id`, when the request carries one, must name the grant's grantee.
/// `roles`, when given, narrows the grant's roles further and must be a
/// non-empty subset of them.
///
/// Side effects, best effort: a grant whose grantor lost every delegated
/// role is disabled as `RoleLost`, an expired one as `Expired`, and
/// `last_redeemed_at` is refreshed at most once per
/// `[delegation] last_redeemed_update_interval`.
pub async fn redeem_service_grant(
    state: &ServiceState,
    domain_id: &str,
    svid: &SpiffeId,
    client_id: Option<&str>,
    grant_id: &str,
    roles: Option<Vec<String>>,
) -> Result<RedeemedServiceGrant, ServiceGrantRedeemError> {
    // Check 3: a grant is only redeemable at its own domain's endpoint,
    // which is the domain of its project (the grantor may belong to
    // another one).
    let grant = state
        .provider
        .get_service_grant_provider()
        .get_service_grant(&ExecutionContext::internal(state), domain_id, grant_id)
        .await
        .map_err(ServiceGrantRedeemError::provider)?
        .ok_or(ServiceGrantRedeemError::UnknownGrant)?;
    redeem_loaded_service_grant(state, svid, client_id, grant, roles, true).await
}

/// Redeem `grant`, already loaded from the endpoint's domain, with checks
/// 2 and 4-6 of [`redeem_service_grant`].
///
/// `touch` tells whether `last_redeemed_at` is refreshed: a redemption at
/// the token endpoint does, the per-request re-evaluation of a presented
/// token (ADR 0036 §8.1) does not, so the field keeps meaning "last
/// redeemed".
pub async fn redeem_loaded_service_grant(
    state: &ServiceState,
    svid: &SpiffeId,
    client_id: Option<&str>,
    grant: ServiceGrant,
    roles: Option<Vec<String>>,
    touch: bool,
) -> Result<RedeemedServiceGrant, ServiceGrantRedeemError> {
    let internal = ExecutionContext::internal(state);

    // Check 2: the client is resolved from the grant (ADR 0036 §3.2) and
    // authenticated by the SVID against its own `spiffe_ids`.
    let client = state
        .provider
        .get_oauth2_client_provider()
        .get_by_client_id(&internal, grant.grantee.client_id())
        .await
        .map_err(ServiceGrantRedeemError::provider)?
        .ok_or(ServiceGrantRedeemError::InvalidClient)?;
    let Grantee::Client {
        client_domain_id, ..
    } = &grant.grantee;
    let policy = client
        .service_grant_policy()
        .ok_or(ServiceGrantRedeemError::InvalidClient)?;
    if &client.domain_id != client_domain_id
        || client.token_endpoint_auth_method != TLS_CLIENT_AUTH
        || !spiffe_id_matches_any(&client.spiffe_ids, svid.as_str())
        || client_id.is_some_and(|id| id != client.client_id)
    {
        return Err(ServiceGrantRedeemError::InvalidClient);
    }
    // Check 4: a grantee acting for a user or on a project of another
    // domain must accept cross-domain grants.
    let grantor = state
        .provider
        .get_identity_provider()
        .get_user(&internal, &grant.grantor_user_id)
        .await
        .map_err(ServiceGrantRedeemError::provider)?
        .ok_or(AuthenticationError::Unauthorized)?;
    if (client.domain_id != grant.domain_id || client.domain_id != grantor.domain_id)
        && !policy.cross_domain
    {
        return Err(ServiceGrantRedeemError::UnknownGrant);
    }

    let now = Utc::now();
    if !grant.enabled {
        return Err(ServiceGrantRedeemError::Disabled(grant.id.clone()));
    }
    if grant.is_expired(now) {
        disable(state, &grant, DisabledReason::Expired).await;
        return Err(ServiceGrantRedeemError::Disabled(grant.id.clone()));
    }

    // The client's current policy bounds the grant: a ceiling or lifetime
    // tightened after creation applies to existing grants at redemption.
    let mut valid_until = grant.expires_at;
    if let Some(max) = policy.max_grant_lifetime {
        let max =
            Duration::try_seconds(i64::try_from(max).unwrap_or(i64::MAX)).unwrap_or(Duration::MAX);
        if let Some(end) = grant.created_at.checked_add_signed(max) {
            if now > end {
                return Err(ServiceGrantRedeemError::Disabled(grant.id.clone()));
            }
            valid_until = Some(valid_until.map_or(end, |v| v.min(end)));
        }
    }
    let mut bounded = grant.clone();
    if !policy.max_role_ids.is_empty() {
        bounded.role_ids.retain(|r| policy.max_role_ids.contains(r));
        if bounded.role_ids.is_empty() {
            return Err(ServiceGrantRedeemError::RoleLost);
        }
    }
    // Losing roles to a narrowing (the caller's, or a tightened ceiling) is
    // not the grantor losing them, so it never disables the grant.
    let narrowed = roles.is_some() || bounded.role_ids.len() != grant.role_ids.len();
    if let Some(roles) = roles {
        if roles.is_empty() || roles.iter().any(|r| !bounded.role_ids.contains(r)) {
            return Err(ServiceGrantRedeemError::InvalidRoles);
        }
        bounded.role_ids = roles;
    }

    // Check 5: the grantor and its domain are enabled (`validate` in
    // `new_for_scope`), and the target project exists and is enabled.
    let resource = state.provider.get_resource_provider();
    let project = resource
        .get_project(&internal, grant.target.project_id())
        .await
        .map_err(ServiceGrantRedeemError::provider)?
        .filter(|p| p.enabled)
        .ok_or_else(|| {
            AuthenticationError::ProjectDisabled(grant.target.project_id().to_string())
        })?;
    let project_domain = resource
        .get_domain(&internal, &project.domain_id)
        .await
        .map_err(ServiceGrantRedeemError::provider)?
        .filter(|d| d.enabled)
        .ok_or_else(|| AuthenticationError::DomainDisabled(project.domain_id.clone()))?;

    let auth_result = AuthenticationResultBuilder::default()
        .context(AuthenticationContext::ServiceGrant {
            grant: bounded,
            actor: ActorInfo {
                client_id: client.client_id.clone(),
                spiffe_id: svid.to_string(),
            },
        })
        .principal(
            PrincipalInfoBuilder::default()
                .identity(IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id(grant.grantor_user_id.clone())
                        .user(grantor)
                        .build()
                        .map_err(AuthenticationError::from)?,
                ))
                .build()
                .map_err(AuthenticationError::from)?,
        )
        .build()
        .map_err(AuthenticationError::from)?;
    let ctx = SecurityContext::try_from(auth_result)?;

    // Check 6: the grant's roles intersected with the grantor's live roles
    // (`calculate_effective_roles`); nothing left fails the redemption.
    let vsc = match ValidatedSecurityContext::new_for_scope(
        ctx,
        ScopeInfo::Project {
            project,
            project_domain,
        },
        state,
    )
    .await
    {
        Ok(vsc) => vsc,
        Err(AuthenticationError::ActorHasNoRolesOnTarget) => {
            // Only the full grant losing every role disables it; an empty
            // narrowing is the caller's choice.
            if !narrowed {
                disable(state, &grant, DisabledReason::RoleLost).await;
            }
            return Err(ServiceGrantRedeemError::RoleLost);
        }
        Err(e) => return Err(e.into()),
    };

    if touch {
        touch_last_redeemed(state, &grant).await;
    }

    Ok(RedeemedServiceGrant {
        vsc,
        grant,
        client,
        valid_until,
    })
}

/// Disable `grant` for `reason`. Failures are logged; the redemption fails
/// regardless.
async fn disable(state: &ServiceState, grant: &ServiceGrant, reason: DisabledReason) {
    if !grant.enabled {
        return;
    }
    if let Err(e) = disable_grant(state, grant, reason).await {
        warn!(grant_id = %grant.id, error = %e, "failed to disable service grant");
    }
}

/// Refresh `last_redeemed_at` when it is older than the configured interval.
/// An inventory hint, not a control: a lost update is acceptable.
async fn touch_last_redeemed(state: &ServiceState, grant: &ServiceGrant) {
    let interval = state
        .config_manager
        .config
        .read()
        .await
        .delegation
        .last_redeemed_update_interval;
    let now = Utc::now();
    let due = grant.last_redeemed_at.is_none_or(|last| {
        now - last >= Duration::seconds(i64::try_from(interval).unwrap_or(i64::MAX))
    });
    if !due {
        return;
    }
    if let Err(e) = state
        .provider
        .get_service_grant_provider()
        .update_service_grant(
            &ExecutionContext::internal(state),
            &grant.domain_id,
            &grant.id,
            ServiceGrantUpdate {
                last_redeemed_at: Some(now),
                ..Default::default()
            },
            grant.version,
        )
        .await
    {
        warn!(grant_id = %grant.id, error = %e, "failed to record service grant redemption");
    }
}

/// Build the access token claims of a redeemed grant (ADR 0036 §5.2): `sub`
/// is the grantor, `act` the service, `amr` is `["service_grant"]` (never
/// the grantor's own methods), and the delegation context carries the grant
/// id and its project. No refresh token exists for this grant type.
///
/// `domain_id` is the issuing domain, which must own the grant's project: a
/// grant whose project is outside it is refused rather than signed (ADR
/// 0026 §5 domain key isolation). The grantor may be of any domain.
#[allow(clippy::too_many_arguments)]
pub fn build_service_grant_claims(
    redeemed: &RedeemedServiceGrant,
    domain_id: &str,
    issuer: &str,
    jti: String,
    iat: i64,
    exp: i64,
    aud: Audience,
) -> Result<OpenStackAccessTokenClaims, ServiceGrantRedeemError> {
    let sc = redeemed.vsc.inner();
    let AuthenticationContext::ServiceGrant { grant, actor } = sc.authentication_context() else {
        return Err(ServiceGrantRedeemError::UnknownGrant);
    };
    let IdentityInfo::User(user) = &sc.principal().identity else {
        return Err(AuthenticationError::AuthzPrincipalMismatch.into());
    };
    let authz = sc
        .authorization()
        .ok_or(AuthenticationError::SecurityContextNotResolved)?;
    let ScopeInfo::Project {
        project,
        project_domain,
    } = &authz.scope
    else {
        return Err(AuthenticationError::ScopeNotAllowed.into());
    };
    if project_domain.id != domain_id || project.id != grant.target.project_id() {
        return Err(ServiceGrantRedeemError::UnknownGrant);
    }

    let roles = authz.effective_roles().unwrap_or(&[]).to_vec();
    let role_names: Vec<String> = roles.iter().filter_map(|r| r.name.clone()).collect();

    Ok(OpenStackAccessTokenClaims {
        iss: issuer.to_string(),
        sub: user.user_id.clone(),
        aud,
        client_id: actor.client_id.clone(),
        exp,
        iat,
        nbf: iat,
        jti,
        // Not mapping-engine-derived; see the token exchange grant.
        keystone_ruleset_version: 0,
        amr: vec!["service_grant".to_string()],
        token_use: "access".to_string(),
        delegation_context: DelegationContext::ServiceGrant {
            project_id: project.id.clone(),
            grant_id: grant.id.clone(),
        },
        act: Some(ActClaim {
            client_id: actor.client_id.clone(),
            sub_type: ActSubType::Spiffe,
            sub: actor.spiffe_id.clone(),
        }),
        openstack_context: OpenStackContext {
            user_id: user.user_id.clone(),
            user_name: user
                .user
                .as_ref()
                .map(|u| u.name.clone())
                .unwrap_or_else(|| user.user_id.clone()),
            user_domain_id: user.user_domain.as_ref().map(|d| d.id.clone()),
            scope: OpenStackScope::Project {
                project_id: project.id.clone(),
                project_domain_id: project_domain.id.clone(),
                roles,
            },
            roles: role_names,
        },
        cnf: None,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use openstack_keystone_core_types::assignment::{Assignment, AssignmentType};
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::oauth2_client::DelegationPolicy;
    use openstack_keystone_core_types::resource::{Domain, Project};

    use super::*;
    use crate::assignment::MockAssignmentProvider;
    use crate::identity::MockIdentityProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::role::MockRoleProvider;
    use crate::service_grant::MockServiceGrantProvider;
    use crate::tests::get_mocked_state;

    const SVID: &str = "spiffe://td/service/heat-engine/host/h1";

    fn grant() -> ServiceGrant {
        ServiceGrant {
            id: "g1".into(),
            version: 4,
            domain_id: "d1".into(),
            grantor_user_id: "u1".into(),
            grantee: Grantee::Client {
                client_id: "heat".into(),
                client_domain_id: "infra".into(),
            },
            target: GrantTarget::Project {
                project_id: "p1".into(),
                project_domain_id: "d1".into(),
            },
            role_ids: vec!["member".into(), "reader".into()],
            expires_at: None,
            description: None,
            enabled: true,
            created_at: Utc::now(),
            last_redeemed_at: None,
            disabled_reason: None,
        }
    }

    fn client(cross_domain: bool) -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_id: "heat".into(),
            provider_id: "heat".into(),
            domain_id: "infra".into(),
            client_secret_hash: None,
            redirect_uris: vec![],
            token_endpoint_auth_method: TLS_CLIENT_AUTH.into(),
            grant_types: vec![],
            require_pkce: false,
            allowed_scopes: vec![],
            pre_authorized: false,
            enabled: true,
            claims_template: HashMap::new(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
            name: "Heat".into(),
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
            spiffe_ids: vec!["spiffe://td/service/heat-engine/host/*".into()],
            delegation: Some(DelegationPolicy {
                service_grants: true,
                cross_domain,
                ..Default::default()
            }),
            dpop_bound_access_tokens: false,
        }
    }

    fn assignment(role_id: &str) -> Assignment {
        Assignment {
            actor_id: "u1".into(),
            role_id: role_id.into(),
            role_name: Some(role_id.into()),
            target_id: "p1".into(),
            r#type: AssignmentType::UserProject,
            inherited: false,
            implied_via: None,
        }
    }

    /// A state where grant `g1` is `stored`, the grantee client is `client`,
    /// and the grantor holds `roles` on `p1`. `expect_update` names the
    /// lifecycle update the redemption must write, if any.
    async fn state(
        stored: ServiceGrant,
        client: OAuth2ClientResource,
        roles: &'static [&'static str],
        expect_update: Option<fn(&ServiceGrantUpdate) -> bool>,
    ) -> ServiceState {
        state_with_grantor_domain(stored, client, roles, expect_update, "d1").await
    }

    /// Like [`state`], with the grantor in `grantor_domain`.
    async fn state_with_grantor_domain(
        stored: ServiceGrant,
        client: OAuth2ClientResource,
        roles: &'static [&'static str],
        expect_update: Option<fn(&ServiceGrantUpdate) -> bool>,
        grantor_domain: &'static str,
    ) -> ServiceState {
        let mut grants = MockServiceGrantProvider::default();
        grants
            .expect_get_service_grant()
            .returning(move |_, d, id| Ok((d == "d1" && id == "g1").then(|| stored.clone())));
        match expect_update {
            Some(check) => {
                grants
                    .expect_update_service_grant()
                    .withf(move |_, _, id, update, version| {
                        id == "g1" && *version == 4 && check(update)
                    })
                    .times(1)
                    .returning(|_, _, _, _, _| Ok(grant()));
            }
            None => {
                grants.expect_update_service_grant().never();
            }
        }
        let mut clients = MockOauth2ClientProvider::default();
        clients
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let mut identity = MockIdentityProvider::default();
        identity.expect_get_user().returning(move |_, id| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id(id)
                    .domain_id(grantor_domain)
                    .enabled(true)
                    .name("alice")
                    .build()
                    .unwrap(),
            ))
        });
        let mut resource = MockResourceProvider::default();
        resource.expect_get_project().returning(|_, id| {
            Ok(Some(Project {
                id: id.to_string(),
                domain_id: "d1".into(),
                enabled: true,
                name: "p".into(),
                ..Default::default()
            }))
        });
        resource.expect_get_domain().returning(|_, id| {
            Ok(Some(Domain {
                id: id.to_string(),
                name: id.to_string(),
                enabled: true,
                ..Default::default()
            }))
        });
        let mut assignments = MockAssignmentProvider::default();
        assignments
            .expect_list_role_assignments()
            .returning(move |_, _| Ok(roles.iter().map(|r| assignment(r)).collect()));
        let mut role = MockRoleProvider::default();
        role.expect_expand_implied_roles().returning(|_, _| Ok(()));
        get_mocked_state(
            None,
            Some(
                Provider::mocked_builder()
                    .mock_service_grant(grants)
                    .mock_oauth2_client(clients)
                    .mock_identity(identity)
                    .mock_resource(resource)
                    .mock_assignment(assignments)
                    .mock_role(role),
            ),
        )
        .await
    }

    fn svid(s: &str) -> SpiffeId {
        SpiffeId::new(s).unwrap()
    }

    fn records_redemption(u: &ServiceGrantUpdate) -> bool {
        u.last_redeemed_at.is_some() && u.enabled.is_none()
    }

    #[tokio::test]
    async fn test_redeem_intersects_roles_and_records_redemption() {
        let state = state(
            grant(),
            client(true),
            &["member", "admin"],
            Some(records_redemption),
        )
        .await;
        let redeemed = redeem_service_grant(&state, "d1", &svid(SVID), Some("heat"), "g1", None)
            .await
            .unwrap();
        let roles: Vec<_> = redeemed
            .vsc
            .inner()
            .authorization()
            .and_then(|a| a.effective_roles())
            .unwrap()
            .iter()
            .map(|r| r.id.clone())
            .collect();
        assert_eq!(roles, ["member"]);

        let claims = build_service_grant_claims(
            &redeemed,
            "d1",
            "https://ks/v4/oauth2/d1",
            "jti".into(),
            1,
            2,
            Audience::control_plane(),
        )
        .unwrap();
        assert_eq!(claims.sub, "u1");
        assert_eq!(claims.client_id, "heat");
        assert_eq!(claims.amr, ["service_grant"]);
        assert_eq!(
            claims.delegation_context,
            DelegationContext::ServiceGrant {
                project_id: "p1".into(),
                grant_id: "g1".into(),
            }
        );
        assert_eq!(
            claims.act,
            Some(ActClaim {
                client_id: "heat".into(),
                sub_type: ActSubType::Spiffe,
                sub: SVID.into(),
            })
        );
        let json = serde_json::to_value(&claims).unwrap();
        assert_eq!(json["act"]["sub_type"], "spiffe");
        assert_eq!(json["delegation_context"]["auth_method"], "service_grant");
        assert_eq!(json["delegation_context"]["delegated_project_id"], "p1");
        // A token is only signed for the grant's own domain.
        assert!(matches!(
            build_service_grant_claims(
                &redeemed,
                "d2",
                "https://ks/v4/oauth2/d2",
                "jti".into(),
                1,
                2,
                Audience::control_plane(),
            ),
            Err(ServiceGrantRedeemError::UnknownGrant)
        ));
    }

    #[tokio::test]
    async fn test_redeem_recent_redemption_is_not_rewritten() {
        let mut stored = grant();
        stored.last_redeemed_at = Some(Utc::now());
        let state = state(stored, client(true), &["member"], None).await;
        assert!(
            redeem_service_grant(&state, "d1", &svid(SVID), None, "g1", None)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_redeem_rejects_unauthenticated_client() {
        let state = state(grant(), client(true), &["member"], None).await;
        for (presented, client_id) in [
            ("spiffe://td/service/nova/host/h1", None),
            ("spiffe://other/service/heat-engine/host/h1", None),
            (SVID, Some("other-client")),
        ] {
            assert!(matches!(
                redeem_service_grant(&state, "d1", &svid(presented), client_id, "g1", None).await,
                Err(ServiceGrantRedeemError::InvalidClient)
            ));
        }
    }

    #[tokio::test]
    async fn test_redeem_rejects_other_domain_and_unknown_grant() {
        let state = state(grant(), client(true), &["member"], None).await;
        for (domain, id) in [("d2", "g1"), ("d1", "missing")] {
            assert!(matches!(
                redeem_service_grant(&state, domain, &svid(SVID), None, id, None).await,
                Err(ServiceGrantRedeemError::UnknownGrant)
            ));
        }
    }

    /// A grantee of another domain must accept cross-domain grants.
    #[tokio::test]
    async fn test_redeem_rejects_cross_domain_without_opt_in() {
        let state = state(grant(), client(false), &["member"], None).await;
        assert!(matches!(
            redeem_service_grant(&state, "d1", &svid(SVID), None, "g1", None).await,
            Err(ServiceGrantRedeemError::UnknownGrant)
        ));
    }

    /// A grantor of another domain than the project redeems at the
    /// project's domain, which signs the token.
    #[tokio::test]
    async fn test_redeem_grantor_of_other_domain() {
        let state = state_with_grantor_domain(
            grant(),
            client(true),
            &["member"],
            Some(records_redemption),
            "users",
        )
        .await;
        let redeemed = redeem_service_grant(&state, "d1", &svid(SVID), None, "g1", None)
            .await
            .unwrap();
        let claims = build_service_grant_claims(
            &redeemed,
            "d1",
            "https://ks/v4/oauth2/d1",
            "jti".into(),
            1,
            2,
            Audience::control_plane(),
        )
        .unwrap();
        assert_eq!(claims.sub, "u1");
        assert_eq!(
            claims.openstack_context.user_domain_id.as_deref(),
            Some("users")
        );
        assert!(matches!(
            claims.openstack_context.scope,
            OpenStackScope::Project { ref project_domain_id, .. } if project_domain_id == "d1"
        ));
    }

    /// A service of the project's domain without the cross-domain opt-in
    /// does not act for a grantor of another domain.
    #[tokio::test]
    async fn test_redeem_rejects_grantor_of_other_domain_without_opt_in() {
        let mut stored = grant();
        stored.grantee = Grantee::Client {
            client_id: "heat".into(),
            client_domain_id: "d1".into(),
        };
        let mut local = client(false);
        local.domain_id = "d1".into();
        let state = state_with_grantor_domain(stored, local, &["member"], None, "users").await;
        assert!(matches!(
            redeem_service_grant(&state, "d1", &svid(SVID), None, "g1", None).await,
            Err(ServiceGrantRedeemError::UnknownGrant)
        ));
    }

    #[tokio::test]
    async fn test_redeem_disabled_grant_is_not_rewritten() {
        let mut stored = grant();
        stored.enabled = false;
        stored.disabled_reason = Some(DisabledReason::Revoked);
        let state = state(stored, client(true), &["member"], None).await;
        assert!(matches!(
            redeem_service_grant(&state, "d1", &svid(SVID), None, "g1", None).await,
            Err(ServiceGrantRedeemError::Disabled(_))
        ));
    }

    #[tokio::test]
    async fn test_redeem_expired_grant_is_disabled() {
        let mut stored = grant();
        stored.expires_at = Some(Utc::now() - Duration::seconds(1));
        let state = state(
            stored,
            client(true),
            &["member"],
            Some(|u| {
                u.enabled == Some(false) && u.disabled_reason == Some(DisabledReason::Expired)
            }),
        )
        .await;
        assert!(matches!(
            redeem_service_grant(&state, "d1", &svid(SVID), None, "g1", None).await,
            Err(ServiceGrantRedeemError::Disabled(_))
        ));
    }

    #[tokio::test]
    async fn test_redeem_role_lost_disables_grant() {
        let state = state(
            grant(),
            client(true),
            &["admin"],
            Some(|u| {
                u.enabled == Some(false) && u.disabled_reason == Some(DisabledReason::RoleLost)
            }),
        )
        .await;
        assert!(matches!(
            redeem_service_grant(&state, "d1", &svid(SVID), None, "g1", None).await,
            Err(ServiceGrantRedeemError::RoleLost)
        ));
    }

    #[tokio::test]
    async fn test_redeem_roles_narrowing() {
        // Narrowing to a role the grantor lost fails without disabling.
        let state = state(grant(), client(true), &["member"], None).await;
        assert!(matches!(
            redeem_service_grant(
                &state,
                "d1",
                &svid(SVID),
                None,
                "g1",
                Some(vec!["reader".into()])
            )
            .await,
            Err(ServiceGrantRedeemError::RoleLost)
        ));
        for roles in [vec![], vec!["admin".to_string()]] {
            assert!(matches!(
                redeem_service_grant(&state, "d1", &svid(SVID), None, "g1", Some(roles)).await,
                Err(ServiceGrantRedeemError::InvalidRoles)
            ));
        }
    }

    #[tokio::test]
    async fn test_redeem_applies_current_max_role_ids() {
        // The ceiling was tightened after the grant was created.
        let mut c = client(true);
        if let Some(d) = c.delegation.as_mut() {
            d.max_role_ids = vec!["reader".into()];
        }
        let st = state(grant(), c.clone(), &["member"], None).await;
        assert!(matches!(
            redeem_service_grant(&st, "d1", &svid(SVID), None, "g1", None).await,
            Err(ServiceGrantRedeemError::RoleLost)
        ));
        // A role outside the ceiling cannot be requested either.
        let st = state(grant(), c, &["member"], None).await;
        assert!(matches!(
            redeem_service_grant(
                &st,
                "d1",
                &svid(SVID),
                None,
                "g1",
                Some(vec!["member".into()])
            )
            .await,
            Err(ServiceGrantRedeemError::InvalidRoles)
        ));
    }

    #[tokio::test]
    async fn test_redeem_applies_current_max_grant_lifetime() {
        let mut stored = grant();
        stored.created_at = Utc::now() - Duration::seconds(7200);
        let mut c = client(true);
        if let Some(d) = c.delegation.as_mut() {
            d.max_grant_lifetime = Some(3600);
        }
        let state = state(stored, c, &["member"], None).await;
        assert!(matches!(
            redeem_service_grant(&state, "d1", &svid(SVID), None, "g1", None).await,
            Err(ServiceGrantRedeemError::Disabled(_))
        ));
    }

    #[tokio::test]
    async fn test_redeem_valid_until_is_earliest_end() {
        let mut stored = grant();
        stored.created_at = Utc::now() - Duration::seconds(600);
        stored.expires_at = Some(Utc::now() + Duration::seconds(86400));
        let mut c = client(true);
        if let Some(d) = c.delegation.as_mut() {
            d.max_grant_lifetime = Some(3600);
        }
        let end = stored.created_at + Duration::seconds(3600);
        let state = state(stored, c, &["member"], Some(records_redemption)).await;
        let redeemed = redeem_service_grant(&state, "d1", &svid(SVID), None, "g1", None)
            .await
            .unwrap();
        assert_eq!(redeemed.valid_until, Some(end));
    }
}
