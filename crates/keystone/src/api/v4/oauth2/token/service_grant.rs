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
//! Service grant redemption grant
//! (`urn:openstack:params:oauth:grant-type:service-grant`, ADR 0036 §5).

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cadf::Outcome;
use governor::clock::Clock as _;

use openstack_keystone_config::Interface;
use openstack_keystone_core::common::SpiffeId;
use openstack_keystone_core::service_grant::redeem::{
    ServiceGrantRedeemError, build_service_grant_claims, redeem_service_grant,
};

use crate::audit::{Oauth2Grant, build_initiator_from_vsc, emit_service_grant_event};
use crate::keystone::ServiceState;

use super::common::sign_jwt;
use super::token_exchange::requested_audience;
use super::{Oauth2TokenError, TokenForm, TokenResponse};
use crate::api::v4::oauth2::well_known::base_url;

/// The service grant redemption grant type (ADR 0036 §5.1).
pub(super) const SERVICE_GRANT_GRANT_TYPE: &str =
    "urn:openstack:params:oauth:grant-type:service-grant";

/// Rate limiter key of a redemption: a bucket of its own per presented
/// SVID, never shared with the `client_id`-keyed grants.
fn rate_limit_key(svid: &str) -> String {
    format!("service_grant:{svid}")
}

/// Redeem a service grant for a short-lived access token acting for the
/// grantor (ADR 0036 §5).
///
/// The grantee authenticates with `tls_client_auth`: the X.509-SVID of the
/// TLS connection on the internal interface must match the grantee client's
/// `spiffe_ids`. No client secret exists, and no refresh token is issued;
/// the service redeems the grant again when the token nears expiry, which
/// re-runs every check.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_service_grant_grant(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    form: &TokenForm,
    oauth2_cfg: &openstack_keystone_config::Oauth2Provider,
    correlation_id: &str,
    interface: Interface,
    svid: Option<&SpiffeId>,
) -> Result<Response, Oauth2TokenError> {
    // `private_key_jwt` with a JWT-SVID on the public interface (§5.1) is
    // not implemented; only `tls_client_auth` is.
    let svid = match svid {
        Some(svid) if interface == Interface::Internal => svid,
        _ => {
            return Err(Oauth2TokenError::invalid_client(
                "service grants are redeemed with an X.509-SVID on the internal interface",
            ));
        }
    };
    let Some(grant_id) = form.grant_id.as_deref().filter(|g| !g.is_empty()) else {
        return Err(Oauth2TokenError::invalid_request(
            "missing required parameter: grant_id",
        ));
    };
    let roles = form
        .roles
        .as_deref()
        .map(|roles| roles.split_whitespace().map(str::to_string).collect());

    // Step 1 (ADR 0026 §7.A): rate limit before any lookup, keyed on the
    // presented identity.
    if let Err(not_until) = state
        .oauth2_token_rate_limiter
        .check_key(&rate_limit_key(&svid.to_string()))
    {
        let retry_after = not_until
            .wait_time_from(state.oauth2_token_rate_limiter.clock().now())
            .as_secs()
            .max(1);
        return Err(Oauth2TokenError::too_many_requests(retry_after));
    }

    let redeemed = redeem_service_grant(
        state,
        domain_id,
        svid,
        form.client_id.as_deref(),
        grant_id,
        roles,
    )
    .await
    .map_err(|e| {
        tracing::info!(grant_id, error = %e, "service grant redemption refused");
        redeem_error(e)
    })?;

    // `scope` keeps its ADR 0026 §4 meaning and has no effect on roles.
    let scope = match form.scope.as_deref() {
        Some(scope) => {
            if scope
                .split_whitespace()
                .any(|s| !redeemed.client.allowed_scopes.iter().any(|a| a == s))
            {
                return Err(Oauth2TokenError::invalid_scope(
                    "requested scope exceeds the client's allowed_scopes",
                ));
            }
            scope.to_string()
        }
        None => "openstack:api".to_string(),
    };
    let audience = requested_audience(state, &form.audience).await?;

    let base = base_url(state, headers).await;
    let issuer = format!("{base}/v4/oauth2/{domain_id}");
    let now = chrono::Utc::now().timestamp();
    // The token never outlives the grant: its expiry or the client's
    // current maximum grant lifetime, whichever comes first.
    let mut access_lifetime = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;
    if let Some(valid_until) = redeemed.valid_until {
        access_lifetime = access_lifetime.min(valid_until.timestamp() - now);
    }
    if access_lifetime <= 0 {
        return Err(Oauth2TokenError::grant_disabled());
    }
    let claims = build_service_grant_claims(
        &redeemed,
        domain_id,
        &issuer,
        uuid::Uuid::new_v4().to_string(),
        now,
        now + access_lifetime,
        audience,
    )
    .map_err(redeem_error)?;
    let access_token = sign_jwt(state, domain_id, &claims).await?;

    emit_service_grant_event(
        &state.audit_dispatcher,
        correlation_id,
        "authenticate",
        build_initiator_from_vsc(&redeemed.vsc),
        Oauth2Grant {
            client_id: &redeemed.client.client_id,
            grant_type: "service_grant",
        },
        cadf::ServiceGrantAudit::new(
            &redeemed.grant.id,
            &redeemed.grant.grantor_user_id,
            &redeemed.client.client_id,
            svid.as_str(),
            redeemed.grant.target.project_id(),
        ),
        Outcome::Success,
        None,
    );

    let response = TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: access_lifetime,
        scope,
        id_token: None,
        refresh_token: None,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Map a refused redemption to its token endpoint error.
fn redeem_error(e: ServiceGrantRedeemError) -> Oauth2TokenError {
    match e {
        ServiceGrantRedeemError::UnknownGrant | ServiceGrantRedeemError::Authentication(_) => {
            Oauth2TokenError::invalid_grant("the service grant is unknown or not redeemable here")
        }
        ServiceGrantRedeemError::InvalidClient => {
            Oauth2TokenError::invalid_client("the client is not the grant's grantee")
        }
        ServiceGrantRedeemError::Disabled(_) | ServiceGrantRedeemError::RoleLost => {
            Oauth2TokenError::grant_disabled()
        }
        ServiceGrantRedeemError::InvalidRoles => Oauth2TokenError::invalid_request(
            "roles must be a non-empty subset of the grant's roles",
        ),
        ServiceGrantRedeemError::Provider(_) => Oauth2TokenError::internal("token issuance failed"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_rate_limit_key_is_namespaced() {
        assert_eq!(
            super::rate_limit_key("spiffe://x/ns/a"),
            "service_grant:spiffe://x/ns/a"
        );
    }

    use axum::http::StatusCode;
    use chrono::Utc;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_config::Interface;
    use openstack_keystone_core::common::SpiffeId;
    use openstack_keystone_core_types::assignment::{Assignment, AssignmentType};
    use openstack_keystone_core_types::oauth2_client::{DelegationPolicy, OAuth2ClientResource};
    use openstack_keystone_core_types::resource::{Domain, Project};
    use openstack_keystone_core_types::service_grant::*;

    use crate::api::tests::get_mocked_state;
    use crate::api::v4::oauth2::openapi_router;
    use crate::api::v4::oauth2::token::test_fixtures::{
        confidential_client, json_body, jwt_claims, ok_key_mock, refresh_identity_mock,
        refresh_user, request,
    };
    use crate::assignment::MockAssignmentProvider;
    use crate::oauth2_client::MockOauth2ClientProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::role::MockRoleProvider;
    use crate::service_grant::MockServiceGrantProvider;

    const SVID: &str = "spiffe://td/service/heat-engine/host/h1";
    const BODY: &str =
        "grant_type=urn%3Aopenstack%3Aparams%3Aoauth%3Agrant-type%3Aservice-grant&grant_id=g1";

    fn grant(enabled: bool) -> ServiceGrant {
        ServiceGrant {
            id: "g1".into(),
            version: 1,
            domain_id: "domain-1".into(),
            grantor_user_id: "user-1".into(),
            grantee: Grantee::Client {
                client_id: "client-1".into(),
                client_domain_id: "domain-1".into(),
            },
            target: GrantTarget::Project {
                project_id: "project-1".into(),
                project_domain_id: "domain-1".into(),
            },
            role_ids: vec!["member".into()],
            expires_at: None,
            description: None,
            enabled,
            created_at: Utc::now(),
            last_redeemed_at: Some(Utc::now()),
            disabled_reason: None,
        }
    }

    async fn service_client() -> OAuth2ClientResource {
        OAuth2ClientResource {
            client_secret_hash: None,
            token_endpoint_auth_method: "tls_client_auth".into(),
            grant_types: vec![],
            spiffe_ids: vec!["spiffe://td/service/heat-engine/host/*".into()],
            delegation: Some(DelegationPolicy {
                service_grants: true,
                ..Default::default()
            }),
            ..confidential_client().await
        }
    }

    /// Mocks for a redemption of `stored` where the grantor holds `roles`.
    async fn provider(
        stored: Option<ServiceGrant>,
        roles: &'static [&'static str],
    ) -> crate::provider::ProviderBuilder {
        let mut grants = MockServiceGrantProvider::default();
        grants
            .expect_get_service_grant()
            .returning(move |_, _, _| Ok(stored.clone()));
        grants
            .expect_update_service_grant()
            .returning(|_, _, _, _, _| Ok(grant(false)));
        let client = service_client().await;
        let mut clients = MockOauth2ClientProvider::default();
        clients
            .expect_get_by_client_id()
            .returning(move |_, _| Ok(Some(client.clone())));
        let mut resource = MockResourceProvider::default();
        resource.expect_get_project().returning(|_, id| {
            Ok(Some(Project {
                id: id.to_string(),
                domain_id: "domain-1".into(),
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
            .returning(move |_, _| {
                Ok(roles
                    .iter()
                    .map(|r| Assignment {
                        actor_id: "user-1".into(),
                        role_id: r.to_string(),
                        role_name: Some(r.to_string()),
                        target_id: "project-1".into(),
                        r#type: AssignmentType::UserProject,
                        inherited: false,
                        implied_via: None,
                    })
                    .collect())
            });
        let mut role = MockRoleProvider::default();
        role.expect_expand_implied_roles().returning(|_, _| Ok(()));
        Provider::mocked_builder()
            .mock_service_grant(grants)
            .mock_oauth2_client(clients)
            .mock_identity(refresh_identity_mock(Some(refresh_user(true, "domain-1"))))
            .mock_resource(resource)
            .mock_assignment(assignments)
            .mock_role(role)
            .mock_oauth2_key(ok_key_mock())
    }

    async fn redeem(
        provider: crate::provider::ProviderBuilder,
        body: &str,
        interface: Interface,
        svid: Option<&str>,
    ) -> axum::response::Response {
        let state = get_mocked_state(provider, true, None).await;
        let mut req = request(body);
        req.extensions_mut().insert(interface);
        if let Some(svid) = svid {
            req.extensions_mut().insert(SpiffeId::new(svid).unwrap());
        }
        openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state)
            .as_service()
            .oneshot(req)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_redeem() {
        let response = redeem(
            provider(Some(grant(true)), &["member", "admin"]).await,
            BODY,
            Interface::Internal,
            Some(SVID),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = json_body(response).await;
        assert!(body.get("refresh_token").is_none());
        let claims = jwt_claims(body["access_token"].as_str().unwrap());
        assert_eq!(claims["sub"], "user-1");
        assert_eq!(claims["client_id"], "client-1");
        assert_eq!(claims["amr"], serde_json::json!(["service_grant"]));
        assert_eq!(claims["act"]["sub"], SVID);
        assert_eq!(claims["act"]["sub_type"], "spiffe");
        assert_eq!(claims["delegation_context"]["auth_method"], "service_grant");
        assert_eq!(claims["delegation_context"]["grant_id"], "g1");
        assert_eq!(
            claims["delegation_context"]["delegated_project_id"],
            "project-1"
        );
        assert_eq!(claims["project_id"], "project-1");
        assert_eq!(claims["roles"], serde_json::json!(["member"]));
    }

    /// A token never outlives the grant it was minted from.
    #[tokio::test]
    async fn test_redeem_token_does_not_outlive_grant() {
        let expires_at = Utc::now() + chrono::Duration::seconds(120);
        let mut stored = grant(true);
        stored.expires_at = Some(expires_at);
        let response = redeem(
            provider(Some(stored), &["member"]).await,
            BODY,
            Interface::Internal,
            Some(SVID),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert!(body["expires_in"].as_i64().unwrap() <= 120);
        let claims = jwt_claims(body["access_token"].as_str().unwrap());
        assert!(claims["exp"].as_i64().unwrap() <= expires_at.timestamp());
    }

    /// Only an X.509-SVID on the internal interface authenticates.
    #[tokio::test]
    async fn test_redeem_requires_internal_svid() {
        for (interface, svid) in [(Interface::Internal, None), (Interface::Public, Some(SVID))] {
            let response = redeem(
                provider(Some(grant(true)), &["member"]).await,
                BODY,
                interface,
                svid,
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(json_body(response).await["error"], "invalid_client");
        }
    }

    #[tokio::test]
    async fn test_redeem_rejects_other_svid() {
        let response = redeem(
            provider(Some(grant(true)), &["member"]).await,
            BODY,
            Interface::Internal,
            Some("spiffe://td/service/nova/host/h1"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["error"], "invalid_client");
    }

    #[tokio::test]
    async fn test_redeem_missing_grant_id() {
        let response = redeem(
            provider(Some(grant(true)), &["member"]).await,
            "grant_type=urn%3Aopenstack%3Aparams%3Aoauth%3Agrant-type%3Aservice-grant",
            Interface::Internal,
            Some(SVID),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_request");
    }

    #[tokio::test]
    async fn test_redeem_unknown_grant() {
        let response = redeem(
            provider(None, &["member"]).await,
            BODY,
            Interface::Internal,
            Some(SVID),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_redeem_disabled_or_role_lost_is_forbidden() {
        const MEMBER: &[&str] = &["member"];
        const ADMIN: &[&str] = &["admin"];
        for (stored, roles) in [(grant(false), MEMBER), (grant(true), ADMIN)] {
            let response = redeem(
                provider(Some(stored), roles).await,
                BODY,
                Interface::Internal,
                Some(SVID),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn test_redeem_roles_outside_grant() {
        let response = redeem(
            provider(Some(grant(true)), &["member"]).await,
            &format!("{BODY}&roles=admin"),
            Interface::Internal,
            Some(SVID),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"], "invalid_request");
    }
}
