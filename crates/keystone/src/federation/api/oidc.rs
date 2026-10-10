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
//! Finish OIDC login.

use axum::{
    Json, debug_handler,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use secrecy::ExposeSecret;
use url::Url;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::common::PeerAddr;
use crate::api::error::KeystoneApiError;
use crate::api::v4::auth::token::types::TokenResponse as KeystoneTokenResponse;
use crate::audit::{
    CorrelationId, build_initiator_unknown, emit_perimeter_authenticate_event, perimeter_outcome,
};
use crate::federation::api::error::OidcError;
use crate::federation::api::types::*;
use crate::keystone::ServiceState;
use cadf::sanitize::{HostKind, sanitize_initiator_host};
use cadf::types::{Host, Initiator};
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::auth::AuthenticationResult;
use openstack_keystone_core_types::federation::{AuthState, IdentityProvider};
use openstack_keystone_core_types::mapping::auth::MappingAuthRequest;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;

use super::common;
use super::oidc_utils::{build_http_client, discover, exchange_code, fetch_jwks, verify_jwt};

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(callback))
}

#[utoipa::path(
    post,
    path = "/oidc/callback",
    operation_id = "federation/oidc/callback",
    request_body = AuthCallbackParameters,
    responses(
        (
            status = OK,
            description = "Authentication Token object",
            body = KeystoneTokenResponse,
            headers(
                ("x-subject-token" = String, description = "Keystone token"),
            ),
        ),
    ),
    security(("oauth2" = ["openid"])),
    tag="identity_providers"
)]
#[tracing::instrument(
    name = "api::identity_provider_auth_callback",
    level = "debug",
    skip(state),
    err(Debug)
)]
#[debug_handler]
pub async fn callback(
    CorrelationId(cid): CorrelationId,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    Json(query): Json<AuthCallbackParameters>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // Security review V6: reached without a Keystone-authenticated caller and
    // ends in an OIDC ID-token signature verification (`verify_jwt`).
    // Rate-limit before any lookup, same posture as `/v3/auth/tokens`.
    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|addr| addr.ip()))
    {
        return Err(KeystoneApiError::TooManyRequests {
            retry_after: retry_after.as_secs(),
        });
    }

    // `idp_id` is a pre-auth signal (known as soon as the auth state / idp
    // lookup resolves, before any token verification happens) so it is
    // recorded as `Initiator.host` regardless of outcome (ADR 0023 §"Perimeter
    // Auditing"). `callback_inner` reports it via `idp_id_out` as soon as it
    // is known, even if a later step in the flow fails.
    let mut idp_id_out: Option<String> = None;
    let result = callback_inner(&state, query, &mut idp_id_out).await;
    let initiator = match &idp_id_out {
        Some(idp_id) => {
            let host = sanitize_initiator_host(idp_id, HostKind::FederationIdpUuid)
                .or_else(|| sanitize_initiator_host(idp_id, HostKind::FederationIdpNonUuid))
                .map(Host::from_id);
            Initiator::new("unknown".to_string(), None, None, host)
        }
        None => build_initiator_unknown(),
    };
    let (outcome, reason) = perimeter_outcome(&result);
    emit_perimeter_authenticate_event(&state.audit_dispatcher, &cid, initiator, outcome, reason);
    result
}

async fn callback_inner(
    state: &ServiceState,
    query: AuthCallbackParameters,
    idp_id_out: &mut Option<String>,
) -> Result<axum::response::Response, KeystoneApiError> {
    let exec = ExecutionContext::internal(state);
    // Validate auth state
    let auth_state = state
        .provider
        .get_federation_provider()
        .get_auth_state(&exec, &query.state)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "auth state".into(),
            identifier: query.state.clone(),
        })?;

    if auth_state.expires_at < Utc::now() {
        return Err(OidcError::AuthStateExpired.into());
    }

    let idp = state
        .provider
        .get_federation_provider()
        .get_identity_provider(&exec, &auth_state.idp_id)
        .await
        .map(|x| {
            x.ok_or_else(|| KeystoneApiError::NotFound {
                resource: "identity provider".into(),
                identifier: auth_state.idp_id.clone(),
            })
        })??;

    *idp_id_out = Some(idp.id.clone());

    if !idp.enabled {
        return Err(OidcError::IdentityProviderDisabled.into());
    }

    let (auth_result, _claims) =
        authenticate_upstream(state, &exec, &auth_state, &idp, &query.code).await?;

    // Resolve scope from the original auth request. The scope may be None
    // (unscoped) or a specific project/domain scope that was requested during
    // OIDC auth init.
    let (token_str, api_token) =
        common::build_token_response(state, &auth_result, auth_state.scope.as_ref()).await?;

    tracing::trace!("Token response is {:?}", api_token);
    Ok((
        StatusCode::OK,
        [("x-subject-token", token_str)],
        axum::Json(api_token),
    )
        .into_response())
}

/// Exchange the authorization `code` at the upstream IdP, verify the ID
/// token and resolve the user through the mapping engine.
///
/// Returns the authentication result and the verified ID token claims.
/// Shared by the v4 federation callback and the OAuth2 OP login page.
pub(crate) async fn authenticate_upstream(
    state: &ServiceState,
    exec: &ExecutionContext<'_>,
    auth_state: &AuthState,
    idp: &IdentityProvider,
    code: &str,
) -> Result<(AuthenticationResult, serde_json::Value), KeystoneApiError> {
    // Build the HTTP client with strict redirect policy.
    let http_client = build_http_client()?;

    let discovery_url = idp
        .oidc_discovery_url
        .as_deref()
        .ok_or(OidcError::ClientWithoutDiscoveryNotSupported)?;

    let metadata = discover(discovery_url, &http_client)
        .await
        .map_err(|err| OidcError::discovery(discovery_url, &err))?;

    let jwks = fetch_jwks(metadata.jwks_uri.as_str(), &http_client)
        .await
        .map_err(|err| OidcError::discovery(&metadata.jwks_uri, &err))?;

    let client_id = idp
        .oidc_client_id
        .as_deref()
        .ok_or(OidcError::ClientIdRequired)?;

    // Exchange the authorization code for tokens.
    let token_response = exchange_code(
        &metadata.token_endpoint,
        client_id,
        // Exposure boundary: unwrapped only to build the token-endpoint request.
        idp.oidc_client_secret.as_ref().map(|s| s.expose_secret()),
        code,
        &auth_state.redirect_uri,
        &auth_state.pkce_verifier,
        &http_client,
    )
    .await?;

    let id_token = token_response.id_token.ok_or(OidcError::NoToken)?;

    // Verify OIDC ID token and extract claims. OIDC Core §3.1.3.7: the `aud`
    // claim MUST contain the RP's client ID.  Validate issuer, nonce, and
    // audience in a single verification pass.
    let claims_value: serde_json::Value = verify_jwt(
        // Exposure boundary: the ID token is unwrapped only to verify it.
        id_token.expose_secret(),
        &jwks,
        Some(metadata.issuer.as_str()),
        Some(&auth_state.nonce),
        &[client_id],
    )?;

    // Validate the bound_issuer against the claims issuer URL to prevent token
    // reuse across different IdPs.
    if let Some(bound_issuer) = &idp.bound_issuer {
        let claims_issuer = claims_value["iss"].as_str().ok_or_else(|| {
            KeystoneApiError::BadRequest("ID token does not contain issuer claim".to_string())
        })?;

        let bound = Url::parse(bound_issuer).map_err(OidcError::from)?;
        let issuer = Url::parse(claims_issuer).map_err(OidcError::from)?;
        if bound != issuer {
            return Err(OidcError::IssuerMismatch {
                expected: bound_issuer.clone(),
                actual: claims_issuer.to_string(),
            }
            .into());
        }
    }

    tracing::trace!(
        "Claims count: {}",
        claims_value.as_object().map(|m| m.len()).unwrap_or(0)
    );

    // Delegate to the mapping engine for identity resolution. The
    // `default_mapping_name` from the IdP, when set, is used as a rule name
    // hint for targeted rule matching.
    let flattened = common::flatten_federation_claims(&claims_value)
        .map_err(|_| OidcError::ClaimsMapTooLarge)?;

    // Extract the unique workload identifier from the required `sub` claim.
    // OIDC Core §3.1.2: "REQUIRED subject identifier"
    let unique_workload_id = claims_value["sub"]
        .as_str()
        .ok_or_else(|| {
            KeystoneApiError::BadRequest("`sub` claim is missing from ID token".to_string())
        })?
        .to_string();

    let domain_id = idp.domain_id.clone().ok_or_else(|| {
        KeystoneApiError::BadRequest("Cannot identify domain_id of the user.".to_string())
    })?;

    let mapping_req = MappingAuthRequest {
        domain_id: Some(domain_id),
        source: IdentitySource::Federation {
            idp_id: idp.id.clone(),
        },
        unique_workload_id,
        claims: flattened,
        rule_name: idp.default_mapping_name.clone(),
    };

    let auth_result: AuthenticationResult = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(exec, &mapping_req)
        .await?;

    Ok((auth_result, claims_value))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use cadf::Outcome;
    use serde_json::json;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use super::openapi_router;
    use crate::federation::MockFederationProvider;
    use crate::provider::Provider;

    /// An unknown auth state is rejected before any IdP is known: the single
    /// perimeter record carries an `unknown` initiator without a host.
    #[tokio::test]
    async fn test_callback_with_unknown_state_emits_failure_event() {
        let mut federation_mock = MockFederationProvider::default();
        federation_mock
            .expect_get_auth_state()
            .returning(|_, _| Ok(None));
        let (state, mut receivers) =
            openstack_keystone_core::api::tests::get_mocked_state_with_audit(
                Provider::mocked_builder().mock_federation(federation_mock),
                true,
                openstack_keystone_config::Config::default(),
            )
            .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/oidc/callback")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"state": "missing", "code": "c"})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let event = receivers
            .perimeter
            .try_recv()
            .expect("perimeter audit event should have been emitted");
        assert_eq!(event.payload().outcome(), Outcome::Failure);
        let initiator = event.payload().initiator();
        assert_eq!(initiator.id(), "unknown");
        assert!(initiator.host().is_none());
        assert!(receivers.perimeter.try_recv().is_err(), "exactly one event");
    }

    fn mapped_user_result() -> openstack_keystone_core_types::auth::AuthenticationResult {
        use openstack_keystone_core_types::auth::*;
        AuthenticationResultBuilder::default()
            .context(AuthenticationContext::Password)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("shadow-user")
                        .build()
                        .unwrap(),
                ),
            })
            .authorization(
                AuthzInfoBuilder::default()
                    .scope(ScopeInfo::Unscoped)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    /// Code exchange, ID-token verification and mapping run end to end
    /// against a mocked upstream; the claims come back for the caller.
    #[tokio::test]
    async fn test_authenticate_upstream_resolves_user_through_mapping() {
        use super::super::oidc_utils::fixtures::*;
        use httpmock::prelude::*;
        use openstack_keystone_core_types::federation::{AuthState, IdentityProvider};

        let server = MockServer::start();
        let issuer = server.base_url();
        server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
            }));
        });
        server.mock(|when, then| {
            when.method(GET).path("/jwks");
            then.status(200).json_body(json!({"keys": [{
                "kty": "RSA", "use": "sig", "alg": "RS256", "kid": TEST_KID,
                "n": TEST_JWK_N, "e": TEST_JWK_E,
            }]}));
        });
        let id_token = make_jwt(
            &json!({
                "iss": issuer,
                "aud": "op-client",
                "sub": "upstream-sub",
                "sid": "upstream-sid",
                "nonce": "the-nonce",
                "iat": chrono::Utc::now().timestamp(),
                "exp": chrono::Utc::now().timestamp() + 600,
            }),
            Some(TEST_KID),
        );
        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200)
                .json_body(json!({"id_token": id_token, "token_type": "Bearer"}));
        });

        let mut mapping_mock = crate::mapping::MockMappingProvider::default();
        mapping_mock
            .expect_authenticate_by_mapping()
            .withf(|_, req| {
                req.unique_workload_id == "upstream-sub"
                    && req.domain_id.as_deref() == Some("domain-1")
                    && req.rule_name.as_deref() == Some("corp-rule")
            })
            .returning(|_, _| Ok(mapped_user_result()));
        let state = openstack_keystone_core::api::tests::get_mocked_state(
            Provider::mocked_builder().mock_mapping(mapping_mock),
            true,
            None,
        )
        .await;

        let idp = IdentityProvider {
            id: "idp-1".into(),
            name: "Corp".into(),
            domain_id: Some("domain-1".into()),
            enabled: true,
            oidc_discovery_url: Some(server.base_url()),
            oidc_client_id: Some("op-client".into()),
            default_mapping_name: Some("corp-rule".into()),
            ..Default::default()
        };
        let auth_state = AuthState {
            idp_id: "idp-1".into(),
            nonce: "the-nonce".into(),
            pkce_verifier: "verifier".into(),
            redirect_uri: "https://op.example.com/cb".into(),
            state: "state-1".into(),
            ..Default::default()
        };

        let exec = openstack_keystone_core::auth::ExecutionContext::internal(&state);
        let (result, claims) =
            super::authenticate_upstream(&state, &exec, &auth_state, &idp, "code")
                .await
                .unwrap();
        assert!(matches!(
            result.principal.identity,
            openstack_keystone_core_types::auth::IdentityInfo::User(ref u) if u.user_id == "shadow-user"
        ));
        assert_eq!(claims["sid"], "upstream-sid");
    }
}
