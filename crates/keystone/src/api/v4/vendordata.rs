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
//! `POST /v4/vendordata`: sign a per-VM-instance attestation JWT (SPIRE
//! integration plan, Phase 2).
//!
//! Lives on the internal SPIFFE mTLS interface (`[interface:internal]`,
//! port 8444): Nova-compute authenticates with its per-host SPIFFE SVID
//! (`spiffe://{trust_domain}/service/nova-compute/host/{hostname}`,
//! Phase 1). Before signing, the handler runs the (cheap, local) OPA
//! policy check, then -- when `[vendordata] verify_placement` is enabled
//! (the default) -- cross-checks the caller's claimed `project_id`/
//! `instance_id` against Nova's own record for that instance (Fix 1,
//! "Ownership verification"), so a compromised compute host cannot
//! request a signed attestation for an instance it does not run.
//!
//! The caller's compute host is derived directly from the raw `SpiffeId`
//! request extension (rather than a mapping-engine claim) via
//! [`SpiffeId::path_claims`], the shared strict path parser Phase 3 added
//! to `crates/core/src/common/spiffe_id.rs`. `Auth`'s own SPIFFE claim
//! flattening (`crates/core/src/api/auth.rs`) uses the same parser to
//! derive the general `spiffe.host` mapping-engine claim; this handler
//! only needs the raw value for its own local ownership check, decoupled
//! from authentication, so it reads it off the extension directly rather
//! than round-tripping through mapping-engine claims.

use axum::{Extension, Json, extract::State, http::StatusCode, response::IntoResponse};
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use openstack_keystone_api_types::v4::vendordata::{
    SpiffeJwt, VendorDataRequest, VendorDataResponse,
};
use openstack_keystone_config::Interface;
use openstack_keystone_core::common::{SpiffeId, SpiffePathMatch};
use openstack_keystone_core_types::vendordata::{
    OpenstackAttestationClaims, SpiffeAttestationClaims, VendordataProviderError,
};
use openstack_keystone_key_repository::asymmetric::{jwt_algorithm, to_encoding_key};

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// OpenApi specification for the vendor data JWT API.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name = "vendordata", description = "Vendor data JWT API (SPIRE integration plan, Phase 2)."),
    )
)]
pub struct ApiDoc;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(create))
}

/// Extract `{hostname}` from
/// `spiffe://{trust_domain}/service/nova-compute/host/{hostname}` via the
/// shared strict path parser ([`SpiffeId::path_claims`]). Returns `None`
/// both for an SVID that isn't a nova-compute host identity at all
/// (`Unrecognized`) and for one that is malformed (`Malformed`) -- this
/// handler's own ownership check already rejects a missing host with
/// `403 Forbidden` (`VendordataProviderError::NotAComputeHost`) regardless
/// of which of those two cases applies, so collapsing them here preserves
/// existing behavior.
fn nova_compute_host_from_spiffe_id(svid: &SpiffeId) -> Option<String> {
    match svid.path_claims() {
        SpiffePathMatch::Matched(claims) => claims.host,
        _ => None,
    }
}

#[utoipa::path(
    post,
    path = "/",
    operation_id = "/vendordata:create",
    request_body = VendorDataRequest,
    responses(
        (status = CREATED, description = "Attestation JWT issued", body = VendorDataResponse),
        (status = FORBIDDEN, description = "Ownership check failed, or not the internal interface"),
        (status = SERVICE_UNAVAILABLE, description = "Nova ownership check unavailable"),
    ),
    security(("x-auth" = [])),
    tag = "vendordata"
)]
#[tracing::instrument(
    name = "api::v4::vendordata::create",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
async fn create(
    Auth(user_auth): Auth,
    interface_ext: Option<Extension<Interface>>,
    svid_ext: Option<Extension<SpiffeId>>,
    State(state): State<ServiceState>,
    Json(body): Json<VendorDataRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    let interface = interface_ext
        .map(|Extension(i)| i)
        .unwrap_or(Interface::Public);
    if interface != Interface::Internal {
        return Err(VendordataProviderError::WrongInterface.into());
    }

    state
        .policy_enforcer
        .enforce(
            "identity/vendordata/create",
            &user_auth,
            serde_json::json!({
                "project_id": body.project_id.clone(),
                "instance_id": body.instance_id.clone(),
            }),
            None,
        )
        .await?;

    let config = state.config_manager.config.read().await.clone();

    if config.vendordata.verify_placement {
        let host = svid_ext
            .as_ref()
            .and_then(|Extension(svid)| nova_compute_host_from_spiffe_id(svid))
            .ok_or(VendordataProviderError::NotAComputeHost)?;

        let owns_instance = state
            .provider
            .get_nova_client_provider()
            .verify_ownership(&state, &body.project_id, &body.instance_id, &host)
            .await?;
        if !owns_instance {
            return Err(VendordataProviderError::OwnershipMismatch.into());
        }
    }

    let ttl_seconds = body
        .ttl_seconds
        .unwrap_or(config.vendordata.default_ttl_seconds);
    if !(60..=600).contains(&ttl_seconds) {
        return Err(VendordataProviderError::InvalidTtl(ttl_seconds).into());
    }
    let max_ttl_seconds = config.oauth2.access_token_lifetime_minutes * 60;
    let ttl_seconds = ttl_seconds.min(max_ttl_seconds);

    let domain_id = body
        .domain_id
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let key = state
        .provider
        .get_spiffe_key_provider()
        .active_signing_key(&state, &domain_id)
        .await?;

    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::seconds(i64::from(ttl_seconds));
    let jti = uuid::Uuid::new_v4().to_string();
    let claims = SpiffeAttestationClaims {
        iss: format!("https://keystone:8444/v4/spiffe/{domain_id}"),
        aud: "spiffe-attestation".to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        jti: jti.clone(),
        sub: format!("vm:{}", body.instance_id),
        openstack: OpenstackAttestationClaims {
            project_id: body.project_id.clone(),
            instance_id: body.instance_id.clone(),
            spiffe_role: "compute-vm".to_string(),
        },
    };

    let encoding_key =
        to_encoding_key(&key).map_err(|e| VendordataProviderError::Crypto(e.to_string()))?;
    let mut header = jsonwebtoken::Header::new(jwt_algorithm(key.algorithm));
    header.kid = Some(key.kid.clone());
    let token = jsonwebtoken::encode(&header, &claims, &encoding_key)
        .map_err(|e| VendordataProviderError::Crypto(e.to_string()))?;

    let algorithm_name = match key.algorithm {
        openstack_keystone_key_repository::asymmetric::SigningAlgorithm::Es256 => "ES256",
        openstack_keystone_key_repository::asymmetric::SigningAlgorithm::Rs256 => "RS256",
    };
    let response = VendorDataResponse {
        spiffe_jwt: SpiffeJwt {
            algorithm: algorithm_name.to_string(),
            jti,
            token,
            expires_at: exp.to_rfc3339(),
        },
    };

    Ok((StatusCode::CREATED, Json(response)).into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_config::{Config, VendordataProvider};
    use openstack_keystone_core::auth::{
        IdentityInfo, PrincipalIdentityInfoBuilder, PrincipalInfoBuilder, ScopeInfo,
        SecurityContextTestingBuilder, ValidatedSecurityContext,
    };
    use openstack_keystone_core::common::SpiffeId;
    use openstack_keystone_core::nova_client::MockNovaClientProvider;

    use super::openapi_router;
    use crate::api::tests::get_mocked_state_with_config;
    use crate::provider::Provider;

    fn compute_host_vsc() -> ValidatedSecurityContext {
        let mut ctx = SecurityContextTestingBuilder::default()
            .authentication_context(openstack_keystone_core::auth::AuthenticationContext::Password)
            .principal(
                PrincipalInfoBuilder::default()
                    .identity(IdentityInfo::Principal(
                        PrincipalIdentityInfoBuilder::default()
                            .id("spiffe://cloud.trust.domain/service/nova-compute/host/compute-1")
                            .issuer("cloud.trust.domain")
                            .build()
                            .unwrap(),
                    ))
                    .build()
                    .unwrap(),
            )
            .build();
        ctx.set_authorization_scope(ScopeInfo::Unscoped).unwrap();
        ValidatedSecurityContext::test_new(ctx)
    }

    fn request(body: serde_json::Value, with_svid: bool) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .extension(openstack_keystone_config::Interface::Internal)
            .extension(compute_host_vsc());
        if with_svid {
            builder = builder.extension(
                SpiffeId::new("spiffe://cloud.trust.domain/service/nova-compute/host/compute-1")
                    .unwrap(),
            );
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    fn vendordata_config(verify_placement: bool, key_repository: std::path::PathBuf) -> Config {
        Config {
            vendordata: VendordataProvider {
                verify_placement,
                key_repository,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// A real, filesystem-backed `SpiffeKeyService` rather than a mock --
    /// these tests exercise the actual JWT-signing path, not just the
    /// handler's control flow.
    fn real_spiffe_key_service(
        config: &Config,
    ) -> openstack_keystone_core::spiffe_key::SpiffeKeyService {
        openstack_keystone_core::spiffe_key::SpiffeKeyService::new(config).unwrap()
    }

    #[tokio::test]
    async fn test_create_valid_svid_positive_policy_returns_201() {
        let key_dir = tempfile::tempdir().unwrap();
        let config = vendordata_config(false, key_dir.path().to_path_buf());
        let provider = Provider::mocked_builder().mock_spiffe_key(real_spiffe_key_service(&config));
        let state = get_mocked_state_with_config(provider, true, None, config).await;
        state
            .provider
            .get_spiffe_key_provider()
            .ensure_domain_keys(&state, "default")
            .await
            .unwrap();

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let body = serde_json::json!({
            "project_id": "project-1",
            "instance_id": "instance-1",
        });
        let response = api
            .as_service()
            .oneshot(request(body, false))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["spiffe_jwt"]["token"].is_string());
    }

    #[tokio::test]
    async fn test_create_negative_policy_returns_403() {
        let key_dir = tempfile::tempdir().unwrap();
        let provider = Provider::mocked_builder();
        let state = get_mocked_state_with_config(
            provider,
            false,
            None,
            vendordata_config(false, key_dir.path().to_path_buf()),
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let body = serde_json::json!({
            "project_id": "project-1",
            "instance_id": "instance-1",
        });
        let response = api
            .as_service()
            .oneshot(request(body, false))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_missing_auth_returns_401() {
        let key_dir = tempfile::tempdir().unwrap();
        let provider = Provider::mocked_builder();
        let state = get_mocked_state_with_config(
            provider,
            true,
            None,
            vendordata_config(false, key_dir.path().to_path_buf()),
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let body = serde_json::json!({
            "project_id": "project-1",
            "instance_id": "instance-1",
        });
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .extension(openstack_keystone_config::Interface::Internal)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_ownership_mismatch_returns_403_when_verify_placement_enabled() {
        let mut nova_mock = MockNovaClientProvider::default();
        nova_mock
            .expect_verify_ownership()
            .returning(|_, _, _, _| Ok(false));

        let key_dir = tempfile::tempdir().unwrap();
        let provider = Provider::mocked_builder().mock_nova_client(nova_mock);
        let state = get_mocked_state_with_config(
            provider,
            true,
            None,
            vendordata_config(true, key_dir.path().to_path_buf()),
        )
        .await;
        // Ownership mismatch is rejected before signing is ever attempted,
        // so the (default, unconfigured) spiffe-key mock is never called.

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let body = serde_json::json!({
            "project_id": "project-1",
            "instance_id": "instance-1",
        });
        let response = api.as_service().oneshot(request(body, true)).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_ownership_match_returns_201_when_verify_placement_enabled() {
        let mut nova_mock = MockNovaClientProvider::default();
        nova_mock
            .expect_verify_ownership()
            .returning(|_, _, _, _| Ok(true));

        let key_dir = tempfile::tempdir().unwrap();
        let config = vendordata_config(true, key_dir.path().to_path_buf());
        let provider = Provider::mocked_builder()
            .mock_nova_client(nova_mock)
            .mock_spiffe_key(real_spiffe_key_service(&config));
        let state = get_mocked_state_with_config(provider, true, None, config).await;
        state
            .provider
            .get_spiffe_key_provider()
            .ensure_domain_keys(&state, "default")
            .await
            .unwrap();

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let body = serde_json::json!({
            "project_id": "project-1",
            "instance_id": "instance-1",
        });
        let response = api.as_service().oneshot(request(body, true)).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_create_wrong_interface_returns_403() {
        let key_dir = tempfile::tempdir().unwrap();
        let provider = Provider::mocked_builder();
        let state = get_mocked_state_with_config(
            provider,
            true,
            None,
            vendordata_config(false, key_dir.path().to_path_buf()),
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let body = serde_json::json!({
            "project_id": "project-1",
            "instance_id": "instance-1",
        });
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .extension(compute_host_vsc())
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_nova_compute_host_from_spiffe_id_valid() {
        let svid = SpiffeId::new("spiffe://cloud.trust.domain/service/nova-compute/host/compute-1")
            .unwrap();
        assert_eq!(
            super::nova_compute_host_from_spiffe_id(&svid).as_deref(),
            Some("compute-1")
        );
    }

    #[test]
    fn test_nova_compute_host_from_spiffe_id_rejects_trailing_slash() {
        let svid = SpiffeId::new("spiffe://cloud.trust.domain/service/nova-compute/host/").unwrap();
        assert!(super::nova_compute_host_from_spiffe_id(&svid).is_none());
    }

    #[test]
    fn test_nova_compute_host_from_spiffe_id_rejects_extra_segment() {
        let svid =
            SpiffeId::new("spiffe://cloud.trust.domain/service/nova-compute/host/compute-1/extra")
                .unwrap();
        assert!(super::nova_compute_host_from_spiffe_id(&svid).is_none());
    }

    #[test]
    fn test_nova_compute_host_from_spiffe_id_rejects_other_service() {
        let svid = SpiffeId::new("spiffe://cloud.trust.domain/service/nova-api").unwrap();
        assert!(super::nova_compute_host_from_spiffe_id(&svid).is_none());
    }
}
