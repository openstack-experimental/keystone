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
//! Validate an S3 string-to-sign signature (ADR 0019 §5).
//!
//! The response describes the identity behind the credential but no token
//! is handed out: there is no `X-Subject-Token` header and the body carries
//! no token id. The `ec2credential` authentication method marker is still
//! carried (the context is the same `Ec2Credential` one as for
//! `/v3/ec2tokens`), and the underlying (stateless, never encoded or
//! stored) token object is only used to render `issued_at`/`expires_at`.

use axum::{Json, extract::State, http::HeaderMap, response::IntoResponse};
use serde_json::json;

use cadf::sanitize::{HostKind, sanitize_initiator_host};
use openstack_keystone_api_types::v3::auth::token::{TokenBuilder, TokenResponse};
use openstack_keystone_core::credential::s3_signature::{
    decode_string_to_sign, validate_timestamp, verify_signature,
};
use openstack_keystone_core_types::auth::AuthenticationError;

use crate::api::auth::Auth;
use crate::api::common::PeerAddr;
use crate::api::v3::ec2tokens::redeem::redeem_ec2_credential;
use crate::api::v3::s3tokens::types::S3TokenAuthRequest;
use crate::api::{Catalog, CatalogService, error::KeystoneApiError};
use crate::audit::{
    CorrelationId, build_initiator_from_vsc, build_initiator_unknown,
    emit_perimeter_authenticate_event, perimeter_outcome,
};
use crate::auth::*;
use crate::common::TracedJson;
use crate::keystone::ServiceState;

/// Validate the signed S3 request and describe the credential owner.
#[utoipa::path(
    post,
    path = "/",
    description = "Validate an S3 request signature (no token is issued)",
    request_body = S3TokenAuthRequest,
    responses(
        (status = OK, description = "Token object (no X-Subject-Token)", body = TokenResponse),
    ),
    tag = "s3tokens"
)]
#[tracing::instrument(name = "api::v3::s3tokens::post", level = "debug", skip(state, req))]
pub(super) async fn create(
    Auth(caller_auth): Auth,
    CorrelationId(cid): CorrelationId,
    State(state): State<ServiceState>,
    headers: HeaderMap,
    PeerAddr(peer_addr): PeerAddr,
    TracedJson(req): TracedJson<S3TokenAuthRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // CVE-2025-65073: authenticated caller required; the target is empty
    // since the credential is unknown until the signature is verified.
    state
        .policy_enforcer
        .enforce("identity/s3tokens/validate", &caller_auth, json!({}), None)
        .await?;

    if let Err(retry_after) = state
        .rate_limiters
        .check_ip(&headers, peer_addr.map(|addr| addr.ip()))
    {
        return Err(KeystoneApiError::TooManyRequests {
            retry_after: retry_after.as_secs(),
        });
    }

    let host_id = req
        .credentials
        .access
        .as_deref()
        .and_then(|a| sanitize_initiator_host(a, HostKind::Ec2AccessKey));
    let result = create_inner(&state, req).await;
    let initiator = result
        .as_ref()
        .ok()
        .map(|(vsc, _)| build_initiator_from_vsc(vsc))
        .unwrap_or_else(build_initiator_unknown);
    let initiator = initiator.with_host_id(host_id);
    let (outcome, reason) = perimeter_outcome(&result);
    emit_perimeter_authenticate_event(&state.audit_dispatcher, &cid, initiator, outcome, reason);
    result.map(|(_, response)| response)
}

async fn create_inner(
    state: &ServiceState,
    req: S3TokenAuthRequest,
) -> Result<(ValidatedSecurityContext, Json<TokenResponse>), KeystoneApiError> {
    let wire = req.credentials;
    let access = wire
        .access
        .filter(|a| !a.is_empty())
        .ok_or(AuthenticationError::Ec2SignatureMissing)?;
    let signature = wire
        .signature
        .filter(|s| !s.is_empty())
        .ok_or(AuthenticationError::Ec2SignatureMissing)?;
    let string_to_sign = decode_string_to_sign(wire.token.as_deref().unwrap_or_default())?;

    let vsc = redeem_ec2_credential(state, &access, |secret, auth_ttl| {
        verify_signature(secret, &string_to_sign, &signature)?;
        validate_timestamp(&string_to_sign, auth_ttl)
    })
    .await?;

    let mut api_token = TokenResponse {
        token: TokenBuilder::try_from(&vsc)?.build()?,
    };
    api_token.token.catalog = Some(Catalog(
        state
            .provider
            .get_catalog_provider()
            .get_catalog(&ExecutionContext::internal(state), true)
            .await?
            .into_iter()
            .map(|(s, es)| CatalogService {
                id: s.id.clone(),
                name: s.name(),
                r#type: s.r#type,
                endpoints: es.into_iter().map(Into::into).collect(),
            })
            .collect::<Vec<_>>(),
    ));
    Ok((vsc, Json(api_token)))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE};
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core::credential::s3_signature::generate_signature;
    use openstack_keystone_core_types::credential::{Credential, CredentialBuilder};
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::resource::{DomainRef, ProjectRef};

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::s3tokens::types::TokenResponse;
    use crate::credential::MockCredentialProvider;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::token::MockTokenProvider;

    fn credential(cred_type: &str) -> Credential {
        CredentialBuilder::default()
            .id("cred_id")
            .blob(json!({"access": "AKIA123", "secret": "s3cr3t"}).to_string())
            .r#type(cred_type)
            .user_id("uid")
            .project_id("pid")
            .build()
            .unwrap()
    }

    fn vsc_for_mock() -> openstack_keystone_core::auth::ValidatedSecurityContext {
        use openstack_keystone_core_types::auth::*;
        use openstack_keystone_core_types::resource::ProjectRefBuilder;
        use openstack_keystone_core_types::role::RoleRefBuilder;
        use openstack_keystone_core_types::token::{FernetToken, ProjectScopePayload};

        let user_resp = UserResponseBuilder::default()
            .id("uid")
            .name("uname".to_string())
            .domain_id("user_domain_id".to_string())
            .enabled(true)
            .build()
            .unwrap();
        let fernet_payload = ProjectScopePayload {
            user_id: "uid".into(),
            methods: Vec::from(["ec2credential".to_string()]),
            project_id: "pid".into(),
            ..Default::default()
        };
        let authz = AuthzInfoBuilder::default()
            .roles(vec![
                RoleRefBuilder::default()
                    .id("member")
                    .name("member")
                    .build()
                    .unwrap(),
            ])
            .scope(ScopeInfo::Project {
                project: ProjectRefBuilder::default()
                    .id("pid")
                    .domain_id("pdid")
                    .enabled(true)
                    .name("pname")
                    .build()
                    .unwrap(),
                project_domain: openstack_keystone_core_types::resource::DomainRefBuilder::default(
                )
                .id("pdid")
                .name("pdname")
                .enabled(true)
                .build()
                .unwrap(),
            })
            .build()
            .unwrap();
        let sc = SecurityContext::test_build()
            .authentication_context(AuthenticationContext::Ec2Credential)
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("uid")
                        .user(user_resp)
                        .user_domain(
                            openstack_keystone_core_types::resource::DomainRefBuilder::default()
                                .id("user_domain_id")
                                .name("user_domain_name")
                                .enabled(true)
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                ),
            })
            .token(FernetToken::ProjectScope(fernet_payload))
            .authorization(authz)
            .build();
        openstack_keystone_core::auth::ValidatedSecurityContext::test_new(sc)
    }

    fn resource_mock() -> MockResourceProvider {
        let mut resource_mock = MockResourceProvider::default();
        resource_mock
            .expect_get_project_ref()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| {
                Ok(Some(ProjectRef {
                    id: "pid".into(),
                    domain_id: "pdid".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_get_domain_ref()
            .withf(|_, id: &'_ str| id == "user_domain_id")
            .returning(|_, _| {
                Ok(Some(DomainRef {
                    id: "user_domain_id".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_get_domain_ref()
            .withf(|_, id: &'_ str| id == "pdid")
            .returning(|_, _| {
                Ok(Some(DomainRef {
                    id: "pdid".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
        resource_mock
    }

    fn v1_sts(ts: i64) -> String {
        format!("GET\n\n\n{ts}\n/bucket/key")
    }

    fn body_for(sts: &str, secret: &str) -> Value {
        json!({"credentials": {
            "access": "AKIA123",
            "signature": generate_signature(secret, sts).unwrap(),
            "token": URL_SAFE.encode(sts),
        }})
    }

    fn good_body() -> Value {
        body_for(&v1_sts(chrono::Utc::now().timestamp()), "s3cr3t")
    }

    fn user_mock(enabled: bool) -> MockIdentityProvider {
        let mut m = MockIdentityProvider::default();
        m.expect_get_user().returning(move |_, _| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id("uid")
                    .name("uname")
                    .domain_id("user_domain_id")
                    .enabled(enabled)
                    .build()
                    .unwrap(),
            ))
        });
        m
    }

    fn cred_mock(c: Option<Credential>) -> MockCredentialProvider {
        let mut m = MockCredentialProvider::default();
        m.expect_get_credential_by_ec2_access()
            .returning(move |_, _| Ok(c.clone()));
        m
    }

    fn ok_provider() -> crate::provider::ProviderBuilder {
        let mut token_mock = MockTokenProvider::default();
        let vsc = vsc_for_mock();
        token_mock
            .expect_issue_token_context()
            .returning(move |_, _, _| Ok(vsc.clone()));
        let mut catalog_mock = crate::catalog::MockCatalogProvider::default();
        catalog_mock
            .expect_get_catalog()
            .returning(|_, _| Ok(Vec::new()));
        Provider::mocked_builder()
            .mock_credential(cred_mock(Some(credential("ec2"))))
            .mock_identity(user_mock(true))
            .mock_resource(resource_mock())
            .mock_token(token_mock)
            .mock_catalog(catalog_mock)
    }

    async fn post(state: crate::keystone::ServiceState, body: Value) -> axum::response::Response {
        post_raw(state, serde_json::to_vec(&body).unwrap()).await
    }

    async fn post_raw(
        state: crate::keystone::ServiceState,
        body: Vec<u8>,
    ) -> axum::response::Response {
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        api.as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .extension(test_fixture_scoped())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn status_with(provider: crate::provider::ProviderBuilder, body: Value) -> StatusCode {
        let state = get_mocked_state(provider, true, None).await;
        post(state, body).await.status()
    }

    #[tokio::test]
    async fn test_unauthenticated() {
        let state = get_mocked_state(ok_provider(), true, None).await;
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&good_body()).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_success_has_no_token() {
        let state = get_mocked_state(ok_provider(), true, None).await;
        let response = post(state, good_body()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("X-Subject-Token"));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let raw: Value = serde_json::from_slice(&body).unwrap();
        assert!(raw["token"].get("id").is_none());
        let res: TokenResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.token.methods, vec!["ec2credential".to_string()]);
        assert_eq!(res.token.user.id, "uid");
    }

    #[tokio::test]
    async fn test_accepts_credential_aliases() {
        for key in ["credential", "ec2Credentials"] {
            let mut body = good_body();
            let inner = body["credentials"].take();
            let body = json!({ key: inner });
            let state = get_mocked_state(ok_provider(), true, None).await;
            assert_eq!(post(state, body).await.status(), StatusCode::OK, "{key}");
        }
    }

    #[tokio::test]
    async fn test_unknown_access_key() {
        let p = Provider::mocked_builder().mock_credential(cred_mock(None));
        assert_eq!(status_with(p, good_body()).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_wrong_credential_type() {
        let p = Provider::mocked_builder().mock_credential(cred_mock(Some(credential("totp"))));
        assert_eq!(status_with(p, good_body()).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_bad_signature() {
        let body = body_for(&v1_sts(chrono::Utc::now().timestamp()), "wrong");
        assert_eq!(
            status_with(ok_provider(), body).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn test_malformed_base64() {
        let mut body = good_body();
        body["credentials"]["token"] = json!("!!!not-base64!!!");
        assert_eq!(
            status_with(ok_provider(), body).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn test_missing_access_or_signature() {
        for field in ["access", "signature"] {
            let mut body = good_body();
            body["credentials"].as_object_mut().unwrap().remove(field);
            assert_eq!(
                status_with(Provider::mocked_builder(), body).await,
                StatusCode::UNAUTHORIZED,
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn test_empty_body_is_rejected() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        // The shared JSON extractor reports a missing `credentials` key as
        // 422 (Python: 400); either way the request is rejected.
        let status = post(state, json!({})).await.status();
        assert!(status.is_client_error() && status != StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_bad_aws4_layouts() {
        for sts in [
            "AWS4-HMAC-SHA256\n20260101T000000Z\nscope".to_string(),
            "AWS4-HMAC-SHA256\n20260101T000000Z\n20260101/r/ec2/aws4_request\nx".to_string(),
            "AWS4-HMAC-SHA256\n20260101T000000Z\n20260101/r/s3\nx".to_string(),
        ] {
            let body = json!({"credentials": {
                "access": "AKIA123", "signature": "abc", "token": URL_SAFE.encode(sts)}});
            assert_eq!(
                status_with(ok_provider(), body).await,
                StatusCode::UNAUTHORIZED
            );
        }
    }

    #[tokio::test]
    async fn test_missing_and_stale_timestamp() {
        let stale = body_for(&v1_sts(1_000_000_000), "s3cr3t");
        assert_eq!(
            status_with(ok_provider(), stale).await,
            StatusCode::UNAUTHORIZED
        );
        let missing = body_for("GET\n\n\n\n/bucket/key", "s3cr3t");
        assert_eq!(
            status_with(ok_provider(), missing).await,
            StatusCode::UNAUTHORIZED
        );
    }

    /// Signature must be verified before any per-user state is inspected:
    /// a caller who knows only the access key (bad signature) must get the
    /// same generic 401 as for any other bad signature, never a
    /// "user disabled" answer or the user id, and the user must not even be
    /// looked up (no pre-auth state oracle).
    #[tokio::test]
    async fn test_bad_signature_does_not_reveal_disabled_user() {
        let mut identity = MockIdentityProvider::default();
        identity.expect_get_user().times(0);
        let p = Provider::mocked_builder()
            .mock_credential(cred_mock(Some(credential("ec2"))))
            .mock_identity(identity);
        let body = body_for(&v1_sts(chrono::Utc::now().timestamp()), "wrong");
        let state = get_mocked_state(p, true, None).await;
        let response = post(state, body).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&bytes).to_lowercase();
        assert!(!text.contains("disabled"), "{text}");
        assert!(!text.contains("uid"), "{text}");
    }

    #[tokio::test]
    async fn test_disabled_user() {
        let p = Provider::mocked_builder()
            .mock_credential(cred_mock(Some(credential("ec2"))))
            .mock_identity(user_mock(false));
        assert_eq!(status_with(p, good_body()).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_policy_denied() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        assert_eq!(
            post(state, good_body()).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn test_policy_input_contract() {
        let (state, policy) = crate::api::tests::get_capturing_state(ok_provider()).await;
        assert_eq!(post(state, good_body()).await.status(), StatusCode::OK);
        let calls = policy.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].policy_name, "identity/s3tokens/validate");
        crate::api::tests::policy_contract::assert_object_keys(&calls[0].target, &[]);
        crate::api::tests::policy_contract::assert_existing_presence(&calls[0].existing, false);
        crate::api::tests::policy_contract::assert_no_secrets(&calls[0].target);
    }

    #[tokio::test]
    async fn test_failure_audit_event() {
        use openstack_keystone_core::audit_context::AuditRequestContext;
        let p = Provider::mocked_builder().mock_credential(cred_mock(None));
        let (state, mut receivers) =
            openstack_keystone_core::api::tests::get_mocked_state_with_audit(
                p,
                true,
                openstack_keystone_config::Config::default(),
            )
            .await;
        let mut body = good_body();
        body["credentials"]["access"] = json!("AKIAABCDEFGHIJKLMNOP");
        let response = AuditRequestContext::new(Some("203.0.113.9".parse().unwrap()), None)
            .scope(post(state, body))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let event = receivers.perimeter.try_recv().expect("perimeter event");
        let initiator = event.payload().initiator();
        assert_eq!(initiator.id(), "unknown");
        assert_eq!(
            initiator.host().expect("host").id(),
            Some("AKIAABCDEFGHIJKLMNOP")
        );
    }
}
