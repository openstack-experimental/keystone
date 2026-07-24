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
//! Validate a signed EC2 request and issue a token (ADR 0019 §5).

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::collections::HashSet;

use openstack_keystone_api_types::v3::auth::token::{TokenBuilder, TokenResponse};
use openstack_keystone_core::api::common::{get_authz_info, get_domain};
use openstack_keystone_core::credential::ec2_signature::{validate_timestamp, verify_signature};
use openstack_keystone_core_types::credential::{
    Credential as CoreCredential, Ec2SignatureRequest,
};
use openstack_keystone_core_types::scope::{Project as ScopeProject, Scope as ProviderScope};

use crate::api::auth::Auth;
use crate::api::v3::ec2tokens::types::Ec2TokenAuthRequest;
use crate::api::{Catalog, CatalogService, error::KeystoneApiError};
use crate::audit::{
    CorrelationId, build_initiator_from_vsc, build_initiator_unknown,
    emit_perimeter_authenticate_event, error_variant_name,
};
use crate::auth::*;
use crate::common::TracedJson;
use crate::keystone::ServiceState;

/// Build the immutable authentication chain for an EC2 redemption.
///
/// Delegated EC2 credentials must retain their Trust/ApplicationCredential
/// context for scope and role bounding, while every token minted by this
/// endpoint must also carry the `ec2credential` method marker used to prevent
/// bearer-token use on ordinary Keystone endpoints.
fn security_context_for_ec2_redemption(
    context: AuthenticationContext,
    principal: PrincipalInfo,
) -> Result<SecurityContext, KeystoneApiError> {
    let result = AuthenticationResultBuilder::default()
        .context(context)
        .principal(principal)
        .build()?;
    // Trust and application-credential contexts are delegation carriers here,
    // not additional authentication mechanisms. Keep the method set exact so
    // Fernet cannot encode a delegated token without preserving the EC2
    // bearer restriction marker.
    Ok(
        SecurityContext::try_from_authentication_result_with_auth_methods(
            result,
            HashSet::from(["ec2credential".to_string()]),
        )?,
    )
}

/// Validate the signed `credentials` object and issue a Keystone token
/// scoped to the referenced EC2 credential's project/user.
#[utoipa::path(
    post,
    path = "/",
    description = "Validate an EC2 request signature and issue a token",
    request_body = Ec2TokenAuthRequest,
    responses(
        (status = OK, description = "Token object", body = TokenResponse),
    ),
    tag = "ec2tokens"
)]
#[tracing::instrument(name = "api::v3::ec2tokens::post", level = "debug", skip(state, req))]
pub(super) async fn create(
    Auth(caller_auth): Auth,
    CorrelationId(cid): CorrelationId,
    State(state): State<ServiceState>,
    TracedJson(req): TracedJson<Ec2TokenAuthRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    // CVE-2025-65073: this endpoint requires an already-authenticated caller
    // (a service validating an end-user's EC2-signed request on their
    // behalf), unlike the historical fully-unauthenticated behaviour.
    state
        .policy_enforcer
        .enforce("identity/ec2tokens/validate", &caller_auth, json!({}), None)
        .await?;

    let result = create_inner(&state, req).await;
    let initiator = result
        .as_ref()
        .ok()
        .map(|(vsc, _)| build_initiator_from_vsc(vsc))
        .unwrap_or_else(build_initiator_unknown);
    let (outcome, reason) = match &result {
        Ok(_) => ("success", None),
        Err(e) => ("failure", Some(error_variant_name(e))),
    };
    emit_perimeter_authenticate_event(&state.audit_dispatcher, &cid, initiator, outcome, reason);
    result.map(|(_, response)| response)
}

async fn create_inner(
    state: &ServiceState,
    req: Ec2TokenAuthRequest,
) -> Result<(ValidatedSecurityContext, Response), KeystoneApiError> {
    let exec = ExecutionContext::internal(state);
    let wire = req.credentials;

    let credential: CoreCredential = state
        .provider
        .get_credential_provider()
        .get_credential_by_ec2_access(&exec, &wire.access)
        .await?
        .ok_or(AuthenticationError::Ec2AccessKeyNotFound)?;

    // Defense-in-depth (ADR 0019 §5): `get_credential_by_ec2_access` keys on
    // `SHA-256(access) == credential.id`, an invariant only established for
    // `type == "ec2"` credentials at creation. Reject any other type so a
    // credential mislabelled to dodge the ec2 create-time guards
    // (project binding, delegation stamping, restricted-app-cred gate —
    // OSSA-2026-005) can never be redeemed here even if its id were to
    // collide with an access hash.
    if credential.r#type != "ec2" {
        return Err(AuthenticationError::Ec2AccessKeyNotFound.into());
    }

    let blob: Value = serde_json::from_str(&credential.blob).map_err(|e| {
        KeystoneApiError::InternalError(format!(
            "credential {}: corrupted ec2 blob: {e}",
            credential.id
        ))
    })?;
    let secret = blob.get("secret").and_then(Value::as_str).ok_or_else(|| {
        KeystoneApiError::InternalError(format!(
            "credential {}: ec2 blob missing `secret`",
            credential.id
        ))
    })?;
    let trust_id = blob.get("trust_id").and_then(Value::as_str);
    let app_cred_id = blob.get("app_cred_id").and_then(Value::as_str);

    // OAuth1 access-token-bound EC2 credentials (`access_token_id`) are not
    // supported: OAuth1 is not implemented, so redeeming such a credential
    // would silently fall through to a plain `Ec2Credential` context and
    // drop the intended OAuth1 delegation restriction (OSSA-2026-005
    // family). Fail closed until the OAuth1 delegation is wired through.
    if blob
        .get("access_token_id")
        .and_then(Value::as_str)
        .is_some()
    {
        return Err(KeystoneApiError::InternalError(format!(
            "credential {}: OAuth1 access-token-bound EC2 credentials are not supported",
            credential.id
        )));
    }

    let project_id = credential.project_id.clone().ok_or_else(|| {
        KeystoneApiError::InternalError(format!(
            "credential {}: ec2 credential missing project_id",
            credential.id
        ))
    })?;

    // User/domain enabled checks (ADR 0019 §5 step 4). Project/project-domain
    // enabled is checked below by `get_authz_info`'s `ScopeInfo::validate()`.
    let user = state
        .provider
        .get_identity_provider()
        .get_user(&exec, &credential.user_id)
        .await?
        .ok_or(AuthenticationError::Ec2AccessKeyNotFound)?;
    if !user.enabled {
        return Err(AuthenticationError::UserDisabled(user.id.clone()).into());
    }
    let user_domain = get_domain(state, Some(&user.domain_id), None::<&str>).await?;
    if !user_domain.enabled {
        return Err(AuthenticationError::UserDomainDisabled.into());
    }

    let auth_ttl = state.config_manager.config.read().await.ec2.auth_ttl;

    let sig_req = Ec2SignatureRequest {
        access: wire.access.clone(),
        signature: wire.signature.clone(),
        host: wire.host.clone(),
        verb: wire.verb.clone(),
        path: wire.path.clone(),
        params: wire.params.clone(),
        headers: wire.headers.clone(),
        body_hash: wire.body_hash.clone(),
    };

    // Timestamp is checked before the signature so a stale replayed request
    // is rejected without depending on signature-comparison timing.
    validate_timestamp(&sig_req, auth_ttl)?;
    verify_signature(secret, &sig_req)?;

    let principal = PrincipalInfo {
        identity: IdentityInfo::User(
            UserIdentityInfoBuilder::default()
                .user_id(user.id.clone())
                .user(user.clone())
                .user_domain(user_domain.clone())
                .build()?,
        ),
    };

    // Delegation metadata pass-through (ADR 0019 §5, "Credential metadata in
    // the token"): reuse the existing Trust/ApplicationCredential contexts so
    // the bounded-object validation already wired into
    // `ValidatedSecurityContext::new_for_scope` (trustee/expiry checks)
    // applies unchanged.
    let context = if let Some(tid) = trust_id {
        let trust = state
            .provider
            .get_trust_provider()
            .get_trust(&exec, tid)
            .await?
            .ok_or_else(|| KeystoneApiError::not_found("trust", tid))?;
        AuthenticationContext::Trust { trust, token: None }
    } else if let Some(aid) = app_cred_id {
        let application_credential = state
            .provider
            .get_application_credential_provider()
            .get_application_credential(&exec, aid)
            .await?
            .ok_or_else(|| KeystoneApiError::not_found("application_credential", aid))?;
        AuthenticationContext::ApplicationCredential {
            application_credential,
            token: None,
        }
    } else {
        AuthenticationContext::Ec2Credential
    };

    let ctx = security_context_for_ec2_redemption(context, principal)?;
    let provider_scope = ProviderScope::Project(ScopeProject {
        id: Some(project_id),
        name: None,
        domain: None,
    });
    let authz_info = get_authz_info(state, Some(&provider_scope)).await?;

    let vsc = state
        .provider
        .get_token_provider()
        .issue_token_context(state, &ctx, &authz_info)
        .await?;

    let mut api_token = TokenResponse {
        token: TokenBuilder::try_from(&vsc)?.build()?,
    };
    let catalog: Catalog = Catalog(
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
    );
    api_token.token.catalog = Some(catalog);

    let response = (
        StatusCode::OK,
        [(
            "X-Subject-Token",
            state
                .provider
                .get_token_provider()
                .encode_token(vsc.token()?)?,
        )],
        Json(api_token),
    )
        .into_response();
    Ok((vsc, response))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_core::credential::ec2_signature::{
        Ec2SignatureVersion, generate_signature,
    };
    use openstack_keystone_core_types::application_credential::ApplicationCredentialBuilder;
    use openstack_keystone_core_types::auth::{
        AuthenticationContext, IdentityInfo, PrincipalInfo, ScopeInfo, SecurityContext,
        UserIdentityInfoBuilder,
    };
    use openstack_keystone_core_types::credential::{Credential, CredentialBuilder};
    use openstack_keystone_core_types::identity::UserResponseBuilder;
    use openstack_keystone_core_types::resource::{Domain, DomainBuilder, Project, ProjectBuilder};
    use openstack_keystone_core_types::token::FernetToken;
    use openstack_keystone_core_types::trust::TrustBuilder;

    use super::{super::openapi_router, security_context_for_ec2_redemption};
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api::v3::ec2tokens::types::TokenResponse;
    use crate::credential::MockCredentialProvider;
    use crate::identity::MockIdentityProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;
    use crate::token::MockTokenProvider;

    fn ec2_credential(secret: &str) -> Credential {
        CredentialBuilder::default()
            .id("cred_id")
            .blob(json!({"access": "AKIA123", "secret": secret}).to_string())
            .r#type("ec2")
            .user_id("uid")
            .project_id("pid")
            .build()
            .unwrap()
    }

    fn signed_body(secret: &str, signature_override: Option<&str>) -> serde_json::Value {
        let mut params = HashMap::new();
        params.insert("SignatureVersion".to_string(), "2".to_string());
        params.insert("SignatureMethod".to_string(), "HmacSHA256".to_string());
        params.insert("Timestamp".to_string(), chrono::Utc::now().to_rfc3339());

        let sig_req = openstack_keystone_core_types::credential::Ec2SignatureRequest {
            access: "AKIA123".into(),
            signature: None,
            host: "identity.example.com".into(),
            verb: "GET".into(),
            path: "/".into(),
            params: params.clone(),
            headers: HashMap::new(),
            body_hash: None,
        };
        let signature = signature_override.map(str::to_string).unwrap_or_else(|| {
            generate_signature(secret, Ec2SignatureVersion::V2, &sig_req).unwrap()
        });

        json!({
            "credentials": {
                "access": "AKIA123",
                "signature": signature,
                "host": "identity.example.com",
                "verb": "GET",
                "path": "/",
                "params": params,
            }
        })
    }

    fn principal() -> PrincipalInfo {
        PrincipalInfo {
            identity: IdentityInfo::User(
                UserIdentityInfoBuilder::default()
                    .user_id("uid")
                    .build()
                    .unwrap(),
            ),
        }
    }

    fn project_scope() -> ScopeInfo {
        ScopeInfo::Project {
            project: ProjectBuilder::default()
                .id("pid")
                .domain_id("pdid")
                .enabled(true)
                .name("project")
                .build()
                .unwrap(),
            project_domain: DomainBuilder::default()
                .id("pdid")
                .enabled(true)
                .name("domain")
                .build()
                .unwrap(),
        }
    }

    fn assert_ec2_payload_methods(context: &mut SecurityContext) -> FernetToken {
        context.set_authorization_scope(project_scope()).unwrap();
        let token = FernetToken::from_security_context(
            context,
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .unwrap();
        assert_eq!(token.methods().as_slice(), ["ec2credential"]);
        token
    }

    #[test]
    fn test_appcred_ec2_context_preserves_delegation_and_method_roundtrip() {
        let app_cred = ApplicationCredentialBuilder::default()
            .id("appcred-id")
            .name("appcred")
            .project_id("pid")
            .roles(vec![])
            .unrestricted(true)
            .user_id("uid")
            .build()
            .unwrap();

        let mut context = security_context_for_ec2_redemption(
            AuthenticationContext::ApplicationCredential {
                application_credential: app_cred.clone(),
                token: None,
            },
            principal(),
        )
        .unwrap();

        assert!(matches!(
            context.authentication_context(),
            AuthenticationContext::ApplicationCredential { .. }
        ));
        assert_eq!(context.auth_methods().len(), 1);
        assert!(context.auth_methods().contains("ec2credential"));
        assert_eq!(context.audit_ids().len(), 1);

        let token = assert_ec2_payload_methods(&mut context);
        let restored = AuthenticationContext::ApplicationCredential {
            application_credential: app_cred,
            token: Some(token),
        };
        assert!(restored.methods().contains("ec2credential"));
    }

    #[test]
    fn test_trust_ec2_context_preserves_delegation_and_method_roundtrip() {
        let trust = TrustBuilder::default()
            .id("trust-id")
            .trustor_user_id("trustor")
            .trustee_user_id("uid")
            .project_id("pid")
            .impersonation(false)
            .build()
            .unwrap();
        let mut context = security_context_for_ec2_redemption(
            AuthenticationContext::Trust {
                trust: trust.clone(),
                token: None,
            },
            principal(),
        )
        .unwrap();

        assert!(matches!(
            context.authentication_context(),
            AuthenticationContext::Trust { .. }
        ));
        assert_eq!(context.auth_methods().len(), 1);
        assert!(context.auth_methods().contains("ec2credential"));
        assert_eq!(context.audit_ids().len(), 1);

        let token = assert_ec2_payload_methods(&mut context);
        let restored = AuthenticationContext::Trust {
            trust,
            token: Some(token),
        };
        assert!(restored.methods().contains("ec2credential"));
    }

    fn vsc_for_mock() -> openstack_keystone_core::auth::ValidatedSecurityContext {
        use openstack_keystone_core_types::auth::*;
        use openstack_keystone_core_types::resource::ProjectBuilder;
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
                project: ProjectBuilder::default()
                    .id("pid")
                    .domain_id("pdid")
                    .enabled(true)
                    .name("pname")
                    .build()
                    .unwrap(),
                project_domain: openstack_keystone_core_types::resource::DomainBuilder::default()
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
                            openstack_keystone_core_types::resource::DomainBuilder::default()
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
            .expect_get_project()
            .withf(|_, id: &'_ str| id == "pid")
            .returning(|_, _| {
                Ok(Some(Project {
                    id: "pid".into(),
                    domain_id: "pdid".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "user_domain_id")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "user_domain_id".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
        resource_mock
            .expect_get_domain()
            .withf(|_, id: &'_ str| id == "pdid")
            .returning(|_, _| {
                Ok(Some(Domain {
                    id: "pdid".into(),
                    enabled: true,
                    ..Default::default()
                }))
            });
        resource_mock
    }

    async fn post(
        state: crate::keystone::ServiceState,
        body: serde_json::Value,
    ) -> axum::response::Response {
        let vsc = test_fixture_scoped();
        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state);
        api.as_service()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method("POST")
                    .extension(vsc)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_create_success() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential_by_ec2_access()
            .withf(|_, access: &'_ str| access == "AKIA123")
            .returning(|_, _| Ok(Some(ec2_credential("s3cr3t"))));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id("uid")
                    .name("uname")
                    .domain_id("user_domain_id")
                    .enabled(true)
                    .build()
                    .unwrap(),
            ))
        });

        let mut token_mock = MockTokenProvider::default();
        let vsc_clone = vsc_for_mock();
        token_mock
            .expect_issue_token_context()
            .returning(move |_, _, _| Ok(vsc_clone.clone()));
        token_mock
            .expect_encode_token()
            .returning(|_| Ok("token".to_string()));

        let mut catalog_mock = crate::catalog::MockCatalogProvider::default();
        catalog_mock
            .expect_get_catalog()
            .returning(|_, _| Ok(Vec::new()));

        let provider = Provider::mocked_builder()
            .mock_credential(credential_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock())
            .mock_token(token_mock)
            .mock_catalog(catalog_mock);

        let state = get_mocked_state(provider, true, None).await;
        let response = post(state, signed_body("s3cr3t", None)).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("X-Subject-Token"));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: TokenResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(res.token.methods, vec!["ec2credential".to_string()]);
    }

    #[tokio::test]
    async fn test_create_access_key_not_found() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential_by_ec2_access()
            .returning(|_, _| Ok(None));

        let provider = Provider::mocked_builder().mock_credential(credential_mock);
        let state = get_mocked_state(provider, true, None).await;
        let response = post(state, signed_body("s3cr3t", None)).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_invalid_signature() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential_by_ec2_access()
            .returning(|_, _| Ok(Some(ec2_credential("s3cr3t"))));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id("uid")
                    .name("uname")
                    .domain_id("user_domain_id")
                    .enabled(true)
                    .build()
                    .unwrap(),
            ))
        });

        let provider = Provider::mocked_builder()
            .mock_credential(credential_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock());
        let state = get_mocked_state(provider, true, None).await;
        let response = post(state, signed_body("wrong-secret", None)).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_disabled_user_rejected() {
        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential_by_ec2_access()
            .returning(|_, _| Ok(Some(ec2_credential("s3cr3t"))));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id("uid")
                    .name("uname")
                    .domain_id("user_domain_id")
                    .enabled(false)
                    .build()
                    .unwrap(),
            ))
        });

        let provider = Provider::mocked_builder()
            .mock_credential(credential_mock)
            .mock_identity(identity_mock);
        let state = get_mocked_state(provider, true, None).await;
        let response = post(state, signed_body("s3cr3t", None)).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_policy_denied() {
        let state = get_mocked_state(Provider::mocked_builder(), false, None).await;
        let response = post(state, signed_body("s3cr3t", None)).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_missing_client_signature() {
        let mut body = signed_body("s3cr3t", None);
        body["credentials"]
            .as_object_mut()
            .unwrap()
            .remove("signature");

        let mut credential_mock = MockCredentialProvider::default();
        credential_mock
            .expect_get_credential_by_ec2_access()
            .returning(|_, _| Ok(Some(ec2_credential("s3cr3t"))));

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock.expect_get_user().returning(|_, _| {
            Ok(Some(
                UserResponseBuilder::default()
                    .id("uid")
                    .name("uname")
                    .domain_id("user_domain_id")
                    .enabled(true)
                    .build()
                    .unwrap(),
            ))
        });

        let provider = Provider::mocked_builder()
            .mock_credential(credential_mock)
            .mock_identity(identity_mock)
            .mock_resource(resource_mock());
        let state = get_mocked_state(provider, true, None).await;
        let response = post(state, body).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
