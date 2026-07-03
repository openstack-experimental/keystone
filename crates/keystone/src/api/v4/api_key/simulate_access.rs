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
//! API Key: dry-run auditing endpoint (ADR 0021 §5.E).
//!
//! Deliberately does not call `MappingApi::authenticate_by_mapping`: that
//! path may provision a real user row for `IdentityMode::Local` rules, which
//! would be a side effect a *dry-run* endpoint must not have. Instead this
//! re-derives the same claims `hydrate_ephemeral_context`
//! (`crates/core/src/api/api_key_auth.rs`) would build, evaluates the
//! ruleset, and reads the matched `Authorization`'s roles directly -- no
//! token, no crypto verification, no provisioning.

use std::collections::HashMap;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use validator::Validate;

use openstack_keystone_api_types::v4::api_key::{
    ApiKey, ApiKeySimulateAccessRequest, ApiKeySimulateAccessResponse, SimulatedScope,
};
use openstack_keystone_core::auth::{ExecutionContext, ValidatedSecurityContext};
use openstack_keystone_core::mapping::engine;
use openstack_keystone_core_types::api_key::ApiClientResource;
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;

use crate::api::auth::Auth;
use crate::api::error::KeystoneApiError;
use crate::keystone::ServiceState;

/// Perform a mock authentication pass for an API Key, returning its fully
/// resolved authorization topology without presenting a bearer token.
#[utoipa::path(
    post,
    path = "/simulate-access",
    operation_id = "/api_key:simulate_access",
    request_body = ApiKeySimulateAccessRequest,
    responses(
        (status = OK, description = "Simulated authorization topology", body = ApiKeySimulateAccessResponse),
    ),
    security(("x-auth" = [])),
    tag="api_key"
)]
#[tracing::instrument(
    name = "api::v4::api_key::simulate_access",
    level = "debug",
    skip(state, user_auth),
    err(Debug)
)]
pub(super) async fn simulate_access(
    Auth(user_auth): Auth,
    State(state): State<ServiceState>,
    Json(req): Json<ApiKeySimulateAccessRequest>,
) -> Result<impl IntoResponse, KeystoneApiError> {
    req.validate()?;

    let current = state
        .provider
        .get_api_key_provider()
        .get_by_client_id(&state, &req.domain_id, &req.client_id)
        .await?
        .ok_or_else(|| KeystoneApiError::NotFound {
            resource: "api_key".into(),
            identifier: req.client_id.clone(),
        })?;

    state
        .policy_enforcer
        .enforce(
            "identity/api_key/simulate_access",
            &user_auth,
            serde_json::json!({"api_key": null}),
            Some(serde_json::json!({"api_key": ApiKey::from(current.clone())})),
        )
        .await?;

    let response = simulate(&state, &user_auth, &current).await?;

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// `base` carries the always-present identifying fields; each early return
/// fills in `reason` and leaves `matched: false`.
async fn simulate(
    state: &ServiceState,
    user_auth: &ValidatedSecurityContext,
    resource: &ApiClientResource,
) -> Result<ApiKeySimulateAccessResponse, KeystoneApiError> {
    let base = ApiKeySimulateAccessResponse {
        client_id: resource.client_id.clone(),
        domain_id: resource.domain_id.clone(),
        provider_id: resource.provider_id.clone(),
        matched: false,
        scope: None,
        roles: Vec::new(),
        reason: None,
    };
    let not_matched = |reason: &str| ApiKeySimulateAccessResponse {
        reason: Some(reason.to_string()),
        ..base.clone()
    };

    if !resource.enabled {
        return Ok(not_matched("API key is disabled"));
    }
    if chrono::Utc::now().timestamp() >= resource.expires_at {
        return Ok(not_matched("API key has expired"));
    }

    let source = IdentitySource::ApiClient {
        provider_id: resource.provider_id.clone(),
    };
    let exec = ExecutionContext::from_auth(state, user_auth);
    let ruleset = state
        .provider
        .get_mapping_provider()
        .get_ruleset_by_source(&exec, &resource.domain_id, &source)
        .await?;

    let Some(ruleset) = ruleset else {
        return Ok(not_matched("no mapping ruleset bound to provider_id"));
    };
    if !ruleset.enabled {
        return Ok(not_matched("mapping ruleset is disabled"));
    }

    let mut claims: HashMap<String, Vec<String>> = HashMap::new();
    claims.insert(
        "api_client.client_id".to_string(),
        vec![resource.client_id.clone()],
    );
    claims.insert(
        "api_client.provider_id".to_string(),
        vec![resource.provider_id.clone()],
    );

    let match_result =
        engine::evaluate_ruleset(&ruleset, &claims, ruleset.domain_id.as_deref(), None)
            .map_err(KeystoneApiError::from)?;

    let Some(mr) = match_result else {
        return Ok(not_matched("no mapping rule matched"));
    };
    if mr.authorizations.is_empty() {
        return Ok(not_matched("mapping resolved zero authorizations"));
    }
    if mr.authorizations.len() > 1 {
        return Ok(not_matched(
            "mapping resolved multiple authorizations (ambiguous scope)",
        ));
    }

    // API Keys are domain-owned machine identities (ADR 0021 §2): only a
    // domain-scoped authorization is accepted. This is an allowlist, not a
    // denylist naming each forbidden variant, so it also covers any
    // authorization type added in the future.
    let (scope, roles) = match &mr.authorizations[0] {
        Authorization::Domain { domain_id, roles } => (
            SimulatedScope::Domain {
                domain_id: domain_id.clone(),
            },
            roles,
        ),
        Authorization::System { .. } => {
            return Ok(not_matched(
                "mapping resolved to system scope, which is forbidden for API keys",
            ));
        }
        _ => {
            return Ok(not_matched(
                "mapping resolved to a non-domain scope, which is forbidden for API keys (only domain scope is accepted)",
            ));
        }
    };

    let mut role_names: Vec<String> = roles
        .iter()
        .map(|r| r.name.clone().unwrap_or_else(|| r.id.clone()))
        .collect();
    role_names.sort();
    role_names.dedup();

    Ok(ApiKeySimulateAccessResponse {
        matched: true,
        scope: Some(scope),
        roles: role_names,
        ..base
    })
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::trace::TraceLayer;

    use openstack_keystone_api_types::v4::api_key::{
        ApiKeySimulateAccessRequest, ApiKeySimulateAccessResponse,
    };
    use openstack_keystone_core_types::api_key as provider_types;
    use openstack_keystone_core_types::mapping as mapping_types;
    use openstack_keystone_core_types::role::RoleRef;

    use super::super::openapi_router;
    use crate::api::tests::{get_mocked_state, test_fixture_scoped};
    use crate::api_key::MockApiKeyProvider;
    use crate::mapping::MockMappingProvider;
    use crate::provider::Provider;

    fn sample_resource_core() -> provider_types::ApiClientResource {
        provider_types::ApiClientResource {
            domain_id: "domain_id".into(),
            provider_id: "provider-1".into(),
            client_id: "client-1".into(),
            lookup_hash: "lookup-hash".into(),
            secret_hash: "$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA".into(),
            allowed_ips: None,
            description: None,
            enabled: true,
            created_at: 1_000,
            expires_at: chrono::Utc::now().timestamp() + 3_600,
            last_used_at: None,
            revoked_at: None,
            revoked_by: None,
        }
    }

    fn sample_ruleset_matching() -> mapping_types::MappingRuleSet {
        mapping_types::MappingRuleSet {
            mapping_id: "test-ruleset".into(),
            domain_id: Some("domain_id".into()),
            source: mapping_types::IdentitySource::ApiClient {
                provider_id: "provider-1".into(),
            },
            domain_resolution_mode: mapping_types::DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![mapping_types::MappingRule {
                name: "rule-1".into(),
                description: None,
                r#match: mapping_types::MatchCriteria::AllOf(vec![]),
                identity: mapping_types::IdentityBinding {
                    identity_mode: None,
                    user_name: "${claims.api_client.client_id}".into(),
                    user_id: None,
                    user_domain_id: None,
                    is_system: false,
                },
                authorizations: vec![mapping_types::Authorization::Domain {
                    domain_id: "domain_id".into(),
                    roles: vec![RoleRef {
                        id: "role-1".into(),
                        name: Some("member".into()),
                        domain_id: None,
                    }],
                }],
                groups: vec![],
            }],
            ruleset_version: 1,
        }
    }

    fn sample_request() -> ApiKeySimulateAccessRequest {
        ApiKeySimulateAccessRequest {
            client_id: "client-1".into(),
            domain_id: "domain_id".into(),
        }
    }

    #[tokio::test]
    async fn test_simulate_access_matched() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut api_key_mock = MockApiKeyProvider::default();
        api_key_mock
            .expect_get_by_client_id()
            .returning(|_, _, _| Ok(Some(sample_resource_core())));
        provider = provider.mock_api_key(api_key_mock);
        let mut mapping_mock = MockMappingProvider::default();
        mapping_mock
            .expect_get_ruleset_by_source()
            .returning(|_, _, _| Ok(Some(sample_ruleset_matching())));
        provider = provider.mock_mapping(mapping_mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_request();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/simulate-access")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApiKeySimulateAccessResponse = serde_json::from_slice(&body).unwrap();
        assert!(res.matched);
        assert_eq!(res.roles, vec!["member".to_string()]);
        assert!(res.reason.is_none());
    }

    fn sample_ruleset_project_scoped() -> mapping_types::MappingRuleSet {
        let mut ruleset = sample_ruleset_matching();
        ruleset.rules[0].authorizations = vec![mapping_types::Authorization::Project {
            project_id: "project-1".into(),
            project_domain_id: "domain_id".into(),
            roles: vec![RoleRef {
                id: "role-1".into(),
                name: Some("member".into()),
                domain_id: None,
            }],
        }];
        ruleset
    }

    #[tokio::test]
    async fn test_simulate_access_project_scope_not_matched() {
        // API Keys are domain-owned machine identities (ADR 0021 §2) and
        // must resolve to a domain scope only; a project-scoped match must
        // not be reported as `matched`.
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut api_key_mock = MockApiKeyProvider::default();
        api_key_mock
            .expect_get_by_client_id()
            .returning(|_, _, _| Ok(Some(sample_resource_core())));
        provider = provider.mock_api_key(api_key_mock);
        let mut mapping_mock = MockMappingProvider::default();
        mapping_mock
            .expect_get_ruleset_by_source()
            .returning(|_, _, _| Ok(Some(sample_ruleset_project_scoped())));
        provider = provider.mock_mapping(mapping_mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_request();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/simulate-access")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApiKeySimulateAccessResponse = serde_json::from_slice(&body).unwrap();
        assert!(!res.matched);
        assert!(res.scope.is_none());
        assert_eq!(
            res.reason.as_deref(),
            Some(
                "mapping resolved to a non-domain scope, which is forbidden for API keys (only domain scope is accepted)"
            )
        );
    }

    #[tokio::test]
    async fn test_simulate_access_disabled_key_not_matched() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut api_key_mock = MockApiKeyProvider::default();
        api_key_mock.expect_get_by_client_id().returning(|_, _, _| {
            let mut res = sample_resource_core();
            res.enabled = false;
            Ok(Some(res))
        });
        provider = provider.mock_api_key(api_key_mock);
        provider = provider.mock_mapping(MockMappingProvider::default());

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_request();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/simulate-access")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let res: ApiKeySimulateAccessResponse = serde_json::from_slice(&body).unwrap();
        assert!(!res.matched);
        assert_eq!(res.reason.as_deref(), Some("API key is disabled"));
    }

    #[tokio::test]
    async fn test_simulate_access_not_found() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut api_key_mock = MockApiKeyProvider::default();
        api_key_mock
            .expect_get_by_client_id()
            .returning(|_, _, _| Ok(None));
        provider = provider.mock_api_key(api_key_mock);

        let state = get_mocked_state(provider, true, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_request();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/simulate-access")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_simulate_access_policy_denied() {
        let vsc = test_fixture_scoped();
        let mut provider = Provider::mocked_builder();
        let mut api_key_mock = MockApiKeyProvider::default();
        api_key_mock
            .expect_get_by_client_id()
            .returning(|_, _, _| Ok(Some(sample_resource_core())));
        provider = provider.mock_api_key(api_key_mock);

        let state = get_mocked_state(provider, false, None).await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_request();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/simulate-access")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(vsc)
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_simulate_access_unauthorized() {
        let state = get_mocked_state(
            Provider::mocked_builder().mock_api_key(MockApiKeyProvider::default()),
            true,
            None,
        )
        .await;

        let mut api = openapi_router()
            .layer(TraceLayer::new_for_http())
            .with_state(state.clone());

        let req = sample_request();

        let response = api
            .as_service()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/simulate-access")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
