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
//! Test the k8s auth functionality (mapping-engine path only).
//!
//! `openstack_sdk::RawQueryAsync` treats non-2xx responses as errors and
//! returns `Err`, so tests that expect failure must match on the `Result`
//! rather than using `.await?` — otherwise the assertion is never reached.
//! See: `test_k8s_auth_invalid_jwt_format` and `test_k8s_auth_cannot_rescope_to_other_project`.

use std::env;
use std::sync::Arc;

use eyre::{Result, eyre};
use secrecy::{ExposeSecret, SecretString};
use tokio::fs;
use uuid::Uuid;

use openstack_sdk::config::CloudConfig;
use openstack_sdk::{AsyncOpenStack, api::RawQueryAsync};

use openstack_keystone_api_types::k8s_auth::{K8sAuthRequest, instance::*};
use openstack_keystone_api_types::v3::auth::token::{Token, TokenResponse};
use openstack_keystone_api_types::v3::project::ProjectCreateBuilder;
use openstack_keystone_api_types::v3::role::{RoleCreate, RoleCreateBuilder, RoleRef};

use test_api::guard::*;
use test_api::k8s_auth::auth::K8sAuthenticationRequestBuilder;
use test_api::k8s_auth::instance::{create_auth_instance, update_auth_instance};
use test_api::mapping::ruleset::create_ruleset;
use test_api::resource::project::create_project;
use test_api::role;
use test_api::role::create_role;

/// Helper: sends a k8s auth request and returns the Token + X-Subject-Token
/// string.
async fn k8s_auth<I: AsRef<str>>(
    client: &Arc<AsyncOpenStack>,
    instance_id: I,
    obj: K8sAuthRequest,
) -> Result<(Token, SecretString)> {
    let rsp: http::Response<bytes::Bytes> = K8sAuthenticationRequestBuilder::default()
        .instance_id(instance_id.as_ref())
        .auth(obj)
        .build()?
        .raw_query_async(client.as_ref())
        .await?;

    if rsp.status() != http::StatusCode::OK {
        return Err(eyre!(
            "Authentication failed with {}: {}",
            rsp.status(),
            String::from_utf8_lossy(rsp.body())
        ));
    }

    let token = SecretString::from(
        rsp.headers()
            .get("X-Subject-Token")
            .ok_or_else(|| eyre!("X-Subject-Token header missing"))?
            .to_str()?,
    );
    let token_info: TokenResponse = serde_json::from_slice(rsp.body())?;
    Ok((token_info.token, token))
}

/// Create a K8s auth instance from the pod's mounted CA cert.
async fn setup_k8s_instance(
    client: &Arc<AsyncOpenStack>,
) -> Result<AsyncResourceGuard<K8sAuthInstance>> {
    let k8s_ca = fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt").await?;
    create_auth_instance(
        client,
        K8sAuthInstanceCreate {
            ca_cert: Some(k8s_ca),
            disable_local_ca_jwt: Some(true),
            domain_id: "default".to_string(),
            enabled: true,
            host: "https://kubernetes.default.svc".to_string(),
            name: Some(Uuid::new_v4().simple().to_string()),
        },
    )
    .await
}

/// Read the pod's K8s service account token from the mounted secret.
async fn read_pod_k8s_token() -> Result<String> {
    fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
        .await
        .map_err(Into::into)
}

/// Build a wildcard MappingRule that matches **any** k8s service account name
/// and namespace (using `MatchesRegex(".*")`).
fn wildcard_k8s_rule(
    name: impl Into<String>,
    user_name: impl Into<String>,
    authorizations: Vec<openstack_keystone_api_types::v4::mapping::ruleset::Authorization>,
) -> openstack_keystone_api_types::v4::mapping::ruleset::MappingRule {
    openstack_keystone_api_types::v4::mapping::ruleset::MappingRule {
        name: name.into(),
        description: None,
        r#match: openstack_keystone_api_types::v4::mapping::ruleset::MatchCriteria::AllOf(vec![
            openstack_keystone_api_types::v4::mapping::ruleset::MatchCondition::Condition(
                openstack_keystone_api_types::v4::mapping::ruleset::ClaimCondition::MatchesRegex {
                    claim: "k8s.serviceaccount.namespace".into(),
                    regex: ".*".into(),
                },
            ),
            openstack_keystone_api_types::v4::mapping::ruleset::MatchCondition::Condition(
                openstack_keystone_api_types::v4::mapping::ruleset::ClaimCondition::MatchesRegex {
                    claim: "k8s.serviceaccount.name".into(),
                    regex: ".*".into(),
                },
            ),
        ]),
        identity: openstack_keystone_api_types::v4::mapping::ruleset::IdentityBinding {
            user_name: user_name.into(),
            user_id: None,
            user_domain_id: None,
            is_system: false,
        },
        authorizations,
        groups: vec![],
    }
}

/// Helper: create a wildcard rule with no authorizations.
fn wildcard_rule_no_auth(
    name: impl Into<String>,
    user_name: impl Into<String>,
) -> openstack_keystone_api_types::v4::mapping::ruleset::MappingRule {
    wildcard_k8s_rule(name, user_name, vec![])
}

/// Helper: create a wildcard rule with a project authorization.
fn wildcard_rule_project(
    name: impl Into<String>,
    user_name: impl Into<String>,
    project_id: impl Into<String>,
    role_name: impl Into<String>,
    role_id: impl Into<String>,
) -> openstack_keystone_api_types::v4::mapping::ruleset::MappingRule {
    let authz = openstack_keystone_api_types::v4::mapping::ruleset::Authorization::Project {
        project_id: project_id.into(),
        project_domain_id: "default".to_string(),
        roles: vec![RoleRef {
            id: role_id.into(),
            name: role_name.into(),
            domain_id: None,
        }],
    };
    wildcard_k8s_rule(name, user_name, vec![authz])
}

#[tokio::test]
async fn test_k8s_auth() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let instance = setup_k8s_instance(&test_client).await?;

    let _ruleset = create_ruleset(
        &test_client,
        openstack_keystone_api_types::v4::mapping::ruleset::MappingRuleSetCreate {
            mapping_id: Some(format!("test-k8s-{}", Uuid::new_v4().simple())),
            domain_id: Some("default".to_string()),
            source: openstack_keystone_api_types::v4::mapping::ruleset::IdentitySource::K8s {
                cluster_id: instance.id.clone(),
            },
            domain_resolution_mode:
                openstack_keystone_api_types::v4::mapping::ruleset::DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![wildcard_rule_no_auth("any-sa", "svc-k8s")],
        },
    )
    .await?;

    let k8s_token = read_pod_k8s_token().await?;
    let (token_data, _token_secret) = k8s_auth(
        &test_client,
        &instance.id,
        K8sAuthRequest {
            jwt: k8s_token.into(),
            rule_name: None,
        },
    )
    .await?;

    // Token should be valid with the correct user_name from the matched rule
    assert_eq!(
        token_data.user.name.as_deref(),
        Some("svc-k8s"),
        "token user name should match the wildcard rule"
    );

    _ruleset.delete().await?;
    instance.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_k8s_auth_invalid_jwt_format() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let instance = setup_k8s_instance(&test_client).await?;

    // Test with invalid JWT format - should fail with unauthorized/bad_request/forbidden
    let res = K8sAuthenticationRequestBuilder::default()
        .instance_id(&instance.id)
        .auth(K8sAuthRequest {
            jwt: "not-a-jwt-token-format".into(),
            rule_name: None,
        })
        .build()?
        .raw_query_async(test_client.as_ref())
        .await;

    // The SDK may return the response or an error for non-2xx status codes;
    // in either case we expect the authentication to be rejected.
    match res {
        Ok(rsp) => {
            assert!(
                rsp.status() == http::StatusCode::UNAUTHORIZED
                    || rsp.status() == http::StatusCode::BAD_REQUEST
                    || rsp.status() == http::StatusCode::FORBIDDEN,
                "invalid JWT must be rejected (got: {} body: {})",
                rsp.status(),
                String::from_utf8_lossy(rsp.body())
            );
        }
        Err(e) => {
            let err_str = e.to_string();
            assert!(
                err_str.contains("403")
                    || err_str.contains("401")
                    || err_str.contains("400")
                    || err_str.contains("forbidden")
                    || err_str.contains("unauthorized"),
                "invalid JWT error message should indicate rejection, got: {}",
                err_str
            );
        }
    }

    instance.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_k8s_auth_rule_name_respected() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let instance = setup_k8s_instance(&test_client).await?;

    let _ruleset = create_ruleset(
        &test_client,
        openstack_keystone_api_types::v4::mapping::ruleset::MappingRuleSetCreate {
            mapping_id: Some(format!("test-rule-name-{}", Uuid::new_v4().simple())),
            domain_id: Some("default".to_string()),
            source: openstack_keystone_api_types::v4::mapping::ruleset::IdentitySource::K8s {
                cluster_id: instance.id.clone(),
            },
            domain_resolution_mode:
                openstack_keystone_api_types::v4::mapping::ruleset::DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![
                wildcard_rule_no_auth("rule-ci-pipeline", "svc-ci-pipeline"),
                wildcard_rule_no_auth("rule-monitoring", "svc-monitoring"),
            ],
        },
    )
    .await?;

    let k8s_token = read_pod_k8s_token().await?;

    // --- Test 1: No rule_name -> first-match-wins -> ci-pipeline. ---
    let (tok1, _) = k8s_auth(
        &test_client,
        &instance.id,
        K8sAuthRequest {
            jwt: k8s_token.clone().into(),
            rule_name: None,
        },
    )
    .await?;
    assert_eq!(
        tok1.user.name,
        Some("svc-ci-pipeline".to_string()),
        "no rule_name: first-match-wins should select ci-pipeline"
    );

    // --- Test 2: rule_name="rule-monitoring" -> targets the monitoring rule. ---
    let (tok2, _) = k8s_auth(
        &test_client,
        &instance.id,
        K8sAuthRequest {
            jwt: k8s_token.clone().into(),
            rule_name: Some("rule-monitoring".to_string()),
        },
    )
    .await?;
    assert_eq!(
        tok2.user.name,
        Some("svc-monitoring".to_string()),
        "rule_name=monitoring should select the monitoring rule"
    );

    // --- Test 3: nonexistent rule_name -> must fail, not fall back. ---
    let err = k8s_auth(
        &test_client,
        &instance.id,
        K8sAuthRequest {
            jwt: k8s_token.into(),
            rule_name: Some("does-not-exist".to_string()),
        },
    )
    .await
    .expect_err("nonexistent rule_name must error, not fall back to first-match-wins");
    let err_str = err.to_string();
    assert!(
        err_str.to_lowercase().contains("403") || err_str.to_lowercase().contains("forbidden"),
        "expected 403 Forbidden for nonexistent rule_name, got: {err_str}"
    );

    _ruleset.delete().await?;
    instance.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_k8s_auth_cannot_rescope_to_other_project() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let project_a = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .name(format!("proj-a-{}", Uuid::new_v4().simple()))
            .build()?,
    )
    .await?;

    let project_b = create_project(
        &test_client,
        ProjectCreateBuilder::default()
            .domain_id("default")
            .name(format!("proj-b-{}", Uuid::new_v4().simple()))
            .build()?,
    )
    .await?;

    let instance = setup_k8s_instance(&test_client).await?;

    // Create a role for the project authorization
    let role = AsyncResourceGuard::new(
        create_role(
            &test_client,
            openstack_keystone_api_types::v3::role::RoleCreateBuilder::default()
                .name(format!("role-{}", Uuid::new_v4().simple()))
                .build()?,
        )
        .await?,
        test_client.clone(),
    );

    // Create ruleset with a project authorization scoped to `project_a`.
    let _ruleset = create_ruleset(
        &test_client,
        openstack_keystone_api_types::v4::mapping::ruleset::MappingRuleSetCreate {
            mapping_id: Some(format!("rescope-test-{}", Uuid::new_v4().simple())),
            domain_id: Some("default".to_string()),
            source: openstack_keystone_api_types::v4::mapping::ruleset::IdentitySource::K8s {
                cluster_id: instance.id.clone(),
            },
            domain_resolution_mode:
                openstack_keystone_api_types::v4::mapping::ruleset::DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![wildcard_rule_project(
                "scoped-sa",
                "svc-k8s",
                project_a.id.clone(),
                role.name.clone(),
                role.id.clone(),
            )],
        },
    )
    .await?;

    let k8s_token = read_pod_k8s_token().await?;

    let (token_data, token_secret) = k8s_auth(
        &test_client,
        &instance.id,
        K8sAuthRequest {
            jwt: k8s_token.into(),
            rule_name: None,
        },
    )
    .await?;

    // Verify token scope is project_a
    assert_eq!(
        token_data.user.name.as_deref(),
        Some("svc-k8s"),
        "token user name should match the wildcard rule"
    );
    assert_eq!(
        token_data
            .project
            .as_ref()
            .expect("token must be scoped to a project")
            .id,
        project_a.id,
        "token must be scoped to project_a"
    );

    // Try to rescope the token to project_b. This should fail.
    let keystone_url =
        env::var("KEYSTONE_URL").unwrap_or_else(|_| "http://localhost:5000".to_string());

    let rescope_rsp = reqwest::Client::new()
        .post(format!("{}/v3/auth/tokens", keystone_url))
        .header("X-Auth-Token", token_secret.expose_secret())
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "auth": {
                "identity": {
                    "methods": ["token"],
                    "token": { "id": token_secret.expose_secret() }
                },
                "scope": { "project": { "id": project_b.id } }
            }
        }))
        .send()
        .await?;

    assert!(
        !rescope_rsp.status().is_success(),
        "rescope to project_b must be rejected (status: {})",
        rescope_rsp.status()
    );

    // Now disable the instance and try again. The disabled instance should
    // return 401 Unauthorized or 403 Forbidden.
    let instance_id = instance.id.clone();
    let _ = update_auth_instance(
        &test_client,
        &instance_id,
        openstack_keystone_api_types::k8s_auth::instance::K8sAuthInstanceUpdate {
            ca_cert: None,
            disable_local_ca_jwt: None,
            enabled: Some(false),
            host: None,
            name: None,
        },
    )
    .await?;

    let k8s_token = read_pod_k8s_token().await?;
    let res = K8sAuthenticationRequestBuilder::default()
        .instance_id(&instance_id)
        .auth(K8sAuthRequest {
            jwt: k8s_token.into(),
            rule_name: None,
        })
        .build()?
        .raw_query_async(test_client.as_ref())
        .await;

    // The SDK converts non-2xx to an error; in either case the disabled
    // instance must be rejected.
    match res {
        Ok(rsp) => {
            assert!(
                rsp.status() == http::StatusCode::UNAUTHORIZED
                    || rsp.status() == http::StatusCode::FORBIDDEN,
                "authentication against disabled instance must be rejected (got: {})",
                rsp.status()
            );
        }
        Err(e) => {
            let err_str = e.to_string();
            assert!(
                err_str.contains("403") || err_str.contains("401"),
                "disabled instance should return 401/403, got error: {}",
                err_str
            );
        }
    }

    _ruleset.delete().await?;
    instance.delete().await?;
    project_a.delete().await?;
    project_b.delete().await?;
    role.delete().await?;
    Ok(())
}
