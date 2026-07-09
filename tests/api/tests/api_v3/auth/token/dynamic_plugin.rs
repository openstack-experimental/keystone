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
//! Real-server (no mocks) integration tests for ADR 0025 dynamic auth
//! plugins - drives the actual `keystone` binary started by
//! `tools/start-api.sh`, which loads three real compiled instances of the
//! reference plugin fixture: `mapper` (`mode = mapping`), `router`
//! (`mode = route`, `inspect_methods = application_credential`,
//! `route_targets = tf_appcred_handler`), and `tf_appcred_handler`
//! (`mode = full_auth`, `provision_domain_id = default`).
//!
//! `test_off_allowlist_target_is_rejected` is deliberately NOT included
//! here: `router`'s `route_targets` is fixed at server-startup config and
//! there's no per-test lever to change it against the shared real server
//! (unlike the in-process tests). That case is already covered at the
//! in-process layer:
//! `common.rs::route_dispatch_tests::test_off_allowlist_target_is_rejected`.

use std::collections::HashMap;
use std::sync::Arc;

use eyre::Result;
use uuid::Uuid;

use openstack_keystone_api_types::v3::auth::token::IdentityBuilder;
use openstack_keystone_api_types::v4::mapping::ruleset::{
    ClaimCondition, DomainResolutionMode, IdentityBinding, IdentitySource, MappingRuleSetCreate,
    MatchCondition, MatchCriteria,
};
use openstack_sdk::AsyncOpenStack;
use openstack_sdk::config::CloudConfig;

use test_api::common::*;
use test_api::mapping::ruleset::create_ruleset;

/// Sends `identity.methods = ["application_credential"]` with the given
/// `application_credential_id`, so `router` (loaded by `start-api.sh`)
/// inspects it.
async fn appcred_auth(client: &mut TestClient, cred_id: &str) -> Result<()> {
    let identity = IdentityBuilder::default()
        .methods(vec!["application_credential".to_string()])
        .extra(HashMap::from([(
            "application_credential".to_string(),
            serde_json::json!({"application_credential_id": cred_id}),
        )]))
        .build()?;
    client.auth(identity, None).await?;
    Ok(())
}

/// (b) A `route`-mode plugin redirects to an allowlisted real `full_auth`
/// target, which independently provisions a real user in the real DB and
/// issues its own token - proves the full chain over real HTTP with no
/// mocks anywhere.
#[tokio::test]
async fn test_route_to_full_auth_target_issues_token() -> Result<()> {
    let mut client = TestClient::default()?;
    let cred_id = format!("tf-{}", Uuid::new_v4().simple());
    appcred_auth(&mut client, &cred_id).await?;
    assert!(client.token.is_some(), "a token should have been issued");
    Ok(())
}

/// (e) A router `Deny` fails the whole request closed over real HTTP.
#[tokio::test]
async fn test_route_deny_is_rejected() -> Result<()> {
    let mut client = TestClient::default()?;
    let err = appcred_auth(&mut client, "deny-me")
        .await
        .expect_err("a plugin Deny response must be rejected");
    let err_str = err.to_string();
    assert!(
        err_str.contains("401") || err_str.to_lowercase().contains("unauthorized"),
        "expected an authentication failure, got: {err_str}"
    );
    Ok(())
}

/// (real Mapping Engine, no mocks) A `mapping`-mode plugin's claims
/// correctly drive a persisted mapping ruleset (`source = WasmPlugin{
/// plugin_name: "mapper" }`, provisioned over the real admin HTTP API
/// exactly like `tests/api/tests/k8s_auth.rs` does for K8s sources) and the
/// resulting token carries the identity bound by the matched rule -
/// and, before that ruleset exists, the same claims are rejected
/// (`MappingProviderError::NoMatchingRule`), not given a fallback
/// identity.
///
/// Both scenarios live in one test function rather than two: only one
/// mapping ruleset can exist per `(domain_id, source)` key
/// (`crates/core/src/mapping/service.rs`'s `get_ruleset_by_source`), and
/// `mapper`/`default` is the only such key this server's fixed config can
/// produce - two independent tests each provisioning their own ruleset for
/// that key would race under nextest's parallel test execution.
#[tokio::test]
async fn test_mapping_plugin_ruleset_lifecycle() -> Result<()> {
    let admin = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let identity = |external_id: String| -> Result<_> {
        Ok(IdentityBuilder::default()
            .methods(vec!["mapper".to_string()])
            .extra(HashMap::from([(
                "mapper".to_string(),
                serde_json::json!({"external_id": external_id, "deny": false}),
            )]))
            .build()?)
    };

    // --- Before any ruleset exists: reject, don't fall back. ---
    let mut client = TestClient::default()?;
    let err = client
        .auth(
            identity(format!("no-rule-{}", Uuid::new_v4().simple()))?,
            None,
        )
        .await
        .expect_err("no matching ruleset must be rejected, not fall back to a default identity");
    let err_str = err.to_string();
    assert!(
        err_str.contains("401") || err_str.to_lowercase().contains("unauthorized"),
        "expected an authentication failure, got: {err_str}"
    );

    // --- Provision a ruleset, then the same shape of request succeeds. ---
    let user_name = format!("mapped-user-{}", Uuid::new_v4().simple());
    let ruleset = create_ruleset(
        &admin,
        MappingRuleSetCreate {
            mapping_id: Some(format!("test-mapper-{}", Uuid::new_v4().simple())),
            domain_id: Some("default".to_string()),
            source: IdentitySource::WasmPlugin {
                plugin_name: "mapper".to_string(),
            },
            domain_resolution_mode: DomainResolutionMode::Fixed,
            enabled: true,
            rules: vec![
                openstack_keystone_api_types::v4::mapping::ruleset::MappingRule {
                    name: "any-mapper-claim".to_string(),
                    description: None,
                    r#match: MatchCriteria::AllOf(vec![MatchCondition::Condition(
                        ClaimCondition::MatchesRegex {
                            claim: "external_id".to_string(),
                            regex: ".*".to_string(),
                        },
                    )]),
                    identity: IdentityBinding {
                        identity_mode: None,
                        user_name: user_name.clone(),
                        user_id: None,
                        user_domain_id: None,
                        is_system: false,
                    },
                    authorizations: vec![],
                    groups: vec![],
                },
            ],
        },
    )
    .await?;

    let mut client = TestClient::default()?;
    client
        .auth(
            identity(format!("alice-{}", Uuid::new_v4().simple()))?,
            None,
        )
        .await?;
    assert_eq!(
        client.auth.as_ref().and_then(|t| t.token.user.name.clone()),
        Some(user_name),
        "token user name should match the mapped rule"
    );

    ruleset.delete().await?;
    Ok(())
}
