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
//! `route_targets = hacked_appcred_handler`), and `hacked_appcred_handler`
//! (`mode = full_auth`, `provision_domain_id = default`).
//!
//! `test_off_allowlist_target_is_rejected` is deliberately NOT included
//! here: `router`'s `route_targets` is fixed at server-startup config and
//! there's no per-test lever to change it against the shared real server
//! (unlike the in-process tests). That case is already covered at the
//! in-process layer:
//! `common.rs::route_dispatch_tests::test_off_allowlist_target_is_rejected`.
//!
//! Plugin instances loaded by `start-api.sh`:
//! - `mapper` (mode = mapping)
//! - `router` (mode = route, inspect_methods = application_credential,
//!   route_targets = hacked_appcred_handler)
//! - `hacked_appcred_handler` (mode = full_auth, provision_domain_id = d)

use std::collections::HashMap;
use std::sync::Arc;

use eyre::Result;
use uuid::Uuid;

use openstack_keystone_api_types::v3::auth::token::IdentityBuilder;
use openstack_keystone_api_types::v3::domain::DomainCreateBuilder;
use openstack_keystone_api_types::v4::mapping::ruleset::{
    ClaimCondition, DomainResolutionMode, IdentityBinding, IdentitySource, MappingRuleSetCreate,
    MatchCondition, MatchCriteria,
};
use openstack_sdk::config::CloudConfig;
use openstack_sdk::{AsyncOpenStack, api::RawQueryAsync};

use test_api::auth::auth_plugin::*;
use test_api::auth::token::auth_token;
use test_api::guard::ResourceGuard;
use test_api::mapping::ruleset::create_ruleset;
use test_api::resource::domain::create_domain;
use test_api::resource::get_system_scope_config;

/// `hacked_appcred_handler` (loaded by `start-api.sh`, `mode = full_auth`)
/// is configured `provision_domain_id = d`, and its `authenticate` export
/// (`reference-plugin/src/lib.rs`) defaults `AuthPayload::domain_id` to `"d"`
/// whenever a caller doesn't set it explicitly - which `router`'s `route`
/// export never does when relabelling an `application_credential` request
/// (it only forwards `external_id`). So the real DB needs a real domain
/// literally named `"d"` for `provision_user`'s downstream "fetch the user's
/// domain" step to resolve, or token issuance 401s with
/// `DomainNotFound("d")` even though provisioning itself succeeded.
/// Idempotent: ignores an already-exists error so this is safe to call from
/// more than one test in the same server lifetime.
async fn ensure_domain_d_exists(admin: &Arc<AsyncOpenStack>) {
    // Intentionally leaked (not `.delete()`d): this domain is meant to
    // outlive this single test, so other tests/reruns sharing the server's
    // DB lifetime see it already there instead of racing to recreate it.
    if let Ok(guard) = create_domain(
        admin,
        DomainCreateBuilder::default()
            .id("d".to_string())
            .name("d".to_string())
            .enabled(true)
            .build()
            .expect("domain create request should build"),
    )
    .await
    {
        std::mem::forget(guard);
    }
}

/// (b) A `route`-mode plugin redirects to an allowlisted real `full_auth`
/// target, which independently provisions a real user in the real DB and
/// issues its own token - proves the full chain over real HTTP with no
/// mocks anywhere.
#[tokio::test]
async fn test_route_to_full_auth_target_issues_token() -> Result<()> {
    // System scope, not project scope: creating a domain requires system
    // admin privileges (`identity/resource/domain/create` policy).
    let admin = Arc::new(AsyncOpenStack::new(&get_system_scope_config()?).await?);
    ensure_domain_d_exists(&admin).await;

    let test_client = AsyncOpenStack::new(&CloudConfig::from_env()?).await?;
    let cred_id = format!("tf-{}", Uuid::new_v4().simple());
    let identity = IdentityBuilder::default()
        .methods(vec!["application_credential".to_string()])
        .extra(HashMap::from([(
            "application_credential".to_string(),
            serde_json::json!({"application_credential_id": cred_id}),
        )]))
        .build()?;
    let (_token, _secret) = auth_token(&test_client, identity, None).await?;
    Ok(())
}

/// (e) A router `Deny` fails the whole request closed over real HTTP.
#[tokio::test]
async fn test_route_deny_is_rejected() -> Result<()> {
    let test_client = AsyncOpenStack::new(&CloudConfig::from_env()?).await?;
    let identity = IdentityBuilder::default()
        .methods(vec!["application_credential".to_string()])
        .extra(HashMap::from([(
            "application_credential".to_string(),
            serde_json::json!({"application_credential_id": "deny-me"}),
        )]))
        .build()?;
    let res = auth_token(&test_client, identity, None).await;

    match res {
        Ok(_) => panic!("a plugin Deny response must be rejected"),
        Err(e) => {
            let err_str = e.to_string();
            assert!(
                err_str.contains("401") || err_str.to_lowercase().contains("unauthorized"),
                "expected an authentication failure, got: {err_str}"
            );
        }
    }
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
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

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
    let ident = identity(format!("no-rule-{}", Uuid::new_v4().simple()))?;
    let res = auth_token(test_client.as_ref(), ident, None).await;
    match res {
        Ok(_) => {
            panic!("no matching ruleset must be rejected, not fall back to a default identity")
        }
        Err(e) => {
            let err_str = e.to_string();
            assert!(
                err_str.contains("401") || err_str.to_lowercase().contains("unauthorized"),
                "expected an authentication failure, got: {err_str}"
            );
        }
    }

    // --- Provision a ruleset, then the same shape of request succeeds. ---
    let user_name = format!("mapped-user-{}", Uuid::new_v4().simple());
    let ruleset = create_ruleset(
        &test_client,
        MappingRuleSetCreate {
            mapping_id: Some(format!("test-mapper-{}", Uuid::new_v4().simple())),
            // `authenticate_via_wasm_mapping_plugin` (crates/core/src/
            // auth_plugin_auth.rs) always looks up the ruleset with
            // `domain_id: None` ("global" composite-index key) - it doesn't
            // thread a domain through from the WASM mapping request. The
            // ruleset must be provisioned as global (`domain_id: None`) to
            // be found; a domain-scoped ruleset here would never match.
            domain_id: None,
            source: IdentitySource::WasmPlugin {
                plugin_name: "mapper".to_string(),
            },
            // Not `Fixed`: `resolve_domain` (crates/core/src/mapping/
            // engine.rs) makes `Fixed` mode ignore the rule's
            // `identity.user_domain_id` entirely and always fall back to
            // `ruleset.domain_id` - which is forced to `None` above, so
            // `Fixed` here would issue a token with no domain and 500
            // ("principal identity: domain not populated"). `ClaimsOnly`
            // rejects a non-templated `user_domain_id` outright ("requires
            // ... a claims interpolation reference"); `ClaimsOrMapping`
            // accepts the literal `"default"` and checks it against
            // `allowed_domains`.
            domain_resolution_mode: DomainResolutionMode::ClaimsOrMapping {
                allowed_domains: vec!["default".to_string()],
            },
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
                        // Ephemeral/virtual identities still need a real
                        // domain: `TokenBuilder::try_from`
                        // (crates/core/src/api/v3/auth/token.rs) requires
                        // `PrincipalIdentityInfo::domain` to be populated to
                        // issue a token at all - `None` here 500s with
                        // "principal identity: domain not populated".
                        user_domain_id: Some("default".to_string()),
                        is_system: false,
                    },
                    authorizations: vec![],
                    groups: vec![],
                },
            ],
        },
    )
    .await?;

    let ident = identity(format!("alice-{}", Uuid::new_v4().simple()))?;
    let (token_data, _secret) = auth_token(test_client.as_ref(), ident, None).await?;
    assert_eq!(
        token_data.user.name.clone(),
        Some(user_name),
        "token user name should match the mapped rule"
    );

    ruleset.delete().await?;
    Ok(())
}

/// The `revoke_all` OPA policy (`policy/auth_plugin/revoke_all.rego`)
/// requires system-scope `admin`. A project-scoped admin token - the common
/// bootstrap admin - must be forbidden. This is the layer where that Rego gate
/// is genuinely exercised (the in-process handler tests mock the enforcer).
///
/// Only the deny path is checked here: `revoke_all` is plugin-scoped and this
/// shared server has a single `hacked_appcred_handler`, so an actually-revoking
/// positive test would disable users other tests provision through it under
/// nextest's parallelism. The 200/idempotency behavior is covered by the
/// in-process handler unit tests instead.
#[tokio::test]
async fn test_revoke_all_requires_system_scope() -> Result<()> {
    let test_client = AsyncOpenStack::new(&CloudConfig::from_env()?).await?;
    let ep = AuthPluginRevokeAllRequest {
        plugin_name: "hacked_appcred_handler".into(),
    };
    let res = ep.raw_query_async_ll(&test_client, Some(false)).await?;

    assert_eq!(
        res.status().as_u16(),
        403,
        "project-scoped admin must be forbidden from system-scoped revoke_all"
    );
    Ok(())
}
