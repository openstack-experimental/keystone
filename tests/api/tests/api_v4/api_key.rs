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
//! API Key (SCIM ingress machine identity, ADR 0021) CRUD authorization
//! matrix (issue #993).
//!
//! | endpoint                              | 2xx                            | 403                        | 401                          |
//! |---------------------------------------|--------------------------------|----------------------------|------------------------------|
//! | POST   /v4/api-keys                   | `create_success_admin`         | `create_forbidden`         | `create_unauthorized`        |
//! | GET    /v4/api-keys/{id}              | `show_success_admin`           | `show_forbidden`           | `show_unauthorized`          |
//! | GET    /v4/api-keys                   | `list_success_admin`           | `list_forbidden`           | `list_unauthorized`          |
//! | PUT    /v4/api-keys/{id}              | `update_success_admin`         | `update_forbidden`         | `update_unauthorized`        |
//! | POST   /v4/api-keys/{id}/revoke       | `revoke_success_admin`         | `revoke_forbidden`         | `revoke_unauthorized`        |
//! | POST   /v4/api-keys/simulate-access   | `simulate_access_success_admin`| `simulate_access_forbidden`| `simulate_access_unauthorized` |
//!
//! Secret handling is covered by `create_returns_token_once` and
//! `show_and_list_withhold_secrets`.
//!
//! `policy/api_key/*.rego` allows `admin`, or `manager` on the key's **own**
//! domain — where "own" means `input.credentials.domain_id`, populated only
//! for a genuinely domain-scoped token. Since no
//! `PUT /v3/domains/{id}/users/{id}/roles/{id}` handler exists, no real user
//! can hold `manager` on a domain scope, so every 2xx here is `admin` and the
//! 403 fixture is a project-scoped `manager` — it holds the role and is still
//! denied, proving the domain-scope gate rather than role absence. Same
//! constraint as `tests/api_v3/identity/group.rs` documents.
//!
//! Secret-absence assertions read the **raw JSON**: `ApiKey`
//! (`crates/api-types/src/v4/api_key.rs`) derives a plain `Deserialize` with
//! no `deny_unknown_fields`, so a `token`/`secret_hash`/`lookup_hash` that
//! leaked into the response would be silently dropped by a typed decode and
//! the assertion would pass vacuously.

use std::sync::Arc;

use chrono::{Duration, Utc};
use eyre::Result;
use secrecy::ExposeSecret;
use uuid::Uuid;

use openstack_keystone_api_types::v4::api_key::{ApiKeyCreate, ApiKeyUpdate};
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::api_key::*;
use test_api::asserts::{assert_forbidden, assert_unauthorized};
use test_api::common::raw_request;
use test_api::fixtures::ProjectScopedUser;
use test_api::guard::ResourceGuard;

const DOMAIN: &str = "default";

/// Fields that must never appear in an admin-surface API Key representation
/// (ADR 0021 §2.B). `token` is returned exactly once, by create.
const SECRET_FIELDS: [&str; 3] = ["token", "secret_hash", "lookup_hash"];

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?,
    ))
}

/// A unique provider id. Key creation does not resolve it against a mapping
/// ruleset, so no IDP/realm plumbing is needed for the CRUD surface.
fn provider_id() -> String {
    format!("api-key-test-{}", Uuid::new_v4().simple())
}

fn key_create(provider: &str) -> ApiKeyCreate {
    ApiKeyCreate {
        allowed_ips: None,
        description: Some("api key authorization matrix".to_string()),
        domain_id: DOMAIN.to_string(),
        expires_at: Utc::now() + Duration::hours(1),
        provider_id: provider.to_string(),
    }
}

/// A project-scoped `manager`: holds the role, never a domain scope.
async fn manager(admin: &Arc<AsyncOpenStack>) -> Result<ProjectScopedUser> {
    ProjectScopedUser::provision(admin, DOMAIN, "manager").await
}

/// Assert no secret-bearing field occurs anywhere in `body`.
fn assert_no_secrets(body: &serde_json::Value, what: &str) {
    let rendered = body.to_string();
    for field in SECRET_FIELDS {
        assert!(
            !rendered.contains(field),
            "{what} must not expose `{field}`; raw body was: {rendered}"
        );
    }
}

// --- create -------------------------------------------------------------

#[tokio::test]
async fn test_api_key_create_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let provider = provider_id();

    let key = create_api_key(&admin, key_create(&provider)).await?;
    assert_eq!(key.api_key.domain_id, DOMAIN);
    assert_eq!(key.api_key.provider_id, provider);
    assert!(key.api_key.enabled, "a fresh key must be enabled");
    assert!(!key.api_key.client_id.is_empty());

    key.delete().await?;
    Ok(())
}

/// The bearer token is returned by create and never again (ADR 0021 §2.B).
#[tokio::test]
async fn test_api_key_create_returns_token_once() -> Result<()> {
    let admin = admin_session().await?;
    let key = create_api_key(&admin, key_create(&provider_id())).await?;

    assert!(
        key.token.expose_secret().starts_with("kscim_"),
        "create must return the one-time bearer token"
    );

    key.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_api_key_create_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = manager(&admin).await?;

    assert_forbidden(
        create_api_key(&actor.session, key_create(&provider_id())).await,
        "a project-scoped manager holds no domain scope and must not create API keys",
    );

    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_api_key_create_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::POST,
        "v4/api-keys",
        Some("invalid-token"),
        Some(serde_json::json!({"api_key": {
            "domain_id": DOMAIN,
            "provider_id": "nope",
            "expires_at": "2030-01-01T00:00:00Z",
        }})),
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- show ---------------------------------------------------------------

#[tokio::test]
async fn test_api_key_show_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let provider = provider_id();
    let key = create_api_key(&admin, key_create(&provider)).await?;

    let shown = get_api_key(&admin, DOMAIN, &key.api_key.client_id).await?;
    assert_eq!(shown.client_id, key.api_key.client_id);
    assert_eq!(shown.provider_id, provider);
    assert_eq!(shown.domain_id, DOMAIN);

    key.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_api_key_show_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = manager(&admin).await?;
    let key = create_api_key(&admin, key_create(&provider_id())).await?;

    assert_forbidden(
        get_api_key(&actor.session, DOMAIN, &key.api_key.client_id).await,
        "a project-scoped manager must not read API keys",
    );

    key.delete().await?;
    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_api_key_show_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        &format!("v4/api-keys/some-key?domain_id={DOMAIN}"),
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- list ---------------------------------------------------------------

#[tokio::test]
async fn test_api_key_list_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let provider = provider_id();
    let key = create_api_key(&admin, key_create(&provider)).await?;

    let by_provider = list_api_keys(&admin, DOMAIN, Some(&provider)).await?;
    assert_eq!(
        by_provider.len(),
        1,
        "the provider filter must match exactly the created key"
    );
    assert_eq!(by_provider[0].client_id, key.api_key.client_id);

    let all = list_api_keys(&admin, DOMAIN, None).await?;
    assert!(
        all.iter()
            .any(|entry| entry.client_id == key.api_key.client_id),
        "the unfiltered domain listing must contain the created key"
    );

    key.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_api_key_list_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = manager(&admin).await?;

    assert_forbidden(
        list_api_keys(&actor.session, DOMAIN, None).await,
        "a project-scoped manager must not list API keys",
    );

    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_api_key_list_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::GET,
        &format!("v4/api-keys?domain_id={DOMAIN}"),
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

/// Neither show nor list may echo the bearer token or either stored hash.
/// Asserted against raw JSON — see the module header.
#[tokio::test]
async fn test_api_key_show_and_list_withhold_secrets() -> Result<()> {
    let admin = admin_session().await?;
    let provider = provider_id();
    let key = create_api_key(&admin, key_create(&provider)).await?;

    let shown = get_api_key_raw(&admin, DOMAIN, &key.api_key.client_id).await?;
    assert_no_secrets(&shown, "the show response");

    let listed = list_api_keys_raw(&admin, DOMAIN, Some(&provider)).await?;
    assert_no_secrets(&listed, "the list response");

    key.delete().await?;
    Ok(())
}

// --- update -------------------------------------------------------------

#[tokio::test]
async fn test_api_key_update_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let key = create_api_key(&admin, key_create(&provider_id())).await?;

    let updated = update_api_key(
        &admin,
        DOMAIN,
        &key.api_key.client_id,
        ApiKeyUpdate {
            allowed_ips: Some(Some(vec!["10.0.0.0/8".to_string()])),
            description: Some(Some("updated by test_api".to_string())),
            enabled: None,
        },
    )
    .await?;
    assert_eq!(updated.description.as_deref(), Some("updated by test_api"));
    assert_eq!(
        updated.allowed_ips.as_deref(),
        Some(["10.0.0.0/8".to_string()].as_slice())
    );

    // Durable, not just echoed back.
    let shown = get_api_key(&admin, DOMAIN, &key.api_key.client_id).await?;
    assert_eq!(shown.description.as_deref(), Some("updated by test_api"));

    key.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_api_key_update_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = manager(&admin).await?;
    let key = create_api_key(&admin, key_create(&provider_id())).await?;

    assert_forbidden(
        update_api_key(
            &actor.session,
            DOMAIN,
            &key.api_key.client_id,
            ApiKeyUpdate {
                allowed_ips: None,
                description: Some(Some("nope".to_string())),
                enabled: None,
            },
        )
        .await,
        "a project-scoped manager must not update API keys",
    );

    key.delete().await?;
    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_api_key_update_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::PUT,
        &format!("v4/api-keys/some-key?domain_id={DOMAIN}"),
        Some("invalid-token"),
        Some(serde_json::json!({"api_key": {"description": "nope"}})),
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- revoke -------------------------------------------------------------

#[tokio::test]
async fn test_api_key_revoke_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    // `into_inner`: revoke *is* the subject here, so the guard must not
    // also revoke.
    let key = create_api_key(&admin, key_create(&provider_id()))
        .await?
        .into_inner();

    let revoked = revoke_api_key(&admin, DOMAIN, &key.api_key.client_id).await?;
    assert!(!revoked.enabled, "a revoked key must be disabled");
    assert!(
        revoked.revoked_at.is_some(),
        "a revoked key must record `revoked_at`"
    );

    // Revocation is a soft state change: the key remains readable.
    let shown = get_api_key(&admin, DOMAIN, &key.api_key.client_id).await?;
    assert!(!shown.enabled);
    Ok(())
}

#[tokio::test]
async fn test_api_key_revoke_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = manager(&admin).await?;
    let key = create_api_key(&admin, key_create(&provider_id())).await?;

    assert_forbidden(
        revoke_api_key(&actor.session, DOMAIN, &key.api_key.client_id).await,
        "a project-scoped manager must not revoke API keys",
    );

    // Still enabled — the denial was enforced before any mutation.
    assert!(
        get_api_key(&admin, DOMAIN, &key.api_key.client_id)
            .await?
            .enabled
    );

    key.delete().await?;
    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_api_key_revoke_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::POST,
        &format!("v4/api-keys/some-key/revoke?domain_id={DOMAIN}"),
        Some("invalid-token"),
        None,
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

// --- simulate-access ----------------------------------------------------

#[tokio::test]
async fn test_api_key_simulate_access_success_admin() -> Result<()> {
    let admin = admin_session().await?;
    let provider = provider_id();
    let key = create_api_key(&admin, key_create(&provider)).await?;

    let simulated = simulate_api_key_access(&admin, DOMAIN, &key.api_key.client_id).await?;
    assert_eq!(simulated.client_id, key.api_key.client_id);
    assert_eq!(simulated.domain_id, DOMAIN);
    assert_eq!(simulated.provider_id, provider);
    // No mapping ruleset is bound to this throwaway provider, so the
    // simulation resolves to no authorization and says why.
    assert!(!simulated.matched);
    assert!(simulated.roles.is_empty());
    assert!(
        simulated.reason.is_some(),
        "an unmatched simulation must explain itself"
    );

    key.delete().await?;
    Ok(())
}

#[tokio::test]
async fn test_api_key_simulate_access_forbidden() -> Result<()> {
    let admin = admin_session().await?;
    let actor = manager(&admin).await?;
    let key = create_api_key(&admin, key_create(&provider_id())).await?;

    assert_forbidden(
        simulate_api_key_access(&actor.session, DOMAIN, &key.api_key.client_id).await,
        "a project-scoped manager must not simulate API key access",
    );

    key.delete().await?;
    actor.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_api_key_simulate_access_unauthorized() -> Result<()> {
    let rsp = raw_request(
        http::Method::POST,
        "v4/api-keys/simulate-access",
        Some("invalid-token"),
        Some(serde_json::json!({"client_id": "nope", "domain_id": DOMAIN})),
    )
    .await?;
    assert_unauthorized(rsp.error_for_status(), "an invalid token must be rejected");
    Ok(())
}

/// `simulate_access` reports the resolved topology, never the credential.
#[tokio::test]
async fn test_api_key_simulate_access_withholds_secrets() -> Result<()> {
    let admin = admin_session().await?;
    let key = create_api_key(&admin, key_create(&provider_id())).await?;

    let simulated = simulate_api_key_access(&admin, DOMAIN, &key.api_key.client_id).await?;
    let body = serde_json::to_value(&simulated)?;
    assert_no_secrets(&body, "the simulate-access response");

    key.delete().await?;
    Ok(())
}
