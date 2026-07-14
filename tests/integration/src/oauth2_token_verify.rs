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
//! # Offline OP-issued access token verification (ADR 0026 §10 Phase 5)
//!
//! Raft-only backend -- these tests only run under the `raft` nextest
//! profile (see `.config/nextest.toml`), matching the `oauth2_session`/
//! `api_key` test suites. Proves the ADR's Phase 5 claim in Rust: mints a
//! real `client_credentials` access token through the same pipeline
//! `POST /v4/oauth2/{domain_id}/token` uses
//! (`hydrate_client_credentials_context` -> `build_access_token_claims` ->
//! sign with the domain's real Raft-backed signing key), fetches the
//! domain's real JWKS, and verifies the token via
//! `openstack_keystone_core::oauth2_client::verify_openstack_access_token`
//! -- the closest in-repo equivalent to the ADR §6 `KeystoneNativeJwtMiddleware`,
//! since that Python file itself ships in downstream service repos, not here.
//! Beyond the happy path, also proves a token minted for one domain is
//! rejected against another domain's JWKS/`aud` (ADR §5, "Domain Key
//! Isolation").
use std::collections::HashSet;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_client::{
    build_access_token_claims, hydrate_client_credentials_context, verify_openstack_access_token,
};
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::mapping::*;
use openstack_keystone_core_types::oauth2_client::{GrantType, OAuth2ClientResourceCreateBuilder};
use openstack_keystone_core_types::role::RoleRefBuilder;
use openstack_keystone_key_repository::asymmetric::{
    SigningAlgorithm as KeySigningAlgorithm, derive_kid, jwt_algorithm, to_encoding_key,
};

use crate::common::get_state;
use crate::{create_domain, create_role};

/// `[oauth2] signing_algorithm` (`openstack_keystone_config`) and the
/// key-repository's own `SigningAlgorithm` are deliberately distinct types
/// (config vs. crypto layering) with no `From` impl between them --
/// `Oauth2KeyService::new` (`crates/core/src/oauth2_key/service.rs`)
/// converts via the same manual match this mirrors.
fn to_key_signing_algorithm(
    algorithm: openstack_keystone_config::SigningAlgorithm,
) -> KeySigningAlgorithm {
    match algorithm {
        openstack_keystone_config::SigningAlgorithm::Es256 => KeySigningAlgorithm::Es256,
        openstack_keystone_config::SigningAlgorithm::Rs256 => KeySigningAlgorithm::Rs256,
    }
}

/// Register a confidential `OAuth2Client` for `client_credentials`, wire a
/// matching ADR 0020 mapping ruleset granting `Authorization::Domain` on
/// the client's own domain (mirrors
/// `tests/integration/src/api_key/ingress.rs`'s `provision_working_api_key`,
/// generalized to `IdentitySource::OAuth2Client`), and return the created
/// resource.
async fn provision_client_credentials_client(
    state: &openstack_keystone::keystone::ServiceState,
    domain_id: &str,
    provider_id: &str,
) -> Result<openstack_keystone_core_types::oauth2_client::OAuth2ClientResource> {
    let exec = ExecutionContext::internal(state);

    // ADR 0026 §3 "Domain creation" promises signing keys are provisioned
    // *synchronously* on domain creation and JWKS "never return[s] an
    // empty key set." In practice `Oauth2KeyHook` fires through the
    // generic fire-and-forget `EventDispatcher` (`crates/core/src/events.rs`),
    // so a caller that proceeds immediately after `create_domain` can race
    // it -- a real gap flagged for the post-Phase-6 review, not something
    // this test works around by skipping key provisioning. Calling the
    // idempotent `ensure_domain_keys` explicitly here just removes the
    // *test's* dependency on hook-firing timing, without masking the gap.
    state
        .provider
        .get_oauth2_key_provider()
        .ensure_domain_keys(state, domain_id)
        .await?;

    let (client, _secret) = state
        .provider
        .get_oauth2_client_provider()
        .create(
            &exec,
            OAuth2ClientResourceCreateBuilder::default()
                .client_id("")
                .provider_id(provider_id)
                .domain_id(domain_id)
                .token_endpoint_auth_method("client_secret_basic")
                .grant_types(vec![GrantType::ClientCredentials])
                .build()?,
            true,
        )
        .await?;

    let member_role = create_role!(state, "member")?;

    let ruleset = MappingRuleSetCreate {
        mapping_id: Some(Uuid::new_v4().simple().to_string()),
        domain_id: Some(domain_id.to_string()),
        source: IdentitySource::OAuth2Client {
            provider_id: provider_id.to_string(),
        },
        domain_resolution_mode: DomainResolutionMode::Fixed,
        enabled: true,
        rules: vec![MappingRule {
            name: "phase5-e2e-rule".into(),
            description: None,
            r#match: MatchCriteria::AllOf(vec![]),
            identity: IdentityBinding {
                identity_mode: None,
                user_name: "${claims.oauth2_client.client_id}".into(),
                user_id: None,
                user_domain_id: None,
                is_system: false,
            },
            authorizations: vec![Authorization::Domain {
                domain_id: domain_id.to_string(),
                roles: vec![
                    RoleRefBuilder::default()
                        .id(member_role.id.clone())
                        .name(member_role.name.clone())
                        .build()
                        .unwrap(),
                ],
            }],
            groups: Vec::new(),
        }],
    };
    state
        .provider
        .get_mapping_provider()
        .create_ruleset(&exec, ruleset)
        .await?;

    Ok(client)
}

/// Mint a real `client_credentials` access token for `client`, exactly as
/// `POST /v4/oauth2/{domain_id}/token` does: hydrate through the mapping
/// engine, build the claims, sign with the domain's real active key.
async fn mint_access_token(
    state: &openstack_keystone::keystone::ServiceState,
    client: &openstack_keystone_core_types::oauth2_client::OAuth2ClientResource,
) -> Result<String> {
    let (vsc, ruleset_version) = hydrate_client_credentials_context(state, client).await?;

    let issuer = format!("https://ks.example/v4/oauth2/{}", client.domain_id);
    let now = chrono::Utc::now().timestamp();
    let exp = now + 900;
    let jti = Uuid::new_v4().to_string();

    let claims = build_access_token_claims(client, &vsc, &issuer, jti, ruleset_version, now, exp)?;

    let signing_key = state
        .provider
        .get_oauth2_key_provider()
        .active_signing_key(state, &client.domain_id)
        .await?;
    let encoding_key = to_encoding_key(&signing_key)?;
    let mut header = jsonwebtoken::Header::new(jwt_algorithm(signing_key.algorithm));
    header.kid = Some(derive_kid(&signing_key.public_key_der));

    Ok(jsonwebtoken::encode(&header, &claims, &encoding_key)?)
}

#[tokio::test]
#[traced_test]
async fn test_client_credentials_token_verifies_fully_offline() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let client = provision_client_credentials_client(&state, &domain.id, "provider-1").await?;

    let token = mint_access_token(&state, &client).await?;

    // The only two calls verification is allowed to make: fetch the JWKS
    // and (in a full deployment) the JTI revocation list. No further
    // Keystone API or database call happens from here on -- everything
    // below is the pure `verify_openstack_access_token` function.
    let jwks = state
        .provider
        .get_oauth2_key_provider()
        .jwks(&state, &domain.id)
        .await?;
    let oauth2_cfg = state.config_manager.config.read().await.oauth2.clone();

    let issuer = format!("https://ks.example/v4/oauth2/{}", domain.id);
    let claims = verify_openstack_access_token(
        &token,
        &jwks,
        to_key_signing_algorithm(oauth2_cfg.signing_algorithm),
        &[issuer],
        &domain.id,
        &HashSet::new(),
    )?;

    assert_eq!(claims.token_use, "access");
    assert_eq!(claims.aud, format!("openstack-apis:{}", domain.id));
    assert_eq!(claims.openstack_context.roles, vec!["member".to_string()]);

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_token_rejected_against_a_different_domains_jwks() -> Result<()> {
    // ADR 0026 §5 "Domain Key Isolation and `aud` Binding": each domain
    // owns an independent signing keypair, so a token minted for one
    // domain must not verify against another domain's published JWKS/aud,
    // even though both are legitimately provisioned, live domains.
    let (state, _tmp) = get_state().await?;
    let domain_a = create_domain!(state)?;
    let domain_b = create_domain!(state)?;
    let client = provision_client_credentials_client(&state, &domain_a.id, "provider-1").await?;
    // domain_b never goes through `provision_client_credentials_client`, so
    // its keys need the same explicit provisioning (see the comment there).
    state
        .provider
        .get_oauth2_key_provider()
        .ensure_domain_keys(&state, &domain_b.id)
        .await?;

    let token = mint_access_token(&state, &client).await?;

    let jwks_b = state
        .provider
        .get_oauth2_key_provider()
        .jwks(&state, &domain_b.id)
        .await?;
    let oauth2_cfg = state.config_manager.config.read().await.oauth2.clone();
    let issuer_a = format!("https://ks.example/v4/oauth2/{}", domain_a.id);

    let result = verify_openstack_access_token(
        &token,
        &jwks_b,
        to_key_signing_algorithm(oauth2_cfg.signing_algorithm),
        &[issuer_a],
        &domain_b.id,
        &HashSet::new(),
    );
    assert!(
        result.is_err(),
        "a domain A token must not verify against domain B's JWKS/aud"
    );

    Ok(())
}
