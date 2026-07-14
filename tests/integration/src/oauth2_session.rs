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
//! # OAuth2 browser session provider integration tests (ADR 0026 §10 Phase
//! 4, §9)
//!
//! Raft-only backend -- these tests only run under the `raft` nextest
//! profile (see `.config/nextest.toml`), matching the `mapping`/`api_key`
//! test suites. Exercises the `authorization_code` flow's storage layer
//! (pre-auth session -> single-use code -> refresh token family) against
//! real Raft-backed storage and a real local password-authenticated user,
//! ending with the ADR's own explicit Phase 4 verification bullet:
//! replaying an already-rotated refresh token must collapse the entire
//! family.

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_session::{
    IssueAuthorizationCodeRequest, IssueRefreshTokenRequest, RefreshTokenRedemption,
    StartPreAuthSessionRequest,
};
use openstack_keystone_core_types::identity::UserCreateBuilder;
use openstack_keystone_core_types::identity::UserPasswordAuthRequestBuilder;

use crate::common::get_state_with_config;
use crate::create_domain;

#[tokio::test]
#[traced_test]
async fn test_authorization_code_flow_and_refresh_reuse_collapses_family() -> Result<()> {
    // Zero the reuse grace window so the second `redeem_refresh_token` call
    // below deterministically hits the "outside grace" breach branch
    // regardless of how fast the test itself runs (the default 10-minute
    // grace would otherwise make this assertion racy/environment-dependent).
    // `Oauth2SessionService` captures `[oauth2]` at construction time, so
    // this must be set before the state is built, not mutated afterwards.
    let (state, _tmp) =
        get_state_with_config(|cfg| cfg.oauth2.refresh_token_reuse_grace_minutes = 0).await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();

    // Real local user, real password verification -- mirrors what the
    // `/authorize/login` handler does via `authenticate_by_password`.
    state
        .provider
        .get_identity_provider()
        .create_user(
            &ExecutionContext::internal(&state),
            UserCreateBuilder::default()
                .id(&uid)
                .name("oauth2-integration-user")
                .domain_id(domain.id.clone())
                .enabled(true)
                .password("s3cr3t-pass")
                .build()?,
        )
        .await?;

    let session_provider = state.provider.get_oauth2_session_provider();

    // GET /authorize equivalent: create the pre-auth session.
    let session = session_provider
        .start_pre_auth_session(
            &state,
            StartPreAuthSessionRequest {
                domain_id: domain.id.clone(),
                client_id: "client-1".to_string(),
                redirect_uri: "https://rp.example.com/callback".to_string(),
                scope: vec!["openid".to_string()],
                state: "state-xyz".to_string(),
                code_challenge: "challenge-abc".to_string(),
                code_challenge_method: "S256".to_string(),
                nonce: Some("nonce-1".to_string()),
            },
        )
        .await?;
    assert!(session.user_id.is_none());

    // POST /authorize/login equivalent: real password verification against
    // the real identity backend.
    let auth_result = state
        .provider
        .get_identity_provider()
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequestBuilder::default()
                .id(&uid)
                .password("s3cr3t-pass")
                .build()?,
        )
        .await;
    assert!(auth_result.is_ok(), "real password auth must succeed");

    let session = session_provider
        .mark_authenticated(&state, &session.session_id, &uid, 1_000)
        .await?;
    assert_eq!(session.user_id.as_deref(), Some(uid.as_str()));

    let session = session_provider
        .mark_consent(&state, &session.session_id, true)
        .await?;
    assert_eq!(session.consent_granted, Some(true));

    // POST /authorize/consent equivalent: mint the single-use code.
    let code = session_provider
        .issue_authorization_code(
            &state,
            IssueAuthorizationCodeRequest {
                domain_id: domain.id.clone(),
                client_id: session.client_id.clone(),
                user_id: uid.clone(),
                redirect_uri: session.redirect_uri.clone(),
                code_challenge: session.code_challenge.clone(),
                code_challenge_method: session.code_challenge_method.clone(),
                scope: session.scope.clone(),
                nonce: session.nonce.clone(),
                auth_time: 1_000,
                amr: vec!["pwd".to_string()],
            },
        )
        .await?;
    session_provider
        .complete_pre_auth_session(&state, &session.session_id)
        .await?;

    // POST /token (authorization_code) equivalent: single-use redemption.
    let redeemed = session_provider
        .redeem_authorization_code(&state, &code)
        .await?;
    assert!(redeemed.is_some(), "the freshly minted code must redeem");
    let redeemed_again = session_provider
        .redeem_authorization_code(&state, &code)
        .await?;
    assert!(
        redeemed_again.is_none(),
        "a second redemption of the same code must fail (single-use)"
    );

    // Mint the refresh token family root (as `handle_authorization_code_grant`
    // would when the client also holds `refresh_token` in `grant_types`).
    let (root, bearer_0) = session_provider
        .issue_refresh_token(
            &state,
            IssueRefreshTokenRequest {
                domain_id: domain.id.clone(),
                client_id: "client-1".to_string(),
                user_id: uid.clone(),
                scope: vec!["openid".to_string()],
            },
        )
        .await?;
    let family_id = root.family_id.clone();

    // Normal rotation: presenting the live leaf rotates it forward.
    let redemption = session_provider
        .redeem_refresh_token(&state, &bearer_0)
        .await?;
    let bearer_1 = match redemption {
        RefreshTokenRedemption::Rotated { bearer, record } => {
            assert_eq!(record.family_id, family_id);
            bearer
        }
        other => panic!("expected Rotated, got {other:?}"),
    };

    // ADR 0026 §9 verification bullet: replaying the already-rotated
    // `bearer_0` (outside the grace window, since we've moved wall-clock-
    // adjacent time by rotating once already and the default grace period
    // is minutes) must be treated as a breach, revoking the whole family --
    // including the just-issued `bearer_1` leaf.
    let reuse = session_provider
        .redeem_refresh_token(&state, &bearer_0)
        .await?;
    match reuse {
        RefreshTokenRedemption::ReuseDetected {
            family_id: reused_family,
        } => assert_eq!(reused_family, family_id),
        other => panic!("expected ReuseDetected, got {other:?}"),
    }

    // The family is dead: the live leaf minted by the legitimate rotation
    // no longer redeems either.
    let after_collapse = session_provider
        .redeem_refresh_token(&state, &bearer_1)
        .await?;
    assert!(matches!(after_collapse, RefreshTokenRedemption::Invalid));

    Ok(())
}
