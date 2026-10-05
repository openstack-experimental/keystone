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

use std::sync::Arc;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_session::backend::Oauth2SessionBackend;
use openstack_keystone_core::oauth2_session::{
    IssueAuthorizationCodeRequest, IssueRefreshTokenRequest, Oauth2SessionHook,
    RefreshTokenRedemption, StartPreAuthSessionRequest,
};
use openstack_keystone_core_types::identity::UserPasswordAuthRequestBuilder;
use openstack_keystone_core_types::identity::{UserCreateBuilder, UserUpdate};
use openstack_keystone_core_types::oauth2_client::{GrantType, OAuth2ClientResourceCreateBuilder};
use openstack_keystone_core_types::resource::DomainUpdateBuilder;
use openstack_keystone_oauth2_session_driver_raft::RaftOauth2SessionBackend;

use crate::common::{get_state, get_state_with_config};
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
        .redeem_refresh_token(&state, &bearer_0, "client-1", &domain.id)
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
        .redeem_refresh_token(&state, &bearer_0, "client-1", &domain.id)
        .await?;
    match reuse {
        RefreshTokenRedemption::ReuseDetected {
            family_id: reused_family,
            ..
        } => assert_eq!(reused_family, family_id),
        other => panic!("expected ReuseDetected, got {other:?}"),
    }

    // The family is dead: the live leaf minted by the legitimate rotation
    // no longer redeems either.
    let after_collapse = session_provider
        .redeem_refresh_token(&state, &bearer_1, "client-1", &domain.id)
        .await?;
    assert!(matches!(after_collapse, RefreshTokenRedemption::Invalid));

    // Replaying the spent root again must hit the tombstone and stay
    // `Invalid` -- not re-trigger the breach cascade (`ReuseDetected`) and
    // a second critical audit event.
    let replay = session_provider
        .redeem_refresh_token(&state, &bearer_0, "client-1", &domain.id)
        .await?;
    assert!(matches!(replay, RefreshTokenRedemption::Invalid));

    // The family is tombstoned, not deleted. The provider API has no
    // family listing, so read the raft backend directly: both members
    // must survive with `revoked_at` and the reason stamped.
    let members = RaftOauth2SessionBackend::default()
        .list_refresh_token_family(&state, &family_id)
        .await?;
    assert_eq!(members.len(), 2);
    for member in &members {
        assert!(member.revoked_at.is_some());
        assert_eq!(member.revocation_reason.as_deref(), Some("reuse_detected"));
    }

    Ok(())
}

/// Issue #1262: presenting a refresh token from a foreign client or domain
/// must not spend it, mint a child or trip reuse detection for the owner.
#[tokio::test]
#[traced_test]
async fn test_foreign_presentation_does_not_spend_refresh_token() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();

    let session_provider = state.provider.get_oauth2_session_provider();
    let (root, bearer) = session_provider
        .issue_refresh_token(
            &state,
            IssueRefreshTokenRequest {
                domain_id: domain.id.clone(),
                client_id: "client-1".to_string(),
                user_id: uid,
                scope: vec!["openid".to_string()],
            },
        )
        .await?;

    // Foreign client, correct domain.
    let foreign_client = session_provider
        .redeem_refresh_token(&state, &bearer, "client-2", &domain.id)
        .await?;
    assert!(matches!(foreign_client, RefreshTokenRedemption::Invalid));

    // Correct client, foreign domain.
    let foreign_domain = session_provider
        .redeem_refresh_token(&state, &bearer, "client-1", "other-domain")
        .await?;
    assert!(matches!(foreign_domain, RefreshTokenRedemption::Invalid));

    // Storage is untouched: no child minted, nothing spent or revoked.
    let members = RaftOauth2SessionBackend::default()
        .list_refresh_token_family(&state, &root.family_id)
        .await?;
    assert_eq!(members.len(), 1);
    assert!(members[0].spent_at.is_none());
    assert!(members[0].revoked_at.is_none());

    // The legitimate owner still rotates normally (not `ReuseDetected`).
    let owner = session_provider
        .redeem_refresh_token(&state, &bearer, "client-1", &domain.id)
        .await?;
    assert!(
        matches!(owner, RefreshTokenRedemption::Rotated { .. }),
        "owner must rotate after foreign attempts, got {owner:?}"
    );

    Ok(())
}

/// Issue #1261: deleting an OAuth2 client must tombstone every refresh
/// token family issued to it, not only reject them at redemption.
#[tokio::test]
#[traced_test]
async fn test_client_delete_revokes_refresh_families() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();
    let ctx = ExecutionContext::internal(&state);

    let (client, _secret) = state
        .provider
        .get_oauth2_client_provider()
        .create(
            &ctx,
            OAuth2ClientResourceCreateBuilder::default()
                .client_id("")
                .provider_id(format!("provider-{}", domain.id))
                .domain_id(domain.id.clone())
                .token_endpoint_auth_method("client_secret_basic")
                .grant_types(vec![GrantType::AuthorizationCode, GrantType::RefreshToken])
                .build()?,
            true,
        )
        .await?;

    let session_provider = state.provider.get_oauth2_session_provider();
    let (root, bearer) = session_provider
        .issue_refresh_token(
            &state,
            IssueRefreshTokenRequest {
                domain_id: domain.id.clone(),
                client_id: client.client_id.clone(),
                user_id: uid,
                scope: vec!["openid".to_string()],
            },
        )
        .await?;

    let (deleted, revoked) = state
        .provider
        .get_oauth2_client_provider()
        .delete(&ctx, &domain.id, &client.provider_id)
        .await?;
    assert!(deleted.deleted_at.is_some());
    assert_eq!(revoked, 1);

    // The refresh token no longer redeems.
    let redemption = session_provider
        .redeem_refresh_token(&state, &bearer, &client.client_id, &domain.id)
        .await?;
    assert!(matches!(redemption, RefreshTokenRedemption::Invalid));

    // The family is tombstoned with the `client_revoked` reason.
    let members = RaftOauth2SessionBackend::default()
        .list_refresh_token_family(&state, &root.family_id)
        .await?;
    assert!(!members.is_empty());
    for member in &members {
        assert!(member.revoked_at.is_some());
        assert_eq!(member.revocation_reason.as_deref(), Some("client_revoked"));
    }

    Ok(())
}

/// Wait for the asynchronously dispatched lifecycle hook to tombstone
/// `family_id`, returning its members.
async fn wait_for_family_revoked(
    state: &openstack_keystone_core::keystone::ServiceState,
    family_id: &str,
) -> Result<Vec<openstack_keystone_core_types::oauth2_session::RefreshToken>> {
    for _ in 0..100 {
        let members = RaftOauth2SessionBackend::default()
            .list_refresh_token_family(state, family_id)
            .await?;
        if !members.is_empty() && members.iter().all(|m| m.revoked_at.is_some()) {
            return Ok(members);
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    eyre::bail!("refresh token family {family_id} was not revoked");
}

/// Issue #1259: disabling a user through the identity provider must
/// tombstone its refresh token families, so the next `refresh_token` grant
/// gets `invalid_grant`, and drop its authenticated pending flows.
#[tokio::test]
#[traced_test]
async fn test_user_disable_revokes_refresh_families() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    state
        .event_dispatcher
        .subscribe(Arc::new(Oauth2SessionHook::new(state.clone())))
        .await;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();
    let ctx = ExecutionContext::internal(&state);
    state
        .provider
        .get_identity_provider()
        .create_user(
            &ctx,
            UserCreateBuilder::default()
                .id(&uid)
                .name("oauth2-lifecycle-user")
                .domain_id(domain.id.clone())
                .enabled(true)
                .build()?,
        )
        .await?;

    let session_provider = state.provider.get_oauth2_session_provider();
    let (root, bearer) = session_provider
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
    let session = session_provider
        .start_pre_auth_session(&state, sample_pre_auth_request(&domain.id))
        .await?;
    session_provider
        .mark_authenticated(&state, &session.session_id, &uid, 1_000)
        .await?;

    state
        .provider
        .get_identity_provider()
        .update_user(
            &ctx,
            &uid,
            UserUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;

    let members = wait_for_family_revoked(&state, &root.family_id).await?;
    for member in &members {
        assert_eq!(member.revocation_reason.as_deref(), Some("user_disabled"));
    }
    let redemption = session_provider
        .redeem_refresh_token(&state, &bearer, "client-1", &domain.id)
        .await?;
    assert!(matches!(redemption, RefreshTokenRedemption::Invalid));
    // Purged after the family was revoked by the same hook run.
    assert!(
        session_provider
            .get_pre_auth_session(&state, &session.session_id)
            .await?
            .is_none()
    );

    Ok(())
}

/// Issue #1259: disabling a domain must tombstone every refresh token
/// family in it and drop its pending flows, leaving other domains alone.
#[tokio::test]
#[traced_test]
async fn test_domain_disable_revokes_refresh_families() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    state
        .event_dispatcher
        .subscribe(Arc::new(Oauth2SessionHook::new(state.clone())))
        .await;
    let domain = create_domain!(state)?;
    let other_domain = create_domain!(state)?;

    let session_provider = state.provider.get_oauth2_session_provider();
    let issue = |domain_id: String| IssueRefreshTokenRequest {
        domain_id,
        client_id: "client-1".to_string(),
        user_id: Uuid::new_v4().simple().to_string(),
        scope: vec!["openid".to_string()],
    };
    let (root, bearer) = session_provider
        .issue_refresh_token(&state, issue(domain.id.clone()))
        .await?;
    let (other_root, _) = session_provider
        .issue_refresh_token(&state, issue(other_domain.id.clone()))
        .await?;
    let session = session_provider
        .start_pre_auth_session(&state, sample_pre_auth_request(&domain.id))
        .await?;
    let other_session = session_provider
        .start_pre_auth_session(&state, sample_pre_auth_request(&other_domain.id))
        .await?;

    state
        .provider
        .get_resource_provider()
        .update_domain(
            &ExecutionContext::internal(&state),
            &domain.id,
            DomainUpdateBuilder::default().enabled(false).build()?,
        )
        .await?;

    let members = wait_for_family_revoked(&state, &root.family_id).await?;
    for member in &members {
        assert_eq!(member.revocation_reason.as_deref(), Some("domain_disabled"));
    }
    let redemption = session_provider
        .redeem_refresh_token(&state, &bearer, "client-1", &domain.id)
        .await?;
    assert!(matches!(redemption, RefreshTokenRedemption::Invalid));
    assert!(
        session_provider
            .get_pre_auth_session(&state, &session.session_id)
            .await?
            .is_none()
    );

    // The other domain is untouched.
    let other_members = RaftOauth2SessionBackend::default()
        .list_refresh_token_family(&state, &other_root.family_id)
        .await?;
    assert!(other_members.iter().all(|m| m.revoked_at.is_none()));
    assert!(
        session_provider
            .get_pre_auth_session(&state, &other_session.session_id)
            .await?
            .is_some()
    );

    Ok(())
}

fn sample_pre_auth_request(domain_id: &str) -> StartPreAuthSessionRequest {
    StartPreAuthSessionRequest {
        domain_id: domain_id.to_string(),
        client_id: "client-1".to_string(),
        redirect_uri: "https://rp.example.com/callback".to_string(),
        scope: vec!["openid".to_string()],
        state: "state-xyz".to_string(),
        code_challenge: "challenge-abc".to_string(),
        code_challenge_method: "S256".to_string(),
        nonce: None,
    }
}
