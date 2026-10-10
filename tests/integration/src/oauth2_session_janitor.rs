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
//! # OAuth2 session janitor integration tests (ADR 0026 §9, §10 Phase 4)
//!
//! Raft-only backend -- these tests only run under the `raft` nextest
//! profile (the `oauth2_session` filter in `.config/nextest.toml` matches
//! this module name). Records are created through the backend directly so
//! `expires_at` can be set in the past, and read back through the backend
//! because the service lazily hides expired records and would mask a leak.

use chrono::Utc;
use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_core::oauth2_session::backend::Oauth2SessionBackend;
use openstack_keystone_core::oauth2_session::janitor;
use openstack_keystone_core_types::oauth2_session::*;
use openstack_keystone_oauth2_session_driver_raft::RaftOauth2SessionBackend;

use crate::common::get_state_with_config;

fn session_create(id: &str, expires_at: i64) -> PreAuthSessionCreate {
    PreAuthSessionCreate {
        session_id: id.to_string(),
        domain_id: "domain-1".to_string(),
        client_id: "client-1".to_string(),
        redirect_uri: "https://rp.example/cb".to_string(),
        scope: vec!["openid".to_string()],
        state: "state-1".to_string(),
        code_challenge: "challenge".to_string(),
        code_challenge_method: "S256".to_string(),
        nonce: None,
        server_side_session_secret: "secret".to_string(),
        created_at: expires_at - 600,
        expires_at,
    }
}

fn refresh_create(token_id: &str, family_id: &str, expires_at: i64) -> RefreshTokenCreate {
    RefreshTokenCreate {
        token_id: token_id.to_string(),
        family_id: family_id.to_string(),
        parent_token_id: None,
        domain_id: "domain-1".to_string(),
        client_id: "client-1".to_string(),
        user_id: "user-1".to_string(),
        scope: vec!["openid".to_string()],
        issued_at: expires_at - 1000,
        expires_at,
        family_expires_at: 0,
        amr: Vec::new(),
    }
}

#[tokio::test]
#[traced_test]
async fn test_janitor_purges_1000_abandoned_pre_auth_sessions() -> Result<()> {
    let (state, _tmp) = get_state_with_config(|_| {}).await?;
    let backend = RaftOauth2SessionBackend::default();
    let now = Utc::now().timestamp();

    let prefix = Uuid::new_v4().simple().to_string();
    let abandoned: Vec<String> = (0..1_000)
        .map(|i| format!("{prefix}-abandoned-{i}"))
        .collect();
    for id in &abandoned {
        backend
            .create_pre_auth_session(&state, session_create(id, now - 3600))
            .await?;
    }
    let live = format!("{prefix}-live");
    backend
        .create_pre_auth_session(&state, session_create(&live, now + 600))
        .await?;

    // The single raft node is the leader, so the leader gate lets the
    // sweep run.
    let report = janitor::sweep_if_leader(&state)
        .await
        .expect("single-node raft cluster must be its own leader")?;
    assert!(
        report.purged_by_kind.get("session").copied().unwrap_or(0) >= abandoned.len(),
        "{report:?}"
    );
    assert_eq!(report.errors, 0);

    for id in &abandoned {
        assert!(
            backend.get_pre_auth_session(&state, id).await?.is_none(),
            "abandoned session {id} must be purged"
        );
    }
    assert!(
        backend.get_pre_auth_session(&state, &live).await?.is_some(),
        "unexpired session must be left alone"
    );
    let remaining = backend
        .list_expired(&state, Some("session"), i64::MAX, 10_000)
        .await?;
    assert!(
        remaining
            .iter()
            .all(|(_, pk)| !pk.starts_with(&prefix) || pk == &live),
        "no abandoned expiry index entries may remain: {remaining:?}"
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_janitor_purges_revoked_refresh_family_only_after_retention() -> Result<()> {
    let (state, _tmp) = get_state_with_config(|_| {}).await?;
    let backend = RaftOauth2SessionBackend::default();
    let now = Utc::now().timestamp();
    let day = 86_400;

    let id = Uuid::new_v4().simple().to_string();
    // Expired 31 days ago: past the default 30-day retention.
    let old = format!("{id}-old");
    // Expired 10 days ago: still inside the retention window.
    let recent = format!("{id}-recent");
    for (token, expires_at) in [(&old, now - 31 * day), (&recent, now - 10 * day)] {
        backend
            .create_refresh_token(
                &state,
                refresh_create(token, &format!("family-{token}"), expires_at),
            )
            .await?;
        backend
            .revoke_refresh_token_family(
                &state,
                &format!("family-{token}"),
                RefreshTokenRevocationReason::Operator,
                now - 40 * day,
            )
            .await?;
    }

    let report = janitor::run_once(&state).await?;
    assert!(
        report
            .purged_by_kind
            .get("refresh_tombstone")
            .copied()
            .unwrap_or(0)
            >= 1
    );

    assert!(
        backend.get_refresh_token(&state, &old).await?.is_none(),
        "tombstone past retention must be purged"
    );
    assert!(
        backend.get_refresh_token(&state, &recent).await?.is_some(),
        "tombstone inside retention must be kept"
    );
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_janitor_purges_unrevoked_expired_refresh_token_without_retention() -> Result<()> {
    let (state, _tmp) = get_state_with_config(|_| {}).await?;
    let backend = RaftOauth2SessionBackend::default();
    let now = Utc::now().timestamp();

    let id = Uuid::new_v4().simple().to_string();
    // Expired an hour ago and never revoked: no tombstone retention.
    let idle = format!("{id}-idle");
    backend
        .create_refresh_token(
            &state,
            refresh_create(&idle, &format!("family-{idle}"), now - 3600),
        )
        .await?;
    // Same age, but its family was revoked: kept for the retention window.
    let revoked = format!("{id}-revoked");
    backend
        .create_refresh_token(
            &state,
            refresh_create(&revoked, &format!("family-{revoked}"), now - 3600),
        )
        .await?;
    backend
        .revoke_refresh_token_family(
            &state,
            &format!("family-{revoked}"),
            RefreshTokenRevocationReason::Operator,
            now - 7200,
        )
        .await?;

    janitor::run_once(&state).await?;

    assert!(backend.get_refresh_token(&state, &idle).await?.is_none());
    assert!(backend.get_refresh_token(&state, &revoked).await?.is_some());
    Ok(())
}
