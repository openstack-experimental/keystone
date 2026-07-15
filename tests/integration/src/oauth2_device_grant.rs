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
//! # RFC 8628 Device Authorization Grant integration tests (ADR 0026 §7.C)
//!
//! Raft-only backend -- these tests only run under the `raft` nextest
//! profile (see `.config/nextest.toml`), matching the `oauth2_session`/
//! `oauth2_token_verify` suites. Exercises `Oauth2SessionApi`'s device-grant
//! state machine (start -> poll pending -> login -> consent -> poll
//! authorized) against real Raft-backed storage.

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_session::{DevicePollOutcome, StartDeviceAuthorizationRequest};
use openstack_keystone_core_types::identity::UserCreateBuilder;

use crate::common::get_state_with_config;
use crate::create_domain;

#[tokio::test]
#[traced_test]
async fn test_device_grant_full_flow_issues_grant_on_poll() -> Result<()> {
    let (state, _tmp) = get_state_with_config(|_| {}).await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();

    state
        .provider
        .get_identity_provider()
        .create_user(
            &ExecutionContext::internal(&state),
            UserCreateBuilder::default()
                .id(&uid)
                .name("device-grant-user")
                .domain_id(domain.id.clone())
                .enabled(true)
                .password("s3cr3t-pass")
                .build()?,
        )
        .await?;

    let session_provider = state.provider.get_oauth2_session_provider();

    // POST /device_authorization equivalent.
    let start = session_provider
        .start_device_authorization(
            &state,
            StartDeviceAuthorizationRequest {
                domain_id: domain.id.clone(),
                client_id: "device-client-1".to_string(),
                scope: vec!["openid".to_string()],
            },
        )
        .await?;
    assert!(!start.device_code.is_empty());
    // "XXXX-XXXX" shape (ADR 0026 §7.C).
    assert_eq!(start.user_code.len(), 9);

    // Polling before the verification page completes: still pending.
    let pending = session_provider
        .poll_device_code_grant(&state, &start.device_code, "device-client-1")
        .await?;
    assert!(matches!(pending, DevicePollOutcome::Pending));

    // GET verification page equivalent: look the grant up by user_code.
    let grant = session_provider
        .get_device_code_grant_by_user_code(&state, &start.user_code)
        .await?
        .expect("grant must be resolvable by its own fresh user_code");
    assert_eq!(grant.device_code, start.device_code);

    // POST verification-page login equivalent.
    session_provider
        .mark_device_authenticated(&state, &start.device_code, &uid, 1_000, vec!["pwd".into()])
        .await?;

    // POST verification-page consent equivalent.
    let decided = session_provider
        .mark_device_decision(&state, &start.device_code, true)
        .await?;
    assert!(matches!(
        decided.status,
        openstack_keystone_core_types::oauth2_session::DeviceGrantStatus::Authorized
    ));

    // Wait past the poll interval so this isn't a `slow_down` (the pending
    // poll above already stamped `last_polled_at`).
    tokio::time::sleep(std::time::Duration::from_secs(
        u64::from(
            state
                .config_manager
                .config
                .read()
                .await
                .oauth2
                .device_code_poll_interval_seconds,
        ) + 1,
    ))
    .await;

    // POST /token (device_code) equivalent: authorized poll redeems the
    // grant exactly once.
    let outcome = session_provider
        .poll_device_code_grant(&state, &start.device_code, "device-client-1")
        .await?;
    match outcome {
        DevicePollOutcome::Authorized(record) => {
            assert_eq!(record.user_id.as_deref(), Some(uid.as_str()));
        }
        other => panic!("expected Authorized, got {other:?}"),
    }

    // A second poll of the same (now-deleted) device_code is no longer a
    // known grant.
    let after_redeem = session_provider
        .poll_device_code_grant(&state, &start.device_code, "device-client-1")
        .await?;
    assert!(matches!(after_redeem, DevicePollOutcome::InvalidGrant));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_device_grant_expired_code_is_rejected_on_poll() -> Result<()> {
    // Shrink the device_code lifetime to effectively zero so the grant is
    // expired by the time we poll, without sleeping minutes in CI.
    let (state, _tmp) =
        get_state_with_config(|cfg| cfg.oauth2.device_code_lifetime_minutes = 0).await?;
    let domain = create_domain!(state)?;
    let session_provider = state.provider.get_oauth2_session_provider();

    let start = session_provider
        .start_device_authorization(
            &state,
            StartDeviceAuthorizationRequest {
                domain_id: domain.id.clone(),
                client_id: "device-client-1".to_string(),
                scope: vec!["openid".to_string()],
            },
        )
        .await?;

    // A zero-minute lifetime means `expires_at <= created_at`; give it a
    // moment to be unambiguously in the past.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let outcome = session_provider
        .poll_device_code_grant(&state, &start.device_code, "device-client-1")
        .await?;
    assert!(matches!(outcome, DevicePollOutcome::Expired));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_device_grant_denied_consent_is_reported_on_poll() -> Result<()> {
    let (state, _tmp) = get_state_with_config(|_| {}).await?;
    let domain = create_domain!(state)?;
    let uid = Uuid::new_v4().simple().to_string();

    state
        .provider
        .get_identity_provider()
        .create_user(
            &ExecutionContext::internal(&state),
            UserCreateBuilder::default()
                .id(&uid)
                .name("device-grant-denier")
                .domain_id(domain.id.clone())
                .enabled(true)
                .password("s3cr3t-pass")
                .build()?,
        )
        .await?;

    let session_provider = state.provider.get_oauth2_session_provider();

    let start = session_provider
        .start_device_authorization(
            &state,
            StartDeviceAuthorizationRequest {
                domain_id: domain.id.clone(),
                client_id: "device-client-1".to_string(),
                scope: vec!["openid".to_string()],
            },
        )
        .await?;

    session_provider
        .mark_device_authenticated(&state, &start.device_code, &uid, 1_000, vec!["pwd".into()])
        .await?;
    session_provider
        .mark_device_decision(&state, &start.device_code, false)
        .await?;

    let outcome = session_provider
        .poll_device_code_grant(&state, &start.device_code, "device-client-1")
        .await?;
    assert!(matches!(outcome, DevicePollOutcome::Denied));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_device_grant_poll_faster_than_interval_is_slow_down() -> Result<()> {
    let (state, _tmp) =
        get_state_with_config(|cfg| cfg.oauth2.device_code_poll_interval_seconds = 60).await?;
    let domain = create_domain!(state)?;
    let session_provider = state.provider.get_oauth2_session_provider();

    let start = session_provider
        .start_device_authorization(
            &state,
            StartDeviceAuthorizationRequest {
                domain_id: domain.id.clone(),
                client_id: "device-client-1".to_string(),
                scope: vec!["openid".to_string()],
            },
        )
        .await?;

    // First poll stamps `last_polled_at`.
    let first = session_provider
        .poll_device_code_grant(&state, &start.device_code, "device-client-1")
        .await?;
    assert!(matches!(first, DevicePollOutcome::Pending));

    // Immediate second poll, well inside the 60s interval, must be
    // throttled rather than treated as a fresh pending poll.
    let second = session_provider
        .poll_device_code_grant(&state, &start.device_code, "device-client-1")
        .await?;
    assert!(matches!(second, DevicePollOutcome::SlowDown));

    Ok(())
}
