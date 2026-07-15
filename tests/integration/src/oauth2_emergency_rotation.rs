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
//! # Emergency signing-key rotation integration tests (ADR 0026 §3)
//!
//! Raft-only backend -- these tests only run under the `raft` nextest
//! profile (see `.config/nextest.toml`). Exercises `Oauth2KeyApi::
//! stage_emergency_rotation`/`confirm_emergency_rotation` against real
//! Raft-backed storage: dual-control (two distinct operators) promotion,
//! same-operator rejection, and the ADR §3 "revocation list, not JWKS
//! removal" posture for the demoted key's JTIs.
//!
//! The 15-minute confirm-window expiry itself is `oauth2-key-driver-raft`'s
//! own unit-test concern (`test_confirm_emergency_rotation_rejects_expired_
//! window`, which backdates the crate-private stored record directly) --
//! that internal representation is not reachable from this crate, and a
//! real 15-minute sleep here would make CI unacceptably slow, so it is
//! deliberately not duplicated at this layer.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::oauth2_key::Oauth2KeyProviderError;

use crate::common::get_state;
use crate::create_domain;

#[tokio::test]
#[traced_test]
async fn test_emergency_rotation_dual_control_promotes_staged_key() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let key_provider = state.provider.get_oauth2_key_provider();

    let primary_before = key_provider.ensure_domain_keys(&state, &domain.id).await?;

    let pending = key_provider
        .stage_emergency_rotation(&state, &domain.id, "operator-a")
        .await?;
    assert!(!pending.rotation_id.is_empty());

    let promoted = key_provider
        .confirm_emergency_rotation(
            &state,
            &domain.id,
            &pending.rotation_id,
            "operator-b",
            vec!["compromised-jti-1".to_string()],
        )
        .await?;

    assert_ne!(
        promoted.public_key_der, primary_before.public_key_der,
        "confirmation must promote the freshly staged key, not the old Primary"
    );

    let active = key_provider
        .list_all_active_keys(&state)
        .await?
        .into_iter()
        .find(|(id, _)| id == &domain.id)
        .expect("domain must be listed");
    assert_eq!(
        active.1.primary.public_key_der, promoted.public_key_der,
        "the newly confirmed key must be the domain's Primary"
    );
    assert_eq!(
        active.1.previous.map(|p| p.public_key_der),
        Some(primary_before.public_key_der),
        "the pre-rotation Primary must be demoted to Previous, not deleted"
    );

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_emergency_rotation_rejects_same_operator_confirmation() -> Result<()> {
    // ADR 0026 §3 dual-control: the confirming operator must differ from
    // the one who staged the rotation.
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let key_provider = state.provider.get_oauth2_key_provider();
    key_provider.ensure_domain_keys(&state, &domain.id).await?;

    let pending = key_provider
        .stage_emergency_rotation(&state, &domain.id, "operator-a")
        .await?;

    let err = key_provider
        .confirm_emergency_rotation(
            &state,
            &domain.id,
            &pending.rotation_id,
            "operator-a",
            vec![],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Oauth2KeyProviderError::DualControlViolation));

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_emergency_rotation_revokes_jtis_without_removing_previous_key_from_jwks() -> Result<()>
{
    // ADR 0026 §3: compromise containment is JTI-revocation-list-based, not
    // JWKS-key-deletion-based -- the demoted key must remain published in
    // `/jwks` (so already-issued, non-compromised tokens signed by it can
    // still be verified) while its named JTIs become unusable via the
    // separate revocation list.
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let key_provider = state.provider.get_oauth2_key_provider();
    key_provider.ensure_domain_keys(&state, &domain.id).await?;

    let pending = key_provider
        .stage_emergency_rotation(&state, &domain.id, "operator-a")
        .await?;
    key_provider
        .confirm_emergency_rotation(
            &state,
            &domain.id,
            &pending.rotation_id,
            "operator-b",
            vec![
                "compromised-jti-1".to_string(),
                "compromised-jti-2".to_string(),
            ],
        )
        .await?;

    let revoked = key_provider.revoked_jtis(&state, &domain.id).await?;
    assert!(revoked.contains("compromised-jti-1"));
    assert!(revoked.contains("compromised-jti-2"));

    let jwks = key_provider.jwks(&state, &domain.id).await?;
    assert_eq!(
        jwks.keys.len(),
        2,
        "the demoted (Previous) key must still be published in JWKS alongside the new Primary"
    );

    Ok(())
}
