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

use super::*;

// Rate limiter — basic token consumption

#[test]
fn rate_limiter_allows_up_to_burst() {
    let limiter: Arc<IdentityLimiter> =
        Arc::new(RateLimiter::keyed(Quota::per_hour(ROTATE_DEK_PER_HOUR)));
    let key = "spiffe://example.com/keystone/storage/storage-operator".to_owned();
    // Initial burst of 2 should be allowed.
    assert!(limiter.check_key(&key).is_ok(), "first request allowed");
    assert!(limiter.check_key(&key).is_ok(), "second request allowed");
    // Third request within the same window should be denied.
    assert!(
        limiter.check_key(&key).is_err(),
        "third request within burst window denied"
    );
}

#[test]
fn rate_limiter_independent_keys() {
    let limiter: Arc<IdentityLimiter> =
        Arc::new(RateLimiter::keyed(Quota::per_hour(ROTATE_DEK_PER_HOUR)));
    let key_a = "spiffe://example.com/keystone/storage/storage-operator".to_owned();
    let key_b = "spiffe://example.com/keystone/storage/other-operator".to_owned();
    // Exhaust key_a.
    limiter.check_key(&key_a).ok();
    limiter.check_key(&key_a).ok();
    assert!(limiter.check_key(&key_a).is_err(), "key_a exhausted");
    // key_b is independent and still has capacity.
    assert!(limiter.check_key(&key_b).is_ok(), "key_b unaffected");
}

#[test]
fn normalize_add_learner_bare_vs_schema() {
    // Simulate address uniqueness check: same node, different address format.
    // Stored: "127.0.0.1:21001", new: "https://127.0.0.1:21001/"
    // After normalization both should match → no conflict.
    let stored = "127.0.0.1:21001";
    let new_with_schema = "https://127.0.0.1:21001/";
    assert_eq!(
        normalize_rpc_addr(stored),
        normalize_rpc_addr(new_with_schema),
        "same host:port with different formats must normalize to identical string"
    );
}

#[test]
fn normalize_add_learner_different_hosts() {
    // Different host:port should NOT match even after normalization.
    let a = "127.0.0.1:21001";
    let b = "https://127.0.0.1:21002/";
    assert_ne!(
        normalize_rpc_addr(a),
        normalize_rpc_addr(b),
        "different ports must not match"
    );
}

#[test]
fn normalize_add_learner_fqdn_from_config() {
    // Replicates the real pod-restart scenario:
    // Committed membership has bare "host:port" from init,
    // config has https:// scheme + trailing slash from Uri::Display.
    let stored = "keystone-rs-1.keystone-rs-internal.default.svc.cluster.local:8300";
    let from_config = "https://keystone-rs-1.keystone-rs-internal.default.svc.cluster.local:8300/";
    assert_eq!(
        normalize_rpc_addr(stored),
        normalize_rpc_addr(from_config),
        "stored bare address must match config Uri::Display format"
    );
}

// SVID TTL enforcement (ADR 0016-v2 §4.1 — force-renewal window)

// Unix timestamp of 2100-01-01 00:00:00 UTC (used as a stable not_after
// anchor).
const NOT_AFTER_2100_UNIX: i64 = 4_102_444_800;

fn make_svid_der_not_after_2100() -> Vec<u8> {
    use rcgen::{CertificateParams, KeyPair, date_time_ymd};
    let mut params = CertificateParams::default();
    params.not_before = date_time_ymd(2000, 1, 1);
    params.not_after = date_time_ymd(2100, 1, 1);
    let key = KeyPair::generate().expect("keygen");
    params
        .self_signed(&key)
        .expect("self-sign")
        .der()
        .as_ref()
        .to_vec()
}

#[test]
fn svid_ttl_ok() {
    let der = make_svid_der_not_after_2100();
    // 10 minutes before expiry — well outside the 5-minute window.
    assert!(check_svid_ttl_der(&der, NOT_AFTER_2100_UNIX - 600).is_ok());
}

#[test]
fn svid_ttl_force_renewal_window() {
    let der = make_svid_der_not_after_2100();
    // 4 minutes before expiry — inside the 5-minute force-renewal window.
    let err = check_svid_ttl_der(&der, NOT_AFTER_2100_UNIX - 240)
        .expect_err("should fail inside force-renewal window");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[test]
fn svid_ttl_expired() {
    let der = make_svid_der_not_after_2100();
    // 1 second past expiry.
    let err =
        check_svid_ttl_der(&der, NOT_AFTER_2100_UNIX + 1).expect_err("should fail when expired");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

// stage_dek_local_emergency_candidate (ADR 0028 §3) — pure business
// logic, independent of Raft/gRPC.

mod stage_dek_local_emergency {
    use chrono::Utc;
    use openstack_keystone_local_emergency_store::InMemoryLocalEmergencyStore;
    use openstack_keystone_storage_crypto::EnvKek;

    use super::*;

    fn kek() -> EnvKek {
        EnvKek::from_bytes([7u8; 32])
    }

    #[tokio::test]
    async fn stages_a_fresh_candidate_and_bumps_version() {
        let store = InMemoryLocalEmergencyStore::new();
        let (rotation_id, new_version) = stage_dek_local_emergency_candidate(
            &store,
            &kek(),
            3,
            "spiffe://example.org/keystone/storage/storage-operator",
            "suspected key compromise",
            Utc::now(),
        )
        .await
        .expect("should stage");

        assert_eq!(new_version, 4);
        let candidates = store
            .list_candidates(Subsystem::Dek, DEK_SCOPE_ID)
            .await
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].rotation_id, rotation_id);
        assert_eq!(candidates[0].justification, "suspected key compromise");
        assert!(!candidates[0].revoked);

        let decoded: DekEmergencyPayload = rmp_serde::from_slice(&candidates[0].payload).unwrap();
        assert_eq!(decoded.dek_version, 4);
    }

    #[tokio::test]
    async fn refuses_a_second_candidate_while_one_is_active() {
        let store = InMemoryLocalEmergencyStore::new();
        stage_dek_local_emergency_candidate(&store, &kek(), 3, "op-a", "reason-1", Utc::now())
            .await
            .expect("first stage should succeed");

        let err =
            stage_dek_local_emergency_candidate(&store, &kek(), 3, "op-b", "reason-2", Utc::now())
                .await
                .expect_err("second stage should be refused while one is active");
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn allows_a_new_candidate_after_the_prior_one_is_revoked() {
        let store = InMemoryLocalEmergencyStore::new();
        let (first_id, _) =
            stage_dek_local_emergency_candidate(&store, &kek(), 3, "op-a", "reason-1", Utc::now())
                .await
                .expect("first stage should succeed");
        store
            .revoke_candidate(Subsystem::Dek, DEK_SCOPE_ID, &first_id)
            .await
            .unwrap();

        let (second_id, new_version) =
            stage_dek_local_emergency_candidate(&store, &kek(), 3, "op-b", "reason-2", Utc::now())
                .await
                .expect("should stage after revocation");
        assert_ne!(first_id, second_id);
        assert_eq!(new_version, 4);
    }

    #[tokio::test]
    async fn refuses_when_dek_version_space_is_exhausted() {
        let store = InMemoryLocalEmergencyStore::new();
        let err = stage_dek_local_emergency_candidate(
            &store,
            &kek(),
            u32::MAX,
            "op-a",
            "reason",
            Utc::now(),
        )
        .await
        .expect_err("version overflow should be refused");
        assert_eq!(err.code(), tonic::Code::Internal);
    }
}

// validate_dek_reconcile_candidate (ADR 0028 §6) — pure validation
// logic, independent of Raft/gRPC.

mod validate_dek_reconcile_candidate_tests {
    use chrono::Utc;
    use openstack_keystone_local_emergency_store::InMemoryLocalEmergencyStore;
    use openstack_keystone_storage_crypto::EnvKek;

    use super::*;

    async fn stage(store: &InMemoryLocalEmergencyStore, initiator: &str) -> String {
        stage_dek_local_emergency_candidate(
            store,
            &EnvKek::from_bytes([7u8; 32]),
            3,
            initiator,
            "suspected key compromise",
            Utc::now(),
        )
        .await
        .unwrap()
        .0
    }

    #[tokio::test]
    async fn accepts_a_fresh_candidate_from_a_different_operator() {
        let store = InMemoryLocalEmergencyStore::new();
        let rotation_id = stage(&store, "op-a").await;

        let payload = validate_dek_reconcile_candidate(&store, &rotation_id, "op-b", 3)
            .await
            .unwrap();
        assert_eq!(payload.dek_version, 4);
    }

    #[tokio::test]
    async fn rejects_unknown_rotation_id() {
        let store = InMemoryLocalEmergencyStore::new();
        let err = validate_dek_reconcile_candidate(&store, "rot-unknown", "op-b", 3)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn rejects_revoked_candidate() {
        let store = InMemoryLocalEmergencyStore::new();
        let rotation_id = stage(&store, "op-a").await;
        store
            .revoke_candidate(Subsystem::Dek, DEK_SCOPE_ID, &rotation_id)
            .await
            .unwrap();

        let err = validate_dek_reconcile_candidate(&store, &rotation_id, "op-b", 3)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn rejects_same_operator_as_initiator() {
        let store = InMemoryLocalEmergencyStore::new();
        let rotation_id = stage(&store, "op-a").await;

        let err = validate_dek_reconcile_candidate(&store, &rotation_id, "op-a", 3)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn rejects_stale_candidate_when_version_has_moved_on() {
        let store = InMemoryLocalEmergencyStore::new();
        // Staged when current_version was 3 (so it targets version 4),
        // but by the time reconciliation runs the live version has
        // already advanced to 5 (e.g. a normal RotateDek committed while
        // this candidate was staged).
        let rotation_id = stage(&store, "op-a").await;

        let err = validate_dek_reconcile_candidate(&store, &rotation_id, "op-b", 5)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }
}

// receive_gossiped_candidate (ADR 0028 §5) — pure business logic,
// independent of Raft/gRPC.

mod receive_gossiped_candidate_tests {
    use chrono::Utc;
    use openstack_keystone_local_emergency_store::InMemoryLocalEmergencyStore;

    use super::*;

    fn incoming(rotation_id: &str, origin_node_id: u64) -> EmergencyCandidate {
        EmergencyCandidate {
            subsystem: Subsystem::Dek,
            scope_id: DEK_SCOPE_ID.to_string(),
            rotation_id: rotation_id.to_string(),
            payload: vec![4, 5, 6],
            initiator: "spiffe://example.org/keystone/storage/storage-operator".to_string(),
            justification: "suspected key compromise".to_string(),
            created_at: Utc::now(),
            revoked: false,
            origin_node_id: Some(origin_node_id),
            conflicted: false,
        }
    }

    #[tokio::test]
    async fn adopts_first_gossiped_candidate() {
        let store = InMemoryLocalEmergencyStore::new();
        let conflict = receive_gossiped_candidate(&store, incoming("rot-remote", 2))
            .await
            .unwrap();
        assert!(!conflict);

        let stored = store
            .get_candidate(Subsystem::Dek, DEK_SCOPE_ID, "rot-remote")
            .await
            .unwrap()
            .expect("candidate should be adopted");
        assert_eq!(stored.origin_node_id, Some(2));
        assert!(!stored.conflicted);
    }

    #[tokio::test]
    async fn re_gossip_of_the_same_candidate_is_a_noop() {
        let store = InMemoryLocalEmergencyStore::new();
        receive_gossiped_candidate(&store, incoming("rot-remote", 2))
            .await
            .unwrap();

        let conflict = receive_gossiped_candidate(&store, incoming("rot-remote", 2))
            .await
            .unwrap();
        assert!(!conflict);
    }

    #[tokio::test]
    async fn conflicting_candidate_marks_both_sides() {
        let store = InMemoryLocalEmergencyStore::new();
        // This node already has its own locally-staged active candidate.
        stage_dek_local_emergency_candidate(
            &store,
            &openstack_keystone_storage_crypto::EnvKek::from_bytes([7u8; 32]),
            3,
            "spiffe://example.org/keystone/storage/storage-operator",
            "suspected key compromise",
            Utc::now(),
        )
        .await
        .unwrap();
        let local_candidates = store
            .list_candidates(Subsystem::Dek, DEK_SCOPE_ID)
            .await
            .unwrap();
        assert_eq!(local_candidates.len(), 1);
        let local_rotation_id = local_candidates[0].rotation_id.clone();

        let conflict = receive_gossiped_candidate(&store, incoming("rot-remote", 2))
            .await
            .unwrap();
        assert!(conflict);

        let local_after = store
            .get_candidate(Subsystem::Dek, DEK_SCOPE_ID, &local_rotation_id)
            .await
            .unwrap()
            .unwrap();
        assert!(local_after.conflicted);
        assert!(!local_after.revoked, "conflict must not itself revoke");

        let remote_after = store
            .get_candidate(Subsystem::Dek, DEK_SCOPE_ID, "rot-remote")
            .await
            .unwrap()
            .unwrap();
        assert!(remote_after.conflicted);
    }

    #[tokio::test]
    async fn adopts_after_local_candidate_is_revoked() {
        let store = InMemoryLocalEmergencyStore::new();
        stage_dek_local_emergency_candidate(
            &store,
            &openstack_keystone_storage_crypto::EnvKek::from_bytes([7u8; 32]),
            3,
            "op-a",
            "reason",
            Utc::now(),
        )
        .await
        .unwrap();
        let local_candidates = store
            .list_candidates(Subsystem::Dek, DEK_SCOPE_ID)
            .await
            .unwrap();
        store
            .revoke_candidate(
                Subsystem::Dek,
                DEK_SCOPE_ID,
                &local_candidates[0].rotation_id,
            )
            .await
            .unwrap();

        let conflict = receive_gossiped_candidate(&store, incoming("rot-remote", 2))
            .await
            .unwrap();
        assert!(!conflict, "a revoked local candidate must not conflict");
    }
}
