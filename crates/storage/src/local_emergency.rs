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

//! Fjall-backed [`LocalEmergencyStore`] (ADR 0028 implementation plan, Phase
//! 2).
//!
//! Wraps a dedicated `local_emergency` Fjall keyspace, opened directly off
//! the same [`Database`] handle [`crate::store::state_machine::FjallStateMachine`]
//! uses — but never touched by Raft's `apply()`, and never written through
//! [`crate::StorageApi`]. That is the whole point of the quorum-bypass path:
//! writes here succeed even when the node cannot reach Raft quorum.
//!
//! The quorum-bypass guardrail itself ([`LeaderlessTracker`],
//! `GuardrailConfig`, `is_quorum_bypass_allowed`) lives in the lightweight
//! `openstack-keystone-local-emergency-store` crate, not here, so that
//! `core` (and other crates that need to evaluate the guardrail without
//! pulling in `fjall`/`openraft`) can depend on it directly. Re-exported here
//! for convenience since callers of this module already need the rest of
//! that crate's API.

use std::sync::Arc;

use async_trait::async_trait;
use fjall::{Database, Keyspace, KeyspaceCreateOptions};
use openstack_keystone_local_emergency_store::{
    EmergencyCandidate, LocalEmergencyStore, LocalEmergencyStoreError, Subsystem, key,
};
pub use openstack_keystone_local_emergency_store::{
    GuardrailConfig, LeaderlessTracker, is_quorum_bypass_allowed,
};
use serde::{Deserialize, Serialize};

/// Name of the dedicated Fjall keyspace backing the local emergency store.
pub const KEYSPACE_NAME: &str = "local_emergency";

/// Scope id used for DEK candidates: unlike OAuth2 signing keys (scoped per
/// domain), there is exactly one DEK per cluster.
pub const DEK_SCOPE_ID: &str = "cluster";

/// Opaque payload stored inside a DEK [`EmergencyCandidate`] (ADR 0028 §3,
/// amending ADR 0016-v2 §6.2): the freshly-generated, KEK-wrapped DEK and its
/// intended version, awaiting reconciliation into the Raft-backed
/// `PendingRotation` flow once quorum returns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DekEmergencyPayload {
    /// The new DEK, wrapped by this node's KEK.
    pub wrapped_dek: Vec<u8>,
    /// The DEK version this candidate would install if reconciled.
    pub dek_version: u32,
}

/// Fjall-backed [`LocalEmergencyStore`] implementation.
pub struct FjallLocalEmergencyStore {
    keyspace: Keyspace,
}

impl FjallLocalEmergencyStore {
    /// Open (creating if absent) the `local_emergency` keyspace on the given
    /// database handle.
    pub fn new(db: &Arc<Database>) -> Result<Self, LocalEmergencyStoreError> {
        let keyspace = db
            .keyspace(KEYSPACE_NAME, KeyspaceCreateOptions::default)
            .map_err(LocalEmergencyStoreError::other)?;
        Ok(Self { keyspace })
    }
}

#[async_trait]
impl LocalEmergencyStore for FjallLocalEmergencyStore {
    async fn put_candidate(
        &self,
        candidate: EmergencyCandidate,
    ) -> Result<(), LocalEmergencyStoreError> {
        let full_key = key::candidate_key(
            candidate.subsystem,
            &candidate.scope_id,
            &candidate.rotation_id,
        );
        if self
            .keyspace
            .get(full_key.as_bytes())
            .map_err(LocalEmergencyStoreError::other)?
            .is_some()
        {
            return Err(LocalEmergencyStoreError::AlreadyExists(full_key));
        }
        let bytes = rmp_serde::to_vec(&candidate).map_err(LocalEmergencyStoreError::other)?;
        self.keyspace
            .insert(full_key.as_bytes(), bytes)
            .map_err(LocalEmergencyStoreError::other)?;
        Ok(())
    }

    async fn get_candidate(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
        rotation_id: &str,
    ) -> Result<Option<EmergencyCandidate>, LocalEmergencyStoreError> {
        let full_key = key::candidate_key(subsystem, scope_id, rotation_id);
        let Some(bytes) = self
            .keyspace
            .get(full_key.as_bytes())
            .map_err(LocalEmergencyStoreError::other)?
        else {
            return Ok(None);
        };
        let candidate = rmp_serde::from_slice(&bytes).map_err(LocalEmergencyStoreError::other)?;
        Ok(Some(candidate))
    }

    async fn list_candidates(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
    ) -> Result<Vec<EmergencyCandidate>, LocalEmergencyStoreError> {
        let prefix = key::candidate_scope_prefix(subsystem, scope_id);
        let mut out = Vec::new();
        for item in self.keyspace.prefix(prefix.as_bytes()) {
            let (_, value) = item.into_inner().map_err(LocalEmergencyStoreError::other)?;
            let candidate =
                rmp_serde::from_slice(&value).map_err(LocalEmergencyStoreError::other)?;
            out.push(candidate);
        }
        Ok(out)
    }

    async fn list_candidates_for_subsystem(
        &self,
        subsystem: Subsystem,
    ) -> Result<Vec<EmergencyCandidate>, LocalEmergencyStoreError> {
        let prefix = key::candidate_subsystem_prefix(subsystem);
        let mut out = Vec::new();
        for item in self.keyspace.prefix(prefix.as_bytes()) {
            let (_, value) = item.into_inner().map_err(LocalEmergencyStoreError::other)?;
            let candidate =
                rmp_serde::from_slice(&value).map_err(LocalEmergencyStoreError::other)?;
            out.push(candidate);
        }
        Ok(out)
    }

    async fn revoke_candidate(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
        rotation_id: &str,
    ) -> Result<(), LocalEmergencyStoreError> {
        let full_key = key::candidate_key(subsystem, scope_id, rotation_id);
        let Some(bytes) = self
            .keyspace
            .get(full_key.as_bytes())
            .map_err(LocalEmergencyStoreError::other)?
        else {
            return Err(LocalEmergencyStoreError::NotFound(full_key));
        };
        let mut candidate: EmergencyCandidate =
            rmp_serde::from_slice(&bytes).map_err(LocalEmergencyStoreError::other)?;
        candidate.revoked = true;
        let bytes = rmp_serde::to_vec(&candidate).map_err(LocalEmergencyStoreError::other)?;
        self.keyspace
            .insert(full_key.as_bytes(), bytes)
            .map_err(LocalEmergencyStoreError::other)?;
        Ok(())
    }

    async fn mark_conflicted(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
        rotation_id: &str,
    ) -> Result<(), LocalEmergencyStoreError> {
        let full_key = key::candidate_key(subsystem, scope_id, rotation_id);
        let Some(bytes) = self
            .keyspace
            .get(full_key.as_bytes())
            .map_err(LocalEmergencyStoreError::other)?
        else {
            return Err(LocalEmergencyStoreError::NotFound(full_key));
        };
        let mut candidate: EmergencyCandidate =
            rmp_serde::from_slice(&bytes).map_err(LocalEmergencyStoreError::other)?;
        candidate.conflicted = true;
        let bytes = rmp_serde::to_vec(&candidate).map_err(LocalEmergencyStoreError::other)?;
        self.keyspace
            .insert(full_key.as_bytes(), bytes)
            .map_err(LocalEmergencyStoreError::other)?;
        Ok(())
    }

    async fn clear_candidate(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
        rotation_id: &str,
    ) -> Result<(), LocalEmergencyStoreError> {
        let full_key = key::candidate_key(subsystem, scope_id, rotation_id);
        if self
            .keyspace
            .get(full_key.as_bytes())
            .map_err(LocalEmergencyStoreError::other)?
            .is_none()
        {
            return Err(LocalEmergencyStoreError::NotFound(full_key));
        }
        self.keyspace
            .remove(full_key.as_bytes())
            .map_err(LocalEmergencyStoreError::other)?;
        Ok(())
    }

    async fn put_audit_pointer(
        &self,
        rotation_id: &str,
        event_id: &str,
    ) -> Result<(), LocalEmergencyStoreError> {
        let full_key = key::audit_pointer_key(rotation_id);
        self.keyspace
            .insert(full_key.as_bytes(), event_id.as_bytes())
            .map_err(LocalEmergencyStoreError::other)?;
        Ok(())
    }

    async fn get_audit_pointer(
        &self,
        rotation_id: &str,
    ) -> Result<Option<String>, LocalEmergencyStoreError> {
        let full_key = key::audit_pointer_key(rotation_id);
        let Some(bytes) = self
            .keyspace
            .get(full_key.as_bytes())
            .map_err(LocalEmergencyStoreError::other)?
        else {
            return Ok(None);
        };
        let event_id =
            String::from_utf8(bytes.to_vec()).map_err(LocalEmergencyStoreError::other)?;
        Ok(Some(event_id))
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use tempfile::TempDir;

    use super::*;

    fn candidate(subsystem: Subsystem, scope_id: &str, rotation_id: &str) -> EmergencyCandidate {
        EmergencyCandidate {
            subsystem,
            scope_id: scope_id.to_string(),
            rotation_id: rotation_id.to_string(),
            payload: vec![9, 9, 9],
            initiator: "spiffe://example.org/operator/alice".to_string(),
            justification: "suspected key compromise".to_string(),
            created_at: Utc::now(),
            revoked: false,
            origin_node_id: None,
            conflicted: false,
        }
    }

    fn open_db() -> (Arc<Database>, TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(Database::builder(dir.path()).open().expect("open db"));
        (db, dir)
    }

    #[tokio::test]
    async fn put_then_get_roundtrips_through_fjall() {
        let (db, _dir) = open_db();
        let store = FjallLocalEmergencyStore::new(&db).unwrap();
        let c = candidate(Subsystem::Dek, "cluster", "rot-1");

        store.put_candidate(c.clone()).await.unwrap();
        let fetched = store
            .get_candidate(Subsystem::Dek, "cluster", "rot-1")
            .await
            .unwrap();
        assert_eq!(fetched, Some(c));
    }

    #[tokio::test]
    async fn direct_fjall_read_sees_the_local_prefix() {
        let (db, _dir) = open_db();
        let store = FjallLocalEmergencyStore::new(&db).unwrap();
        store
            .put_candidate(candidate(Subsystem::Oauth2SigningKey, "default", "rot-1"))
            .await
            .unwrap();

        // Read the raw Fjall keyspace directly (bypassing the trait) to
        // confirm the write actually lands at the documented `_local:...`
        // key, not merely somewhere the trait's own getter can find it.
        let ks = db
            .keyspace(KEYSPACE_NAME, KeyspaceCreateOptions::default)
            .unwrap();
        let raw = ks
            .get(key::candidate_key(Subsystem::Oauth2SigningKey, "default", "rot-1").as_bytes())
            .unwrap();
        assert!(raw.is_some());
    }

    #[tokio::test]
    async fn put_duplicate_fails() {
        let (db, _dir) = open_db();
        let store = FjallLocalEmergencyStore::new(&db).unwrap();
        let c = candidate(Subsystem::Dek, "cluster", "rot-1");
        store.put_candidate(c.clone()).await.unwrap();

        let err = store.put_candidate(c).await.unwrap_err();
        assert!(matches!(err, LocalEmergencyStoreError::AlreadyExists(_)));
    }

    #[tokio::test]
    async fn list_candidates_scans_by_prefix() {
        let (db, _dir) = open_db();
        let store = FjallLocalEmergencyStore::new(&db).unwrap();
        store
            .put_candidate(candidate(Subsystem::Dek, "cluster", "rot-1"))
            .await
            .unwrap();
        store
            .put_candidate(candidate(Subsystem::Dek, "cluster", "rot-2"))
            .await
            .unwrap();
        store
            .put_candidate(candidate(Subsystem::Oauth2SigningKey, "cluster", "rot-3"))
            .await
            .unwrap();

        let found = store
            .list_candidates(Subsystem::Dek, "cluster")
            .await
            .unwrap();
        assert_eq!(found.len(), 2);
    }

    #[tokio::test]
    async fn revoke_persists_across_reopen() {
        let (db, _dir) = open_db();
        {
            let store = FjallLocalEmergencyStore::new(&db).unwrap();
            store
                .put_candidate(candidate(Subsystem::Dek, "cluster", "rot-1"))
                .await
                .unwrap();
            store
                .revoke_candidate(Subsystem::Dek, "cluster", "rot-1")
                .await
                .unwrap();
        }
        // Re-open the store on the same db handle (simulating a fresh
        // `FjallLocalEmergencyStore` after restart) to confirm the revoked
        // flag survived the round trip through Fjall, not just in-process.
        let store = FjallLocalEmergencyStore::new(&db).unwrap();
        let fetched = store
            .get_candidate(Subsystem::Dek, "cluster", "rot-1")
            .await
            .unwrap()
            .unwrap();
        assert!(fetched.revoked);
    }

    #[tokio::test]
    async fn clear_removes_from_fjall() {
        let (db, _dir) = open_db();
        let store = FjallLocalEmergencyStore::new(&db).unwrap();
        store
            .put_candidate(candidate(Subsystem::Dek, "cluster", "rot-1"))
            .await
            .unwrap();

        store
            .clear_candidate(Subsystem::Dek, "cluster", "rot-1")
            .await
            .unwrap();

        let fetched = store
            .get_candidate(Subsystem::Dek, "cluster", "rot-1")
            .await
            .unwrap();
        assert_eq!(fetched, None);
    }

    #[tokio::test]
    async fn audit_pointer_survives_reopen() {
        let (db, _dir) = open_db();
        {
            let store = FjallLocalEmergencyStore::new(&db).unwrap();
            store
                .put_audit_pointer("rot-1", "node-1:event-uuid")
                .await
                .unwrap();
        }
        let store = FjallLocalEmergencyStore::new(&db).unwrap();
        let fetched = store.get_audit_pointer("rot-1").await.unwrap();
        assert_eq!(fetched, Some("node-1:event-uuid".to_string()));
    }

    #[tokio::test]
    async fn audit_pointer_missing_returns_none() {
        let (db, _dir) = open_db();
        let store = FjallLocalEmergencyStore::new(&db).unwrap();
        let fetched = store.get_audit_pointer("rot-missing").await.unwrap();
        assert_eq!(fetched, None);
    }
}
