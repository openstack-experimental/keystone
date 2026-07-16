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

//! In-memory [`LocalEmergencyStore`] used by subsystem crates' unit tests
//! (`oauth2-key-driver-raft`, `storage`) so they don't need a real Fjall
//! database to exercise staging/reconciliation logic. The Fjall-backed
//! production implementation lands in Phase 2 of the ADR 0028 implementation
//! plan, in `crates/storage`.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::{EmergencyCandidate, LocalEmergencyStore, LocalEmergencyStoreError, Subsystem, key};

/// In-memory, process-local [`LocalEmergencyStore`] implementation.
#[derive(Default)]
pub struct InMemoryLocalEmergencyStore {
    candidates: Mutex<HashMap<String, EmergencyCandidate>>,
    audit_pointers: Mutex<HashMap<String, String>>,
}

impl InMemoryLocalEmergencyStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl LocalEmergencyStore for InMemoryLocalEmergencyStore {
    async fn put_candidate(
        &self,
        candidate: EmergencyCandidate,
    ) -> Result<(), LocalEmergencyStoreError> {
        let full_key = key::candidate_key(
            candidate.subsystem,
            &candidate.scope_id,
            &candidate.rotation_id,
        );
        let mut guard = self
            .candidates
            .lock()
            .map_err(|e| LocalEmergencyStoreError::other(e.to_string()))?;
        if guard.contains_key(&full_key) {
            return Err(LocalEmergencyStoreError::AlreadyExists(full_key));
        }
        guard.insert(full_key, candidate);
        Ok(())
    }

    async fn get_candidate(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
        rotation_id: &str,
    ) -> Result<Option<EmergencyCandidate>, LocalEmergencyStoreError> {
        let full_key = key::candidate_key(subsystem, scope_id, rotation_id);
        let guard = self
            .candidates
            .lock()
            .map_err(|e| LocalEmergencyStoreError::other(e.to_string()))?;
        Ok(guard.get(&full_key).cloned())
    }

    async fn list_candidates(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
    ) -> Result<Vec<EmergencyCandidate>, LocalEmergencyStoreError> {
        let prefix = key::candidate_scope_prefix(subsystem, scope_id);
        let guard = self
            .candidates
            .lock()
            .map_err(|e| LocalEmergencyStoreError::other(e.to_string()))?;
        Ok(guard
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect())
    }

    async fn list_candidates_for_subsystem(
        &self,
        subsystem: Subsystem,
    ) -> Result<Vec<EmergencyCandidate>, LocalEmergencyStoreError> {
        let prefix = key::candidate_subsystem_prefix(subsystem);
        let guard = self
            .candidates
            .lock()
            .map_err(|e| LocalEmergencyStoreError::other(e.to_string()))?;
        Ok(guard
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect())
    }

    async fn revoke_candidate(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
        rotation_id: &str,
    ) -> Result<(), LocalEmergencyStoreError> {
        let full_key = key::candidate_key(subsystem, scope_id, rotation_id);
        let mut guard = self
            .candidates
            .lock()
            .map_err(|e| LocalEmergencyStoreError::other(e.to_string()))?;
        let candidate = guard
            .get_mut(&full_key)
            .ok_or_else(|| LocalEmergencyStoreError::NotFound(full_key.clone()))?;
        candidate.revoked = true;
        Ok(())
    }

    async fn mark_conflicted(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
        rotation_id: &str,
    ) -> Result<(), LocalEmergencyStoreError> {
        let full_key = key::candidate_key(subsystem, scope_id, rotation_id);
        let mut guard = self
            .candidates
            .lock()
            .map_err(|e| LocalEmergencyStoreError::other(e.to_string()))?;
        let candidate = guard
            .get_mut(&full_key)
            .ok_or_else(|| LocalEmergencyStoreError::NotFound(full_key.clone()))?;
        candidate.conflicted = true;
        Ok(())
    }

    async fn clear_candidate(
        &self,
        subsystem: Subsystem,
        scope_id: &str,
        rotation_id: &str,
    ) -> Result<(), LocalEmergencyStoreError> {
        let full_key = key::candidate_key(subsystem, scope_id, rotation_id);
        let mut guard = self
            .candidates
            .lock()
            .map_err(|e| LocalEmergencyStoreError::other(e.to_string()))?;
        guard
            .remove(&full_key)
            .ok_or(LocalEmergencyStoreError::NotFound(full_key))?;
        Ok(())
    }

    async fn put_audit_pointer(
        &self,
        rotation_id: &str,
        event_id: &str,
    ) -> Result<(), LocalEmergencyStoreError> {
        let mut guard = self
            .audit_pointers
            .lock()
            .map_err(|e| LocalEmergencyStoreError::other(e.to_string()))?;
        guard.insert(key::audit_pointer_key(rotation_id), event_id.to_string());
        Ok(())
    }

    async fn get_audit_pointer(
        &self,
        rotation_id: &str,
    ) -> Result<Option<String>, LocalEmergencyStoreError> {
        let guard = self
            .audit_pointers
            .lock()
            .map_err(|e| LocalEmergencyStoreError::other(e.to_string()))?;
        Ok(guard.get(&key::audit_pointer_key(rotation_id)).cloned())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn candidate(subsystem: Subsystem, scope_id: &str, rotation_id: &str) -> EmergencyCandidate {
        EmergencyCandidate {
            subsystem,
            scope_id: scope_id.to_string(),
            rotation_id: rotation_id.to_string(),
            payload: vec![1, 2, 3],
            initiator: "spiffe://example.org/operator/alice".to_string(),
            justification: "suspected key compromise".to_string(),
            created_at: Utc::now(),
            revoked: false,
            origin_node_id: None,
            conflicted: false,
        }
    }

    #[tokio::test]
    async fn put_then_get_roundtrips() {
        let store = InMemoryLocalEmergencyStore::new();
        let c = candidate(Subsystem::Oauth2SigningKey, "default", "rot-1");
        store.put_candidate(c.clone()).await.unwrap();

        let fetched = store
            .get_candidate(Subsystem::Oauth2SigningKey, "default", "rot-1")
            .await
            .unwrap();
        assert_eq!(fetched, Some(c));
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let store = InMemoryLocalEmergencyStore::new();
        let fetched = store
            .get_candidate(Subsystem::Dek, "cluster", "missing")
            .await
            .unwrap();
        assert_eq!(fetched, None);
    }

    #[tokio::test]
    async fn put_duplicate_rotation_id_fails() {
        let store = InMemoryLocalEmergencyStore::new();
        let c = candidate(Subsystem::Dek, "cluster", "rot-1");
        store.put_candidate(c.clone()).await.unwrap();

        let err = store.put_candidate(c).await.unwrap_err();
        assert!(matches!(err, LocalEmergencyStoreError::AlreadyExists(_)));
    }

    #[tokio::test]
    async fn list_candidates_scopes_by_subsystem_and_scope() {
        let store = InMemoryLocalEmergencyStore::new();
        store
            .put_candidate(candidate(Subsystem::Dek, "cluster", "rot-1"))
            .await
            .unwrap();
        store
            .put_candidate(candidate(Subsystem::Dek, "cluster", "rot-2"))
            .await
            .unwrap();
        store
            .put_candidate(candidate(Subsystem::Dek, "other-cluster", "rot-3"))
            .await
            .unwrap();
        store
            .put_candidate(candidate(Subsystem::Oauth2SigningKey, "cluster", "rot-4"))
            .await
            .unwrap();

        let mut ids: Vec<String> = store
            .list_candidates(Subsystem::Dek, "cluster")
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.rotation_id)
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["rot-1".to_string(), "rot-2".to_string()]);
    }

    #[tokio::test]
    async fn revoke_marks_candidate_without_deleting_it() {
        let store = InMemoryLocalEmergencyStore::new();
        store
            .put_candidate(candidate(Subsystem::Oauth2SigningKey, "default", "rot-1"))
            .await
            .unwrap();

        store
            .revoke_candidate(Subsystem::Oauth2SigningKey, "default", "rot-1")
            .await
            .unwrap();

        let fetched = store
            .get_candidate(Subsystem::Oauth2SigningKey, "default", "rot-1")
            .await
            .unwrap()
            .unwrap();
        assert!(fetched.revoked);
    }

    #[tokio::test]
    async fn revoke_missing_candidate_fails() {
        let store = InMemoryLocalEmergencyStore::new();
        let err = store
            .revoke_candidate(Subsystem::Dek, "cluster", "missing")
            .await
            .unwrap_err();
        assert!(matches!(err, LocalEmergencyStoreError::NotFound(_)));
    }

    #[tokio::test]
    async fn clear_removes_candidate() {
        let store = InMemoryLocalEmergencyStore::new();
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
    async fn clear_missing_candidate_fails() {
        let store = InMemoryLocalEmergencyStore::new();
        let err = store
            .clear_candidate(Subsystem::Dek, "cluster", "missing")
            .await
            .unwrap_err();
        assert!(matches!(err, LocalEmergencyStoreError::NotFound(_)));
    }

    #[tokio::test]
    async fn audit_pointer_put_then_get_roundtrips() {
        let store = InMemoryLocalEmergencyStore::new();
        store
            .put_audit_pointer("rot-1", "node-1:event-uuid")
            .await
            .unwrap();

        let fetched = store.get_audit_pointer("rot-1").await.unwrap();
        assert_eq!(fetched, Some("node-1:event-uuid".to_string()));
    }

    #[tokio::test]
    async fn audit_pointer_missing_returns_none() {
        let store = InMemoryLocalEmergencyStore::new();
        let fetched = store.get_audit_pointer("rot-missing").await.unwrap();
        assert_eq!(fetched, None);
    }
}
