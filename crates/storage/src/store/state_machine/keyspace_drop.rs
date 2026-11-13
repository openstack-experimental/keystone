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
//! Replicated keyspace drop (ADR 0044 §3).
//!
//! `MutationInner::DropKeyspace` removes a whole keyspace on every node. To
//! keep a bug in a caller's name computation from reaching unrelated state,
//! only keyspaces whose name matches a registered prefix pattern may be
//! dropped.

use super::*;

/// Violation type emitted when a drop names a keyspace outside the allow-list.
pub(crate) const KEYSPACE_DROP_REFUSED: &str = "KEYSPACE_DROP_REFUSED";

/// Prefix of the single-use credential registry keyspaces
/// (`single_use_{use_case}_{bucket}`, ADR 0044 §3).
pub(crate) const SINGLE_USE_KEYSPACE_PREFIX: &str = "single_use_";

/// Longest keyspace name accepted for a replicated drop.
const MAX_DROPPABLE_NAME_LEN: usize = 128;

/// Returns `true` if `name` may be dropped through `DropKeyspace`.
///
/// The name must have the form `single_use_{use_case}_{bucket}` where
/// `use_case` is a non-empty run of `[a-z0-9_]` and `bucket` is a non-empty
/// run of ASCII digits. Core, reserved and other feature keyspaces never
/// match. A feature that adopts the mutation later registers its own pattern
/// here.
pub(crate) fn keyspace_drop_allowed(name: &str) -> bool {
    if name.len() > MAX_DROPPABLE_NAME_LEN {
        return false;
    }
    let Some(rest) = name.strip_prefix(SINGLE_USE_KEYSPACE_PREFIX) else {
        return false;
    };
    let Some((use_case, bucket)) = rest.rsplit_once('_') else {
        return false;
    };
    !use_case.is_empty()
        && use_case
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !bucket.is_empty()
        && bucket.bytes().all(|b| b.is_ascii_digit())
}

impl FjallStateMachine {
    /// Drops `name` with all its data and the per-record metadata.
    ///
    /// Called by `apply()` after the batch of the entry committed, with the
    /// lifecycle read guard released.
    ///
    /// Unlike [`Self::drop_keyspace`] the keyspace need not be empty. A
    /// missing keyspace is a no-op. The caller has checked
    /// [`keyspace_drop_allowed`].
    pub(super) fn drop_keyspace_replicated(&self, name: &str) -> Result<(), StoreError> {
        // Keyspaces are either ephemeral or Fjall-backed, but do not rely on
        // it: clear both sides.
        self.ephemeral.remove(name);
        // Excludes `apply()` and the snapshot walk, as in `drop_keyspace`.
        let _lifecycle_guard = self
            .keyspace_lifecycle
            .write()
            .unwrap_or_else(|p| p.into_inner());
        // The per-record metadata lives in the `meta` keyspace under
        // `<keyspace>\0<key>` (see `meta_key`). Remove it first, or a record
        // created again later would find the stale entry and conflict. A
        // crash between the two steps replays this entry on restart, and both
        // steps are idempotent.
        let mut prefix = name.as_bytes().to_vec();
        prefix.push(0);
        let mut batch = self.db.batch();
        for item in self.meta.prefix(&prefix) {
            batch.remove(&self.meta, item.key()?);
        }
        batch.commit()?;
        if !self.db.keyspace_exists(name) {
            return Ok(());
        }
        let ks = self.db.keyspace(name, KeyspaceCreateOptions::default)?;
        self.db.delete_keyspace(ks)?;
        Ok(())
    }

    /// Names of the existing keyspaces that start with `prefix`, sorted.
    ///
    /// Read-only: never creates a keyspace. Includes ephemeral keyspaces.
    pub fn list_keyspaces(&self, prefix: &str) -> Vec<String> {
        let mut names: Vec<String> = self
            .db
            .list_keyspace_names()
            .into_iter()
            .map(|n| n.to_string())
            .chain(self.ephemeral.iter().map(|e| e.key().clone()))
            .filter(|n| n.starts_with(prefix))
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_accepts_single_use_buckets() {
        for name in [
            "single_use_assertion_5000",
            "single_use_totp_0",
            "single_use_dpop_token_123456",
            "single_use_a_b_c_9",
        ] {
            assert!(keyspace_drop_allowed(name), "{name}");
        }
    }

    #[test]
    fn allow_list_refuses_everything_else() {
        for name in [
            "data",
            "meta",
            "index",
            "oauth2_keys",
            "webauthn_state_1",
            "single_use_",
            "single_use_assertion",
            "single_use__5",
            "single_use_assertion_",
            "single_use_assertion_5x",
            "single_use_Assertion_5",
            "single_use_assertion_-5",
            "single_use_assertion_5/..",
            "xsingle_use_assertion_5",
            "SINGLE_USE_assertion_5",
            "",
        ] {
            assert!(!keyspace_drop_allowed(name), "{name}");
        }
        let long = format!("single_use_{}_5", "a".repeat(200));
        assert!(!keyspace_drop_allowed(&long));
    }

    fn put(sm: &FjallStateMachine, keyspace: &str, key: &[u8]) {
        let ks = sm.keyspace(keyspace).expect("keyspace");
        let (cipher, dek_version) = sm
            .encrypt_and_store(&ks, key, keyspace.as_bytes(), DataTier::Internal as u8, b"")
            .expect("encrypt");
        ks.insert(key, cipher).expect("insert");
        let mut metadata = Metadata::new();
        metadata.dek_version = Some(dek_version);
        sm.meta()
            .insert(meta_key(keyspace, key), metadata.pack().expect("pack"))
            .expect("insert meta");
    }

    #[test]
    fn replicated_drop_removes_data_meta_and_snapshot_entry() {
        let (sm, _td) = make_seeded_sm(0x31);
        put(&sm, "single_use_totp_5", b"a");
        put(&sm, "single_use_totp_5", b"b");
        put(&sm, "single_use_totp_6", b"a");
        put(&sm, "data", b"a");

        assert_eq!(
            vec!["single_use_totp_5", "single_use_totp_6"],
            sm.list_keyspaces("single_use_")
        );

        sm.drop_keyspace_replicated("single_use_totp_5")
            .expect("drop non-empty keyspace");

        assert!(!sm.keyspace_exists("single_use_totp_5"));
        assert_eq!(vec!["single_use_totp_6"], sm.list_keyspaces("single_use_"));
        // The record metadata went with it, so the key can be created again.
        assert!(
            sm.meta()
                .get(meta_key("single_use_totp_5", b"a"))
                .expect("get")
                .is_none()
        );
        assert!(
            sm.meta()
                .get(meta_key("single_use_totp_5", b"b"))
                .expect("get")
                .is_none()
        );
        // Neighbours are untouched, including the same key elsewhere.
        assert!(
            sm.meta()
                .get(meta_key("single_use_totp_6", b"a"))
                .expect("get")
                .is_some()
        );
        assert!(
            sm.meta()
                .get(meta_key("data", b"a"))
                .expect("get")
                .is_some()
        );
        assert!(sm.data().get(b"a").expect("get").is_some());

        // A snapshot taken after the drop does not carry the keyspace, so a
        // follower that installs it ends in the same state.
        let payload = sm.snapshot_payload().expect("payload");
        let names: Vec<&str> = payload.keyspaces.iter().map(|(n, _)| n.as_str()).collect();
        assert!(!names.contains(&"single_use_totp_5"), "{names:?}");
        assert!(names.contains(&"single_use_totp_6"));

        // Idempotent.
        sm.drop_keyspace_replicated("single_use_totp_5")
            .expect("second drop is a no-op");
        sm.drop_keyspace_replicated("single_use_never_created_9")
            .expect("missing keyspace is a no-op");
        assert!(!sm.keyspace_exists("single_use_never_created_9"));
    }
}
