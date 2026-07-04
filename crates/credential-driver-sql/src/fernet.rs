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
//! # Credential Fernet key repository (ADR 0019 §4)
//!
//! Thin adapter over [`openstack_keystone_key_repository`], which owns the
//! actual key parsing/rotation/Null-Key-detection logic shared with the
//! Fernet token driver. This module exists to keep this crate's existing
//! public API (`FernetKeyRepository`, `LoadedKeys`, `MAX_ACTIVE_KEYS`,
//! `CredentialFernetError`) stable for its callers.
//!
//! Separate from `[fernet_tokens] key_repository`. Hard-capped at
//! [`MAX_ACTIVE_KEYS`] active keys, matching the Python Keystone constant —
//! unlike token Fernet keys this is intentionally not configurable.
use std::path::PathBuf;

pub use openstack_keystone_key_repository::LoadedKeys;
use openstack_keystone_key_repository::{FilesystemKeySource, KeyRepository};

use crate::error::CredentialFernetError;

/// The credential Fernet key repository is hard-capped at this many active
/// keys (ADR 0019 §4). Intentionally not configurable.
pub const MAX_ACTIVE_KEYS: usize = 3;

/// The Fernet key repository on the local filesystem.
///
/// Per ADR 0019 §4, this directory must resolve to the identical file set on
/// every Python and Rust node — that synchronization is an operational
/// deployment requirement, not something this type enforces.
pub struct FernetKeyRepository(KeyRepository<FilesystemKeySource>);

impl FernetKeyRepository {
    /// Create a new repository handle for the given directory.
    pub fn new(key_repository: PathBuf) -> Self {
        Self(KeyRepository::new(
            FilesystemKeySource::new(key_repository),
            MAX_ACTIVE_KEYS,
        ))
    }

    /// Compute `key_hash` per the ADR 0019 §4 specification: SHA-1 hex
    /// digest over the raw base64url-encoded key-file bytes, as read from
    /// disk (i.e. *before* base64url-decoding).
    #[must_use]
    pub fn key_hash(raw_key_file_bytes: &[u8]) -> String {
        KeyRepository::<FilesystemKeySource>::key_hash(raw_key_file_bytes)
    }

    /// Whether the given raw (base64url-encoded) key-file bytes decode to
    /// the well-known Null Key (32 zero bytes).
    #[must_use]
    pub fn is_null_key(raw_key_file_bytes: &[u8]) -> bool {
        KeyRepository::<FilesystemKeySource>::is_null_key(raw_key_file_bytes)
    }

    /// `credential_setup`: create the initial staged key (`0.tmp` -> `0`).
    /// Idempotent-ish: overwrites `0` if it already exists, matching the
    /// underlying atomic-rename semantics.
    pub async fn setup(&self) -> Result<(), CredentialFernetError> {
        self.0.setup().await.map_err(Into::into)
    }

    /// Load all active keys, primary first (highest index).
    ///
    /// # Errors
    /// - [`CredentialFernetError::KeysMissing`] if the repository is empty.
    /// - [`CredentialFernetError::NullKeyDetected`] if any key file decodes to
    ///   the Null Key and `insecure_allow_null_key` is `false`.
    pub async fn load(
        &self,
        insecure_allow_null_key: bool,
    ) -> Result<LoadedKeys, CredentialFernetError> {
        self.0
            .load_keys(insecure_allow_null_key)
            .await
            .map_err(Into::into)
    }

    /// Startup-time Null Key check (ADR 0019 §4, Security).
    ///
    /// Unlike [`Self::load`], this does not require any key files to be
    /// present — an unconfigured repository (before `credential_setup` has
    /// run) is not itself a Null Key problem. It only inspects whatever key
    /// files already exist and, for any that decode to the well-known Null
    /// Key, emits a hard warning log and — unless `insecure_allow_null_key`
    /// is set — returns an error so the caller can refuse to start the
    /// service.
    ///
    /// # Errors
    /// [`CredentialFernetError::NullKeyDetected`] if a key file decodes to
    /// the Null Key and `insecure_allow_null_key` is `false`.
    pub async fn check_startup_null_key(
        &self,
        insecure_allow_null_key: bool,
    ) -> Result<(), CredentialFernetError> {
        self.0
            .check_startup_null_key(insecure_allow_null_key)
            .await
            .map_err(Into::into)
    }

    /// Promote the staged key `0` to primary, stage a fresh key `0`, and
    /// prune beyond [`MAX_ACTIVE_KEYS`].
    ///
    /// # Warning
    /// This performs **no safety check**. Calling it while any credential
    /// is still encrypted with a non-primary key can permanently strand
    /// that credential once its key is pruned. Application code must not
    /// call this directly — use [`crate::rotate::rotate`], which performs
    /// the mandatory stale-credential check before promoting.
    pub async fn rotate(&self) -> Result<(), CredentialFernetError> {
        self.0.rotate().await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE;
    use fernet::Fernet;
    use openstack_keystone_key_repository::KeySource as _;

    use super::*;

    #[test]
    fn test_key_hash_matches_python_semantics() {
        // key_hash = SHA-1(raw base64url bytes of the key file), lowercase
        // hex — NOT over the decoded 32-byte key.
        let raw = Fernet::generate_key().into_bytes();
        let hash = FernetKeyRepository::key_hash(&raw);
        assert_eq!(hash.len(), 40);
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );

        // Sanity: hashing the decoded key bytes must NOT produce the same
        // digest — this guards against silently hashing the wrong input.
        let decoded = URL_SAFE.decode(&raw).unwrap();
        assert_ne!(hash, FernetKeyRepository::key_hash(&decoded));
    }

    #[test]
    fn test_is_null_key_detection() {
        let null_key_raw = URL_SAFE.encode([0u8; 32]);
        assert!(FernetKeyRepository::is_null_key(null_key_raw.as_bytes()));

        let real_key_raw = Fernet::generate_key();
        assert!(!FernetKeyRepository::is_null_key(real_key_raw.as_bytes()));
    }

    #[tokio::test]
    async fn test_setup_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let repo = FernetKeyRepository::new(dir.path().to_path_buf());
        repo.setup().await.unwrap();

        let loaded = repo.load(false).await.unwrap();
        assert_eq!(loaded.key_count, 1);

        let plaintext = b"super secret ec2 key";
        let token = loaded.multi_fernet.encrypt(plaintext);
        let decrypted = loaded.multi_fernet.decrypt(&token).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_load_refuses_null_key_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let repo = FernetKeyRepository::new(dir.path().to_path_buf());
        let null_key = URL_SAFE.encode([0u8; 32]);
        std::fs::write(dir.path().join("0"), null_key).unwrap();

        assert!(matches!(
            repo.load(false).await,
            Err(CredentialFernetError::NullKeyDetected)
        ));
        // Explicit opt-in still loads it.
        assert!(repo.load(true).await.is_ok());
    }

    #[tokio::test]
    async fn test_check_startup_null_key_on_unconfigured_repository() {
        let dir = tempfile::tempdir().unwrap();
        let repo = FernetKeyRepository::new(dir.path().join("does-not-exist"));
        // No key files at all (repository not yet set up) is not itself a
        // Null Key problem.
        assert!(repo.check_startup_null_key(false).await.is_ok());
    }

    #[tokio::test]
    async fn test_check_startup_null_key_refuses_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let repo = FernetKeyRepository::new(dir.path().to_path_buf());
        let null_key = URL_SAFE.encode([0u8; 32]);
        std::fs::write(dir.path().join("0"), null_key).unwrap();

        assert!(matches!(
            repo.check_startup_null_key(false).await,
            Err(CredentialFernetError::NullKeyDetected)
        ));
        // Explicit opt-in allows startup to proceed.
        assert!(repo.check_startup_null_key(true).await.is_ok());
    }

    #[tokio::test]
    async fn test_check_startup_null_key_passes_with_real_key() {
        let dir = tempfile::tempdir().unwrap();
        let repo = FernetKeyRepository::new(dir.path().to_path_buf());
        repo.setup().await.unwrap();
        assert!(repo.check_startup_null_key(false).await.is_ok());
    }

    #[tokio::test]
    async fn test_rotate_promotes_staged_key_and_keeps_old_primary_decryptable() {
        let dir = tempfile::tempdir().unwrap();
        let repo = FernetKeyRepository::new(dir.path().to_path_buf());
        repo.setup().await.unwrap();
        // First rotation: 0 -> 1, new 0 staged.
        repo.rotate().await.unwrap();
        assert!(dir.path().join("1").exists());
        assert!(dir.path().join("0").exists());

        let after_first_rotation = repo.load(false).await.unwrap();
        let token_v1 = after_first_rotation.multi_fernet.encrypt(b"payload-v1");
        // key_hash after first rotation must reflect key `1` as primary.
        let key1_raw = std::fs::read(dir.path().join("1")).unwrap();
        assert_eq!(
            after_first_rotation.primary_key_hash,
            FernetKeyRepository::key_hash(&key1_raw)
        );

        // Second rotation: staged 0 -> 2 (not overwriting 1). Old primary
        // (1) must remain in place and still decryptable.
        repo.rotate().await.unwrap();
        assert!(dir.path().join("2").exists());
        assert!(
            dir.path().join("1").exists(),
            "old primary must be retained for decryption"
        );
        assert!(dir.path().join("0").exists(), "a fresh key must be staged");

        let after_second_rotation = repo.load(false).await.unwrap();
        assert_eq!(after_second_rotation.key_count, 3);
        // A blob encrypted with the now-superseded key `1` must still
        // decrypt via MultiFernet.
        let decrypted = after_second_rotation
            .multi_fernet
            .decrypt(&token_v1)
            .unwrap();
        assert_eq!(decrypted, b"payload-v1");
    }

    #[tokio::test]
    async fn test_rotate_prunes_beyond_max_active_keys() {
        let dir = tempfile::tempdir().unwrap();
        let repo = FernetKeyRepository::new(dir.path().to_path_buf());
        repo.setup().await.unwrap();
        // Rotate MAX_ACTIVE_KEYS + 2 times; repository must never exceed
        // MAX_ACTIVE_KEYS files, and the oldest primaries get pruned first.
        for _ in 0..(MAX_ACTIVE_KEYS + 2) {
            repo.rotate().await.unwrap();
        }
        let remaining = repo.0.source().load().await.unwrap();
        assert_eq!(remaining.len(), MAX_ACTIVE_KEYS);
        assert!(
            remaining.contains_key(&0),
            "staged key must always survive pruning"
        );
    }
}
