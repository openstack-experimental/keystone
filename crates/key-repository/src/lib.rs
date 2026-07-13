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
//! # Shared Fernet key repository
//!
//! Both the credential provider (ADR 0019 §4) and the Fernet token provider
//! need the exact same thing: a directory of integer-indexed Fernet key
//! files, with index `0` always the staged key, the highest other index the
//! primary, and a `rotate` operation that promotes the staged key and prunes
//! beyond a configured maximum. This crate implements that once.
//!
//! The backend is abstracted behind [`KeySource`] so a future Vault-backed
//! (or other KV secret store) implementation can plug in without changing
//! [`KeyRepository`] or [`CachedKeyRepository`] at all — see [`filesystem`]
//! for the only implementation that exists today.
//!
//! [`KeyRepository`] is the mechanical, backend-agnostic operations
//! (`setup`/`load_keys`/`rotate`/Null Key checks). Driver-specific safety
//! checks that need other context (e.g. the credential driver's "refuse to
//! rotate while any credential is still encrypted with a non-primary key,
//! which needs a database query) stay in the driver crate, wrapping this
//! type rather than being reimplemented here.
use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE;
use fernet::{Fernet, MultiFernet};
use sha1::{Digest, Sha1};
use tokio::sync::watch;
use tracing::info;

pub mod error;
pub mod filesystem;
mod source;

pub use error::KeyRepositoryError;
pub use filesystem::FilesystemKeySource;
pub use source::KeySource;

/// A loaded, ready-to-use view of the key repository.
pub struct LoadedKeys {
    /// All active keys, primary first, wrapped for
    /// decrypt-any/encrypt-with-primary use.
    pub multi_fernet: MultiFernet,

    /// SHA-1 hex digest of the *raw base64url bytes* of the primary key
    /// entry (ADR 0019 §4 `key_hash` specification) — not the decoded
    /// 32-byte AES key.
    pub primary_key_hash: String,

    /// Number of active keys loaded.
    pub key_count: usize,
}

/// Backend-agnostic Fernet key repository logic, generic over the
/// underlying [`KeySource`].
pub struct KeyRepository<S: KeySource> {
    source: S,
    max_active_keys: usize,
}

impl<S: KeySource> KeyRepository<S> {
    /// Wrap `source`, hard-capping active keys at `max_active_keys` on
    /// [`Self::rotate`].
    pub fn new(source: S, max_active_keys: usize) -> Self {
        Self {
            source,
            max_active_keys,
        }
    }

    /// The wrapped source, e.g. to call [`KeySource::subscribe`] directly.
    pub fn source(&self) -> &S {
        &self.source
    }

    /// Compute `key_hash` per the ADR 0019 §4 specification: SHA-1 hex
    /// digest over the raw base64url-encoded key bytes, as read from the
    /// source (i.e. *before* base64url-decoding).
    #[must_use]
    pub fn key_hash(raw_key_bytes: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(raw_key_bytes);
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Whether the given raw (base64url-encoded) key bytes decode to the
    /// well-known Null Key (32 zero bytes).
    #[must_use]
    pub fn is_null_key(raw_key_bytes: &[u8]) -> bool {
        match URL_SAFE.decode(raw_key_bytes) {
            Ok(decoded) => decoded.len() == 32 && decoded.iter().all(|b| *b == 0),
            Err(_) => false,
        }
    }

    /// `{credential,token}_setup`: create the initial staged key at index
    /// `0`. Idempotent-ish: overwrites `0` if it already exists, matching
    /// the underlying atomic-write semantics.
    pub async fn setup(&self) -> Result<(), KeyRepositoryError> {
        let key = Fernet::generate_key();
        self.source.write(0, key.as_bytes()).await?;
        info!("Created new staged Fernet key at index 0");
        Ok(())
    }

    /// Load all active keys, primary first (highest index).
    ///
    /// # Errors
    /// - [`KeyRepositoryError::KeysMissing`] if the repository is empty.
    /// - [`KeyRepositoryError::NullKeyDetected`] if any key decodes to the Null
    ///   Key and `insecure_allow_null_key` is `false`.
    pub async fn load_keys(
        &self,
        insecure_allow_null_key: bool,
    ) -> Result<LoadedKeys, KeyRepositoryError> {
        let key_files = self.source.load().await?;
        if key_files.is_empty() {
            return Err(KeyRepositoryError::KeysMissing);
        }
        self.check_null_keys(&key_files, insecure_allow_null_key)?;

        let mut fernets = Vec::with_capacity(key_files.len());
        let mut primary_key_hash = None;
        // Highest index first == primary first.
        for (idx, raw) in key_files.iter().rev() {
            let key_str = String::from_utf8_lossy(raw);
            let fernet = Fernet::new(key_str.trim()).ok_or(KeyRepositoryError::InvalidKey(*idx))?;
            if primary_key_hash.is_none() {
                primary_key_hash = Some(Self::key_hash(raw));
            }
            fernets.push(fernet);
        }

        Ok(LoadedKeys {
            multi_fernet: MultiFernet::new(fernets),
            primary_key_hash: primary_key_hash.ok_or(KeyRepositoryError::KeysMissing)?,
            key_count: key_files.len(),
        })
    }

    /// Startup-time Null Key check (ADR 0019 §4, Security).
    ///
    /// Unlike [`Self::load_keys`], this does not require any keys to be
    /// present — an unconfigured repository (before `setup` has run) is not
    /// itself a Null Key problem. It only inspects whatever keys already
    /// exist and, for any that decode to the well-known Null Key, emits a
    /// hard error log and — unless `insecure_allow_null_key` is set —
    /// returns an error so the caller can refuse to start the service.
    ///
    /// # Errors
    /// [`KeyRepositoryError::NullKeyDetected`] if a key decodes to the Null
    /// Key and `insecure_allow_null_key` is `false`.
    pub async fn check_startup_null_key(
        &self,
        insecure_allow_null_key: bool,
    ) -> Result<(), KeyRepositoryError> {
        let key_files = self.source.load().await?;
        self.check_null_keys(&key_files, insecure_allow_null_key)
    }

    fn check_null_keys(
        &self,
        key_files: &BTreeMap<i8, Vec<u8>>,
        insecure_allow_null_key: bool,
    ) -> Result<(), KeyRepositoryError> {
        for (idx, raw) in key_files {
            if Self::is_null_key(raw) {
                tracing::error!(
                    key_index = idx,
                    insecure_allow_null_key,
                    "key repository contains the well-known Null Key"
                );
                if !insecure_allow_null_key {
                    return Err(KeyRepositoryError::NullKeyDetected);
                }
            }
        }
        Ok(())
    }

    /// Promote the staged key `0` to primary, stage a fresh key `0`, and
    /// prune beyond `max_active_keys`.
    ///
    /// # Warning
    /// This performs **no safety check** beyond the mechanics themselves.
    /// Calling it while any data is still encrypted with a non-primary key
    /// can permanently strand that data once its key is pruned — driver
    /// crates that need such a check (e.g. the credential driver, which
    /// must check the database for stale-key credentials) must perform it
    /// before calling this.
    pub async fn rotate(&self) -> Result<(), KeyRepositoryError> {
        let key_files = self.source.load().await?;
        let staged = key_files
            .get(&0)
            .ok_or(KeyRepositoryError::KeysMissing)?
            .clone();

        let old_primary_idx = key_files
            .keys()
            .copied()
            .filter(|i| *i != 0)
            .max()
            .unwrap_or(0);
        let new_primary_idx = old_primary_idx
            .checked_add(1)
            .ok_or(KeyRepositoryError::IndexOverflow)?;

        // 1. Promote: move staged `0` -> new_primary_idx. The outgoing primary keeps
        //    its own entry and stays active for decryption.
        self.source.promote(0, new_primary_idx, &staged).await?;

        // 2. Stage a fresh key `0` for the next rotation cycle.
        self.setup().await?;

        // 3. Prune beyond max_active_keys, oldest (smallest positive index) first. `0`
        //    (staged) is never pruned.
        let mut remaining = self.source.load().await?;
        remaining.remove(&0);
        while remaining.len() + 1 > self.max_active_keys {
            let Some((&oldest, _)) = remaining.iter().min_by_key(|(idx, _)| **idx) else {
                break;
            };
            self.source.remove(oldest).await?;
            remaining.remove(&oldest);
        }

        info!(
            new_primary = new_primary_idx,
            "Rotated Fernet key repository"
        );
        Ok(())
    }
}

/// A [`KeyRepository`] wrapped with an always-fresh, cheaply-cloneable
/// snapshot kept up to date by a background task subscribed to
/// [`KeySource::subscribe`].
///
/// This replaces two anti-patterns that existed before this crate: reading
/// every key file from disk on every single encrypt/decrypt call, and
/// loading keys once at startup and never picking up a subsequent rotation
/// without a process restart.
pub struct CachedKeyRepository<S: KeySource + 'static> {
    repo: Arc<KeyRepository<S>>,
    keys: watch::Receiver<Arc<LoadedKeys>>,
    refresh_handle: tokio::task::JoinHandle<()>,
}

impl<S: KeySource + 'static> CachedKeyRepository<S> {
    /// Load the initial snapshot and spawn the background refresh task.
    /// Must be called from within a Tokio runtime.
    ///
    /// # Errors
    /// Whatever [`KeyRepository::load_keys`] returns for the initial load.
    pub async fn start(
        repo: KeyRepository<S>,
        insecure_allow_null_key: bool,
    ) -> Result<Self, KeyRepositoryError> {
        let repo = Arc::new(repo);
        let initial = repo.load_keys(insecure_allow_null_key).await?;
        let (tx, rx) = watch::channel(Arc::new(initial));

        let mut changes = repo.source().subscribe();
        let repo_for_task = Arc::clone(&repo);
        let handle = tokio::spawn(async move {
            loop {
                // `Lagged` just means we missed some notifications while
                // busy — since a reload always fetches the *current* state
                // rather than replaying a diff, it's safe (and correct) to
                // treat it the same as a normal notification rather than
                // tearing down the refresh loop.
                match changes.recv().await {
                    Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
                match repo_for_task.load_keys(insecure_allow_null_key).await {
                    Ok(loaded) => {
                        let _ = tx.send(Arc::new(loaded));
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to reload Fernet keys; keeping previous snapshot");
                    }
                }
            }
        });

        Ok(Self {
            repo,
            keys: rx,
            refresh_handle: handle,
        })
    }

    /// The current snapshot. Cheap (an `Arc` clone); safe to call on every
    /// encrypt/decrypt.
    pub fn current(&self) -> Arc<LoadedKeys> {
        self.keys.borrow().clone()
    }

    /// The underlying repository, e.g. to call [`KeyRepository::rotate`].
    pub fn repository(&self) -> &KeyRepository<S> {
        &self.repo
    }
}

impl<S: KeySource + 'static> Drop for CachedKeyRepository<S> {
    fn drop(&mut self) {
        // Signal the source's background resources (e.g. a filesystem
        // watcher task) to stop immediately. Synchronous, unlike waiting for
        // `refresh_handle`'s abort below to actually release its
        // `Arc<KeyRepository<S>>` clone — that happens whenever the runtime
        // gets around to dropping the aborted task, not right away.
        self.repo.source().request_shutdown();
        // Abort the background refresh task so it releases its Arc ref to
        // the KeyRepository, letting the source (and its broadcast sender)
        // actually drop once this function returns.
        self.refresh_handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn repo(dir: &std::path::Path, max_active_keys: usize) -> KeyRepository<FilesystemKeySource> {
        KeyRepository::new(FilesystemKeySource::new(dir.to_path_buf()), max_active_keys)
    }

    #[test]
    fn test_key_hash_matches_python_semantics() {
        let raw = Fernet::generate_key().into_bytes();
        let hash = KeyRepository::<FilesystemKeySource>::key_hash(&raw);
        assert_eq!(hash.len(), 40);
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );

        let decoded = URL_SAFE.decode(&raw).unwrap();
        assert_ne!(
            hash,
            KeyRepository::<FilesystemKeySource>::key_hash(&decoded)
        );
    }

    #[test]
    fn test_is_null_key_detection() {
        let null_key_raw = URL_SAFE.encode([0u8; 32]);
        assert!(KeyRepository::<FilesystemKeySource>::is_null_key(
            null_key_raw.as_bytes()
        ));
        let real_key_raw = Fernet::generate_key();
        assert!(!KeyRepository::<FilesystemKeySource>::is_null_key(
            real_key_raw.as_bytes()
        ));
    }

    #[tokio::test]
    async fn test_setup_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repo(dir.path(), 3);
        repo.setup().await.unwrap();

        let loaded = repo.load_keys(false).await.unwrap();
        assert_eq!(loaded.key_count, 1);

        let plaintext = b"super secret payload";
        let token = loaded.multi_fernet.encrypt(plaintext);
        assert_eq!(loaded.multi_fernet.decrypt(&token).unwrap(), plaintext);
    }

    #[tokio::test]
    async fn test_load_keys_refuses_null_key_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repo(dir.path(), 3);
        let null_key = URL_SAFE.encode([0u8; 32]);
        std::fs::write(dir.path().join("0"), null_key).unwrap();

        assert!(matches!(
            repo.load_keys(false).await,
            Err(KeyRepositoryError::NullKeyDetected)
        ));
        assert!(repo.load_keys(true).await.is_ok());
    }

    #[tokio::test]
    async fn test_check_startup_null_key_on_unconfigured_repository() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repo(&dir.path().join("does-not-exist"), 3);
        assert!(repo.check_startup_null_key(false).await.is_ok());
    }

    #[tokio::test]
    async fn test_check_startup_null_key_refuses_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repo(dir.path(), 3);
        let null_key = URL_SAFE.encode([0u8; 32]);
        std::fs::write(dir.path().join("0"), null_key).unwrap();

        assert!(matches!(
            repo.check_startup_null_key(false).await,
            Err(KeyRepositoryError::NullKeyDetected)
        ));
        assert!(repo.check_startup_null_key(true).await.is_ok());
    }

    #[tokio::test]
    async fn test_rotate_promotes_staged_key_and_keeps_old_primary_decryptable() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repo(dir.path(), 3);
        repo.setup().await.unwrap();
        repo.rotate().await.unwrap();
        assert!(dir.path().join("1").exists());
        assert!(dir.path().join("0").exists());

        let after_first = repo.load_keys(false).await.unwrap();
        let token_v1 = after_first.multi_fernet.encrypt(b"payload-v1");
        let key1_raw = std::fs::read(dir.path().join("1")).unwrap();
        assert_eq!(
            after_first.primary_key_hash,
            KeyRepository::<FilesystemKeySource>::key_hash(&key1_raw)
        );

        repo.rotate().await.unwrap();
        assert!(dir.path().join("2").exists());
        assert!(
            dir.path().join("1").exists(),
            "old primary must be retained for decryption"
        );
        assert!(dir.path().join("0").exists(), "a fresh key must be staged");

        let after_second = repo.load_keys(false).await.unwrap();
        assert_eq!(after_second.key_count, 3);
        assert_eq!(
            after_second.multi_fernet.decrypt(&token_v1).unwrap(),
            b"payload-v1"
        );
    }

    #[tokio::test]
    async fn test_rotate_prunes_beyond_max_active_keys() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repo(dir.path(), 3);
        repo.setup().await.unwrap();
        for _ in 0..5 {
            repo.rotate().await.unwrap();
        }
        let remaining = repo.source().load().await.unwrap();
        assert_eq!(remaining.len(), 3);
        assert!(
            remaining.contains_key(&0),
            "staged key must always survive pruning"
        );
    }

    #[tokio::test]
    async fn test_rotate_without_setup_fails() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repo(dir.path(), 3);
        assert!(matches!(
            repo.rotate().await,
            Err(KeyRepositoryError::KeysMissing)
        ));
    }

    #[tokio::test]
    async fn test_cached_repository_reflects_rotation_without_manual_reload() {
        let dir = tempfile::tempdir().unwrap();
        let repo = KeyRepository::new(
            FilesystemKeySource::watched(dir.path().to_path_buf(), Duration::from_millis(100)),
            3,
        );
        repo.setup().await.unwrap();

        let cached = CachedKeyRepository::start(repo, false).await.unwrap();
        assert_eq!(cached.current().key_count, 1);

        cached.repository().rotate().await.unwrap();

        // Poll until the background task has picked up the rotation.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if cached.current().key_count == 2 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "cached snapshot never picked up the rotation"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        drop(cached);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
