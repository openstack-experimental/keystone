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
//! Separate from `[fernet_tokens] key_repository`. Hard-capped at
//! [`MAX_ACTIVE_KEYS`] active keys, matching the Python Keystone constant —
//! unlike token Fernet keys this is intentionally not configurable.
//!
//! Rotation is staged-key promotion, not primary renumbering: the staged key
//! `0` is renamed to `old_primary + 1` (becoming the new primary), the old
//! primary is left in place for decryption, a fresh key is staged as the new
//! `0`, and files beyond [`MAX_ACTIVE_KEYS`] are pruned.
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE;
use fernet::{Fernet, MultiFernet};
use nix::sys::stat::{Mode, umask};
use sha1::{Digest, Sha1};
use tempfile::NamedTempFile;
use tracing::{info, warn};

use crate::error::CredentialFernetError;

/// The credential Fernet key repository is hard-capped at this many active
/// keys (ADR 0019 §4). Intentionally not configurable.
pub const MAX_ACTIVE_KEYS: usize = 3;

/// A loaded, ready-to-use view of the key repository.
pub struct LoadedKeys {
    /// All active keys, primary first, wrapped for
    /// decrypt-any/encrypt-with-primary use.
    pub multi_fernet: MultiFernet,

    /// SHA-1 hex digest of the *raw base64url bytes* of the primary key
    /// file (ADR 0019 §4, `key_hash` Specification) — not the decoded
    /// 32-byte AES key.
    pub primary_key_hash: String,

    /// Number of active key files loaded.
    pub key_count: usize,
}

/// The Fernet key repository on the local filesystem.
///
/// Per ADR 0019 §4, this directory must resolve to the identical file set on
/// every Python and Rust node — that synchronization is an operational
/// deployment requirement, not something this type enforces.
#[derive(Clone, Debug)]
pub struct FernetKeyRepository {
    pub key_repository: PathBuf,
}

impl FernetKeyRepository {
    /// Create a new repository handle for the given directory.
    pub fn new(key_repository: PathBuf) -> Self {
        Self { key_repository }
    }

    /// Compute `key_hash` per the ADR 0019 §4 specification: SHA-1 hex
    /// digest over the raw base64url-encoded key-file bytes, as read from
    /// disk (i.e. *before* base64url-decoding).
    #[must_use]
    pub fn key_hash(raw_key_file_bytes: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(raw_key_file_bytes);
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Whether the given raw (base64url-encoded) key-file bytes decode to
    /// the well-known Null Key (32 zero bytes).
    #[must_use]
    pub fn is_null_key(raw_key_file_bytes: &[u8]) -> bool {
        match URL_SAFE.decode(raw_key_file_bytes) {
            Ok(decoded) => decoded.len() == 32 && decoded.iter().all(|b| *b == 0),
            Err(_) => false,
        }
    }

    /// Read all integer-named key files, keyed by their file-name index.
    /// The raw bytes are exactly as read from disk with a single trailing
    /// newline stripped (matching Python's `hashlib.sha1(keys[0]).hexdigest()`
    /// over the file's content stripped of its trailing newline).
    fn read_key_files(&self) -> Result<BTreeMap<i8, Vec<u8>>, CredentialFernetError> {
        let mut keys = BTreeMap::new();
        if !self.key_repository.exists() {
            return Ok(keys);
        }
        for entry in fs::read_dir(&self.key_repository).map_err(|e| CredentialFernetError::Io {
            source: e,
            path: self.key_repository.clone(),
        })? {
            let entry = entry.map_err(|e| CredentialFernetError::Io {
                source: e,
                path: self.key_repository.clone(),
            })?;
            let Ok(fname) = entry.file_name().into_string() else {
                continue;
            };
            let Ok(idx) = fname.parse::<i8>() else {
                continue;
            };
            let mut raw = fs::read(entry.path()).map_err(|e| CredentialFernetError::Io {
                source: e,
                path: entry.path(),
            })?;
            if raw.last() == Some(&b'\n') {
                raw.pop();
            }
            keys.insert(idx, raw);
        }
        Ok(keys)
    }

    /// Atomically write `contents` to `key_repository/<name>` using a
    /// temp-file-then-rename strategy with `umask 0o177` (ADR 0019 §4,
    /// Security).
    fn write_key_file(&self, name: &str, contents: &[u8]) -> Result<(), CredentialFernetError> {
        fs::create_dir_all(&self.key_repository).map_err(|e| CredentialFernetError::Io {
            source: e,
            path: self.key_repository.clone(),
        })?;
        let old_umask = umask(Mode::from_bits_truncate(0o177));
        let _umask_guard = scopeguard::guard(old_umask, |old| {
            umask(old);
        });

        let mut tmp_file =
            NamedTempFile::new_in(&self.key_repository).map_err(|e| CredentialFernetError::Io {
                source: e,
                path: self.key_repository.clone(),
            })?;
        tmp_file
            .write_all(contents)
            .map_err(|e| CredentialFernetError::Io {
                source: e,
                path: self.key_repository.clone(),
            })?;
        tmp_file.flush().map_err(|e| CredentialFernetError::Io {
            source: e,
            path: self.key_repository.clone(),
        })?;
        tmp_file
            .persist(self.key_repository.join(name))
            .map_err(|e| CredentialFernetError::Persist(e.to_string()))?;
        Ok(())
    }

    /// `credential_setup`: create the initial staged key (`0.tmp` -> `0`).
    /// Idempotent-ish: overwrites `0` if it already exists, matching the
    /// underlying atomic-rename semantics.
    pub fn setup(&self) -> Result<(), CredentialFernetError> {
        let key = Fernet::generate_key();
        self.write_key_file("0", key.as_bytes())?;
        info!("Created new credential Fernet staged key at index 0");
        Ok(())
    }

    /// Load all active keys, primary first (highest index).
    ///
    /// # Errors
    /// - [`CredentialFernetError::KeysMissing`] if the repository is empty.
    /// - [`CredentialFernetError::NullKeyDetected`] if any key file decodes to
    ///   the Null Key and `insecure_allow_null_key` is `false`.
    pub fn load(&self, insecure_allow_null_key: bool) -> Result<LoadedKeys, CredentialFernetError> {
        let key_files = self.read_key_files()?;
        if key_files.is_empty() {
            return Err(CredentialFernetError::KeysMissing);
        }

        for (idx, raw) in &key_files {
            if Self::is_null_key(raw) {
                if insecure_allow_null_key {
                    warn!(
                        key_index = idx,
                        "credential key repository contains the well-known Null Key \
                         (insecure_allow_null_key=true — any credential encrypted with it \
                         is effectively stored in plaintext)"
                    );
                } else {
                    return Err(CredentialFernetError::NullKeyDetected);
                }
            }
        }

        let mut fernets = Vec::with_capacity(key_files.len());
        let mut primary_key_hash = None;
        // Highest index first == primary first.
        for (_idx, raw) in key_files.iter().rev() {
            let key_str = String::from_utf8_lossy(raw);
            let fernet =
                Fernet::new(key_str.trim()).ok_or(CredentialFernetError::InvalidKey(*_idx))?;
            if primary_key_hash.is_none() {
                primary_key_hash = Some(Self::key_hash(raw));
            }
            fernets.push(fernet);
        }

        Ok(LoadedKeys {
            multi_fernet: MultiFernet::new(fernets),
            primary_key_hash: primary_key_hash.ok_or(CredentialFernetError::KeysMissing)?,
            key_count: key_files.len(),
        })
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
    pub fn rotate(&self) -> Result<(), CredentialFernetError> {
        let key_files = self.read_key_files()?;
        if !key_files.contains_key(&0) {
            return Err(CredentialFernetError::KeysMissing);
        }

        let old_primary_idx = key_files
            .keys()
            .copied()
            .filter(|i| *i != 0)
            .max()
            .unwrap_or(0);
        let new_primary_idx = old_primary_idx
            .checked_add(1)
            .ok_or(CredentialFernetError::IndexOverflow)?;

        // 1. Promote: rename staged `0` -> new_primary_idx. This is a rename of the
        //    *staged* file, not the outgoing primary — the outgoing primary keeps its
        //    own file name and stays active for decryption.
        fs::rename(
            self.key_repository.join("0"),
            self.key_repository.join(new_primary_idx.to_string()),
        )
        .map_err(|e| CredentialFernetError::Io {
            source: e,
            path: self.key_repository.clone(),
        })?;

        // 2. Stage a fresh key `0` for the next rotation cycle.
        self.setup()?;

        // 3. Prune beyond MAX_ACTIVE_KEYS, oldest (smallest positive index) first. `0`
        //    (staged) is never pruned.
        let mut remaining = self.read_key_files()?;
        remaining.remove(&0);
        while remaining.len() + 1 > MAX_ACTIVE_KEYS {
            if let Some((&oldest, _)) = remaining.iter().min_by_key(|(idx, _)| **idx) {
                fs::remove_file(self.key_repository.join(oldest.to_string())).map_err(|e| {
                    CredentialFernetError::Io {
                        source: e,
                        path: self.key_repository.clone(),
                    }
                })?;
                remaining.remove(&oldest);
            } else {
                break;
            }
        }

        info!(
            new_primary = new_primary_idx,
            "Rotated credential Fernet key repository"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn test_setup_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let repo = FernetKeyRepository::new(dir.path().to_path_buf());
        repo.setup().unwrap();

        let loaded = repo.load(false).unwrap();
        assert_eq!(loaded.key_count, 1);

        let plaintext = b"super secret ec2 key";
        let token = loaded.multi_fernet.encrypt(plaintext);
        let decrypted = loaded.multi_fernet.decrypt(&token).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_load_refuses_null_key_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let repo = FernetKeyRepository::new(dir.path().to_path_buf());
        let null_key = URL_SAFE.encode([0u8; 32]);
        std::fs::write(dir.path().join("0"), null_key).unwrap();

        assert!(matches!(
            repo.load(false),
            Err(CredentialFernetError::NullKeyDetected)
        ));
        // Explicit opt-in still loads it.
        assert!(repo.load(true).is_ok());
    }

    #[test]
    fn test_rotate_promotes_staged_key_and_keeps_old_primary_decryptable() {
        let dir = tempfile::tempdir().unwrap();
        let repo = FernetKeyRepository::new(dir.path().to_path_buf());
        repo.setup().unwrap();
        // First rotation: 0 -> 1, new 0 staged.
        repo.rotate().unwrap();
        assert!(dir.path().join("1").exists());
        assert!(dir.path().join("0").exists());

        let after_first_rotation = repo.load(false).unwrap();
        let token_v1 = after_first_rotation.multi_fernet.encrypt(b"payload-v1");
        // key_hash after first rotation must reflect key `1` as primary.
        let key1_raw = std::fs::read(dir.path().join("1")).unwrap();
        assert_eq!(
            after_first_rotation.primary_key_hash,
            FernetKeyRepository::key_hash(&key1_raw)
        );

        // Second rotation: staged 0 -> 2 (not overwriting 1). Old primary
        // (1) must remain in place and still decryptable.
        repo.rotate().unwrap();
        assert!(dir.path().join("2").exists());
        assert!(
            dir.path().join("1").exists(),
            "old primary must be retained for decryption"
        );
        assert!(dir.path().join("0").exists(), "a fresh key must be staged");

        let after_second_rotation = repo.load(false).unwrap();
        assert_eq!(after_second_rotation.key_count, 3);
        // A blob encrypted with the now-superseded key `1` must still
        // decrypt via MultiFernet.
        let decrypted = after_second_rotation
            .multi_fernet
            .decrypt(&token_v1)
            .unwrap();
        assert_eq!(decrypted, b"payload-v1");
    }

    #[test]
    fn test_rotate_prunes_beyond_max_active_keys() {
        let dir = tempfile::tempdir().unwrap();
        let repo = FernetKeyRepository::new(dir.path().to_path_buf());
        repo.setup().unwrap();
        // Rotate MAX_ACTIVE_KEYS + 2 times; repository must never exceed
        // MAX_ACTIVE_KEYS files, and the oldest primaries get pruned first.
        for _ in 0..(MAX_ACTIVE_KEYS + 2) {
            repo.rotate().unwrap();
        }
        let remaining = repo.read_key_files().unwrap();
        assert_eq!(remaining.len(), MAX_ACTIVE_KEYS);
        assert!(
            remaining.contains_key(&0),
            "staged key must always survive pruning"
        );
    }
}
