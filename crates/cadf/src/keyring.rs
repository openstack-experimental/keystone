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

//! Persistent, versioned audit HMAC key material (ADR 0023, #1318).
//!
//! The keyring file holds one 32-byte key-encryption-key (KEK) per key
//! version. Per-node signing keys are derived from a KEK with
//! [`derive_audit_hmac_key`], so only the KEKs are stored. Rotation adds a new
//! version and makes it current; older versions are kept so events already
//! signed (and still sitting in the spool or a SIEM) remain verifiable.
//!
//! # File format
//!
//! Two encodings are read:
//!
//! - **Legacy**: exactly 32 raw bytes, written by earlier releases. It is
//!   treated as a keyring with the single version `1`.
//! - **Keyring**: JSON `{"current": <version>, "keys": {"<version>":
//!   "<64 hex chars>", ..}}`.
//!
//! New and rotated keyrings are always written in the JSON form, atomically
//! (temporary file plus rename) with mode `0600`, so a concurrent reader never
//! sees a partial file.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::ServiceIdentity;
use crate::kdf::derive_audit_hmac_key;
use crate::spool::HmacKeyStore;

/// Length in bytes of a KEK.
const KEK_LEN: usize = 32;
/// The first key version; also the version of a legacy raw-bytes key file.
pub const INITIAL_KEY_VERSION: u64 = 1;

/// Errors raised while loading, creating or rotating the keyring.
#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    #[error("audit key file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "audit key file {path} is neither a 32-byte legacy key nor a valid keyring ({reason}); \
         refusing to overwrite it"
    )]
    Invalid { path: PathBuf, reason: String },
    #[error("audit key file {0} does not exist; start the service once to create it")]
    Missing(PathBuf),
    #[error("cannot generate random key material: {0}")]
    Random(#[from] getrandom::Error),
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> KeyringError + '_ {
    move |source| KeyringError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Serialize, Deserialize)]
struct KeyringFile {
    current: u64,
    keys: BTreeMap<u64, String>,
}

/// All audit KEK versions and which one signs new events.
#[derive(Clone)]
pub struct HmacKeyring {
    current: u64,
    /// Copy of `keks[current]`, kept so the signing key never needs a lookup
    /// that could fail.
    current_kek: [u8; KEK_LEN],
    keks: BTreeMap<u64, [u8; KEK_LEN]>,
}

impl fmt::Debug for HmacKeyring {
    // Never print key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacKeyring")
            .field("current", &self.current)
            .field("versions", &self.keks.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl HmacKeyring {
    fn single(kek: [u8; KEK_LEN]) -> Self {
        Self {
            current: INITIAL_KEY_VERSION,
            current_kek: kek,
            keks: BTreeMap::from([(INITIAL_KEY_VERSION, kek)]),
        }
    }

    /// The version that signs new events.
    pub fn current_version(&self) -> u64 {
        self.current
    }

    /// All known key versions, ascending.
    pub fn versions(&self) -> Vec<u64> {
        self.keks.keys().copied().collect()
    }

    /// The per-node signing key for `version`, if that version is known.
    pub fn node_key(
        &self,
        service: &ServiceIdentity,
        version: u64,
        node_id: &str,
    ) -> Option<[u8; 32]> {
        self.keks
            .get(&version)
            .map(|kek| derive_audit_hmac_key(service, kek, node_id))
    }

    /// The per-node signing key for the current version.
    pub fn current_node_key(&self, service: &ServiceIdentity, node_id: &str) -> [u8; 32] {
        derive_audit_hmac_key(service, &self.current_kek, node_id)
    }

    /// A [`HmacKeyStore`] resolving every version for `node_id`.
    pub fn key_store(&self, service: &ServiceIdentity, node_id: &str) -> NodeKeyStore {
        NodeKeyStore {
            keyring: self.clone(),
            service: *service,
            node_id: node_id.to_string(),
        }
    }

    /// Read the keyring at `path`; `None` if the file does not exist.
    pub fn load(path: &Path) -> Result<Option<Self>, KeyringError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(path)(e)),
        };
        Self::parse(path, &bytes).map(Some)
    }

    fn parse(path: &Path, bytes: &[u8]) -> Result<Self, KeyringError> {
        let invalid = |reason: String| KeyringError::Invalid {
            path: path.to_path_buf(),
            reason,
        };
        if let Ok(kek) = <[u8; KEK_LEN]>::try_from(bytes) {
            return Ok(Self::single(kek));
        }
        let file: KeyringFile = serde_json::from_slice(bytes)
            .map_err(|e| invalid(format!("{} bytes, not JSON: {e}", bytes.len())))?;
        let mut keks = BTreeMap::new();
        for (version, hex_key) in file.keys {
            let raw =
                decode_hex(&hex_key).ok_or_else(|| invalid(format!("key {version} is not hex")))?;
            let kek = <[u8; KEK_LEN]>::try_from(raw.as_slice())
                .map_err(|_| invalid(format!("key {version} is not {KEK_LEN} bytes")))?;
            keks.insert(version, kek);
        }
        let Some(current_kek) = keks.get(&file.current).copied() else {
            return Err(invalid(format!(
                "current version {} has no key",
                file.current
            )));
        };
        Ok(Self {
            current: file.current,
            current_kek,
            keks,
        })
    }

    /// Read the keyring at `path`, creating it with a fresh random version-1
    /// KEK if the file does not exist.
    ///
    /// Creation is race-safe: if another process creates the file first, its
    /// key is used.
    pub fn load_or_create(path: &Path) -> Result<Self, KeyringError> {
        if let Some(existing) = Self::load(path)? {
            return Ok(existing);
        }
        let keyring = Self::single(random_kek()?);
        match keyring.write(path, true) {
            Ok(()) => Ok(keyring),
            Err(KeyringError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                Self::load(path)?.ok_or_else(|| KeyringError::Missing(path.to_path_buf()))
            }
            Err(e) => Err(e),
        }
    }

    /// Add a new random KEK as the next version, make it current and persist
    /// the keyring. Returns the new current version.
    ///
    /// Older versions are kept. The keyring must already exist. Concurrent
    /// rotations are not supported and must be serialised by the operator.
    pub fn rotate(path: &Path) -> Result<u64, KeyringError> {
        let mut keyring =
            Self::load(path)?.ok_or_else(|| KeyringError::Missing(path.to_path_buf()))?;
        let next = keyring.keks.keys().next_back().copied().unwrap_or(0) + 1;
        let kek = random_kek()?;
        keyring.keks.insert(next, kek);
        keyring.current = next;
        keyring.current_kek = kek;
        keyring.write(path, false)?;
        Ok(next)
    }

    /// Persist atomically with mode `0600`. With `create_new` the final path
    /// must not exist yet.
    fn write(&self, path: &Path, create_new: bool) -> Result<(), KeyringError> {
        let file = KeyringFile {
            current: self.current,
            keys: self
                .keks
                .iter()
                .map(|(version, kek)| (*version, encode_hex(kek)))
                .collect(),
        };
        let json = serde_json::to_vec(&file).map_err(|e| KeyringError::Invalid {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(io_err(parent))?;
        }
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        let result = (|| {
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            out.write_all(&json)?;
            out.sync_all()?;
            if create_new {
                // `hard_link` fails if the target exists, unlike `rename`,
                // which would silently replace a key another process just
                // created.
                std::fs::hard_link(&tmp, path)?;
                std::fs::remove_file(&tmp)
            } else {
                std::fs::rename(&tmp, path)
            }
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result.map_err(io_err(path))
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn random_kek() -> Result<[u8; KEK_LEN], KeyringError> {
    let mut raw = [0u8; KEK_LEN];
    getrandom::fill(&mut raw)?;
    Ok(raw)
}

/// Resolves any known key version to the per-node signing key.
pub struct NodeKeyStore {
    keyring: HmacKeyring,
    service: ServiceIdentity,
    node_id: String,
}

impl HmacKeyStore for NodeKeyStore {
    fn get_key(&self, version: u64) -> Option<Arc<[u8]>> {
        self.keyring
            .node_key(&self.service, version, &self.node_id)
            .map(|key| Arc::from(key.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: ServiceIdentity = ServiceIdentity::new("keystone");
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn creates_a_private_version_one_keyring_and_reuses_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys").join("audit.keyring");

        let created = HmacKeyring::load_or_create(&path).unwrap();
        assert_eq!(created.current_version(), 1);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let reloaded = HmacKeyring::load_or_create(&path).unwrap();
        assert_eq!(
            created.current_node_key(&SERVICE, "n"),
            reloaded.current_node_key(&SERVICE, "n")
        );
    }

    #[test]
    fn legacy_raw_key_file_loads_as_version_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hmac-key.bin");
        std::fs::write(&path, [7u8; 32]).unwrap();

        let keyring = HmacKeyring::load(&path).unwrap().unwrap();
        assert_eq!(keyring.versions(), vec![1]);
        // Same key as the pre-keyring releases derived.
        assert_eq!(
            keyring.current_node_key(&SERVICE, "n"),
            derive_audit_hmac_key(&SERVICE, &[7u8; 32], "n")
        );
        // The file is left untouched until a rotation.
        assert_eq!(std::fs::read(&path).unwrap(), vec![7u8; 32]);
    }

    #[test]
    fn rotate_adds_a_version_and_keeps_the_old_ones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.keyring");
        std::fs::write(&path, [7u8; 32]).unwrap();

        assert_eq!(HmacKeyring::rotate(&path).unwrap(), 2);
        assert_eq!(HmacKeyring::rotate(&path).unwrap(), 3);

        let keyring = HmacKeyring::load(&path).unwrap().unwrap();
        assert_eq!(keyring.current_version(), 3);
        assert_eq!(keyring.versions(), vec![1, 2, 3]);
        // Version 1 is still the legacy key, so old events stay verifiable.
        assert_eq!(
            keyring.node_key(&SERVICE, 1, "n").unwrap(),
            derive_audit_hmac_key(&SERVICE, &[7u8; 32], "n")
        );
        assert_ne!(
            keyring.node_key(&SERVICE, 2, "n"),
            keyring.node_key(&SERVICE, 3, "n")
        );
        assert_eq!(
            keyring.key_store(&SERVICE, "n").get_key(2).unwrap().len(),
            32
        );
        assert!(keyring.key_store(&SERVICE, "n").get_key(9).is_none());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn rotate_requires_an_existing_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let err = HmacKeyring::rotate(&dir.path().join("none")).unwrap_err();
        assert!(matches!(err, KeyringError::Missing(_)), "got {err}");
    }

    #[test]
    fn garbage_is_rejected_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.keyring");
        std::fs::write(&path, b"too-short").unwrap();

        assert!(matches!(
            HmacKeyring::load_or_create(&path),
            Err(KeyringError::Invalid { .. })
        ));
        assert!(HmacKeyring::rotate(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"too-short");
    }

    #[test]
    fn current_version_must_have_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.keyring");
        std::fs::write(&path, br#"{"current": 2, "keys": {}}"#).unwrap();
        assert!(matches!(
            HmacKeyring::load(&path),
            Err(KeyringError::Invalid { .. })
        ));
    }

    #[test]
    fn debug_output_hides_key_material() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.keyring");
        std::fs::write(&path, [0xabu8; 32]).unwrap();
        let keyring = HmacKeyring::load(&path).unwrap().unwrap();
        let shown = format!("{keyring:?}");
        assert!(!shown.contains("abab"), "{shown}");
    }
}
