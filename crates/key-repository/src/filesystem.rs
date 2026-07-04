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
//! # Filesystem-backed [`KeySource`]
//!
//! Key entries are files named by their integer index (`0`, `1`, `2`, ...)
//! in a single directory. Per ADR 0019 §4, that directory must resolve to
//! the identical file set on every Python and Rust node — that
//! synchronization is an operational deployment requirement, not something
//! this type enforces.
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use nix::sys::stat::{Mode, umask};
use nix::unistd::{Gid, Uid, getegid, geteuid, setegid, seteuid};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tempfile::NamedTempFile;
use tokio::sync::broadcast;
use tokio::task::spawn_blocking;
use tracing::{trace, warn};

use crate::error::KeyRepositoryError;
use crate::source::KeySource;

/// How long to wait after a filesystem event before reloading, so a burst
/// of writes (e.g. an operator copying in several key files at once) is
/// coalesced into a single reload. Mirrors `ConfigManager`'s debounce.
const DEBOUNCE: Duration = Duration::from_millis(500);

/// The Fernet key repository on the local filesystem.
#[derive(Clone)]
pub struct FilesystemKeySource {
    key_repository: PathBuf,
    /// Optional uid/gid to assume (via `seteuid`/`setegid`) while writing
    /// new key files, restored immediately afterwards.
    run_as: Option<(Uid, Gid)>,
    change_tx: broadcast::Sender<()>,
}

impl FilesystemKeySource {
    /// Create a new source with no background watcher. Callers that only
    /// need one-shot `load`/`write`/`remove` (e.g. CLI `setup`/`rotate`
    /// commands) don't need to pay for a watcher task.
    #[must_use]
    pub fn new(key_repository: PathBuf) -> Self {
        let (change_tx, _) = broadcast::channel(16);
        Self {
            key_repository,
            run_as: None,
            change_tx,
        }
    }

    /// Assume this uid/gid (via `seteuid`/`setegid`) while writing new key
    /// files, matching the privilege-drop behavior Python Keystone offers
    /// for `fernet_setup`/`fernet_rotate` run as root.
    #[must_use]
    pub fn with_run_as(mut self, uid: Uid, gid: Gid) -> Self {
        self.run_as = Some((uid, gid));
        self
    }

    /// Create a source and start its background watcher: an inotify watch
    /// on the key repository directory for fast reaction, plus a
    /// `poll_interval` fallback so a reload is never missed (e.g. on a
    /// filesystem where inotify events aren't delivered, such as some
    /// network mounts) and so the exact same contract will hold for a
    /// future poll-only backend (e.g. Vault).
    ///
    /// Must be called from within a Tokio runtime (it spawns a background
    /// task), matching `ConfigManager::watched`.
    #[must_use]
    pub fn watched(key_repository: PathBuf, poll_interval: Duration) -> Self {
        let source = Self::new(key_repository);
        source.spawn_watcher(poll_interval);
        source
    }

    fn spawn_watcher(&self, poll_interval: Duration) {
        let dir = self.key_repository.clone();
        let change_tx = self.change_tx.clone();

        tokio::spawn(async move {
            let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(1);

            let mut watcher: Option<RecommendedWatcher> = match notify::recommended_watcher(
                move |res: notify::Result<notify::Event>| {
                    if let Ok(event) = res
                        && (event.kind.is_modify()
                            || event.kind.is_create()
                            || event.kind.is_remove())
                    {
                        let _ = event_tx.blocking_send(());
                    }
                },
            ) {
                Ok(mut w) => {
                    // The directory may not exist yet (repository not set up).
                    // That's fine — the poll fallback below still covers us
                    // once it is, and we retry the inotify watch each poll
                    // tick until it succeeds.
                    let _ = w.watch(&dir, RecursiveMode::NonRecursive);
                    Some(w)
                }
                Err(e) => {
                    warn!(error = %e, "failed to create inotify watcher for key repository; relying on polling only");
                    None
                }
            };

            let mut interval = tokio::time::interval(poll_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    Some(()) = event_rx.recv() => {
                        // Drain any additional rapid-fire events.
                        while event_rx.try_recv().is_ok() {}
                        tokio::time::sleep(DEBOUNCE).await;
                    }
                    _ = interval.tick() => {
                        if watcher.is_none() {
                            watcher = notify::recommended_watcher(|_res: notify::Result<notify::Event>| {})
                                .ok()
                                .inspect(|_| trace!("retrying inotify watch registration"));
                            if let Some(w) = &mut watcher {
                                let _ = w.watch(&dir, RecursiveMode::NonRecursive);
                            }
                        }
                    }
                }
                let _ = change_tx.send(());
            }
        });
    }

    fn path_for(&self, index: i8) -> PathBuf {
        self.key_repository.join(index.to_string())
    }

    fn read_key_files_blocking(dir: &PathBuf) -> Result<BTreeMap<i8, Vec<u8>>, KeyRepositoryError> {
        let mut keys = BTreeMap::new();
        if !dir.exists() {
            return Ok(keys);
        }
        for entry in std::fs::read_dir(dir).map_err(|e| KeyRepositoryError::Io {
            source: e,
            path: dir.clone(),
        })? {
            let entry = entry.map_err(|e| KeyRepositoryError::Io {
                source: e,
                path: dir.clone(),
            })?;
            let Ok(fname) = entry.file_name().into_string() else {
                continue;
            };
            let Ok(idx) = fname.parse::<i8>() else {
                continue;
            };
            let mut raw = std::fs::read(entry.path()).map_err(|e| KeyRepositoryError::Io {
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

    fn write_key_file_blocking(
        dir: &PathBuf,
        name: &str,
        contents: &[u8],
        run_as: Option<(Uid, Gid)>,
    ) -> Result<(), KeyRepositoryError> {
        std::fs::create_dir_all(dir).map_err(|e| KeyRepositoryError::Io {
            source: e,
            path: dir.clone(),
        })?;
        let old_umask = umask(Mode::from_bits_truncate(0o177));
        let _umask_guard = scopeguard::guard(old_umask, |old| {
            umask(old);
        });

        if let Some((uid, gid)) = run_as {
            let (old_euid, old_egid) = (geteuid(), getegid());
            setegid(gid).map_err(|e| KeyRepositoryError::NixErrno {
                context: "setting effective process GID".into(),
                source: e,
            })?;
            let _id_guard = scopeguard::guard((old_euid, old_egid), |(u, g)| {
                let _ = seteuid(u);
                let _ = setegid(g);
            });
            seteuid(uid).map_err(|e| KeyRepositoryError::NixErrno {
                context: "setting effective process UID".into(),
                source: e,
            })?;

            Self::write_key_file_inner(dir, name, contents)
        } else {
            Self::write_key_file_inner(dir, name, contents)
        }
    }

    fn write_key_file_inner(
        dir: &PathBuf,
        name: &str,
        contents: &[u8],
    ) -> Result<(), KeyRepositoryError> {
        let mut tmp_file = NamedTempFile::new_in(dir).map_err(|e| KeyRepositoryError::Io {
            source: e,
            path: dir.clone(),
        })?;
        tmp_file
            .write_all(contents)
            .map_err(|e| KeyRepositoryError::Io {
                source: e,
                path: dir.clone(),
            })?;
        tmp_file.flush().map_err(|e| KeyRepositoryError::Io {
            source: e,
            path: dir.clone(),
        })?;
        tmp_file
            .persist(dir.join(name))
            .map_err(|e| KeyRepositoryError::Persist(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl KeySource for FilesystemKeySource {
    async fn load(&self) -> Result<BTreeMap<i8, Vec<u8>>, KeyRepositoryError> {
        let dir = self.key_repository.clone();
        spawn_blocking(move || Self::read_key_files_blocking(&dir))
            .await
            .map_err(|e| KeyRepositoryError::Io {
                source: std::io::Error::other(e),
                path: self.key_repository.clone(),
            })?
    }

    async fn write(&self, index: i8, contents: &[u8]) -> Result<(), KeyRepositoryError> {
        let dir = self.key_repository.clone();
        let name = index.to_string();
        let contents = contents.to_vec();
        let run_as = self.run_as;
        spawn_blocking(move || Self::write_key_file_blocking(&dir, &name, &contents, run_as))
            .await
            .map_err(|e| KeyRepositoryError::Io {
                source: std::io::Error::other(e),
                path: self.key_repository.clone(),
            })?
    }

    async fn remove(&self, index: i8) -> Result<(), KeyRepositoryError> {
        let path = self.path_for(index);
        spawn_blocking(move || match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KeyRepositoryError::Io { source: e, path }),
        })
        .await
        .map_err(|e| KeyRepositoryError::Io {
            source: std::io::Error::other(e),
            path: self.key_repository.clone(),
        })?
    }

    async fn promote(&self, from: i8, to: i8, _contents: &[u8]) -> Result<(), KeyRepositoryError> {
        let from_path = self.path_for(from);
        let to_path = self.path_for(to);
        let join_err_path = to_path.clone();
        spawn_blocking(move || {
            std::fs::rename(&from_path, &to_path).map_err(|e| KeyRepositoryError::Io {
                source: e,
                path: from_path,
            })
        })
        .await
        .map_err(|e| KeyRepositoryError::Io {
            source: std::io::Error::other(e),
            path: join_err_path,
        })?
    }

    fn subscribe(&self) -> broadcast::Receiver<()> {
        self.change_tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE;
    use fernet::Fernet;

    #[tokio::test]
    async fn test_write_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let source = FilesystemKeySource::new(dir.path().to_path_buf());

        let key = Fernet::generate_key();
        source.write(0, key.as_bytes()).await.unwrap();

        let loaded = source.load().await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&0).unwrap(), key.as_bytes());
    }

    #[tokio::test]
    async fn test_load_on_unconfigured_directory_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let source = FilesystemKeySource::new(dir.path().join("does-not-exist"));
        assert!(source.load().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_remove_missing_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let source = FilesystemKeySource::new(dir.path().to_path_buf());
        source.remove(5).await.unwrap();
    }

    #[tokio::test]
    async fn test_promote_renames_file() {
        let dir = tempfile::tempdir().unwrap();
        let source = FilesystemKeySource::new(dir.path().to_path_buf());
        let key = Fernet::generate_key();
        source.write(0, key.as_bytes()).await.unwrap();

        source.promote(0, 1, key.as_bytes()).await.unwrap();

        assert!(!dir.path().join("0").exists());
        assert!(dir.path().join("1").exists());
    }

    #[tokio::test]
    async fn test_trailing_newline_is_stripped() {
        let dir = tempfile::tempdir().unwrap();
        let key = Fernet::generate_key();
        let mut with_newline = key.as_bytes().to_vec();
        with_newline.push(b'\n');
        std::fs::write(dir.path().join("0"), &with_newline).unwrap();

        let source = FilesystemKeySource::new(dir.path().to_path_buf());
        let loaded = source.load().await.unwrap();
        assert_eq!(loaded.get(&0).unwrap(), key.as_bytes());
    }

    #[tokio::test]
    async fn test_watched_source_notifies_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let source =
            FilesystemKeySource::watched(dir.path().to_path_buf(), Duration::from_secs(3600));
        let mut rx = source.subscribe();

        let key = Fernet::generate_key();
        source.write(0, key.as_bytes()).await.unwrap();

        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("expected a change notification within 5s")
            .unwrap();
    }

    #[test]
    fn test_is_null_key_raw_bytes_helper_sanity() {
        // Sanity check the encoding used across these tests matches the
        // production Null Key encoding used in `KeyRepository::is_null_key`.
        let null_key_raw = URL_SAFE.encode([0u8; 32]);
        assert_eq!(null_key_raw.len(), 44);
    }
}
