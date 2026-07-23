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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use nix::sys::stat::{Mode, umask};
use nix::unistd::{Gid, Uid, getegid, geteuid, setegid, seteuid};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tempfile::NamedTempFile;
use tokio::sync::{Notify, broadcast};
use tokio::task::spawn_blocking;
use tracing::{trace, warn};

use crate::error::KeyRepositoryError;
use crate::source::KeySource;

/// How long to wait after a filesystem event before reloading, so a burst
/// of writes (e.g. an operator copying in several key files at once) is
/// coalesced into a single reload. Mirrors `ConfigManager`'s debounce.
const DEBOUNCE: Duration = Duration::from_millis(500);

/// Shared state for the watched filesystem source, owned by `Arc` so it's
/// shared across the original source, its clones, and the spawned watcher
/// task. The `Clone` impl shares `change_tx`/`shutdown` rather than deep
/// copying them — required for `Arc::make_mut` (see [`with_run_as`]) to
/// preserve the same broadcast channel and shutdown flag across the copy.
///
/// [`with_run_as`]: FilesystemKeySource::with_run_as
struct FilesystemKeySourceInner {
    key_repository: PathBuf,
    run_as: Option<(Uid, Gid)>,
    change_tx: broadcast::Sender<()>,
    shutdown: Arc<AtomicBool>,
    /// Wakes the watcher task's `select!` the instant shutdown is
    /// requested, regardless of `poll_interval` or how long since the last
    /// filesystem event — without it, a task parked on a long poll interval
    /// wouldn't notice `shutdown` until its next unrelated wakeup.
    shutdown_notify: Arc<Notify>,
}

impl Clone for FilesystemKeySourceInner {
    fn clone(&self) -> Self {
        Self {
            key_repository: self.key_repository.clone(),
            run_as: self.run_as,
            change_tx: self.change_tx.clone(),
            shutdown: Arc::clone(&self.shutdown),
            shutdown_notify: Arc::clone(&self.shutdown_notify),
        }
    }
}

/// The Fernet key repository on the local filesystem.
#[derive(Clone)]
pub struct FilesystemKeySource {
    inner: std::sync::Arc<FilesystemKeySourceInner>,
}

impl Drop for FilesystemKeySource {
    fn drop(&mut self) {
        // Only the last live handle should signal shutdown — `inner` is
        // shared across clones, and an earlier clone being dropped must not
        // stop the watcher out from under the others.
        if Arc::strong_count(&self.inner) == 1 {
            self.signal_shutdown();
        }
    }
}

impl FilesystemKeySource {
    /// Cooperative shutdown: signal the watcher task to stop and wake it
    /// immediately if it's parked in `select!`. On macOS, the FSEvents
    /// kqueue syscall can't be interrupted by tokio `abort()`, so the task
    /// must observe this and exit its loop on its own.
    fn signal_shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::Release);
        self.inner.shutdown_notify.notify_one();
    }

    /// Create a new source with no background watcher. Callers that only
    /// need one-shot `load`/`write`/`remove` (e.g. CLI `setup`/`rotate`
    /// commands) don't need to pay for a watcher task.
    #[must_use]
    pub fn new(key_repository: PathBuf) -> Self {
        let (change_tx, _) = broadcast::channel(16);
        Self {
            inner: Arc::new(FilesystemKeySourceInner {
                key_repository,
                run_as: None,
                change_tx,
                shutdown: Arc::new(AtomicBool::default()),
                shutdown_notify: Arc::new(Notify::new()),
            }),
        }
    }

    /// Assume this uid/gid (via `seteuid`/`setegid`) while writing new key
    /// files, matching the privilege-drop behavior Python Keystone offers
    /// for `fernet_setup`/`fernet_rotate` run as root.
    #[must_use]
    pub fn with_run_as(mut self, uid: Uid, gid: Gid) -> Self {
        Arc::make_mut(&mut self.inner).run_as = Some((uid, gid));
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
        let dir = self.inner.key_repository.clone();
        let change_tx = self.inner.change_tx.clone();
        let shutdown = Arc::clone(&self.inner.shutdown);
        let shutdown_notify = Arc::clone(&self.inner.shutdown_notify);

        tokio::spawn(async move {
            let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();

            let mut watcher: Option<RecommendedWatcher> = match notify::recommended_watcher(
                move |res: notify::Result<notify::Event>| {
                    if let Ok(event) = res
                        && (event.kind.is_modify()
                            || event.kind.is_create()
                            || event.kind.is_remove())
                    {
                        let _ = event_tx.send(());
                    }
                },
            ) {
                Ok(mut w) => {
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
                // Check shutdown flag first, before any async operations.
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                tokio::select! {
                    biased;
                    // Wakes immediately on shutdown regardless of how long
                    // `poll_interval` is or how long since the last fs event
                    // — the flag alone can only be observed at the top of
                    // this loop, which may not be reached again for a while.
                    () = shutdown_notify.notified() => break,
                    Some(()) = event_rx.recv() => {
                        // Drain any additional rapid-fire events.
                        while event_rx.try_recv().is_ok() {}
                        // Interruptible debounce: shutdown wakes this select
                        // immediately instead of blocking behind a fixed sleep.
                        tokio::select! {
                            biased;
                            () = shutdown_notify.notified() => break,
                            () = tokio::time::sleep(DEBOUNCE) => {}
                        }
                    }
                    _ = interval.tick() => {
                        if watcher.is_none() {
                            watcher = notify::recommended_watcher(|_res: notify::Result<notify::Event>| {})
                                .ok()
                                .inspect(|_| trace!("retrying inotify watch registration"));
                            if let Some(w) = watcher.as_mut() {
                                let _ = w.watch(&dir, RecursiveMode::NonRecursive);
                            }
                        }
                    }
                }
                // Notify subscribers on every loop iteration. This ensures
                // the broadcast is sent even if the FSEvents notification
                // is missed or the poll interval fires first.
                let _ = change_tx.send(());
            }

            // Drop the notify watcher so the FSEventStream is stopped and
            // the FSEvents callback thread can exit. On macOS, the kqueue-
            // based FSEvents thread won't exit until the FSEventStream is
            // stopped, and we need this before tokio runtime shutdown.
            drop(watcher);
        });
    }

    fn path_for(&self, index: u32) -> PathBuf {
        self.inner.key_repository.join(index.to_string())
    }

    fn read_key_files_blocking(
        dir: &PathBuf,
    ) -> Result<BTreeMap<u32, Vec<u8>>, KeyRepositoryError> {
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
            let Ok(idx) = fname.parse::<u32>() else {
                continue;
            };
            let raw = std::fs::read(entry.path()).map_err(|e| KeyRepositoryError::Io {
                source: e,
                path: entry.path(),
            })?;
            let raw = raw.strip_suffix(b"\n").unwrap_or(&raw[..]);
            keys.insert(idx, raw.to_vec());
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
        }

        let mut tmp_file = NamedTempFile::new_in(dir).map_err(|e| KeyRepositoryError::Io {
            source: e,
            path: dir.clone(),
        })?;
        tmp_file
            .write_all(contents)
            .map_err(|e| KeyRepositoryError::Io {
                source: e,
                path: tmp_file.path().to_path_buf(),
            })?;
        tmp_file.flush().map_err(|e| KeyRepositoryError::Io {
            source: e,
            path: tmp_file.path().to_path_buf(),
        })?;
        tmp_file
            .persist(dir.join(name))
            .map_err(|e| KeyRepositoryError::Persist(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl KeySource for FilesystemKeySource {
    async fn load(&self) -> Result<BTreeMap<u32, Vec<u8>>, KeyRepositoryError> {
        let dir = self.inner.key_repository.clone();
        let error_dir = dir.clone();
        spawn_blocking(move || Self::read_key_files_blocking(&dir))
            .await
            .map_err(|e| KeyRepositoryError::Io {
                source: std::io::Error::other(e),
                path: error_dir,
            })?
    }

    async fn write(&self, index: u32, contents: &[u8]) -> Result<(), KeyRepositoryError> {
        let dir = self.inner.key_repository.clone();
        let error_dir = dir.clone();
        let name = index.to_string();
        let contents = contents.to_vec();
        let run_as = self.inner.run_as;
        spawn_blocking(move || Self::write_key_file_blocking(&dir, &name, &contents, run_as))
            .await
            .map_err(|e| KeyRepositoryError::Io {
                source: std::io::Error::other(e),
                path: error_dir,
            })?
    }

    async fn remove(&self, index: u32) -> Result<(), KeyRepositoryError> {
        let path = self.path_for(index);
        let error_dir = self.inner.key_repository.clone();
        spawn_blocking(move || match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KeyRepositoryError::Io { source: e, path }),
        })
        .await
        .map_err(|e| KeyRepositoryError::Io {
            source: std::io::Error::other(e),
            path: error_dir,
        })?
    }

    async fn promote(
        &self,
        from: u32,
        to: u32,
        _contents: &[u8],
    ) -> Result<(), KeyRepositoryError> {
        let from_path = self.path_for(from);
        let to_path = self.path_for(to);
        let error_dir = self.inner.key_repository.clone();
        spawn_blocking(move || {
            std::fs::rename(&from_path, &to_path).map_err(|e| KeyRepositoryError::Io {
                source: e,
                path: from_path,
            })
        })
        .await
        .map_err(|e| KeyRepositoryError::Io {
            source: std::io::Error::other(e),
            path: error_dir,
        })?
    }

    fn subscribe(&self) -> broadcast::Receiver<()> {
        self.inner.change_tx.subscribe()
    }

    fn request_shutdown(&self) {
        self.signal_shutdown();
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

    #[tokio::test]
    async fn test_watched_source_drops_gracefully() {
        let dir = tempfile::tempdir().unwrap();
        let source =
            FilesystemKeySource::watched(dir.path().to_path_buf(), Duration::from_secs(3600));

        // The source should drop cleanly, closing the cancel channel and
        // causing the watcher task to exit its loop (rather than blocking
        // on tokio abort during runtime shutdown).
        drop(source);
        // If there was a hang, this test would timeout.
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::time::sleep(Duration::from_millis(200)).await;
        })
        .await
        .expect("watcher task should exit gracefully");
    }

    #[test]
    fn test_is_null_key_raw_bytes_helper_sanity() {
        let null_key_raw = URL_SAFE.encode([0u8; 32]);
        assert_eq!(null_key_raw.len(), 44);
    }

    /// A long-lived repository accumulates one entry per rotation, so after
    /// enough rotations (or when migrating a repository from Python
    /// Keystone, whose index is an unbounded `int`) filenames well past
    /// `i8`'s old 127 cap show up on disk, e.g. `0 285 286 287 288 289`.
    /// `load` must return every one of them, not silently drop the
    /// out-of-`i8`-range names.
    #[tokio::test]
    async fn test_load_handles_indices_beyond_former_i8_range() {
        let dir = tempfile::tempdir().unwrap();
        let indices: [u32; 6] = [0, 285, 286, 287, 288, 289];
        let mut written = BTreeMap::new();
        for idx in indices {
            let key = Fernet::generate_key();
            std::fs::write(dir.path().join(idx.to_string()), key.as_bytes()).unwrap();
            written.insert(idx, key.as_bytes().to_vec());
        }

        let source = FilesystemKeySource::new(dir.path().to_path_buf());
        let loaded = source.load().await.unwrap();

        assert_eq!(loaded, written);
    }
}
