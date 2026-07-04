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
//! # Key source abstraction
//!
//! [`KeySource`] is the backend-agnostic contract [`crate::KeyRepository`]
//! is built on. [`crate::filesystem::FilesystemKeySource`] is the only
//! implementation today; a future Vault-backed source (or any other KV
//! secret store) implements the same trait and plugs into
//! [`crate::KeyRepository`]/[`crate::CachedKeyRepository`] unchanged.
use std::collections::BTreeMap;

use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::error::KeyRepositoryError;

/// A source of indexed Fernet key material.
///
/// Indices follow the Python Keystone convention: `0` is always the
/// "staged" key (queued for the next rotation, never used for encryption
/// until promoted), all other indices are active keys usable for
/// decryption, and the highest non-zero index is the current primary
/// (used for encryption).
#[async_trait]
pub trait KeySource: Send + Sync {
    /// Read every key entry currently present, keyed by index.
    ///
    /// An empty map means the repository has not been set up yet — this is
    /// a valid, non-error state; callers decide whether that's acceptable
    /// (e.g. [`crate::KeyRepository::check_startup_null_key`] tolerates it,
    /// [`crate::KeyRepository::load_keys`] does not).
    async fn load(&self) -> Result<BTreeMap<i8, Vec<u8>>, KeyRepositoryError>;

    /// Atomically create or overwrite the entry at `index` with `contents`.
    async fn write(&self, index: i8, contents: &[u8]) -> Result<(), KeyRepositoryError>;

    /// Remove the entry at `index`. Must not error if the entry is already
    /// absent (rotation pruning may race with manual cleanup).
    async fn remove(&self, index: i8) -> Result<(), KeyRepositoryError>;

    /// Move key material from `from` to `to` as atomically as the backend
    /// allows, used by [`crate::KeyRepository::rotate`] to promote the
    /// staged key without a window where it's briefly missing.
    ///
    /// The default implementation is write-then-remove: not atomic (a
    /// crash between the two steps leaves the key present at both indices,
    /// or briefly at neither), but safe for any backend that can only
    /// write/delete individual entries (e.g. a Vault KV store) — a
    /// duplicated entry is harmless and self-heals on the next rotation, and
    /// [`crate::KeyRepository::rotate`] never removes `from` before `to` is
    /// durably written. Backends capable of a true move (the filesystem,
    /// via `rename(2)`) should override this for a stronger guarantee.
    async fn promote(&self, from: i8, to: i8, contents: &[u8]) -> Result<(), KeyRepositoryError> {
        self.write(to, contents).await?;
        self.remove(from).await?;
        Ok(())
    }

    /// Subscribe to change notifications. A message means "key material may
    /// have changed, reload via [`Self::load`]" — it carries no payload.
    ///
    /// Contract: fires within the source's configured reload interval of an
    /// actual change, sooner if the backend can detect changes natively
    /// (e.g. filesystem inotify events). A source that never mutates after
    /// construction may never send anything; that's a valid (if useless)
    /// implementation.
    fn subscribe(&self) -> broadcast::Receiver<()>;
}
