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
//! # Asymmetric key source abstraction (ADR 0026 §3, §10 Phase 0/1)
//!
//! Parallel to [`crate::KeySource`], but keyed by role rather than integer
//! index: ES256/RS256 signing keys aren't a flat N-key ring like Fernet —
//! there is exactly one `Primary` (used for signing), at most one
//! `Previous` (retained for verification only, during a rotation's grace
//! window), and at most one `Pending` (staged, not yet promoted).
use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrecy::SecretBox;
use tokio::sync::broadcast;

use crate::error::KeyRepositoryError;

/// Signing algorithm for an asymmetric keypair (ADR 0026 §3).
///
/// A local copy rather than a dependency on `openstack-keystone-config`'s
/// `SigningAlgorithm`: this crate sits below `config` in the dependency
/// graph (mirroring every other `*-driver-*`/foundational crate, which
/// depend on `core`/`core-types`, never the other way around). Callers
/// that hold `config::SigningAlgorithm` convert to this type at the call
/// site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// ECDSA over P-256, SHA-256.
    Es256,
    /// RSA-2048, SHA-256.
    Rs256,
}

/// The role a stored asymmetric key currently plays (ADR 0026 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyRole {
    /// Used exclusively for signing newly minted outbound tokens.
    Primary,
    /// No longer used for signing, retained for verification only during
    /// the post-rotation grace window.
    Previous,
    /// Staged, not yet promoted to `Primary`.
    Pending,
}

/// A single stored asymmetric keypair.
pub struct KeyMaterial {
    /// The signing algorithm this keypair was generated for.
    pub algorithm: SigningAlgorithm,
    /// PKCS#8 DER-encoded private key. Wrapped in [`SecretBox`] so it's
    /// zeroized on drop.
    pub private_key_der: SecretBox<Vec<u8>>,
    /// SubjectPublicKeyInfo DER-encoded public key.
    pub public_key_der: Vec<u8>,
    /// `kid` derived from `public_key_der` via
    /// [`crate::asymmetric::derive_kid`].
    pub kid: String,
    /// When this keypair was generated.
    pub created_at: DateTime<Utc>,
}

impl Clone for KeyMaterial {
    fn clone(&self) -> Self {
        use secrecy::ExposeSecret;
        Self {
            algorithm: self.algorithm,
            private_key_der: SecretBox::new(Box::new(self.private_key_der.expose_secret().clone())),
            public_key_der: self.public_key_der.clone(),
            kid: self.kid.clone(),
            created_at: self.created_at,
        }
    }
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("algorithm", &self.algorithm)
            .field("kid", &self.kid)
            .field("created_at", &self.created_at)
            .field("private_key_der", &"<redacted>")
            .finish()
    }
}

/// A source of role-keyed asymmetric key material.
#[async_trait]
pub trait AsymmetricKeySource: Send + Sync {
    /// Read every key entry currently present, keyed by role.
    ///
    /// An empty map means the repository has not been set up yet — a
    /// valid, non-error state; callers decide whether that's acceptable.
    async fn load(&self) -> Result<BTreeMap<KeyRole, KeyMaterial>, KeyRepositoryError>;

    /// Atomically create or overwrite the entry at `role`.
    async fn write(&self, role: KeyRole, material: &KeyMaterial) -> Result<(), KeyRepositoryError>;

    /// Remove the entry at `role`. Must not error if already absent.
    async fn remove(&self, role: KeyRole) -> Result<(), KeyRepositoryError>;

    /// Promote `Pending` to `Primary`, demoting the previous `Primary` (if
    /// any) to `Previous` and dropping any prior `Previous`, as atomically
    /// as the backend allows.
    ///
    /// The default implementation is a sequence of `load`/`write`/`remove`
    /// calls — not atomic, but safe for any backend where a transient
    /// duplicated or briefly-missing role self-heals on the next
    /// operation. Backends capable of a true atomic multi-key commit (e.g.
    /// a Raft-backed `StorageApi::transaction`) should override this.
    async fn promote_pending_to_primary(&self) -> Result<(), KeyRepositoryError> {
        let mut current = self.load().await?;
        let pending = current
            .remove(&KeyRole::Pending)
            .ok_or(KeyRepositoryError::RoleMissing(KeyRole::Pending))?;
        if let Some(old_primary) = current.remove(&KeyRole::Primary) {
            self.write(KeyRole::Previous, &old_primary).await?;
        }
        self.write(KeyRole::Primary, &pending).await?;
        self.remove(KeyRole::Pending).await?;
        Ok(())
    }

    /// Subscribe to change notifications. A message means "key material may
    /// have changed, reload via [`Self::load`]" — no payload.
    fn subscribe(&self) -> broadcast::Receiver<()>;

    /// Request that any background resources begin shutting down
    /// immediately. Sources with no background resources use the no-op
    /// default.
    fn request_shutdown(&self) {}
}
