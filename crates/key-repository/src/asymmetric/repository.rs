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
//! # Backend-agnostic asymmetric key repository (ADR 0026 §3, §10 Phase 0/1)
//!
//! Mechanical operations only, generic over [`AsymmetricKeySource`] — no
//! rotation policy (timing, dual-control, CLI wiring). That mirrors the
//! existing symmetric [`crate::KeyRepository`] vs. driver-specific
//! rotation-check split (e.g. the credential driver's own pre-rotate
//! database check).
use crate::asymmetric::keygen::generate_keypair;
use crate::asymmetric::source::{AsymmetricKeySource, KeyMaterial, KeyRole, SigningAlgorithm};
use crate::error::KeyRepositoryError;

/// The currently active keys for a signing domain: always a `Primary`, and
/// optionally a `Previous` retained for verification during a rotation's
/// grace window (ADR 0026 §3).
#[derive(Debug, Clone)]
pub struct ActiveKeys {
    /// Used for signing newly minted tokens.
    pub primary: KeyMaterial,
    /// Retained for verification only, if a rotation happened recently.
    pub previous: Option<KeyMaterial>,
}

/// Backend-agnostic asymmetric key repository, generic over the underlying
/// [`AsymmetricKeySource`].
pub struct AsymmetricKeyRepository<S: AsymmetricKeySource> {
    source: S,
}

impl<S: AsymmetricKeySource> AsymmetricKeyRepository<S> {
    /// Wrap `source`.
    pub fn new(source: S) -> Self {
        Self { source }
    }

    /// The wrapped source, e.g. to call [`AsymmetricKeySource::subscribe`].
    pub fn source(&self) -> &S {
        &self.source
    }

    /// Generate a fresh keypair for `algorithm`. Pure computation, no I/O —
    /// callers decide where to store the result (e.g. as `Primary` via
    /// [`Self::setup`], or as a driver-specific staged/pending record
    /// during rotation).
    pub fn generate_keypair(
        &self,
        algorithm: SigningAlgorithm,
    ) -> Result<KeyMaterial, KeyRepositoryError> {
        generate_keypair(algorithm)
    }

    /// Idempotently ensure a `Primary` key exists: if one is already
    /// present, return it unchanged; otherwise generate and store a fresh
    /// one. Safe to call on a retried domain-creation request (ADR 0026
    /// §3, "Domain creation").
    pub async fn setup(
        &self,
        algorithm: SigningAlgorithm,
    ) -> Result<KeyMaterial, KeyRepositoryError> {
        let existing = self.source.load().await?;
        if let Some(primary) = existing.get(&KeyRole::Primary) {
            return Ok(primary.clone());
        }
        let material = generate_keypair(algorithm)?;
        self.source.write(KeyRole::Primary, &material).await?;
        Ok(material)
    }

    /// Load the current `Primary` (and `Previous`, if any).
    ///
    /// # Errors
    /// [`KeyRepositoryError::KeysMissing`] if no `Primary` is present.
    pub async fn load_active(&self) -> Result<ActiveKeys, KeyRepositoryError> {
        let mut loaded = self.source.load().await?;
        let primary = loaded
            .remove(&KeyRole::Primary)
            .ok_or(KeyRepositoryError::KeysMissing)?;
        let previous = loaded.remove(&KeyRole::Previous);
        Ok(ActiveKeys { primary, previous })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use tokio::sync::broadcast;

    use super::*;

    #[derive(Default)]
    struct InMemorySource {
        keys: Mutex<BTreeMap<KeyRole, KeyMaterial>>,
    }

    #[async_trait]
    impl AsymmetricKeySource for InMemorySource {
        async fn load(&self) -> Result<BTreeMap<KeyRole, KeyMaterial>, KeyRepositoryError> {
            Ok(self.keys.lock().unwrap().clone())
        }

        async fn write(
            &self,
            role: KeyRole,
            material: &KeyMaterial,
        ) -> Result<(), KeyRepositoryError> {
            self.keys.lock().unwrap().insert(role, material.clone());
            Ok(())
        }

        async fn remove(&self, role: KeyRole) -> Result<(), KeyRepositoryError> {
            self.keys.lock().unwrap().remove(&role);
            Ok(())
        }

        fn subscribe(&self) -> broadcast::Receiver<()> {
            broadcast::channel(1).1
        }
    }

    fn repo() -> AsymmetricKeyRepository<InMemorySource> {
        AsymmetricKeyRepository::new(InMemorySource::default())
    }

    #[tokio::test]
    async fn test_setup_generates_primary_when_absent() {
        let repo = repo();
        let key = repo.setup(SigningAlgorithm::Es256).await.unwrap();
        assert_eq!(key.algorithm, SigningAlgorithm::Es256);

        let active = repo.load_active().await.unwrap();
        assert_eq!(active.primary.kid, key.kid);
        assert!(active.previous.is_none());
    }

    #[tokio::test]
    async fn test_setup_is_idempotent() {
        let repo = repo();
        let first = repo.setup(SigningAlgorithm::Es256).await.unwrap();
        let second = repo.setup(SigningAlgorithm::Es256).await.unwrap();
        assert_eq!(first.kid, second.kid);
    }

    #[tokio::test]
    async fn test_load_active_without_setup_fails() {
        let repo = repo();
        assert!(matches!(
            repo.load_active().await,
            Err(KeyRepositoryError::KeysMissing)
        ));
    }

    #[tokio::test]
    async fn test_load_active_includes_previous_when_present() {
        let repo = repo();
        let primary = repo.setup(SigningAlgorithm::Es256).await.unwrap();
        let previous = repo.generate_keypair(SigningAlgorithm::Es256).unwrap();
        repo.source()
            .write(KeyRole::Previous, &previous)
            .await
            .unwrap();

        let active = repo.load_active().await.unwrap();
        assert_eq!(active.primary.kid, primary.kid);
        assert_eq!(active.previous.unwrap().kid, previous.kid);
    }
}
