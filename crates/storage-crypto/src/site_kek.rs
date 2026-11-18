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
// Crypto inventory: STO-13; see doc/src/contributor/crypto-inventory.md
//! Per-site KEK: one wrapped DEK that every registered site can open
//! (ADR 0045 §11.2).
//!
//! [`SiteKek`] is a [`KekProvider`] whose "wrapped DEK" is an *envelope*: the
//! DEK wrapped once for each registered site (RSA-OAEP, see [`site_wrap`]) and
//! once for an optional escrow key. Everything downstream of [`KekProvider`]
//! (the Raft log, snapshots, backup manifests, `FetchDek`) carries the
//! envelope as an opaque blob, so a snapshot or backup made at one site is
//! readable at every other registered site, although each site's private key
//! stays in its own key store.
//!
//! A node opens only its own site's entry. The escrow entry is named after
//! the escrow site: a cluster restored from nothing is started with the
//! escrow private key as the local site key and `site = <escrow name>`.
//!
//! Envelope layout: `"KSE1" | count u16 | { name_len u8 | name | key_version
//! u32 | blob_len u16 | blob }*`, big-endian.
//!
//! [`site_wrap`]: crate::site_wrap

use std::sync::{Arc, RwLock};

use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::kek::KekProvider;
use crate::site_wrap::{SiteBinding, SiteKeyUnwrapper, unwrap_dek_for_site, wrap_dek_for_site};

const MAGIC: &[u8; 4] = b"KSE1";

/// DEK epoch the blobs are bound to. A [`KekProvider`] wraps a bare DEK and
/// does not know its epoch, so envelopes bind cluster and site only.
const BOUND_DEK_VERSION: u32 = 0;

/// A site that can open the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteEntry {
    /// Site name, unique in the registry.
    pub name: String,
    /// RSA public key, SubjectPublicKeyInfo DER, at least 2048 bits.
    pub public_key_der: Vec<u8>,
    /// Version of the site's key pair, passed back to the key store on
    /// decryption.
    pub key_version: u32,
}

/// Shared, mutable set of sites a new envelope is wrapped for.
#[derive(Debug, Default)]
pub struct SiteRegistry {
    sites: RwLock<Vec<SiteEntry>>,
}

impl SiteRegistry {
    /// A registry holding `sites`.
    pub fn new(sites: Vec<SiteEntry>) -> Self {
        Self {
            sites: RwLock::new(sites),
        }
    }

    /// Replace the whole set.
    pub fn replace(&self, sites: Vec<SiteEntry>) {
        *self.sites.write().unwrap_or_else(|p| p.into_inner()) = sites;
    }

    /// Insert `entry`, replacing a site of the same name.
    pub fn upsert(&self, entry: SiteEntry) {
        let mut sites = self.sites.write().unwrap_or_else(|p| p.into_inner());
        match sites.iter_mut().find(|s| s.name == entry.name) {
            Some(existing) => *existing = entry,
            None => sites.push(entry),
        }
    }

    /// Remove the site called `name`; returns whether it was present.
    pub fn remove(&self, name: &str) -> bool {
        let mut sites = self.sites.write().unwrap_or_else(|p| p.into_inner());
        let before = sites.len();
        sites.retain(|s| s.name != name);
        sites.len() != before
    }

    /// The current sites.
    pub fn list(&self) -> Vec<SiteEntry> {
        self.sites.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// Names and key versions in an envelope, without opening it.
pub fn envelope_sites(envelope: &[u8]) -> Result<Vec<(String, u32)>, CryptoError> {
    Ok(parse(envelope)?
        .into_iter()
        .map(|e| (e.name, e.key_version))
        .collect())
}

struct EnvelopeEntry {
    name: String,
    key_version: u32,
    blob: Vec<u8>,
}

fn parse(envelope: &[u8]) -> Result<Vec<EnvelopeEntry>, CryptoError> {
    let bad = || CryptoError::WrappedDekSize;
    let rest = envelope.strip_prefix(MAGIC).ok_or_else(bad)?;
    let (count, mut rest) = rest.split_first_chunk::<2>().ok_or_else(bad)?;
    let count = usize::from(u16::from_be_bytes(*count));
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let (&name_len, r) = rest.split_first().ok_or_else(bad)?;
        let (name, r) = r.split_at_checked(usize::from(name_len)).ok_or_else(bad)?;
        let (ver, r) = r.split_first_chunk::<4>().ok_or_else(bad)?;
        let (len, r) = r.split_first_chunk::<2>().ok_or_else(bad)?;
        let (blob, r) = r
            .split_at_checked(usize::from(u16::from_be_bytes(*len)))
            .ok_or_else(bad)?;
        out.push(EnvelopeEntry {
            name: String::from_utf8(name.to_vec()).map_err(|_| bad())?,
            key_version: u32::from_be_bytes(*ver),
            blob: blob.to_vec(),
        });
        rest = r;
    }
    if !rest.is_empty() {
        return Err(bad());
    }
    Ok(out)
}

fn encode(entries: &[(&SiteEntry, Vec<u8>)]) -> Result<Vec<u8>, CryptoError> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(
        &u16::try_from(entries.len())
            .map_err(|_| CryptoError::InvalidArrayLength)?
            .to_be_bytes(),
    );
    for (site, blob) in entries {
        out.push(u8::try_from(site.name.len()).map_err(|_| CryptoError::InvalidArrayLength)?);
        out.extend_from_slice(site.name.as_bytes());
        out.extend_from_slice(&site.key_version.to_be_bytes());
        out.extend_from_slice(
            &u16::try_from(blob.len())
                .map_err(|_| CryptoError::InvalidArrayLength)?
                .to_be_bytes(),
        );
        out.extend_from_slice(blob);
    }
    Ok(out)
}

/// A [`KekProvider`] for clusters whose sites have separate roots of trust.
pub struct SiteKek {
    cluster_id: String,
    escrow: Option<SiteEntry>,
    registry: Arc<SiteRegistry>,
    site: String,
    unwrappers: Vec<(u32, Arc<dyn SiteKeyUnwrapper>)>,
}

impl SiteKek {
    /// `site` is this node's site, `unwrappers` the key store per key version, `registry` the
    /// sites a new envelope is wrapped for and `escrow` an optional extra
    /// recipient (kept offline).
    pub fn new(
        cluster_id: impl Into<String>,
        site: impl Into<String>,
        unwrappers: Vec<(u32, Arc<dyn SiteKeyUnwrapper>)>,
        registry: Arc<SiteRegistry>,
        escrow: Option<SiteEntry>,
    ) -> Self {
        Self {
            cluster_id: cluster_id.into(),
            escrow,
            registry,
            site: site.into(),
            unwrappers,
        }
    }

    /// The registry new envelopes are wrapped for.
    pub fn registry(&self) -> &Arc<SiteRegistry> {
        &self.registry
    }

    fn binding<'a>(&'a self, site: &'a str) -> SiteBinding<'a> {
        SiteBinding {
            cluster_id: &self.cluster_id,
            dek_version: BOUND_DEK_VERSION,
            site,
        }
    }
}

impl SiteKek {
    /// Wrap `dek` for `sites` plus the escrow site. Refuses a list without
    /// the local site, which could not reopen what it wraps.
    pub fn wrap_for(&self, sites: &[SiteEntry], dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        if !sites.iter().any(|s| s.name == self.site)
            && self.escrow.as_ref().map(|e| &e.name) != Some(&self.site)
        {
            return Err(CryptoError::SiteWrap(format!(
                "the local site '{}' is not in the site registry",
                self.site
            )));
        }
        let mut recipients: Vec<&SiteEntry> = sites.iter().collect();
        if let Some(escrow) = &self.escrow
            && !recipients.iter().any(|s| s.name == escrow.name)
        {
            recipients.push(escrow);
        }
        let mut entries = Vec::with_capacity(recipients.len());
        for site in recipients {
            let blob = wrap_dek_for_site(&site.public_key_der, dek, &self.binding(&site.name))?;
            entries.push((site, blob));
        }
        encode(&entries)
    }

    /// Open `envelope` with the local site key and wrap its DEK again for
    /// `sites` plus the escrow site, for a site list that changed.
    pub async fn rewrap_for(
        &self,
        sites: &[SiteEntry],
        envelope: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let dek = self.unwrap_dek(envelope).await?;
        self.wrap_for(sites, &dek)
    }
}

#[async_trait::async_trait]
impl KekProvider for SiteKek {
    fn as_site_kek(&self) -> Option<&SiteKek> {
        Some(self)
    }

    async fn wrap_dek(&self, dek: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        self.wrap_for(&self.registry.list(), dek)
    }

    async fn unwrap_dek(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let entry = parse(wrapped)?
            .into_iter()
            .find(|e| e.name == self.site)
            .ok_or_else(|| {
                CryptoError::SiteWrap(format!(
                    "the wrapped DEK has no entry for site '{}'",
                    self.site
                ))
            })?;
        let unwrapper = self
            .unwrappers
            .iter()
            .find(|(v, _)| *v == entry.key_version)
            .map(|(_, u)| u)
            .ok_or_else(|| {
                CryptoError::SiteWrap(format!(
                    "no key of version {} for site '{}'",
                    entry.key_version, self.site
                ))
            })?;
        unwrap_dek_for_site(unwrapper.as_ref(), &entry.blob, &self.binding(&self.site)).await
    }
}

#[cfg(test)]
mod tests {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

    use crate::site_wrap::SoftwareSiteKey;

    use super::*;

    struct Site {
        entry: SiteEntry,
        key: Arc<SoftwareSiteKey>,
    }

    fn site(name: &str) -> Site {
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        Site {
            entry: SiteEntry {
                name: name.into(),
                public_key_der: key.to_public_key().to_public_key_der().unwrap().into_vec(),
                key_version: 1,
            },
            key: Arc::new(
                SoftwareSiteKey::from_pkcs8_der(key.to_pkcs8_der().unwrap().as_bytes()).unwrap(),
            ),
        }
    }

    fn kek_for(local: &Site, sites: &[&Site], escrow: Option<&Site>) -> SiteKek {
        SiteKek::new(
            "c1",
            local.entry.name.clone(),
            vec![(
                local.entry.key_version,
                local.key.clone() as Arc<dyn SiteKeyUnwrapper>,
            )],
            Arc::new(SiteRegistry::new(
                sites.iter().map(|s| s.entry.clone()).collect(),
            )),
            escrow.map(|e| e.entry.clone()),
        )
    }

    #[tokio::test]
    async fn every_registered_site_opens_the_same_envelope() {
        let (a, b) = (site("a"), site("b"));
        let ka = kek_for(&a, &[&a, &b], None);
        let kb = kek_for(&b, &[&a, &b], None);
        let envelope = ka.wrap_dek(&[3u8; 32]).await.unwrap();
        assert_eq!(*ka.unwrap_dek(&envelope).await.unwrap(), [3u8; 32]);
        assert_eq!(*kb.unwrap_dek(&envelope).await.unwrap(), [3u8; 32]);
        assert_eq!(
            envelope_sites(&envelope).unwrap(),
            vec![("a".to_owned(), 1), ("b".to_owned(), 1)]
        );
    }

    #[tokio::test]
    async fn an_unregistered_site_cannot_open_it() {
        let (a, b, c) = (site("a"), site("b"), site("c"));
        let envelope = kek_for(&a, &[&a, &b], None)
            .wrap_dek(&[3u8; 32])
            .await
            .unwrap();
        let err = kek_for(&c, &[&a, &b, &c], None)
            .unwrap_dek(&envelope)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no entry for site 'c'"), "{err}");
    }

    #[tokio::test]
    async fn a_site_cannot_open_another_sites_entry() {
        let (a, b) = (site("a"), site("b"));
        let envelope = kek_for(&a, &[&a, &b], None)
            .wrap_dek(&[3u8; 32])
            .await
            .unwrap();
        // `b` with `a`'s private key: right entry name, wrong key.
        let impostor = SiteKek::new(
            "c1",
            "b",
            vec![(1, a.key.clone() as Arc<dyn SiteKeyUnwrapper>)],
            Arc::new(SiteRegistry::default()),
            None,
        );
        assert!(impostor.unwrap_dek(&envelope).await.is_err());
    }

    #[tokio::test]
    async fn escrow_site_opens_it_when_started_as_that_site() {
        let (a, escrow) = (site("a"), site("escrow"));
        let envelope = kek_for(&a, &[&a], Some(&escrow))
            .wrap_dek(&[4u8; 32])
            .await
            .unwrap();
        let restored = SiteKek::new(
            "c1",
            "escrow",
            vec![(1, escrow.key.clone() as Arc<dyn SiteKeyUnwrapper>)],
            Arc::new(SiteRegistry::default()),
            None,
        );
        assert_eq!(*restored.unwrap_dek(&envelope).await.unwrap(), [4u8; 32]);
    }

    #[tokio::test]
    async fn envelope_is_bound_to_the_cluster() {
        let a = site("a");
        let envelope = kek_for(&a, &[&a], None).wrap_dek(&[3u8; 32]).await.unwrap();
        let other = SiteKek::new(
            "c2",
            "a",
            vec![(1, a.key.clone() as Arc<dyn SiteKeyUnwrapper>)],
            Arc::new(SiteRegistry::default()),
            None,
        );
        assert!(matches!(
            other.unwrap_dek(&envelope).await,
            Err(CryptoError::SiteBindingMismatch)
        ));
    }

    #[tokio::test]
    async fn wrapping_requires_the_local_site_in_the_registry() {
        let (a, b) = (site("a"), site("b"));
        let err = kek_for(&a, &[&b], None)
            .wrap_dek(&[3u8; 32])
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("local site 'a'"), "{err}");
    }

    #[tokio::test]
    async fn malformed_envelopes_are_rejected() {
        let a = site("a");
        let kek = kek_for(&a, &[&a], None);
        let good = kek.wrap_dek(&[3u8; 32]).await.unwrap();
        assert!(kek.unwrap_dek(b"").await.is_err());
        assert!(kek.unwrap_dek(b"XXXX\0\0").await.is_err());
        assert!(kek.unwrap_dek(&good[..good.len() - 1]).await.is_err());
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(kek.unwrap_dek(&trailing).await.is_err());
    }

    #[test]
    fn registry_edits() {
        let (a, b) = (site("a"), site("b"));
        let r = SiteRegistry::new(vec![a.entry.clone()]);
        r.upsert(b.entry.clone());
        let mut bumped = a.entry.clone();
        bumped.key_version = 2;
        r.upsert(bumped);
        assert_eq!(r.list().len(), 2);
        assert_eq!(r.list()[0].key_version, 2);
        assert!(r.remove("b"));
        assert!(!r.remove("b"));
    }

    #[tokio::test]
    async fn rewrap_adds_a_site() {
        let (a, b, c) = (site("a"), site("b"), site("c"));
        let ka = kek_for(&a, &[&a, &b], None);
        let old = ka.wrap_dek(&[5u8; 32]).await.unwrap();
        let new = ka
            .rewrap_for(&[a.entry.clone(), b.entry.clone(), c.entry.clone()], &old)
            .await
            .unwrap();
        assert_eq!(
            *kek_for(&c, &[&a], None).unwrap_dek(&new).await.unwrap(),
            [5u8; 32]
        );
        assert!(kek_for(&c, &[&a], None).unwrap_dek(&old).await.is_err());
        // Dropping the local site is refused.
        assert!(
            ka.rewrap_for(std::slice::from_ref(&b.entry), &old)
                .await
                .is_err()
        );
    }
}
