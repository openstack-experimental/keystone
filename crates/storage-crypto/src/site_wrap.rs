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
//! Per-site DEK wrapping (ADR 0045 §11.2).
//!
//! A cluster whose Raft members span several sites cannot share one KEK: each
//! site has its own root of trust. The leader instead wraps every DEK version
//! **offline** to the public key of each site with RSA-OAEP-SHA256
//! ([`wrap_dek_for_site`]) and stores one blob per site. A node recovers the
//! DEK by asking its own site's key to decrypt that site's blob
//! ([`unwrap_dek_for_site`]); the private key never leaves the site, which in
//! production means OpenBao Transit (an `rsa-2048`/`rsa-4096` key, whose
//! `decrypt` is RSA-OAEP with SHA-256 and no label) behind
//! [`SiteKeyUnwrapper`]. [`SoftwareSiteKey`] is the software fallback for
//! sites without such a key.
//!
//! The cluster id, DEK version and site name are written inside the OAEP
//! plaintext and checked after decryption, so the scheme does not depend on
//! the key store honouring an OAEP label and a blob cannot be replayed for
//! another cluster, version or site.

use zeroize::Zeroizing;

use crate::backend::rsa_oaep;
use crate::error::CryptoError;

/// Format version of the plaintext inside the OAEP blob.
const FORMAT_V1: u8 = 1;

/// Longest cluster id or site name; keeps the plaintext inside the OAEP limit
/// of a 2048-bit key (190 bytes).
const MAX_NAME_LEN: usize = 64;

/// What a per-site blob is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiteBinding<'a> {
    /// Raft cluster identifier.
    pub cluster_id: &'a str,
    /// DEK epoch version being wrapped.
    pub dek_version: u32,
    /// Site the blob is for.
    pub site: &'a str,
}

impl SiteBinding<'_> {
    fn validate(&self) -> Result<(), CryptoError> {
        for (what, v) in [("cluster id", self.cluster_id), ("site", self.site)] {
            if v.is_empty() || v.len() > MAX_NAME_LEN {
                return Err(CryptoError::SiteWrap(format!(
                    "{what} must be 1..={MAX_NAME_LEN} bytes"
                )));
            }
        }
        Ok(())
    }

    /// `v1 | dek_version | len | cluster_id | len | site` (lengths are one byte).
    fn encode(&self, dek: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.validate()?;
        let mut out = Zeroizing::new(Vec::with_capacity(8 + 2 * MAX_NAME_LEN + 32));
        out.push(FORMAT_V1);
        out.extend_from_slice(&self.dek_version.to_be_bytes());
        for v in [self.cluster_id, self.site] {
            out.push(u8::try_from(v.len()).map_err(|_| CryptoError::InvalidArrayLength)?);
            out.extend_from_slice(v.as_bytes());
        }
        out.extend_from_slice(dek);
        Ok(out)
    }
}

/// The private-key side of a site: decrypts RSA-OAEP-SHA256 ciphertexts made
/// for the site's public key.
#[async_trait::async_trait]
pub trait SiteKeyUnwrapper: Send + Sync {
    /// Decrypt `ciphertext`; the plaintext is key material.
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

/// Wrap `dek` for the site whose RSA public key (SubjectPublicKeyInfo DER,
/// at least 2048 bits) is `site_public_key_der`. Needs no network access.
pub fn wrap_dek_for_site(
    site_public_key_der: &[u8],
    dek: &[u8; 32],
    binding: &SiteBinding<'_>,
) -> Result<Vec<u8>, CryptoError> {
    let plaintext = binding.encode(dek)?;
    rsa_oaep::encrypt(site_public_key_der, &plaintext)
}

/// Recover a DEK from `blob` through `site_key` and check it is bound to
/// `binding`.
pub async fn unwrap_dek_for_site(
    site_key: &dyn SiteKeyUnwrapper,
    blob: &[u8],
    binding: &SiteBinding<'_>,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let plaintext = site_key.decrypt(blob).await?;
    // The expected plaintext without the DEK is a prefix of what was wrapped.
    let expected = binding.encode(&[0u8; 32])?;
    let prefix_len = expected.len() - 32;
    let (head, dek) = plaintext
        .split_at_checked(prefix_len)
        .ok_or(CryptoError::SiteBindingMismatch)?;
    let head_ok = expected.get(..prefix_len) == Some(head);
    if !head_ok || dek.len() != 32 {
        return Err(CryptoError::SiteBindingMismatch);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(dek);
    Ok(out)
}

/// Software site key: an RSA private key (PKCS#8 DER) held in process memory.
///
/// Fallback for sites without a Transit key or HSM. The key sits next to the
/// process that uses it, so it protects the DEK only as well as the secret
/// store it was loaded from.
///
/// In the default (non-`fips`) build unwrapping uses the RustCrypto `rsa`
/// crate, whose decryption is not constant time (Marvin attack,
/// RUSTSEC-2023-0071). Do not expose it to callers that can submit chosen
/// ciphertexts and observe timing; prefer the `fips` build or a Transit key.
pub struct SoftwareSiteKey {
    key: rsa_oaep::PrivateKey,
}

impl SoftwareSiteKey {
    /// Parse a PKCS#8 DER RSA private key of at least 2048 bits.
    ///
    /// The key is parsed once here, not on every unwrap.
    pub fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            key: rsa_oaep::PrivateKey::from_pkcs8_der(pkcs8_der)?,
        })
    }
}

#[async_trait::async_trait]
impl SiteKeyUnwrapper for SoftwareSiteKey {
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.key.decrypt(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

    use super::*;

    fn keypair(bits: usize) -> (Vec<u8>, SoftwareSiteKey) {
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).unwrap();
        let public = key.to_public_key().to_public_key_der().unwrap();
        let private = key.to_pkcs8_der().unwrap();
        (
            public.as_bytes().to_vec(),
            SoftwareSiteKey::from_pkcs8_der(private.as_bytes()).unwrap(),
        )
    }

    #[test]
    fn rejects_small_private_key() {
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
        let der = key.to_pkcs8_der().unwrap();
        assert!(matches!(
            SoftwareSiteKey::from_pkcs8_der(der.as_bytes()),
            Err(CryptoError::SiteUnwrap(_))
        ));
    }

    const B: SiteBinding<'static> = SiteBinding {
        cluster_id: "cluster-a",
        dek_version: 3,
        site: "eu-1",
    };

    #[tokio::test]
    async fn round_trip() {
        let (public, key) = keypair(2048);
        let dek = [7u8; 32];
        let blob = wrap_dek_for_site(&public, &dek, &B).unwrap();
        assert_eq!(*unwrap_dek_for_site(&key, &blob, &B).await.unwrap(), dek);
    }

    #[test]
    fn wrapping_is_randomised() {
        let (public, _) = keypair(2048);
        let dek = [7u8; 32];
        assert_ne!(
            wrap_dek_for_site(&public, &dek, &B).unwrap(),
            wrap_dek_for_site(&public, &dek, &B).unwrap()
        );
    }

    #[tokio::test]
    async fn blob_is_bound_to_cluster_version_and_site() {
        let (public, key) = keypair(2048);
        let blob = wrap_dek_for_site(&public, &[7u8; 32], &B).unwrap();
        for other in [
            SiteBinding {
                cluster_id: "cluster-b",
                ..B
            },
            SiteBinding {
                dek_version: 4,
                ..B
            },
            SiteBinding { site: "us-1", ..B },
        ] {
            assert!(matches!(
                unwrap_dek_for_site(&key, &blob, &other).await,
                Err(CryptoError::SiteBindingMismatch)
            ));
        }
    }

    #[tokio::test]
    async fn other_sites_key_cannot_unwrap() {
        let (public, _) = keypair(2048);
        let (_, other_key) = keypair(2048);
        let blob = wrap_dek_for_site(&public, &[7u8; 32], &B).unwrap();
        assert!(unwrap_dek_for_site(&other_key, &blob, &B).await.is_err());
    }

    #[tokio::test]
    async fn tampered_blob_is_rejected() {
        let (public, key) = keypair(2048);
        let mut blob = wrap_dek_for_site(&public, &[7u8; 32], &B).unwrap();
        blob[10] ^= 1;
        assert!(unwrap_dek_for_site(&key, &blob, &B).await.is_err());
    }

    #[test]
    fn small_keys_and_bad_names_are_refused() {
        let small = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
        let public = small.to_public_key().to_public_key_der().unwrap();
        assert!(wrap_dek_for_site(public.as_bytes(), &[0u8; 32], &B).is_err());
        let (public, _) = keypair(2048);
        let long = "x".repeat(MAX_NAME_LEN + 1);
        assert!(wrap_dek_for_site(&public, &[0u8; 32], &SiteBinding { site: &long, ..B }).is_err());
        assert!(wrap_dek_for_site(&public, &[0u8; 32], &SiteBinding { site: "", ..B }).is_err());
    }
}
