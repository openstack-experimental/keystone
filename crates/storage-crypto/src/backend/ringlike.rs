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
// Crypto inventory: STO-1, STO-2; see doc/src/contributor/crypto-inventory.md
//! Implementation of the [`crate::backend`] primitives for the `ring` API.
//!
//! `aws-lc-rs` is a drop-in for the subset of `ring` used here, so one body
//! serves both providers; `provider` below is the only thing that differs.

#[cfg(feature = "fips")]
use aws_lc_rs as provider;
#[cfg(not(feature = "fips"))]
use ring as provider;

use provider::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use provider::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};
use provider::hmac;
use provider::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::error::CryptoError;

fn key_for(key: &[u8]) -> Result<LessSafeKey, CryptoError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| CryptoError::InvalidKeyLength)
}

/// Encrypt `buf` in place with a caller-supplied nonce and return the
/// detached 16-byte tag. A non-approved service in the FIPS module, so the
/// `fips` build only keeps it for tests.
#[cfg(any(not(feature = "fips"), test))]
pub(crate) fn gcm_seal(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; 16], CryptoError> {
    let tag = key_for(key)?
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), buf)
        .map_err(|_| CryptoError::AesEncrypt)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

/// Encrypt `buf` in place with an IV generated inside the validated module
/// (SP 800-38D §8.2.2) and return that IV with the detached tag.
///
/// This is the only AES-GCM encrypt service the module reports as approved:
/// sealing with a caller-supplied nonce is flagged non-approved. `ring` has
/// no equivalent, so this exists for the `fips` provider only.
#[cfg(feature = "fips")]
pub(crate) fn gcm_seal_random(
    key: &[u8],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<([u8; 12], [u8; 16]), CryptoError> {
    use aws_lc_rs::aead::RandomizedNonceKey;

    let key =
        RandomizedNonceKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::InvalidKeyLength)?;
    let (nonce, tag) = key
        .seal_in_place_separate_tag(Aad::from(aad), buf)
        .map_err(|_| CryptoError::AesEncrypt)?;
    let iv: [u8; 12] = *nonce.as_ref();
    let tag: [u8; 16] = tag
        .as_ref()
        .try_into()
        .map_err(|_| CryptoError::InvalidArrayLength)?;
    Ok((iv, tag))
}

/// Verify `tag` and decrypt `buf` in place.
pub(crate) fn gcm_open(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), CryptoError> {
    // The providers want ciphertext and tag contiguous.
    let mut joined = Zeroizing::new(Vec::with_capacity(buf.len() + tag.len()));
    joined.extend_from_slice(buf);
    joined.extend_from_slice(tag);
    let plain = key_for(key)?
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            joined.as_mut_slice(),
        )
        .map_err(|_| CryptoError::AesDecrypt)?;
    buf.copy_from_slice(plain);
    Ok(())
}

struct OutLen(usize);

impl KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Expand (no Extract) with SHA-256 using `prk` directly.
pub(crate) fn hkdf_expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    Prk::new_less_safe(HKDF_SHA256, prk)
        .expand(&[info], OutLen(out.len()))
        .map_err(|_| CryptoError::InvalidKeyLength)?
        .fill(out)
        .map_err(|_| CryptoError::InvalidKeyLength)
}

/// Full HKDF (Extract-then-Expand) with SHA-256.
///
/// This is the flow the validated module documents as an approved service:
/// the PRK comes from `Salt::extract` with a non-empty salt and the info is
/// non-empty.
pub(crate) fn hkdf_extract_expand(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if salt.is_empty() || info.is_empty() {
        return Err(CryptoError::HkdfEmptyInput);
    }
    Salt::new(HKDF_SHA256, salt)
        .extract(ikm)
        .expand(&[info], OutLen(out.len()))
        .map_err(|_| CryptoError::InvalidKeyLength)?
        .fill(out)
        .map_err(|_| CryptoError::InvalidKeyLength)
}

/// HMAC-SHA256.
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<[u8; 32], CryptoError> {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

/// Fill `out` from the provider's CSPRNG.
pub(crate) fn fill_random(out: &mut [u8]) -> Result<(), CryptoError> {
    SystemRandom::new().fill(out).map_err(|_| CryptoError::Rng)
}
