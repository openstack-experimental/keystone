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
//! AWS-LC (FIPS 140-3 validated module) implementation of the
//! [`crate::backend`] primitives.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Prk};
use aws_lc_rs::hmac;
use zeroize::Zeroizing;

use crate::error::CryptoError;

fn key_for(key: &[u8]) -> Result<LessSafeKey, CryptoError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| CryptoError::InvalidKeyLength)
}

fn nonce_for(nonce: &[u8; 12]) -> Result<Nonce, CryptoError> {
    Nonce::try_assume_unique_for_key(nonce).map_err(|_| CryptoError::InvalidArrayLength)
}

/// Encrypt `buf` in place and return the detached 16-byte tag.
pub(crate) fn gcm_seal(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; 16], CryptoError> {
    let tag = key_for(key)?
        .seal_in_place_separate_tag(nonce_for(nonce)?, Aad::from(aad), buf)
        .map_err(|_| CryptoError::AesEncrypt)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

/// Verify `tag` and decrypt `buf` in place.
pub(crate) fn gcm_open(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), CryptoError> {
    // aws-lc-rs wants ciphertext and tag contiguous.
    let mut joined = Zeroizing::new(Vec::with_capacity(buf.len() + tag.len()));
    joined.extend_from_slice(buf);
    joined.extend_from_slice(tag);
    let plain = key_for(key)?
        .open_in_place(nonce_for(nonce)?, Aad::from(aad), joined.as_mut_slice())
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

/// HMAC-SHA256.
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<[u8; 32], CryptoError> {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

/// Fill `out` from the validated module's DRBG.
pub(crate) fn fill_random(out: &mut [u8]) -> Result<(), CryptoError> {
    aws_lc_rs::rand::fill(out).map_err(|_| CryptoError::Rng)
}

/// Ok only when the validated module is running in FIPS mode.
pub(super) fn fips_active() -> Result<(), CryptoError> {
    aws_lc_rs::try_fips_mode().map_err(|_| CryptoError::FipsUnavailable)
}
