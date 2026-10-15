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
//! RustCrypto implementation of the [`crate::backend`] primitives.

use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hybrid_array::Array;
use rand::RngExt;
use sha2::Sha256;

use crate::error::CryptoError;

fn cipher(key: &[u8]) -> Result<Aes256Gcm, CryptoError> {
    let key = Array::slice_as_array(key).ok_or(CryptoError::InvalidKeyLength)?;
    Ok(Aes256Gcm::new(key))
}

/// Encrypt `buf` in place and return the detached 16-byte tag.
pub(crate) fn gcm_seal(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; 16], CryptoError> {
    let nonce = Array::slice_as_array(nonce).ok_or(CryptoError::InvalidArrayLength)?;
    let tag = cipher(key)?
        .encrypt_inout_detached(nonce, aad, buf.into())
        .map_err(|_| CryptoError::AesEncrypt)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
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
    let nonce = Array::slice_as_array(nonce).ok_or(CryptoError::InvalidArrayLength)?;
    let tag = Array::slice_as_array(tag).ok_or(CryptoError::InvalidArrayLength)?;
    cipher(key)?
        .decrypt_inout_detached(nonce, aad, buf.into(), tag)
        .map_err(|_| CryptoError::AesDecrypt)
}

/// HKDF-Expand (no Extract) with SHA-256 using `prk` directly.
pub(crate) fn hkdf_expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| CryptoError::InvalidKeyLength)?
        .expand(info, out)
        .map_err(|_| CryptoError::InvalidKeyLength)
}

/// HMAC-SHA256.
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

/// Fill `out` from the operating system backed CSPRNG.
pub(crate) fn fill_random(out: &mut [u8]) -> Result<(), CryptoError> {
    rand::rng().fill(out);
    Ok(())
}
