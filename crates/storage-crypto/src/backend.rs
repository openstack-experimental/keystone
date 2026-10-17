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
// Crypto inventory: STO-1, STO-2, STO-3, STO-4, STO-5; see
// doc/src/contributor/crypto-inventory.md
//! # Cryptographic backend selection
//!
//! Every AES-256-GCM, HKDF-SHA256, HMAC-SHA256 and random-bytes operation of
//! this crate goes through the handful of functions below, so the primitive
//! provider can be swapped without touching the call sites:
//!
//! * default (`ring` feature): the `ring` crate ([`ringlike`]);
//! * `fips` feature: `aws-lc-rs` built against the FIPS 140-3 validated AWS-LC
//!   module, through the same [`ringlike`] code. When both features are enabled
//!   `fips` wins, because cargo features are additive and a workspace-wide
//!   build must not silently fall back to non-validated primitives.
//!
//! ## Adding a backend
//!
//! A backend is a module exporting `gcm_seal`, `gcm_open`, `hkdf_expand`,
//! `hkdf_extract_expand`, `hmac_sha256` and `fill_random` with the signatures
//! of [`ringlike`]. To add one (for example the RustCrypto crates), add a cargo
//! feature with optional dependencies, a module, and one arm to each `cfg`
//! chain below; `fips` stays first so it keeps precedence. Both [`ringlike`]
//! and the new module must pass `test_gcm_known_answer`.
//!
//! Caveat: the validated module only treats AES-GCM encryption as an approved
//! service when it generates the IV itself. [`gcm_seal_iv`] therefore lets the
//! `fips` build generate the IV (and `cipher` derives a per-message key so no
//! key sees many random IVs), while the default build keeps the deterministic
//! IVs of ADR 0016-v2 §2.2 and invariant 10. [`assert_fips`] proves the module
//! is the validated one, not that every call is an approved service. See the
//! "FIPS builds" paragraph of the ADR.
//!
//! A deployment that claims FIPS operation must call [`assert_fips`] during
//! start-up; it fails unless the validated module is compiled in and active.

use crate::error::CryptoError;

#[cfg(not(any(feature = "fips", feature = "ring")))]
compile_error!("enable either the `ring` (default) or the `fips` feature");

mod ringlike;

pub(crate) use ringlike::{fill_random, gcm_open, hkdf_expand, hkdf_extract_expand, hmac_sha256};
// Sealing with a caller-supplied IV is a non-approved service in the FIPS
// module, so the `fips` build only keeps it for tests.
#[cfg(any(not(feature = "fips"), test))]
pub(crate) use ringlike::gcm_seal;

/// Encrypt `buf` in place and return the IV that was actually used with the
/// detached tag. This is what every encrypt path in the crate calls.
///
/// `nonce` produces the IV for the default build (the caller owns uniqueness:
/// a durable counter or a derived value, ADR §2.2). It is a closure so that a
/// `fips` build never has to build, or even see, a placeholder value:
///
/// * default build: `nonce()` is called once and its result is used as the IV;
/// * `fips` build: `nonce` is dropped without being called and the validated
///   module generates a random 96-bit IV, because it only reports AES-GCM
///   encryption with an internally generated IV as an approved service.
///   Uniqueness is then statistical, so a key must see fewer than 2^32
///   encryptions; `cipher` keeps every log and state key far below that by
///   deriving one key per message.
pub(crate) fn gcm_seal_iv<N>(
    key: &[u8],
    nonce: N,
    aad: &[u8],
    buf: &mut [u8],
) -> Result<([u8; 12], [u8; 16]), CryptoError>
where
    N: FnOnce() -> Result<[u8; 12], CryptoError>,
{
    #[cfg(feature = "fips")]
    {
        drop(nonce);
        ringlike::gcm_seal_random(key, aad, buf)
    }
    #[cfg(not(feature = "fips"))]
    {
        let nonce = nonce()?;
        gcm_seal(key, &nonce, aad, buf).map(|tag| (nonce, tag))
    }
}

/// Fill `out` with cryptographically secure random bytes: the OS CSPRNG by
/// default, the validated module's DRBG with the `fips` feature. Callers
/// outside this crate that need random material (for example the snapshot
/// nonce salt) should use this instead of their own RNG so a FIPS build stays
/// on the validated generator.
pub fn random_bytes(out: &mut [u8]) -> Result<(), CryptoError> {
    fill_random(out)
}

/// Whether the crate was built with the FIPS validated backend.
pub const FIPS_BUILD: bool = cfg!(feature = "fips");

/// Fail unless the FIPS validated cryptographic module is compiled in and
/// running in FIPS mode.
///
/// # Errors
/// [`CryptoError::FipsUnavailable`] for a build without the `fips` feature or
/// when the module reports that FIPS mode is not active.
pub fn assert_fips() -> Result<(), CryptoError> {
    #[cfg(feature = "fips")]
    {
        aws_lc_rs::try_fips_mode().map_err(|_| CryptoError::FipsUnavailable)
    }
    #[cfg(not(feature = "fips"))]
    {
        Err(CryptoError::FipsUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assert_fips_matches_build() {
        let res = assert_fips();
        if FIPS_BUILD {
            res.expect("validated module must run in FIPS mode");
        } else {
            assert!(matches!(res, Err(CryptoError::FipsUnavailable)));
        }
    }

    /// RFC 5869 test case 1 (HKDF-SHA256): both backends must reproduce the
    /// same output keying material.
    #[test]
    fn test_hkdf_extract_expand_known_answer() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut okm = [0u8; 42];
        hkdf_extract_expand(&salt, &ikm, &info, &mut okm).expect("hkdf");
        assert_eq!(
            okm,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
            ]
        );
        assert!(matches!(
            hkdf_extract_expand(&[], &ikm, &info, &mut okm),
            Err(CryptoError::HkdfEmptyInput)
        ));
        assert!(matches!(
            hkdf_extract_expand(&salt, &ikm, &[], &mut okm),
            Err(CryptoError::HkdfEmptyInput)
        ));
    }

    /// NIST GCM test case 16 (AES-256, 96-bit IV, AAD): both backends must
    /// reproduce the same ciphertext and tag.
    #[test]
    fn test_gcm_known_answer() {
        let key = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
            0x67, 0x30, 0x83, 0x08,
        ];
        let nonce = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let aad = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let mut buf = vec![
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let plain = buf.clone();
        let tag = gcm_seal(&key, &nonce, &aad, &mut buf).expect("seal");
        assert_eq!(
            tag,
            [
                0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d,
                0x55, 0x1b
            ]
        );
        gcm_open(&key, &nonce, &aad, &mut buf, &tag).expect("open");
        assert_eq!(buf, plain);
    }
}
