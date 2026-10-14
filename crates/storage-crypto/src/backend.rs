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
//! # Cryptographic backend selection
//!
//! Every AES-256-GCM, HKDF-SHA256, HMAC-SHA256 and random-bytes operation of
//! this crate goes through the handful of functions below, so the primitive
//! provider can be swapped without touching the call sites:
//!
//! * default: the pure-Rust RustCrypto crates ([`rustcrypto`]);
//! * `fips` feature: `aws-lc-rs` built against the FIPS 140-3 validated
//!   AWS-LC module ([`awslc`]). When both are enabled `fips` wins, because
//!   cargo features are additive and a workspace-wide build must not silently
//!   fall back to non-validated primitives.
//!
//! A deployment that claims FIPS operation must call [`assert_fips`] during
//! start-up; it fails unless the validated module is compiled in and active.

use crate::error::CryptoError;

#[cfg(feature = "fips")]
mod awslc;
#[cfg(not(feature = "fips"))]
mod rustcrypto;

#[cfg(feature = "fips")]
pub(crate) use awslc::{fill_random, gcm_open, gcm_seal, hkdf_expand, hmac_sha256};
#[cfg(not(feature = "fips"))]
pub(crate) use rustcrypto::{fill_random, gcm_open, gcm_seal, hkdf_expand, hmac_sha256};

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
        awslc::fips_active()
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
