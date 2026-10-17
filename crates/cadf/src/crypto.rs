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
// Crypto inventory: AUD-1, AUD-2, AUD-3; see
// doc/src/contributor/crypto-inventory.md
//! Cryptographic primitive seam of the audit framework.
//!
//! Every HMAC-SHA256, HKDF-SHA256 and random-bytes operation of this crate
//! goes through the functions below, so the provider can be swapped without
//! touching the call sites:
//!
//! * default (`ring` feature): the `ring` crate;
//! * `fips` feature: `aws-lc-rs` built against the FIPS 140-3 validated AWS-LC
//!   module. It wins when both features are enabled, because cargo features are
//!   additive and a workspace-wide build must not silently fall back to
//!   non-validated primitives.
//!
//! The TLS provider of the syslog sink is chosen by
//! `openstack-keystone-tls-provider`, not by this crate's features.
//!
//! The `imp` module below mirrors `ringlike` in
//! `openstack-keystone-storage-crypto` on purpose: that crate pulls in far more
//! than the audit framework needs. Keep the two in step when changing either.
//!
//! A deployment that claims FIPS operation calls [`assert_fips`] at start-up.

use thiserror::Error;

#[cfg(not(any(feature = "fips", feature = "ring")))]
compile_error!("enable either the `ring` (default) or the `fips` feature");

/// Cryptographic backend failure.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// HKDF was called with an empty salt or info; the approved
    /// Extract-then-Expand flow needs both.
    #[error("HKDF salt and info must be non-empty")]
    KdfEmptyInput,
    /// HKDF failed (for example an oversized output).
    #[error("key derivation failed")]
    Kdf,
    /// The MAC rejected its key.
    /// The random number generator failed.
    #[error("random number generator failed")]
    Rng,
    /// A FIPS claim was made but the validated module is not active.
    #[error("the FIPS 140-3 validated cryptographic module is not active")]
    FipsUnavailable,
}

/// Whether this build routes primitives through the FIPS-validated module.
pub const FIPS_BUILD: bool = cfg!(feature = "fips");

/// Ok only when the validated module is compiled in and running in FIPS
/// mode. Always an error in a build without the `fips` feature.
pub fn assert_fips() -> Result<(), CryptoError> {
    imp::fips_active()
}

/// HMAC-SHA256 of `msg` under `key` (any key length). Infallible: both
/// providers accept every key length.
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    imp::hmac_sha256(key, msg)
}

/// Constant-time verification of an HMAC-SHA256 `tag`.
pub(crate) fn hmac_sha256_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    imp::hmac_sha256_verify(key, msg, tag)
}

/// Full HKDF-SHA256 (Extract-then-Expand, RFC 5869). `salt` and `info` must
/// be non-empty: that is the flow the validated module documents as an
/// approved service.
pub(crate) fn hkdf_extract_expand(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if salt.is_empty() || info.is_empty() {
        return Err(CryptoError::KdfEmptyInput);
    }
    imp::hkdf_extract_expand(salt, ikm, info, out)
}

/// Fill `out` from the operating system RNG (default build) or the validated
/// module's DRBG (`fips`).
pub(crate) fn fill_random(out: &mut [u8]) -> Result<(), CryptoError> {
    imp::fill_random(out)
}

/// One body serves both providers: `aws-lc-rs` is a drop-in for the subset of
/// the `ring` API used here, so `provider` is the only thing that differs.
mod imp {
    #[cfg(feature = "fips")]
    use aws_lc_rs as provider;
    #[cfg(not(feature = "fips"))]
    use ring as provider;

    use provider::hkdf::{HKDF_SHA256, KeyType, Salt};
    use provider::hmac;
    use provider::rand::{SecureRandom, SystemRandom};

    use super::CryptoError;

    struct OutLen(usize);

    impl KeyType for OutLen {
        fn len(&self) -> usize {
            self.0
        }
    }

    pub(super) fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), msg);
        // A SHA-256 tag is always 32 bytes; zip keeps this panic-free.
        let mut out = [0u8; 32];
        for (o, t) in out.iter_mut().zip(tag.as_ref()) {
            *o = *t;
        }
        out
    }

    pub(super) fn hmac_sha256_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
        hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), msg, tag).is_ok()
    }

    pub(super) fn hkdf_extract_expand(
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        Salt::new(HKDF_SHA256, salt)
            .extract(ikm)
            .expand(&[info], OutLen(out.len()))
            .map_err(|_| CryptoError::Kdf)?
            .fill(out)
            .map_err(|_| CryptoError::Kdf)
    }

    pub(super) fn fill_random(out: &mut [u8]) -> Result<(), CryptoError> {
        SystemRandom::new().fill(out).map_err(|_| CryptoError::Rng)
    }

    #[cfg(feature = "fips")]
    pub(super) fn fips_active() -> Result<(), CryptoError> {
        aws_lc_rs::try_fips_mode().map_err(|_| CryptoError::FipsUnavailable)
    }

    #[cfg(not(feature = "fips"))]
    pub(super) fn fips_active() -> Result<(), CryptoError> {
        Err(CryptoError::FipsUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_known_answer_rfc4231_case_2() {
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert!(hmac_sha256_verify(
            b"Jefe",
            b"what do ya want for nothing?",
            &tag
        ));
        assert!(!hmac_sha256_verify(b"Jefe", b"other", &tag));
    }

    #[test]
    fn hkdf_known_answer_rfc5869_case_1() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut okm = [0u8; 42];
        hkdf_extract_expand(&salt, &ikm, &info, &mut okm).unwrap();
        let hex: String = okm.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_rejects_empty_salt_and_info() {
        let mut out = [0u8; 32];
        assert!(matches!(
            hkdf_extract_expand(b"", b"ikm", b"info", &mut out),
            Err(CryptoError::KdfEmptyInput)
        ));
        assert!(matches!(
            hkdf_extract_expand(b"salt", b"ikm", b"", &mut out),
            Err(CryptoError::KdfEmptyInput)
        ));
    }

    #[test]
    fn random_bytes_differ() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random(&mut a).unwrap();
        fill_random(&mut b).unwrap();
        assert_ne!(a, b);
    }

    #[cfg(feature = "fips")]
    #[test]
    fn fips_module_is_active() {
        assert!(std::hint::black_box(FIPS_BUILD));
        assert_fips().unwrap();
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn default_build_is_not_fips() {
        assert!(!std::hint::black_box(FIPS_BUILD));
        assert!(matches!(assert_fips(), Err(CryptoError::FipsUnavailable)));
    }
}
