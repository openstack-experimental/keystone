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
//! RSA-OAEP (SHA-256, MGF1-SHA-256, empty label) for per-site DEK wrapping.
//!
//! The `fips` build uses the validated AWS-LC module; the default build uses
//! the RustCrypto `rsa` crate, which has no FIPS validation (STO-13).
//!
//! The `rsa` 0.9 decryption path is not constant time (Marvin attack,
//! RUSTSEC-2023-0071). A caller that can submit chosen ciphertexts to a
//! software site key and time the responses may recover the plaintext, i.e.
//! the DEK. Use the `fips` build (AWS-LC) or a Transit/HSM site key where
//! that matters. `rsa` 0.10.0 fixes this, but the workspace pins `rsa` 0.9
//! (also used by `core` and `jwt-crypto`), and cargo cannot resolve 0.10.0
//! while `crypto-glue` (via `webauthn-rs`, currently on an `rsa` 0.10
//! release candidate) asks for the `sha2` feature that 0.10.0 removed.

use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Smallest RSA modulus accepted for a site wrapping key.
pub(crate) const MIN_RSA_BITS: usize = 2048;

#[cfg(feature = "fips")]
mod imp {
    use aws_lc_rs::rsa::{
        OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, OaepPublicEncryptingKey,
        PrivateDecryptingKey, PublicEncryptingKey,
    };

    use super::*;

    pub(crate) fn encrypt(spki_der: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = PublicEncryptingKey::from_der(spki_der)
            .map_err(|e| CryptoError::SiteWrap(format!("public key rejected: {e}")))?;
        if key.key_size_bytes() * 8 < MIN_RSA_BITS {
            return Err(CryptoError::SiteWrap(
                "RSA key smaller than 2048 bits".into(),
            ));
        }
        let key = OaepPublicEncryptingKey::new(key)
            .map_err(|_| CryptoError::SiteWrap("OAEP key setup failed".into()))?;
        if msg.len() > key.max_plaintext_size(&OAEP_SHA256_MGF1SHA256) {
            return Err(CryptoError::SiteWrap("message too long for key".into()));
        }
        let mut out = vec![0u8; key.ciphertext_size()];
        let n = key
            .encrypt(&OAEP_SHA256_MGF1SHA256, msg, &mut out, None)
            .map_err(|_| CryptoError::SiteWrap("OAEP encryption failed".into()))?
            .len();
        out.truncate(n);
        Ok(out)
    }

    /// A parsed RSA private key, ready for OAEP decryption.
    pub(crate) struct PrivateKey(OaepPrivateDecryptingKey);

    impl PrivateKey {
        pub(crate) fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, CryptoError> {
            let key = PrivateDecryptingKey::from_pkcs8(pkcs8_der)
                .map_err(|e| CryptoError::SiteUnwrap(format!("private key rejected: {e}")))?;
            if key.key_size_bytes() * 8 < MIN_RSA_BITS {
                return Err(CryptoError::SiteUnwrap(
                    "RSA key smaller than 2048 bits".into(),
                ));
            }
            OaepPrivateDecryptingKey::new(key)
                .map(Self)
                .map_err(|_| CryptoError::SiteUnwrap("OAEP key setup failed".into()))
        }

        pub(crate) fn decrypt(&self, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
            let mut out = Zeroizing::new(vec![0u8; self.0.min_output_size()]);
            let n = self
                .0
                .decrypt(&OAEP_SHA256_MGF1SHA256, ct, &mut out, None)
                .map_err(|_| CryptoError::SiteUnwrap("OAEP decryption failed".into()))?
                .len();
            out.truncate(n);
            Ok(out)
        }
    }
}

#[cfg(all(not(feature = "fips"), feature = "ring"))]
mod imp {
    use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
    use rsa::sha2::Sha256;
    use rsa::traits::PublicKeyParts;
    use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};

    use super::*;

    pub(crate) fn encrypt(spki_der: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = RsaPublicKey::from_public_key_der(spki_der)
            .map_err(|e| CryptoError::SiteWrap(format!("public key rejected: {e}")))?;
        if key.size() * 8 < MIN_RSA_BITS {
            return Err(CryptoError::SiteWrap(
                "RSA key smaller than 2048 bits".into(),
            ));
        }
        key.encrypt(&mut rsa::rand_core::OsRng, Oaep::new::<Sha256>(), msg)
            .map_err(|e| CryptoError::SiteWrap(format!("OAEP encryption failed: {e}")))
    }

    /// A parsed RSA private key, ready for OAEP decryption.
    pub(crate) struct PrivateKey(RsaPrivateKey);

    impl PrivateKey {
        pub(crate) fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, CryptoError> {
            let key = RsaPrivateKey::from_pkcs8_der(pkcs8_der)
                .map_err(|e| CryptoError::SiteUnwrap(format!("private key rejected: {e}")))?;
            if key.size() * 8 < MIN_RSA_BITS {
                return Err(CryptoError::SiteUnwrap(
                    "RSA key smaller than 2048 bits".into(),
                ));
            }
            Ok(Self(key))
        }

        pub(crate) fn decrypt(&self, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
            self.0
                .decrypt(Oaep::new::<Sha256>(), ct)
                .map(Zeroizing::new)
                .map_err(|_| CryptoError::SiteUnwrap("OAEP decryption failed".into()))
        }
    }
}

pub(crate) use imp::{PrivateKey, encrypt};
