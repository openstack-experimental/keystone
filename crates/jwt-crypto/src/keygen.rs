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
// Crypto inventory: TOK-2; see doc/src/contributor/crypto-inventory.md
//! Signing key generation and key-format helpers.
//!
//! Private keys are PKCS#8 DER and public keys SPKI DER, the formats the key
//! repository stores.
//!
//! * EC P-256 keys come from `ring` or, with `fips`, from AWS-LC.
//! * RSA keys come from AWS-LC with `fips`. `ring` cannot generate RSA
//!   keys, so otherwise the `rsa-keygen` feature (the `rsa` crate) provides
//!   them, and without it generation fails with
//!   [`KeygenError::Unsupported`].

#[cfg(feature = "fips")]
use aws_lc_rs as provider;
#[cfg(not(feature = "fips"))]
use ring as provider;

use provider::rand::SystemRandom;
use provider::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use zeroize::Zeroizing;

use crate::der;

/// Kind of key to generate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// EC P-256, for ES256.
    P256,
    /// RSA with a 2048 bit modulus, for RS256.
    Rsa2048,
}

/// A generated key pair.
pub struct GeneratedKey {
    /// PKCS#8 `PrivateKeyInfo` DER.
    pub private_pkcs8: Zeroizing<Vec<u8>>,
    /// `SubjectPublicKeyInfo` DER.
    pub public_spki: Vec<u8>,
}

/// Key generation failure.
#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    /// The backend failed to generate or encode the key.
    #[error("{kind:?} key generation failed: {reason}")]
    Backend {
        /// Requested key kind.
        kind: KeyKind,
        /// Backend message.
        reason: String,
    },

    /// The build cannot generate this kind of key.
    #[error(
        "{0:?} key generation is unavailable: `ring` cannot generate RSA keys, \
         enable the `rsa-keygen` or `fips` feature"
    )]
    Unsupported(KeyKind),
}

/// ASN.1 prefix of a P-256 `SubjectPublicKeyInfo`, followed by the 65 byte
/// uncompressed point.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Generate a key pair.
pub fn generate(kind: KeyKind) -> Result<GeneratedKey, KeygenError> {
    match kind {
        KeyKind::P256 => generate_p256(),
        KeyKind::Rsa2048 => generate_rsa2048(),
    }
}

fn backend(kind: KeyKind, reason: impl std::fmt::Display) -> KeygenError {
    KeygenError::Backend {
        kind,
        reason: reason.to_string(),
    }
}

fn generate_p256() -> Result<GeneratedKey, KeygenError> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|e| backend(KeyKind::P256, e))?;
    let private_pkcs8 = Zeroizing::new(pkcs8.as_ref().to_vec());
    let point = crate::backend::ec_pair(&ECDSA_P256_SHA256_FIXED_SIGNING, &private_pkcs8)
        .map_err(|e| backend(KeyKind::P256, e))?
        .public_key()
        .as_ref()
        .to_vec();
    let mut public_spki = P256_SPKI_PREFIX.to_vec();
    public_spki.extend_from_slice(&point);
    Ok(GeneratedKey {
        private_pkcs8,
        public_spki,
    })
}

#[cfg(feature = "fips")]
fn generate_rsa2048() -> Result<GeneratedKey, KeygenError> {
    use aws_lc_rs::encoding::AsDer as _;
    use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};

    let kind = KeyKind::Rsa2048;
    let pair = RsaKeyPair::generate(KeySize::Rsa2048).map_err(|e| backend(kind, e))?;
    let private_pkcs8 = Zeroizing::new(
        pair.as_der()
            .map_err(|e| backend(kind, e))?
            .as_ref()
            .to_vec(),
    );
    let public_spki = pair
        .public_key()
        .as_der()
        .map_err(|e| backend(kind, e))?
        .as_ref()
        .to_vec();
    Ok(GeneratedKey {
        private_pkcs8,
        public_spki,
    })
}

#[cfg(all(not(feature = "fips"), feature = "rsa-keygen"))]
fn generate_rsa2048() -> Result<GeneratedKey, KeygenError> {
    use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};

    let kind = KeyKind::Rsa2048;
    let private =
        rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).map_err(|e| backend(kind, e))?;
    let private_pkcs8 = Zeroizing::new(
        private
            .to_pkcs8_der()
            .map_err(|e| backend(kind, e))?
            .as_bytes()
            .to_vec(),
    );
    let public_spki = private
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| backend(kind, e))?
        .as_bytes()
        .to_vec();
    Ok(GeneratedKey {
        private_pkcs8,
        public_spki,
    })
}

#[cfg(all(not(feature = "fips"), not(feature = "rsa-keygen")))]
fn generate_rsa2048() -> Result<GeneratedKey, KeygenError> {
    Err(KeygenError::Unsupported(KeyKind::Rsa2048))
}

/// The uncompressed point of a P-256 `SubjectPublicKeyInfo`, the content of
/// a `jsonwebtoken` EC `DecodingKey`.
#[must_use]
pub fn p256_point_from_spki(spki: &[u8]) -> Option<&[u8]> {
    spki.strip_prefix(&P256_SPKI_PREFIX[..])
        .filter(|point| point.len() == 65 && point[0] == 4)
}

/// The PKCS#1 `RSAPublicKey` of an RSA `SubjectPublicKeyInfo`, the content of
/// a `jsonwebtoken` RSA `DecodingKey`.
#[must_use]
pub fn rsa_pkcs1_from_spki(spki: &[u8]) -> Option<&[u8]> {
    der::spki_key_bits(spki)
}
