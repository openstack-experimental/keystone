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
// Crypto inventory: TOK-2, TOK-4, TOK-11; see
// doc/src/contributor/crypto-inventory.md
//! Signers and verifiers for the `jsonwebtoken` provider.
//!
//! One body serves `ring` and `aws-lc-rs`; `provider` is the only thing
//! that differs. Keys arrive as the bytes held by `jsonwebtoken`'s
//! `EncodingKey` / `DecodingKey`: PKCS#8 for EC and Ed25519 private keys,
//! PKCS#1 or PKCS#8 for RSA private keys, the SEC1 point for EC public keys,
//! PKCS#1 `RSAPublicKey` or modulus/exponent for RSA public keys, the raw key
//! for Ed25519 and the secret for HMAC.

#[cfg(feature = "fips")]
use aws_lc_rs as provider;
#[cfg(not(feature = "fips"))]
use ring as provider;

use jsonwebtoken::crypto::{JwtSigner, JwtVerifier};
use jsonwebtoken::errors::{ErrorKind, Result};
use jsonwebtoken::signature::{self, Signer, Verifier};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, DecodingKeyKind, EncodingKey};
use provider::hmac;
use provider::rand::SystemRandom;
use provider::signature::{self as sig, UnparsedPublicKey};

fn unspecified() -> signature::Error {
    signature::Error::new()
}

fn family(algorithm: Algorithm) -> AlgorithmFamily {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => AlgorithmFamily::Hmac,
        Algorithm::ES256 | Algorithm::ES384 => AlgorithmFamily::Ec,
        Algorithm::EdDSA => AlgorithmFamily::Ed,
        _ => AlgorithmFamily::Rsa,
    }
}

pub(crate) fn ec_pair(
    alg: &'static sig::EcdsaSigningAlgorithm,
    pkcs8: &[u8],
) -> Result<sig::EcdsaKeyPair> {
    #[cfg(feature = "fips")]
    let pair = sig::EcdsaKeyPair::from_pkcs8(alg, pkcs8);
    #[cfg(not(feature = "fips"))]
    let pair = sig::EcdsaKeyPair::from_pkcs8(alg, pkcs8, &SystemRandom::new());
    pair.map_err(|_| ErrorKind::InvalidEcdsaKey.into())
}

pub(crate) fn ed_pair(pkcs8: &[u8]) -> Result<sig::Ed25519KeyPair> {
    sig::Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| ErrorKind::InvalidEddsaKey.into())
}

/// Load an RSA private key stored as PKCS#1 or PKCS#8.
pub(crate) fn rsa_pair(der: &[u8]) -> Result<sig::RsaKeyPair> {
    sig::RsaKeyPair::from_der(der)
        .or_else(|_| sig::RsaKeyPair::from_pkcs8(der))
        .map_err(|e| ErrorKind::InvalidRsaKey(e.to_string()).into())
}

struct HmacSigner {
    alg: Algorithm,
    key: hmac::Key,
}

impl Signer<Vec<u8>> for HmacSigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        Ok(hmac::sign(&self.key, msg).as_ref().to_vec())
    }
}

impl JwtSigner for HmacSigner {
    fn algorithm(&self) -> Algorithm {
        self.alg
    }
}

struct HmacVerifier {
    alg: Algorithm,
    key: hmac::Key,
}

impl Verifier<Vec<u8>> for HmacVerifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        hmac::verify(&self.key, msg, signature).map_err(|_| unspecified())
    }
}

impl JwtVerifier for HmacVerifier {
    fn algorithm(&self) -> Algorithm {
        self.alg
    }
}

struct EcSigner {
    alg: Algorithm,
    pair: sig::EcdsaKeyPair,
}

impl Signer<Vec<u8>> for EcSigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        let signature = self
            .pair
            .sign(&SystemRandom::new(), msg)
            .map_err(|_| unspecified())?;
        Ok(signature.as_ref().to_vec())
    }
}

impl JwtSigner for EcSigner {
    fn algorithm(&self) -> Algorithm {
        self.alg
    }
}

struct EdSigner(sig::Ed25519KeyPair);

impl Signer<Vec<u8>> for EdSigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        Ok(self.0.sign(msg).as_ref().to_vec())
    }
}

impl JwtSigner for EdSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

struct RsaSigner {
    alg: Algorithm,
    padding: &'static dyn sig::RsaEncoding,
    pair: sig::RsaKeyPair,
}

impl Signer<Vec<u8>> for RsaSigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        #[cfg(feature = "fips")]
        let modulus_len = self.pair.public_modulus_len();
        #[cfg(not(feature = "fips"))]
        let modulus_len = self.pair.public().modulus_len();
        let mut signature = vec![0; modulus_len];
        self.pair
            .sign(self.padding, &SystemRandom::new(), msg, &mut signature)
            .map_err(|_| unspecified())?;
        Ok(signature)
    }
}

impl JwtSigner for RsaSigner {
    fn algorithm(&self) -> Algorithm {
        self.alg
    }
}

/// Verifier over an `UnparsedPublicKey`-style algorithm: EC and Ed25519.
struct PointVerifier {
    alg: Algorithm,
    verification: &'static dyn sig::VerificationAlgorithm,
    key: Vec<u8>,
}

impl Verifier<Vec<u8>> for PointVerifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        UnparsedPublicKey::new(self.verification, &self.key)
            .verify(msg, signature)
            .map_err(|_| unspecified())
    }
}

impl JwtVerifier for PointVerifier {
    fn algorithm(&self) -> Algorithm {
        self.alg
    }
}

struct RsaVerifier {
    alg: Algorithm,
    parameters: &'static sig::RsaParameters,
    key: DecodingKey,
}

impl Verifier<Vec<u8>> for RsaVerifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        match self.key.kind() {
            DecodingKeyKind::SecretOrDer(der) => {
                UnparsedPublicKey::new(self.parameters, der).verify(msg, signature)
            }
            DecodingKeyKind::RsaModulusExponent { n, e } => {
                sig::RsaPublicKeyComponents { n, e }.verify(self.parameters, msg, signature)
            }
        }
        .map_err(|_| unspecified())
    }
}

impl JwtVerifier for RsaVerifier {
    fn algorithm(&self) -> Algorithm {
        self.alg
    }
}

pub(crate) fn new_signer(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
    let alg = *algorithm;
    if key.family() != family(alg) {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    let der = key.as_bytes();
    let rsa = |padding: &'static dyn sig::RsaEncoding| -> Result<Box<dyn JwtSigner>> {
        Ok(Box::new(RsaSigner {
            alg,
            padding,
            pair: rsa_pair(der)?,
        }))
    };
    let hmac = |a: hmac::Algorithm| -> Result<Box<dyn JwtSigner>> {
        Ok(Box::new(HmacSigner {
            alg,
            key: hmac::Key::new(a, der),
        }))
    };
    match alg {
        Algorithm::HS256 => hmac(hmac::HMAC_SHA256),
        Algorithm::HS384 => hmac(hmac::HMAC_SHA384),
        Algorithm::HS512 => hmac(hmac::HMAC_SHA512),
        Algorithm::ES256 => Ok(Box::new(EcSigner {
            alg,
            pair: ec_pair(&sig::ECDSA_P256_SHA256_FIXED_SIGNING, der)?,
        })),
        Algorithm::ES384 => Ok(Box::new(EcSigner {
            alg,
            pair: ec_pair(&sig::ECDSA_P384_SHA384_FIXED_SIGNING, der)?,
        })),
        Algorithm::EdDSA => Ok(Box::new(EdSigner(ed_pair(der)?))),
        Algorithm::RS256 => rsa(&sig::RSA_PKCS1_SHA256),
        Algorithm::RS384 => rsa(&sig::RSA_PKCS1_SHA384),
        Algorithm::RS512 => rsa(&sig::RSA_PKCS1_SHA512),
        Algorithm::PS256 => rsa(&sig::RSA_PSS_SHA256),
        Algorithm::PS384 => rsa(&sig::RSA_PSS_SHA384),
        Algorithm::PS512 => rsa(&sig::RSA_PSS_SHA512),
        _ => Err(ErrorKind::InvalidAlgorithm.into()),
    }
}

pub(crate) fn new_verifier(
    algorithm: &Algorithm,
    key: &DecodingKey,
) -> Result<Box<dyn JwtVerifier>> {
    let alg = *algorithm;
    if key.family() != family(alg) {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    let rsa = |parameters: &'static sig::RsaParameters| -> Result<Box<dyn JwtVerifier>> {
        Ok(Box::new(RsaVerifier {
            alg,
            parameters,
            key: key.clone(),
        }))
    };
    let point = |verification: &'static dyn sig::VerificationAlgorithm| {
        Ok::<Box<dyn JwtVerifier>, jsonwebtoken::errors::Error>(Box::new(PointVerifier {
            alg,
            verification,
            key: key.try_get_as_bytes()?.to_vec(),
        }))
    };
    let hmac = |a: hmac::Algorithm| -> Result<Box<dyn JwtVerifier>> {
        Ok(Box::new(HmacVerifier {
            alg,
            key: hmac::Key::new(a, key.try_get_as_bytes()?),
        }))
    };
    match alg {
        Algorithm::HS256 => hmac(hmac::HMAC_SHA256),
        Algorithm::HS384 => hmac(hmac::HMAC_SHA384),
        Algorithm::HS512 => hmac(hmac::HMAC_SHA512),
        Algorithm::ES256 => point(&sig::ECDSA_P256_SHA256_FIXED),
        Algorithm::ES384 => point(&sig::ECDSA_P384_SHA384_FIXED),
        Algorithm::EdDSA => point(&sig::ED25519),
        Algorithm::RS256 => rsa(&sig::RSA_PKCS1_2048_8192_SHA256),
        Algorithm::RS384 => rsa(&sig::RSA_PKCS1_2048_8192_SHA384),
        Algorithm::RS512 => rsa(&sig::RSA_PKCS1_2048_8192_SHA512),
        Algorithm::PS256 => rsa(&sig::RSA_PSS_2048_8192_SHA256),
        Algorithm::PS384 => rsa(&sig::RSA_PSS_2048_8192_SHA384),
        Algorithm::PS512 => rsa(&sig::RSA_PSS_2048_8192_SHA512),
        _ => Err(ErrorKind::InvalidAlgorithm.into()),
    }
}
