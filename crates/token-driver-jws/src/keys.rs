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
//! # `KeyMaterial` <-> `jsonwebtoken` key format conversion
//!
//! [`openstack_keystone_key_repository::asymmetric::KeyMaterial`] stores
//! keys in a uniform, algorithm-agnostic shape: PKCS#8 DER for the private
//! key, SubjectPublicKeyInfo (SPKI) DER for the public key (the same shape
//! `derive_kid` hashes, ADR 0026 §3). `jsonwebtoken`'s `rust_crypto`
//! backend expects different per-algorithm shapes internally (PKCS#8 DER
//! for EC private keys, but raw SEC1 point bytes for EC public keys;
//! PKCS#1 DER for both halves of an RSA key) — this module bridges the
//! two so the rest of the crate never has to know the difference.
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use openstack_keystone_key_repository::asymmetric::{KeyMaterial, SigningAlgorithm};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use secrecy::ExposeSecret;

use crate::error::JwsDriverError;

/// The `jsonwebtoken` [`Algorithm`] corresponding to a [`SigningAlgorithm`].
#[must_use]
pub fn jwt_algorithm(algorithm: SigningAlgorithm) -> Algorithm {
    match algorithm {
        SigningAlgorithm::Es256 => Algorithm::ES256,
        SigningAlgorithm::Rs256 => Algorithm::RS256,
    }
}

/// Build a `jsonwebtoken` [`EncodingKey`] from stored [`KeyMaterial`].
pub fn to_encoding_key(material: &KeyMaterial) -> Result<EncodingKey, JwsDriverError> {
    match material.algorithm {
        // jsonwebtoken's rust_crypto ECDSA signer loads its EncodingKey
        // content directly via `SigningKey::from_pkcs8_der`, the same
        // format we already store — no conversion needed.
        SigningAlgorithm::Es256 => Ok(EncodingKey::from_ec_der(
            material.private_key_der.expose_secret(),
        )),
        // jsonwebtoken's rust_crypto RSA signer loads via
        // `RsaPrivateKey::from_pkcs1_der`, but we store PKCS#8 — convert.
        SigningAlgorithm::Rs256 => {
            let private_key =
                rsa::RsaPrivateKey::from_pkcs8_der(material.private_key_der.expose_secret())
                    .map_err(|e| JwsDriverError::KeyConversion(format!("RSA private key: {e}")))?;
            let pkcs1_der = private_key
                .to_pkcs1_der()
                .map_err(|e| JwsDriverError::KeyConversion(format!("RSA private key: {e}")))?;
            Ok(EncodingKey::from_rsa_der(pkcs1_der.as_bytes()))
        }
    }
}

/// Build a `jsonwebtoken` [`DecodingKey`] from stored [`KeyMaterial`].
pub fn to_decoding_key(material: &KeyMaterial) -> Result<DecodingKey, JwsDriverError> {
    match material.algorithm {
        // jsonwebtoken's rust_crypto ECDSA verifier loads via
        // `VerifyingKey::from_sec1_bytes` (the raw EC point), but we store
        // SPKI DER — parse then re-encode as a raw SEC1 point.
        SigningAlgorithm::Es256 => {
            let verifying_key =
                p256::ecdsa::VerifyingKey::from_public_key_der(&material.public_key_der)
                    .map_err(|e| JwsDriverError::KeyConversion(format!("EC public key: {e}")))?;
            let sec1_point = verifying_key.to_encoded_point(false);
            Ok(DecodingKey::from_ec_der(sec1_point.as_bytes()))
        }
        // jsonwebtoken's rust_crypto RSA verifier loads via
        // `RsaPublicKey::from_pkcs1_der`, but we store SPKI DER — convert.
        SigningAlgorithm::Rs256 => {
            let public_key = rsa::RsaPublicKey::from_public_key_der(&material.public_key_der)
                .map_err(|e| JwsDriverError::KeyConversion(format!("RSA public key: {e}")))?;
            let pkcs1_der = public_key
                .to_pkcs1_der()
                .map_err(|e| JwsDriverError::KeyConversion(format!("RSA public key: {e}")))?;
            Ok(DecodingKey::from_rsa_der(pkcs1_der.as_bytes()))
        }
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{Header, Validation, decode, encode};
    use openstack_keystone_key_repository::asymmetric::generate_keypair;
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claims {
        sub: String,
        exp: i64,
    }

    #[test]
    fn test_es256_sign_and_verify_roundtrip() {
        let material = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let encoding_key = to_encoding_key(&material).unwrap();
        let decoding_key = to_decoding_key(&material).unwrap();

        let claims = Claims {
            sub: "user-1".into(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
        };
        let token = encode(
            &Header::new(jwt_algorithm(SigningAlgorithm::Es256)),
            &claims,
            &encoding_key,
        )
        .unwrap();

        let mut validation = Validation::new(jwt_algorithm(SigningAlgorithm::Es256));
        validation.validate_exp = true;
        let decoded = decode::<Claims>(&token, &decoding_key, &validation).unwrap();
        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_rs256_sign_and_verify_roundtrip() {
        let material = generate_keypair(SigningAlgorithm::Rs256).unwrap();
        let encoding_key = to_encoding_key(&material).unwrap();
        let decoding_key = to_decoding_key(&material).unwrap();

        let claims = Claims {
            sub: "user-1".into(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
        };
        let token = encode(
            &Header::new(jwt_algorithm(SigningAlgorithm::Rs256)),
            &claims,
            &encoding_key,
        )
        .unwrap();

        let mut validation = Validation::new(jwt_algorithm(SigningAlgorithm::Rs256));
        validation.validate_exp = true;
        let decoded = decode::<Claims>(&token, &decoding_key, &validation).unwrap();
        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_es256_verify_fails_for_wrong_key() {
        let material = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let other = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let encoding_key = to_encoding_key(&material).unwrap();
        let wrong_decoding_key = to_decoding_key(&other).unwrap();

        let claims = Claims {
            sub: "user-1".into(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
        };
        let token = encode(
            &Header::new(jwt_algorithm(SigningAlgorithm::Es256)),
            &claims,
            &encoding_key,
        )
        .unwrap();

        let validation = Validation::new(jwt_algorithm(SigningAlgorithm::Es256));
        assert!(decode::<Claims>(&token, &wrong_decoding_key, &validation).is_err());
    }
}
