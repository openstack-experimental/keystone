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
//! # `KeyMaterial` <-> `jsonwebtoken` key format conversion
//!
//! [`KeyMaterial`] stores keys in a uniform, algorithm-agnostic shape:
//! PKCS#8 DER for the private key, SubjectPublicKeyInfo (SPKI) DER for the
//! public key (the same shape [`super::derive_kid`] hashes, ADR 0026 §3).
//! The `jwt-crypto` provider (`ring` or FIPS `aws-lc-rs`) behind
//! `jsonwebtoken` expects different per-algorithm shapes (PKCS#8 DER for EC
//! private keys, but the raw SEC1 point for EC public keys; PKCS#8 or
//! PKCS#1 DER for an RSA private key and PKCS#1 `RSAPublicKey` DER for the
//! public half) — this module bridges the two. Shared by every JWT-signing consumer of
//! this repository (the Phase 0 JWS token driver, the Phase 3 OAuth2
//! `/token` signer), so the conversion lives here rather than in any one
//! driver crate.
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use openstack_keystone_jwt_crypto::{
    KeyKind, p256_point_from_spki, rsa_pkcs1_from_spki, validate_private_key,
};
use secrecy::ExposeSecret;

use crate::error::KeyRepositoryError;

use super::{KeyMaterial, SigningAlgorithm};

/// The `jsonwebtoken` [`Algorithm`] corresponding to a [`SigningAlgorithm`].
#[must_use]
pub fn jwt_algorithm(algorithm: SigningAlgorithm) -> Algorithm {
    match algorithm {
        SigningAlgorithm::Es256 => Algorithm::ES256,
        SigningAlgorithm::Rs256 => Algorithm::RS256,
    }
}

/// Build a `jsonwebtoken` [`EncodingKey`] from stored [`KeyMaterial`].
///
/// The key is loaded once to check it, so corrupt material fails here and
/// not at signing time.
///
/// # Errors
///
/// [`KeyRepositoryError::Crypto`] when the stored private key does not load
/// as a key of the material's algorithm.
pub fn to_encoding_key(material: &KeyMaterial) -> Result<EncodingKey, KeyRepositoryError> {
    // The provider loads the stored PKCS#8 as is.
    let der = material.private_key_der.expose_secret();
    let (kind, key) = match material.algorithm {
        SigningAlgorithm::Es256 => (KeyKind::P256, EncodingKey::from_ec_der(der)),
        SigningAlgorithm::Rs256 => (KeyKind::Rsa2048, EncodingKey::from_rsa_der(der)),
    };
    validate_private_key(kind, der).map_err(|e| KeyRepositoryError::Crypto(e.to_string()))?;
    Ok(key)
}

/// Build a `jsonwebtoken` [`DecodingKey`] from stored [`KeyMaterial`].
///
/// # Errors
///
/// [`KeyRepositoryError::Crypto`] when the stored public key is not an SPKI
/// of the material's algorithm.
pub fn to_decoding_key(material: &KeyMaterial) -> Result<DecodingKey, KeyRepositoryError> {
    // The provider verifies against the raw EC point and the PKCS#1 RSA key,
    // while we store SPKI DER.
    match material.algorithm {
        SigningAlgorithm::Es256 => p256_point_from_spki(&material.public_key_der)
            .map(DecodingKey::from_ec_der)
            .ok_or_else(|| KeyRepositoryError::Crypto("EC public key: not a P-256 SPKI".into())),
        SigningAlgorithm::Rs256 => rsa_pkcs1_from_spki(&material.public_key_der)
            .map(DecodingKey::from_rsa_der)
            .ok_or_else(|| KeyRepositoryError::Crypto("RSA public key: not an RSA SPKI".into())),
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{Header, Validation, decode, encode};
    use serde::{Deserialize, Serialize};

    use super::super::generate_keypair;
    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claims {
        sub: String,
        exp: i64,
    }

    #[test]
    fn test_es256_sign_and_verify_roundtrip() {
        openstack_keystone_jwt_crypto::install().unwrap();
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
        openstack_keystone_jwt_crypto::install().unwrap();
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
        openstack_keystone_jwt_crypto::install().unwrap();
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

    #[test]
    fn test_encoding_key_rejects_corrupt_private_key() {
        let mut material = generate_keypair(SigningAlgorithm::Es256).unwrap();
        material.private_key_der = secrecy::SecretBox::new(Box::new(vec![0u8; 32]));
        assert!(matches!(
            to_encoding_key(&material),
            Err(KeyRepositoryError::Crypto(_))
        ));
    }
}
