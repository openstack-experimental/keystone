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
//! # Asymmetric keypair generation (ADR 0026 §3)
use chrono::Utc;
use openstack_keystone_jwt_crypto::{KeyKind, generate};
use secrecy::SecretBox;

use crate::asymmetric::kid::derive_kid;
use crate::asymmetric::source::{KeyMaterial, SigningAlgorithm};
use crate::error::KeyRepositoryError;

/// Generate a fresh keypair for `algorithm`, deriving its `kid` from the
/// DER-encoded public key (ADR 0026 §3). `Rs256` is RSA-2048 (ADR 0026 §3).
pub fn generate_keypair(algorithm: SigningAlgorithm) -> Result<KeyMaterial, KeyRepositoryError> {
    let kind = match algorithm {
        SigningAlgorithm::Es256 => KeyKind::P256,
        SigningAlgorithm::Rs256 => KeyKind::Rsa2048,
    };
    let key = generate(kind).map_err(|e| KeyRepositoryError::Crypto(e.to_string()))?;
    let private_key_der = key.private_pkcs8.to_vec();
    let public_key_der = key.public_spki;

    let kid = derive_kid(&public_key_der);
    Ok(KeyMaterial {
        algorithm,
        private_key_der: SecretBox::new(Box::new(private_key_der)),
        public_key_der: public_key_der.to_vec(),
        kid,
        created_at: Utc::now(),
        demoted_at: None,
    })
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn test_generate_es256_keypair() {
        let key = generate_keypair(SigningAlgorithm::Es256).unwrap();
        assert_eq!(key.algorithm, SigningAlgorithm::Es256);
        assert_eq!(key.kid.len(), 32);
        assert!(!key.private_key_der.expose_secret().is_empty());
        assert!(!key.public_key_der.is_empty());
    }

    #[test]
    fn test_generate_rs256_keypair() {
        let key = generate_keypair(SigningAlgorithm::Rs256).unwrap();
        assert_eq!(key.algorithm, SigningAlgorithm::Rs256);
        assert_eq!(key.kid.len(), 32);
        assert!(!key.private_key_der.expose_secret().is_empty());
        assert!(!key.public_key_der.is_empty());
    }

    #[test]
    fn test_each_generation_yields_a_distinct_kid() {
        let a = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let b = generate_keypair(SigningAlgorithm::Es256).unwrap();
        assert_ne!(a.kid, b.kid);
    }
}
