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
//! # `KeyMaterial` → JWK conversion (ADR 0026 §3)
//!
//! Publishes only the public half of a keypair: `public_key_der` is parsed
//! back into its raw EC point (`x`/`y`) or RSA modulus/exponent (`n`/`e`)
//! coordinates, base64url-encoded per RFC 7518.
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
    EllipticCurveKeyType, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse, RSAKeyParameters, RSAKeyType,
};
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::pkcs8::DecodePublicKey as _;
use rsa::traits::PublicKeyParts as _;

use openstack_keystone_key_repository::asymmetric::{ActiveKeys, KeyMaterial, SigningAlgorithm};

use crate::oauth2_key::Oauth2KeyProviderError;

fn key_material_to_jwk(material: &KeyMaterial) -> Result<Jwk, Oauth2KeyProviderError> {
    let algorithm = match material.algorithm {
        SigningAlgorithm::Es256 => {
            let public_key = p256::PublicKey::from_public_key_der(&material.public_key_der)
                .map_err(Oauth2KeyProviderError::crypto)?;
            let point = public_key.to_encoded_point(false);
            let x = point.x().ok_or_else(|| {
                Oauth2KeyProviderError::Crypto("EC public key missing x coordinate".into())
            })?;
            let y = point.y().ok_or_else(|| {
                Oauth2KeyProviderError::Crypto("EC public key missing y coordinate".into())
            })?;
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P256,
                x: URL_SAFE_NO_PAD.encode(x),
                y: URL_SAFE_NO_PAD.encode(y),
            })
        }
        SigningAlgorithm::Rs256 => {
            let public_key = rsa::RsaPublicKey::from_public_key_der(&material.public_key_der)
                .map_err(Oauth2KeyProviderError::crypto)?;
            AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
            })
        }
    };

    let key_algorithm = match material.algorithm {
        SigningAlgorithm::Es256 => KeyAlgorithm::ES256,
        SigningAlgorithm::Rs256 => KeyAlgorithm::RS256,
    };

    Ok(Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_algorithm: Some(key_algorithm),
            key_id: Some(material.kid.clone()),
            ..Default::default()
        },
        algorithm,
    })
}

/// Convert a domain's [`ActiveKeys`] into a [`JwkSet`], publishing `Primary`
/// (and `Previous`, if present) — the multi-generational publishing pool
/// (ADR 0026 §3).
pub fn active_keys_to_jwk_set(active: &ActiveKeys) -> Result<JwkSet, Oauth2KeyProviderError> {
    let mut keys = vec![key_material_to_jwk(&active.primary)?];
    if let Some(previous) = &active.previous {
        keys.push(key_material_to_jwk(previous)?);
    }
    Ok(JwkSet { keys })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_key_repository::asymmetric::generate_keypair;

    #[test]
    fn test_es256_jwk_round_trips_through_decode() {
        let material = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let jwk = key_material_to_jwk(&material).unwrap();
        assert_eq!(jwk.common.key_id.as_deref(), Some(material.kid.as_str()));
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(&jwk).unwrap();
        // A `DecodingKey` was built without error, proving the x/y encoding
        // is well-formed per RFC 7518.
        drop(decoding_key);
    }

    #[test]
    fn test_rs256_jwk_round_trips_through_decode() {
        let material = generate_keypair(SigningAlgorithm::Rs256).unwrap();
        let jwk = key_material_to_jwk(&material).unwrap();
        assert_eq!(jwk.common.key_id.as_deref(), Some(material.kid.as_str()));
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(&jwk).unwrap();
        drop(decoding_key);
    }

    #[test]
    fn test_active_keys_to_jwk_set_includes_previous_when_present() {
        let primary = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let previous = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let active = ActiveKeys {
            primary,
            previous: Some(previous),
        };
        let set = active_keys_to_jwk_set(&active).unwrap();
        assert_eq!(set.keys.len(), 2);
    }

    #[test]
    fn test_active_keys_to_jwk_set_single_key_without_previous() {
        let primary = generate_keypair(SigningAlgorithm::Es256).unwrap();
        let active = ActiveKeys {
            primary,
            previous: None,
        };
        let set = active_keys_to_jwk_set(&active).unwrap();
        assert_eq!(set.keys.len(), 1);
    }
}
