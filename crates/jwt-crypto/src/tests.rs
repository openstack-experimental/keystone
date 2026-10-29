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
//! Round trips through `jsonwebtoken` with the provider installed.

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, ThumbprintHash};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair,
    KeyPair,
};
use serde::{Deserialize, Serialize};

use super::*;

// Test-only RSA-2048 key in PKCS#8, PKCS#1 and SPKI/PKCS#1 public forms.
const RSA_PKCS8: &str = "MIIEpAIBAAKCAQEA1Bm5cKU7NsY3Gd7aJYKQunwptyNiyzi6r/3QdVaFoQ0c8lSRjXg0SwneV8pf32FvAAtBgBUbRUke6hBS/sc97JyTahQbkEnMWSQ4j00yIndnMMFz1GOco6za1+uUTrgCYBLqST+PTqjtFjkb/rS+80wds7IN0Ayw4gnUjygZwl/ezUVTCxcFslSPztV+NtqU59LEhECtLX+xLg6FGoWJgmEPwOIK1Qqq4LlsK0NWUkSu39hIfLAnI7+kTuQjBqBaDKGt5RSOevOFAPeD/MoiJHI6elqr36wBdj0BvvqLKk5zsqvGLGNjRkNopX5NBm0TvVLye0sspbfhM4ZQRAo7UwIDAQABAoIBABEDufCOELX601Nr9oFT0VsPDXmiM7wBt62D5ZkZcRbTqnggzfGqAZKTdBau0V9mEuAksa3IrlYHNkeoj5UzU9sLTyK6Aja3n4D3JY0OsEWQ4Teet+ADLamjpYVKDKz+mJIvHO71/lUHusfcRPaly+ZQkNa9eIYxaRnOQr2ehefQYPPdks2GDUn5LvagOiiYIWlNSKwQsGBZ0DTi5W/3tSMiTtAWpI23OZgRwtHv6mQUra/GW8jTgA7ukJXF8vr7BndZfVqMfiMSXnLM+UWRrZ/XbyS5DlMS/PhERA3AEHL7KEpULUX41WdPDdw675ePtj+RSVtEOR6oBc3GGH6MzMECgYEA8FJueB7GHkeckt6eQ9Y8/SodITfh8xgMaT5hqjxJh9k/xsCak50/Ki6HL+HSbqx4U11A78nvRx/rMFtPCVMAn8J46Aayq3E89CsD8Knr04/htorYxoRjKOmRac33VfFjuBRofKHSXPxRtNR1O2+1xKPDa9KycLUdnWErKu6ghJkCgYEA4e/4nb4c062qgL7peXHW0vKv5K1d7SEYW80+XnY7wgaE+vlkIaEMqAKa4lC1lGnq6oSqppVP7VYG/P36FlhfDoMJL17HhrxMNY8U0EtjYMAT6I/c5wnN8LzqGdLRCyHjPK6Z6rX2ulHHHpahAJYqZex11efBv4AYt37unD7BhssCgYAc696tiA6RsE6QgkgLo+m9EedliwMfLUK5G6/HO/AhcCyzr5QqtZ7XZbgRNB0OAqWMasmY0fWA2r+EF0kAt0N49n90dPHlngAW5mJYASsHT+Z7AGSsJ1yDnPBKCmZ8qks06QfWD+dwF1GB8JuXJo96dbbb8ARXegRxXzNBvGwG6QKBgQDAjVBXt0dAC9iswoed7awEubm37RyIVFU7H68QuDjzgbThY5u3oVZ09Utkpx4pLx964LfDIqssfM2V3Sm+02+noXs5eNAY/u8AEkHNxwIZ2XjeEYVVDaEKkyX7/hQUJbxQ4gjg5FUyszE822i5ZEEb/irqswoHF7d44t+eH0m1gwKBgQDlgHRxTzAjG/sxzddjehm7ClIRWRw9xJom5b5ksRrF8nfzzPeGzT5eEJPNS5IKChI8ZtD9T/tFliDnwgTLjqDYXBP+Vw/OwZFvAczNFVsiiM+yK7abE44PB/utINVIA2XvcQlwb/SHw9wXCT/KLK9Tja0PyiLJd+jE0tqOgo3ukA==";
const RSA_PKCS1: &str = "MIIEpAIBAAKCAQEA1Bm5cKU7NsY3Gd7aJYKQunwptyNiyzi6r/3QdVaFoQ0c8lSRjXg0SwneV8pf32FvAAtBgBUbRUke6hBS/sc97JyTahQbkEnMWSQ4j00yIndnMMFz1GOco6za1+uUTrgCYBLqST+PTqjtFjkb/rS+80wds7IN0Ayw4gnUjygZwl/ezUVTCxcFslSPztV+NtqU59LEhECtLX+xLg6FGoWJgmEPwOIK1Qqq4LlsK0NWUkSu39hIfLAnI7+kTuQjBqBaDKGt5RSOevOFAPeD/MoiJHI6elqr36wBdj0BvvqLKk5zsqvGLGNjRkNopX5NBm0TvVLye0sspbfhM4ZQRAo7UwIDAQABAoIBABEDufCOELX601Nr9oFT0VsPDXmiM7wBt62D5ZkZcRbTqnggzfGqAZKTdBau0V9mEuAksa3IrlYHNkeoj5UzU9sLTyK6Aja3n4D3JY0OsEWQ4Teet+ADLamjpYVKDKz+mJIvHO71/lUHusfcRPaly+ZQkNa9eIYxaRnOQr2ehefQYPPdks2GDUn5LvagOiiYIWlNSKwQsGBZ0DTi5W/3tSMiTtAWpI23OZgRwtHv6mQUra/GW8jTgA7ukJXF8vr7BndZfVqMfiMSXnLM+UWRrZ/XbyS5DlMS/PhERA3AEHL7KEpULUX41WdPDdw675ePtj+RSVtEOR6oBc3GGH6MzMECgYEA8FJueB7GHkeckt6eQ9Y8/SodITfh8xgMaT5hqjxJh9k/xsCak50/Ki6HL+HSbqx4U11A78nvRx/rMFtPCVMAn8J46Aayq3E89CsD8Knr04/htorYxoRjKOmRac33VfFjuBRofKHSXPxRtNR1O2+1xKPDa9KycLUdnWErKu6ghJkCgYEA4e/4nb4c062qgL7peXHW0vKv5K1d7SEYW80+XnY7wgaE+vlkIaEMqAKa4lC1lGnq6oSqppVP7VYG/P36FlhfDoMJL17HhrxMNY8U0EtjYMAT6I/c5wnN8LzqGdLRCyHjPK6Z6rX2ulHHHpahAJYqZex11efBv4AYt37unD7BhssCgYAc696tiA6RsE6QgkgLo+m9EedliwMfLUK5G6/HO/AhcCyzr5QqtZ7XZbgRNB0OAqWMasmY0fWA2r+EF0kAt0N49n90dPHlngAW5mJYASsHT+Z7AGSsJ1yDnPBKCmZ8qks06QfWD+dwF1GB8JuXJo96dbbb8ARXegRxXzNBvGwG6QKBgQDAjVBXt0dAC9iswoed7awEubm37RyIVFU7H68QuDjzgbThY5u3oVZ09Utkpx4pLx964LfDIqssfM2V3Sm+02+noXs5eNAY/u8AEkHNxwIZ2XjeEYVVDaEKkyX7/hQUJbxQ4gjg5FUyszE822i5ZEEb/irqswoHF7d44t+eH0m1gwKBgQDlgHRxTzAjG/sxzddjehm7ClIRWRw9xJom5b5ksRrF8nfzzPeGzT5eEJPNS5IKChI8ZtD9T/tFliDnwgTLjqDYXBP+Vw/OwZFvAczNFVsiiM+yK7abE44PB/utINVIA2XvcQlwb/SHw9wXCT/KLK9Tja0PyiLJd+jE0tqOgo3ukA==";
const RSA_SPKI: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Bm5cKU7NsY3Gd7aJYKQunwptyNiyzi6r/3QdVaFoQ0c8lSRjXg0SwneV8pf32FvAAtBgBUbRUke6hBS/sc97JyTahQbkEnMWSQ4j00yIndnMMFz1GOco6za1+uUTrgCYBLqST+PTqjtFjkb/rS+80wds7IN0Ayw4gnUjygZwl/ezUVTCxcFslSPztV+NtqU59LEhECtLX+xLg6FGoWJgmEPwOIK1Qqq4LlsK0NWUkSu39hIfLAnI7+kTuQjBqBaDKGt5RSOevOFAPeD/MoiJHI6elqr36wBdj0BvvqLKk5zsqvGLGNjRkNopX5NBm0TvVLye0sspbfhM4ZQRAo7UwIDAQAB";
const RSA_PKCS1_PUB: &str = "MIIBCgKCAQEA1Bm5cKU7NsY3Gd7aJYKQunwptyNiyzi6r/3QdVaFoQ0c8lSRjXg0SwneV8pf32FvAAtBgBUbRUke6hBS/sc97JyTahQbkEnMWSQ4j00yIndnMMFz1GOco6za1+uUTrgCYBLqST+PTqjtFjkb/rS+80wds7IN0Ayw4gnUjygZwl/ezUVTCxcFslSPztV+NtqU59LEhECtLX+xLg6FGoWJgmEPwOIK1Qqq4LlsK0NWUkSu39hIfLAnI7+kTuQjBqBaDKGt5RSOevOFAPeD/MoiJHI6elqr36wBdj0BvvqLKk5zsqvGLGNjRkNopX5NBm0TvVLye0sspbfhM4ZQRAo7UwIDAQAB";

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Claims {
    sub: String,
    exp: u64,
}

fn claims() -> Claims {
    Claims {
        sub: "user-1".into(),
        exp: jsonwebtoken::get_current_timestamp() + 3600,
    }
}

fn b64(s: &str) -> Vec<u8> {
    use std::io::Write as _;
    let mut child = std::process::Command::new("base64")
        .arg("-d")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    child.wait_with_output().unwrap().stdout
}

fn roundtrip(alg: Algorithm, enc: &EncodingKey, dec: &DecodingKey) {
    install();
    let token = encode(&Header::new(alg), &claims(), enc).unwrap();
    let decoded = decode::<Claims>(&token, dec, &Validation::new(alg)).unwrap();
    assert_eq!(decoded.claims, claims());
}

fn ec_keys(signing: &'static ring::signature::EcdsaSigningAlgorithm) -> (Vec<u8>, Vec<u8>) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(signing, &rng).unwrap();
    let pair = EcdsaKeyPair::from_pkcs8(signing, pkcs8.as_ref(), &rng).unwrap();
    (pkcs8.as_ref().to_vec(), pair.public_key().as_ref().to_vec())
}

#[test]
fn es256_roundtrip() {
    let (private, public) = ec_keys(&ECDSA_P256_SHA256_FIXED_SIGNING);
    roundtrip(
        Algorithm::ES256,
        &EncodingKey::from_ec_der(&private),
        &DecodingKey::from_ec_der(&public),
    );
}

#[test]
fn es384_roundtrip() {
    let (private, public) = ec_keys(&ECDSA_P384_SHA384_FIXED_SIGNING);
    roundtrip(
        Algorithm::ES384,
        &EncodingKey::from_ec_der(&private),
        &DecodingKey::from_ec_der(&public),
    );
}

#[test]
fn es256_rejects_other_key() {
    install();
    let (private, _) = ec_keys(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let (_, other_public) = ec_keys(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let token = encode(
        &Header::new(Algorithm::ES256),
        &claims(),
        &EncodingKey::from_ec_der(&private),
    )
    .unwrap();
    assert!(
        decode::<Claims>(
            &token,
            &DecodingKey::from_ec_der(&other_public),
            &Validation::new(Algorithm::ES256)
        )
        .is_err()
    );
}

#[test]
fn eddsa_roundtrip() {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    roundtrip(
        Algorithm::EdDSA,
        &EncodingKey::from_ed_der(pkcs8.as_ref()),
        &DecodingKey::from_ed_der(pair.public_key().as_ref()),
    );
}

#[test]
fn hmac_roundtrip() {
    for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
        roundtrip(
            alg,
            &EncodingKey::from_secret(b"secret"),
            &DecodingKey::from_secret(b"secret"),
        );
    }
}

#[test]
fn rsa_roundtrip_all_algorithms() {
    let pkcs8 = b64(RSA_PKCS8);
    let pkcs1 = b64(RSA_PKCS1);
    let public = b64(RSA_PKCS1_PUB);
    for alg in [
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
    ] {
        let dec = DecodingKey::from_rsa_der(&public);
        // Both private key encodings are accepted.
        roundtrip(alg, &EncodingKey::from_rsa_der(&pkcs8), &dec);
        roundtrip(alg, &EncodingKey::from_rsa_der(&pkcs1), &dec);
    }
}

#[test]
fn rsa_verifies_with_jwk_components() {
    install();
    let enc = EncodingKey::from_rsa_der(&b64(RSA_PKCS1));
    let jwk = Jwk::from_encoding_key(&enc, Algorithm::RS256).unwrap();
    let dec = DecodingKey::from_jwk(&jwk).unwrap();
    let token = encode(&Header::new(Algorithm::RS256), &claims(), &enc).unwrap();
    decode::<Claims>(&token, &dec, &Validation::new(Algorithm::RS256)).unwrap();
}

#[test]
fn rsa_public_components_agree() {
    install();
    let from_private = keys::rsa_components_from_private_key(&b64(RSA_PKCS8)).unwrap();
    let from_pkcs1 = keys::rsa_components_from_public_key(&b64(RSA_PKCS1_PUB)).unwrap();
    let from_spki = keys::rsa_components_from_public_key(&b64(RSA_SPKI)).unwrap();
    assert_eq!(from_private, from_pkcs1);
    assert_eq!(from_private, from_spki);
    assert_eq!(from_private.1, vec![1, 0, 1]);
    assert!(keys::rsa_components_from_public_key(&[0x30, 0x03, 0x02, 0x01]).is_err());
}

#[test]
fn ec_jwk_and_thumbprint() {
    install();
    let (private, public) = ec_keys(&ECDSA_P256_SHA256_FIXED_SIGNING);
    let jwk =
        Jwk::from_encoding_key(&EncodingKey::from_ec_der(&private), Algorithm::ES256).unwrap();
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) => {
            assert_eq!(ec.x.len(), 43);
            assert_eq!(ec.y.len(), 43);
        }
        other => panic!("unexpected {other:?}"),
    }
    // The JWK drives a verifier for the same public key.
    let dec = DecodingKey::from_jwk(&jwk).unwrap();
    let token = encode(
        &Header::new(Algorithm::ES256),
        &claims(),
        &EncodingKey::from_ec_der(&private),
    )
    .unwrap();
    decode::<Claims>(&token, &dec, &Validation::new(Algorithm::ES256)).unwrap();
    assert!(!public.is_empty());
    assert_eq!(jwk.thumbprint(ThumbprintHash::SHA256).unwrap().len(), 43);
}

#[test]
fn key_family_mismatch_is_rejected() {
    install();
    let (private, _) = ec_keys(&ECDSA_P256_SHA256_FIXED_SIGNING);
    assert!(
        encode(
            &Header::new(Algorithm::RS256),
            &claims(),
            &EncodingKey::from_ec_der(&private)
        )
        .is_err()
    );
}

#[test]
fn generated_p256_signs_and_verifies() {
    for _ in 0..2 {
        let key = generate(KeyKind::P256).unwrap();
        let point = p256_point_from_spki(&key.public_spki).unwrap();
        roundtrip(
            Algorithm::ES256,
            &EncodingKey::from_ec_der(&key.private_pkcs8),
            &DecodingKey::from_ec_der(point),
        );
    }
    assert!(p256_point_from_spki(&[0x30, 0x00]).is_none());
}

#[test]
fn generated_rsa_signs_and_verifies() {
    let key = generate(KeyKind::Rsa2048).unwrap();
    let pkcs1 = rsa_pkcs1_from_spki(&key.public_spki).unwrap();
    roundtrip(
        Algorithm::RS256,
        &EncodingKey::from_rsa_der(&key.private_pkcs8),
        &DecodingKey::from_rsa_der(pkcs1),
    );
    assert!(rsa_pkcs1_from_spki(&[0x30, 0x00]).is_none());
}
