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
//! `KeyUtils` of the provider: public-key components for JWK publication and
//! thumbprint hashing.

#[cfg(feature = "fips")]
use aws_lc_rs as provider;
#[cfg(not(feature = "fips"))]
use ring as provider;

use jsonwebtoken::Algorithm;
use jsonwebtoken::errors::{ErrorKind, Result};
use jsonwebtoken::jwk::{EllipticCurve, ThumbprintHash};
use provider::digest;
use provider::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, KeyPair,
};

use crate::backend::{ec_pair, ed_pair, rsa_pair};
use crate::der;

pub(crate) fn rsa_components_from_private_key(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // The public key of a pair is its PKCS#1 `RSAPublicKey`.
    let pair = rsa_pair(der)?;
    rsa_components_from_public_key(KeyPair::public_key(&pair).as_ref())
}

pub(crate) fn rsa_components_from_public_key(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    der::rsa_public_components(der)
        .ok_or_else(|| ErrorKind::InvalidRsaKey("unparsable public key".into()).into())
}

pub(crate) fn ec_components_from_private_key(
    pkcs8: &[u8],
    alg: Algorithm,
) -> Result<(EllipticCurve, Vec<u8>, Vec<u8>)> {
    let (signing, curve, len) = match alg {
        Algorithm::ES256 => (&ECDSA_P256_SHA256_FIXED_SIGNING, EllipticCurve::P256, 32),
        Algorithm::ES384 => (&ECDSA_P384_SHA384_FIXED_SIGNING, EllipticCurve::P384, 48),
        _ => return Err(ErrorKind::InvalidEcdsaKey.into()),
    };
    let pair = ec_pair(signing, pkcs8)?;
    let point = pair.public_key().as_ref();
    match point.split_first() {
        Some((4, xy)) if xy.len() == 2 * len => {
            let (x, y) = xy.split_at(len);
            Ok((curve, x.to_vec(), y.to_vec()))
        }
        _ => Err(ErrorKind::InvalidEcdsaKey.into()),
    }
}

pub(crate) fn ed_components_from_private_key(
    pkcs8: &[u8],
    curve: &EllipticCurve,
) -> Result<Vec<u8>> {
    match curve {
        EllipticCurve::Ed25519 => Ok(ed_pair(pkcs8)?.public_key().as_ref().to_vec()),
        _ => Err(ErrorKind::InvalidAlgorithm.into()),
    }
}

pub(crate) fn compute_digest(data: &[u8], hash: ThumbprintHash) -> Result<Vec<u8>> {
    let algorithm = match hash {
        ThumbprintHash::SHA256 => &digest::SHA256,
        ThumbprintHash::SHA384 => &digest::SHA384,
        ThumbprintHash::SHA512 => &digest::SHA512,
        _ => return Err(ErrorKind::InvalidAlgorithm.into()),
    };
    Ok(digest::digest(algorithm, data).as_ref().to_vec())
}
