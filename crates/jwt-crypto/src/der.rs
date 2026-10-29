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
//! Minimal DER reader for RSA public keys.
//!
//! `ring` verifies against a PKCS#1 `RSAPublicKey` but cannot parse one back
//! into its components, which JWK publication needs.

/// Read one TLV with tag `tag`; return its content and the remaining input.
fn read(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&t, rest) = input.split_first()?;
    if t != tag {
        return None;
    }
    let (&l, rest) = rest.split_first()?;
    let (len, rest) = if l < 0x80 {
        (usize::from(l), rest)
    } else {
        let n = usize::from(l & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let (len_bytes, rest) = rest.split_at(n);
        let len = len_bytes
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, rest)
    };
    if rest.len() < len {
        return None;
    }
    Some(rest.split_at(len))
}

/// Strip the sign-padding zero of a DER INTEGER.
fn unsigned(int: &[u8]) -> Vec<u8> {
    match int.split_first() {
        Some((0, tail)) if !tail.is_empty() => tail.to_vec(),
        _ => int.to_vec(),
    }
}

/// Split a PKCS#1 `RSAPublicKey` into big-endian `(n, e)`.
fn pkcs1(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (seq, rest) = read(der, 0x30)?;
    if !rest.is_empty() {
        return None;
    }
    let (n, seq) = read(seq, 0x02)?;
    let (e, seq) = read(seq, 0x02)?;
    seq.is_empty().then(|| (unsigned(n), unsigned(e)))
}

/// The content of the BIT STRING of an SPKI, without the unused-bits byte.
pub(crate) fn spki_key_bits(der: &[u8]) -> Option<&[u8]> {
    let (spki, rest) = read(der, 0x30)?;
    if !rest.is_empty() {
        return None;
    }
    let (_algorithm, spki) = read(spki, 0x30)?;
    let (bits, spki) = read(spki, 0x03)?;
    if !spki.is_empty() {
        return None;
    }
    // The first content byte counts unused bits, always 0 for a key.
    match bits.split_first() {
        Some((0, inner)) => Some(inner),
        _ => None,
    }
}

/// Split a PKCS#1 `RSAPublicKey` or an SPKI `SubjectPublicKeyInfo` carrying
/// one into big-endian `(n, e)`.
pub(crate) fn rsa_public_components(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    pkcs1(der).or_else(|| pkcs1(spki_key_bits(der)?))
}
