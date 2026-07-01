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
//! # API Key opaque token format (ADR 0021 §2.C, §3 Step 1)
//!
//! Format: `kscim_{entropy}_{crc32}`, where `entropy` is high-entropy
//! alphanumeric ("base62") random data and `crc32` is a lowercase hex CRC32
//! checksum of `entropy`. The CRC32 is strictly a cheap format-validity
//! check to cheaply reject malformed data before touching storage or the
//! Argon2id verifier; it is not a cryptographic security boundary.
use rand::distr::{Alphanumeric, SampleString};
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use thiserror::Error;

const TOKEN_PREFIX: &str = "kscim";
/// ~256 bits of entropy over the 62-character alphanumeric alphabet
/// (log2(62) ≈ 5.954 bits/char), matching the ADR's "32 bytes" target.
const ENTROPY_LEN: usize = 43;

/// Token format validation error. Deliberately uninformative in its
/// `Display` impl at the point where it is surfaced to a client — callers on
/// the authentication path should map any variant to a generic
/// unauthorized response rather than reveal which check failed.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenFormatError {
    /// Token does not start with the expected `kscim_` prefix.
    #[error("token prefix is invalid")]
    InvalidPrefix,

    /// Token does not split into an entropy and checksum segment.
    #[error("token structure is invalid")]
    InvalidFormat,

    /// The CRC32 checksum does not match the entropy segment.
    #[error("token checksum does not match")]
    ChecksumMismatch,
}

/// A freshly generated API Key. `token` is the full opaque bearer value
/// returned to the administrator exactly once; `entropy` and `lookup_hash`
/// are what gets persisted (as `secret_hash` after Argon2id hashing, and
/// `lookup_hash` respectively — see ADR 0021 §2.C).
#[derive(Debug)]
pub struct GeneratedApiKey {
    /// The full `kscim_...` bearer token, shown once.
    pub token: SecretString,
    /// The raw entropy segment, to be Argon2id-hashed by the caller.
    pub entropy: SecretString,
    /// `SHA-256(entropy)`, the non-secret storage index.
    pub lookup_hash: String,
}

/// A token that passed format validation (prefix + checksum), ready for the
/// storage lookup and Argon2id verification steps.
#[derive(Debug)]
pub struct ParsedApiKey {
    /// The raw entropy segment, to be Argon2id-verified by the caller.
    pub entropy: SecretString,
    /// `SHA-256(entropy)`, used to look up the stored `ApiClientResource`.
    pub lookup_hash: String,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `SHA-256(entropy)` as a lowercase hex string.
pub fn compute_lookup_hash(entropy: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entropy.as_bytes());
    to_hex(&hasher.finalize())
}

/// Generate a new API Key token.
pub fn generate() -> GeneratedApiKey {
    let entropy_plain = Alphanumeric.sample_string(&mut rand::rng(), ENTROPY_LEN);
    let lookup_hash = compute_lookup_hash(&entropy_plain);
    let crc = crc32fast::hash(entropy_plain.as_bytes());
    let token_plain = format!("{TOKEN_PREFIX}_{entropy_plain}_{crc:08x}");
    GeneratedApiKey {
        token: SecretString::from(token_plain),
        entropy: SecretString::from(entropy_plain),
        lookup_hash,
    }
}

/// Parse and format-validate a presented bearer token (ADR 0021 §3 Step 1).
///
/// Does not touch storage or perform Argon2id verification; it only checks
/// that the token is well-formed and its checksum is internally consistent.
pub fn parse(token: &str) -> Result<ParsedApiKey, TokenFormatError> {
    let rest = token
        .strip_prefix(TOKEN_PREFIX)
        .and_then(|r| r.strip_prefix('_'))
        .ok_or(TokenFormatError::InvalidPrefix)?;
    let (entropy, crc_hex) = rest
        .rsplit_once('_')
        .ok_or(TokenFormatError::InvalidFormat)?;
    if entropy.is_empty() || crc_hex.len() != 8 {
        return Err(TokenFormatError::InvalidFormat);
    }
    let expected_crc =
        u32::from_str_radix(crc_hex, 16).map_err(|_| TokenFormatError::InvalidFormat)?;
    if crc32fast::hash(entropy.as_bytes()) != expected_crc {
        return Err(TokenFormatError::ChecksumMismatch);
    }
    Ok(ParsedApiKey {
        entropy: SecretString::from(entropy.to_string()),
        lookup_hash: compute_lookup_hash(entropy),
    })
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn test_generate_roundtrips_through_parse() {
        let generated = generate();
        let parsed = parse(generated.token.expose_secret()).unwrap();
        assert_eq!(
            parsed.entropy.expose_secret(),
            generated.entropy.expose_secret()
        );
        assert_eq!(parsed.lookup_hash, generated.lookup_hash);
    }

    #[test]
    fn test_generate_has_expected_prefix_and_length() {
        let generated = generate();
        let token = generated.token.expose_secret();
        assert!(token.starts_with("kscim_"));
        // prefix (5) + '_' + entropy (43) + '_' + crc32 hex (8)
        assert_eq!(token.len(), 5 + 1 + ENTROPY_LEN + 1 + 8);
    }

    #[test]
    fn test_parse_rejects_bad_prefix() {
        let err = parse("notkscim_abc_00000000").unwrap_err();
        assert_eq!(err, TokenFormatError::InvalidPrefix);
    }

    #[test]
    fn test_parse_rejects_missing_segments() {
        let err = parse("kscim_onlyoneseg").unwrap_err();
        assert_eq!(err, TokenFormatError::InvalidFormat);
    }

    #[test]
    fn test_parse_rejects_bad_checksum() {
        let generated = generate();
        let token = generated.token.expose_secret();
        // Flip the last hex digit of the CRC32 segment, preserving overall
        // structure/length so this exercises the checksum check specifically
        // rather than the format check.
        let mut chars: Vec<char> = token.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        let tampered: String = chars.into_iter().collect();

        let err = parse(&tampered).unwrap_err();
        assert_eq!(err, TokenFormatError::ChecksumMismatch);
    }

    #[test]
    fn test_lookup_hash_is_deterministic() {
        assert_eq!(
            compute_lookup_hash("same-entropy"),
            compute_lookup_hash("same-entropy")
        );
        assert_ne!(
            compute_lookup_hash("entropy-a"),
            compute_lookup_hash("entropy-b")
        );
    }
}
