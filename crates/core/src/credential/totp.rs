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
//! TOTP passcode verification (ADR 0019 §3).
//!
//! Pure, DB-free implementation of RFC 4226 (HOTP) / RFC 6238 (TOTP). Since
//! both are public IETF standards (not a Keystone-specific format), any
//! compliant implementation - Python's `pyotp`, Google Authenticator, this
//! module - independently derives the same passcode from the same decrypted
//! `seed`, so no cross-service byte-compatibility work is required beyond the
//! Fernet decryption that already produces the shared plaintext seed.

use data_encoding::BASE32_NOPAD;
use secrecy::{ExposeSecret, SecretString};

use super::ec2_signature::hmac_sha1_raw;

/// Decode a Base32-encoded TOTP seed (RFC 4648), tolerating the optional
/// `=` padding and lower-case input some authenticator apps and enrollment
/// UIs produce.
fn decode_base32_seed(seed: &str) -> Option<Vec<u8>> {
    let cleaned: String = seed.chars().filter(|c| !c.is_whitespace()).collect();
    let trimmed = cleaned.trim_end_matches('=').to_ascii_uppercase();
    if trimmed.is_empty() {
        return None;
    }
    BASE32_NOPAD.decode(trimmed.as_bytes()).ok()
}

/// Generate an HOTP passcode (RFC 4226) for the given counter value.
fn generate_hotp(secret: &[u8], counter: u64, digits: u32) -> String {
    let hash = hmac_sha1_raw(secret, &counter.to_be_bytes());
    let offset = (hash[19] & 0x0f) as usize;
    let binary = (u32::from(hash[offset] & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    let code = binary % 10u32.pow(digits);
    format!("{code:0width$}", width = digits as usize)
}

/// Verify a user-submitted passcode against a decrypted TOTP seed.
///
/// Per ADR 0019 §3, checks the current time-step's passcode and the
/// immediately preceding one (a one-step backward window), to tolerate
/// network/input latency between the authenticator app generating the code
/// and the request reaching the server.
///
/// # Parameters
/// - `seed`: Base32-encoded shared secret (the credential blob's `seed`).
/// - `passcode`: the user-submitted code to verify.
/// - `digits`: passcode length (the credential blob's `digits`, typically 6).
/// - `period`: time-step size in seconds (the credential blob's `period`,
///   typically 30).
/// - `now_unix`: current time as a Unix timestamp (seconds).
///
/// # Returns
/// `true` if `passcode` matches the current or immediately preceding
/// time-step's HOTP value; `false` on any mismatch or malformed seed.
#[must_use]
pub fn verify_totp(
    seed: &str,
    passcode: &SecretString,
    digits: u32,
    period: u32,
    now_unix: i64,
) -> bool {
    let passcode = passcode.expose_secret();
    if digits == 0 || digits > 10 || period == 0 || passcode.len() != digits as usize {
        return false;
    }
    let Some(secret) = decode_base32_seed(seed) else {
        return false;
    };
    let counter = (now_unix.max(0) as u64) / u64::from(period);

    for candidate in [counter, counter.saturating_sub(1)] {
        let expected = generate_hotp(&secret, candidate, digits);
        if subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), passcode.as_bytes()).into() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors use a 20-byte SHA-1 seed
    // "12345678901234567890" (ASCII), Base32-encoded below, with an 8-digit
    // passcode. Time 59s -> counter 1 (period 30) is the first vector.
    const RFC6238_SEED_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn test_generate_hotp_rfc6238_vector_counter_1() {
        // T=59, X=30 => counter=1 => expected 8-digit code "94287082"
        let secret = decode_base32_seed(RFC6238_SEED_BASE32).unwrap();
        assert_eq!(generate_hotp(&secret, 1, 8), "94287082");
    }

    #[test]
    fn test_generate_hotp_rfc6238_vector_counter_37037036() {
        // T=1111111109, X=30 => counter=37037036 => expected "07081804"
        let secret = decode_base32_seed(RFC6238_SEED_BASE32).unwrap();
        assert_eq!(generate_hotp(&secret, 37_037_036, 8), "07081804");
    }

    #[test]
    fn test_verify_totp_current_window() {
        assert!(verify_totp(
            RFC6238_SEED_BASE32,
            &SecretString::from("94287082"),
            8,
            30,
            59, // counter = 59/30 = 1
        ));
    }

    #[test]
    fn test_verify_totp_previous_window() {
        // counter for now_unix=90 is 3; passcode for counter=1 must still be
        // rejected since it is two windows back (only current & previous are
        // accepted).
        assert!(!verify_totp(
            RFC6238_SEED_BASE32,
            &SecretString::from("94287082"),
            8,
            30,
            90
        ));
        // But the passcode for counter=2 (previous window relative to now=90,
        // counter=3) must be accepted.
        let secret = decode_base32_seed(RFC6238_SEED_BASE32).unwrap();
        let previous_code = generate_hotp(&secret, 2, 8);
        assert!(verify_totp(
            RFC6238_SEED_BASE32,
            &SecretString::from(previous_code),
            8,
            30,
            90
        ));
    }

    #[test]
    fn test_verify_totp_wrong_passcode() {
        assert!(!verify_totp(
            RFC6238_SEED_BASE32,
            &SecretString::from("00000000"),
            8,
            30,
            59
        ));
    }

    #[test]
    fn test_verify_totp_malformed_seed() {
        assert!(!verify_totp(
            "not-valid-base32!!!",
            &SecretString::from("123456"),
            6,
            30,
            59
        ));
    }

    #[test]
    fn test_verify_totp_wrong_length_passcode_rejected() {
        // A 4-digit passcode against a 6-digit credential must be rejected
        // outright rather than falling through to a (mismatched-length)
        // constant-time comparison.
        assert!(!verify_totp(
            "JBSWY3DPEHPK3PXP",
            &SecretString::from("1234"),
            6,
            30,
            59
        ));
    }

    #[test]
    fn test_decode_base32_seed_tolerates_padding_and_case() {
        assert_eq!(
            decode_base32_seed("jbswy3dpehpk3pxp"),
            decode_base32_seed("JBSWY3DPEHPK3PXP")
        );
        assert!(decode_base32_seed("").is_none());
    }
}
