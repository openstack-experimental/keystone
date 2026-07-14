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
//! # PKCE (RFC 7636) `S256` code challenge verification (ADR 0026 §1, §10 Phase 4)
//!
//! `S256` is the only supported method -- `plain` is never accepted, per the
//! ADR's Threat Model (§1): mandatory PKCE closes authorization code
//! hijacking at `/authorize`.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Verify a PKCE `code_verifier` presented at `/token` against the
/// `code_challenge` recorded at `/authorize` (RFC 7636 §4.6):
/// `BASE64URL(SHA256(code_verifier)) == code_challenge`.
///
/// Comparison is constant-time to avoid leaking a partial-match timing
/// signal on the challenge string.
pub fn verify_code_challenge(code_verifier: &str, code_challenge: &str) -> bool {
    let digest = Sha256::digest(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest);
    constant_time_eq(computed.as_bytes(), code_challenge.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B worked example.
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn test_rfc7636_appendix_b_vector_matches() {
        assert!(verify_code_challenge(VERIFIER, CHALLENGE));
    }

    #[test]
    fn test_wrong_verifier_rejected() {
        assert!(!verify_code_challenge("wrong-verifier", CHALLENGE));
    }

    #[test]
    fn test_empty_challenge_rejected() {
        assert!(!verify_code_challenge(VERIFIER, ""));
    }
}
