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
// Crypto inventory: TOK-11; see doc/src/contributor/crypto-inventory.md
//! # DPoP proof validation (RFC 9449, ADR 0043 §2)
//!
//! Stateless verification of a single `DPoP` proof JWT: the structure of the
//! proof, its signature against the embedded public `jwk`, the binding to the
//! HTTP method and URI (`htm`, `htu`), freshness (`iat`), the access token
//! hash (`ath`) and the server nonce. Replay detection (`jti` cache), nonce
//! issuing and the "exactly one `DPoP` header" rule belong to the callers.
//!
//! The verifier is shared by `/token`, the other Keystone endpoints and the
//! reference resource-side verifier. Every failure is a
//! [`DpopProofError`]; callers decide how to map it onto the wire
//! (`invalid_dpop_proof`, `use_dpop_nonce`, `WWW-Authenticate: DPoP`).
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, crypto};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::Url;

pub use openstack_keystone_core_types::oauth2_client::Confirmation;

/// Minimum RSA modulus size accepted for a proof key, in bits.
pub const MIN_RSA_BITS: usize = 2048;

/// Maximum accepted size of a whole proof, in bytes. Checked before any
/// decoding: the verifier runs before the client is authenticated.
const MAX_PROOF_LEN: usize = 8192;

/// Maximum accepted length of a proof `jti`, in bytes. A longer `jti` is
/// rejected before the caller stores it in the replay cache.
const MAX_JTI_LEN: usize = 128;

/// Header `typ` of a DPoP proof.
const DPOP_TYP: &str = "dpop+jwt";

/// Members that make a JWK private. A proof key carrying any of them is
/// rejected: the client must never send private key material.
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Signature algorithms accepted for proofs (advertised in discovery as
/// `dpop_signing_alg_values_supported`). `none` and symmetric algorithms are
/// never accepted. This is the only allow-list: [`verify_dpop_proof`] parses
/// the header `alg` only when it is listed here.
pub const SUPPORTED_ALGORITHMS: [&str; 2] = ["ES256", "RS256"];

/// DPoP proof validation failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DpopProofError {
    /// `ath` is missing or differs from the hash of the access token.
    #[error("DPoP proof `ath` does not match the access token")]
    AccessTokenHashMismatch,

    /// `iat` is outside of the accepted window.
    #[error("DPoP proof `iat` is outside of the accepted window")]
    Expired,

    /// The `jwk` is not an acceptable public key.
    #[error("DPoP proof key is not acceptable: {0}")]
    InvalidKey(String),

    /// Signature verification failed.
    #[error("DPoP proof signature is invalid")]
    InvalidSignature,

    /// Header `typ` is not `dpop+jwt`.
    #[error("DPoP proof `typ` must be `dpop+jwt`")]
    InvalidType,

    /// `jti` is longer than [`MAX_JTI_LEN`] bytes.
    #[error("DPoP proof `jti` is too long")]
    JtiTooLong,

    /// The proof is not a well-formed compact JWT or has undecodable parts.
    #[error("malformed DPoP proof: {0}")]
    Malformed(String),

    /// `htm` differs from the request method.
    #[error("DPoP proof `htm` does not match the request method")]
    MethodMismatch,

    /// A required claim is missing or empty.
    #[error("DPoP proof claim `{0}` is missing")]
    MissingClaim(&'static str),

    /// The header carries no `jwk`.
    #[error("DPoP proof header has no `jwk`")]
    MissingKey,

    /// The server requires a nonce and the proof carries none or a stale one.
    #[error("DPoP proof requires a server-provided nonce")]
    NonceRequired,

    /// The proof carries an `ath` but the request has no access token.
    #[error("DPoP proof carries an unexpected `ath`")]
    UnexpectedAccessTokenHash,

    /// The signature algorithm is not allowed.
    #[error("DPoP proof algorithm `{0}` is not supported")]
    UnsupportedAlgorithm(String),

    /// `htu` differs from the request URI.
    #[error("DPoP proof `htu` does not match the request URI")]
    UriMismatch,
}

/// Request-side expectations a proof is validated against.
#[derive(Clone, Debug)]
pub struct DpopProofContext<'a> {
    /// Access token presented with the request. When set, the proof must carry
    /// the matching `ath`; when `None` (token endpoint) `ath` is not allowed.
    pub access_token: Option<&'a str>,
    /// Nonces the server accepts (see `DpopNonceGenerator::accepted`). `None`
    /// means no nonce is required (a nonce present in the proof is then
    /// ignored); `Some` requires the proof to carry one of them.
    pub accepted_nonces: Option<&'a [String]>,
    /// Accepted distance of `iat` from `now`, in both directions.
    pub max_skew_secs: u64,
    /// HTTP method of the request (`htm`).
    pub method: &'a str,
    /// Current time, unix seconds.
    pub now: i64,
    /// External URI of the request (`htu`); query and fragment are ignored.
    pub uri: &'a Url,
}

/// Outcome of a successful validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDpopProof {
    /// Time of issue, unix seconds.
    pub iat: i64,
    /// RFC 7638 SHA-256 thumbprint of the proof key (base64url, unpadded).
    pub jkt: String,
    /// Unique proof identifier for the replay cache.
    pub jti: String,
}

#[derive(Debug, Deserialize)]
struct ProofClaims {
    ath: Option<String>,
    htm: Option<String>,
    htu: Option<String>,
    iat: Option<i64>,
    jti: Option<String>,
    nonce: Option<String>,
}

/// Base64url SHA-256 of an access token, the `ath` value (RFC 9449 §4.2).
pub fn access_token_hash(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

/// Normalise a URI for `htu` comparison (RFC 9449 §4.3 item 5, RFC 3986
/// §6.2.2): scheme and host lower-cased, default port removed, userinfo,
/// query and fragment dropped, percent-escapes of unreserved characters
/// decoded and the remaining escapes upper-cased.
fn normalize_htu(uri: &Url) -> String {
    let mut uri = uri.clone();
    uri.set_query(None);
    uri.set_fragment(None);
    // Fails only for cannot-be-a-base URLs, which have no userinfo anyway.
    let _ = uri.set_username("");
    let _ = uri.set_password(None);

    let path = uri.path().as_bytes();
    let mut normalized = String::with_capacity(path.len());
    let mut idx = 0;
    while idx < path.len() {
        let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
        let decoded = match (path[idx], path.get(idx + 1), path.get(idx + 2)) {
            (b'%', Some(hi), Some(lo)) => hex(*hi).zip(hex(*lo)).map(|(h, l)| (h << 4) | l),
            _ => None,
        };
        match decoded {
            Some(byte) if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) => {
                normalized.push(byte as char);
                idx += 3;
            }
            Some(byte) => {
                normalized.push_str(&format!("%{byte:02X}"));
                idx += 3;
            }
            None => {
                normalized.push(path[idx] as char);
                idx += 1;
            }
        }
    }
    uri.set_path(&normalized);
    uri.to_string()
}

fn b64_member<'a>(jwk: &'a Map<String, Value>, name: &str) -> Result<&'a str, DpopProofError> {
    jwk.get(name)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| DpopProofError::InvalidKey(format!("missing `{name}`")))
}

/// Canonical base64url of a key member. Leading zero bytes of a big-endian
/// integer (`n`, `e`) are not significant and are stripped, so one key has
/// exactly one encoding and one thumbprint. Non-canonical base64url (padding,
/// non-zero trailing bits) fails to decode.
fn canonical_member(
    jwk: &Map<String, Value>,
    name: &str,
    integer: bool,
) -> Result<String, DpopProofError> {
    let raw = URL_SAFE_NO_PAD
        .decode(b64_member(jwk, name)?)
        .map_err(|_| DpopProofError::InvalidKey(format!("bad `{name}`")))?;
    let raw = if integer {
        let start = raw.iter().position(|b| *b != 0).unwrap_or(raw.len());
        &raw[start..]
    } else {
        &raw[..]
    };
    if raw.is_empty() {
        return Err(DpopProofError::InvalidKey(format!("empty `{name}`")));
    }
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

/// RFC 7638 thumbprint of a public `EC` or `RSA` JWK given as a JSON object.
///
/// Only the required members are hashed, in lexicographic order, so any
/// optional member (`kid`, `use`, ...) does not influence the result. The
/// members are hashed in canonical form, see [`canonical_member`].
pub fn jwk_thumbprint(jwk: &Map<String, Value>) -> Result<String, DpopProofError> {
    let canonical = match jwk.get("kty").and_then(Value::as_str) {
        Some("EC") => serde_json::json!({
            "crv": b64_member(jwk, "crv")?,
            "kty": "EC",
            "x": canonical_member(jwk, "x", false)?,
            "y": canonical_member(jwk, "y", false)?,
        }),
        Some("RSA") => serde_json::json!({
            "e": canonical_member(jwk, "e", true)?,
            "kty": "RSA",
            "n": canonical_member(jwk, "n", true)?,
        }),
        other => {
            return Err(DpopProofError::InvalidKey(format!(
                "unsupported `kty` {other:?}"
            )));
        }
    };
    // serde_json (without `preserve_order`) serializes object keys sorted and
    // without whitespace, which is the RFC 7638 canonical form.
    let bytes =
        serde_json::to_vec(&canonical).map_err(|e| DpopProofError::InvalidKey(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}

/// JOSE name of an accepted proof algorithm.
fn alg_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::ES256 => "ES256",
        _ => "RS256",
    }
}

/// Check the proof key against the algorithm and the key rules of ADR 0043 §2.
fn validate_key(alg: Algorithm, jwk: &Map<String, Value>) -> Result<(), DpopProofError> {
    if let Some(member) = PRIVATE_JWK_MEMBERS.iter().find(|m| jwk.contains_key(**m)) {
        return Err(DpopProofError::InvalidKey(format!(
            "private member `{member}`"
        )));
    }
    // The proof key is a bare key chosen by the client and trusted only via
    // its thumbprint (`jkt`). Certificate members bring a trust model that
    // does not apply: `x5u` would invite a pre-auth fetch (SSRF), `x5c` a
    // chain nobody validates but a later change might start to honour.
    // Rejecting them keeps all verifiers (ADR 0043 §2) in agreement.
    if jwk.contains_key("x5c") || jwk.contains_key("x5u") {
        return Err(DpopProofError::InvalidKey("`x5c`/`x5u` present".into()));
    }
    if jwk.get("use").is_some_and(|u| u.as_str() != Some("sig")) {
        return Err(DpopProofError::InvalidKey("`use` must be `sig`".into()));
    }
    if let Some(ops) = jwk.get("key_ops")
        && !ops
            .as_array()
            .is_some_and(|ops| ops.iter().any(|op| op.as_str() == Some("verify")))
    {
        return Err(DpopProofError::InvalidKey(
            "`key_ops` does not allow `verify`".into(),
        ));
    }
    if let Some(key_alg) = jwk.get("alg")
        && key_alg.as_str() != Some(alg_name(alg))
    {
        return Err(DpopProofError::InvalidKey(
            "`alg` does not match the proof algorithm".into(),
        ));
    }
    match (alg, jwk.get("kty").and_then(Value::as_str)) {
        (Algorithm::ES256, Some("EC")) => {
            if jwk.get("crv").and_then(Value::as_str) != Some("P-256") {
                return Err(DpopProofError::InvalidKey(
                    "`crv` must be P-256 for ES256".into(),
                ));
            }
            for member in ["x", "y"] {
                let raw = URL_SAFE_NO_PAD
                    .decode(b64_member(jwk, member)?)
                    .map_err(|_| DpopProofError::InvalidKey(format!("bad `{member}`")))?;
                if raw.len() != 32 {
                    return Err(DpopProofError::InvalidKey(format!("bad `{member}` length")));
                }
            }
            Ok(())
        }
        (Algorithm::RS256, Some("RSA")) => {
            let n = URL_SAFE_NO_PAD
                .decode(b64_member(jwk, "n")?)
                .map_err(|_| DpopProofError::InvalidKey("bad `n`".into()))?;
            // True bit length of the modulus, not just the byte count: a
            // 256-byte `n` whose top byte is 0x01 is only 2041 bits
            // and must be rejected.
            let bitlen = match n.iter().position(|b| *b != 0) {
                None => 0,
                Some(idx) => (n.len() - idx) * 8 - n[idx].leading_zeros() as usize,
            };
            if bitlen < MIN_RSA_BITS {
                return Err(DpopProofError::InvalidKey(format!(
                    "RSA key shorter than {MIN_RSA_BITS} bits"
                )));
            }
            // Only odd exponents of at least 65537 that fit 32 bits are
            // accepted.
            let e = URL_SAFE_NO_PAD
                .decode(canonical_member(jwk, "e", true)?)
                .map_err(|_| DpopProofError::InvalidKey("bad `e`".into()))?;
            let e =
                (e.len() <= 4).then(|| e.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b)));
            if !e.is_some_and(|e| e >= 65537 && e % 2 == 1) {
                return Err(DpopProofError::InvalidKey("unacceptable `e`".into()));
            }
            Ok(())
        }
        _ => Err(DpopProofError::InvalidKey(
            "`kty` does not match the proof algorithm".into(),
        )),
    }
}

/// Validate a DPoP proof against the request (ADR 0043 §2).
///
/// All checks are fail-closed. The returned thumbprint is what the caller
/// compares with `cnf.jkt` or stores with a code or refresh family.
///
/// # Errors
/// See [`DpopProofError`] for each rejection reason.
pub fn verify_dpop_proof(
    proof: &str,
    ctx: &DpopProofContext<'_>,
) -> Result<VerifiedDpopProof, DpopProofError> {
    if proof.len() > MAX_PROOF_LEN {
        return Err(DpopProofError::Malformed("proof too large".into()));
    }
    let mut parts = proof.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(DpopProofError::Malformed("not a compact JWS".into()));
    };
    // Peek the header as raw JSON: a typed header would hide private members
    // of the `jwk`.
    let header: Map<String, Value> = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| DpopProofError::Malformed(e.to_string()))
        .and_then(|raw| {
            serde_json::from_slice(&raw).map_err(|e| DpopProofError::Malformed(e.to_string()))
        })?;

    match header.get("typ").and_then(Value::as_str) {
        Some(typ) if typ.eq_ignore_ascii_case(DPOP_TYP) => {}
        _ => return Err(DpopProofError::InvalidType),
    }
    // Extensions this verifier does not understand must be rejected
    // (RFC 7515 §4.1.11).
    if header.contains_key("crit") {
        return Err(DpopProofError::Malformed("`crit` is not supported".into()));
    }

    let alg_name = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| DpopProofError::Malformed("missing `alg`".into()))?;
    let alg = SUPPORTED_ALGORITHMS
        .contains(&alg_name)
        .then(|| Algorithm::from_str(alg_name).ok())
        .flatten()
        .ok_or_else(|| DpopProofError::UnsupportedAlgorithm(alg_name.to_string()))?;

    let jwk_map = header
        .get("jwk")
        .ok_or(DpopProofError::MissingKey)?
        .as_object()
        .ok_or_else(|| DpopProofError::InvalidKey("`jwk` is not an object".into()))?;
    validate_key(alg, jwk_map)?;
    let jkt = jwk_thumbprint(jwk_map)?;
    openstack_keystone_jwt_crypto::install();
    let decoding_key = match alg {
        Algorithm::ES256 => DecodingKey::from_ec_components(
            &canonical_member(jwk_map, "x", false)?,
            &canonical_member(jwk_map, "y", false)?,
        ),
        _ => DecodingKey::from_rsa_components(
            &canonical_member(jwk_map, "n", true)?,
            &canonical_member(jwk_map, "e", true)?,
        ),
    }
    .map_err(|e| DpopProofError::InvalidKey(e.to_string()))?;

    // The claims are read before the signature is verified so that the cheap
    // rejections below run first. Nothing is trusted until the signature
    // check at the end: every outcome before it is a rejection.
    let claims: ProofClaims = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| DpopProofError::Malformed(e.to_string()))
        .and_then(|raw| {
            serde_json::from_slice(&raw).map_err(|e| DpopProofError::Malformed(e.to_string()))
        })?;

    let jti = claims
        .jti
        .filter(|v| !v.is_empty())
        .ok_or(DpopProofError::MissingClaim("jti"))?;
    if jti.len() > MAX_JTI_LEN {
        return Err(DpopProofError::JtiTooLong);
    }
    let htm = claims.htm.ok_or(DpopProofError::MissingClaim("htm"))?;
    let htu = claims.htu.ok_or(DpopProofError::MissingClaim("htu"))?;
    let iat = claims.iat.ok_or(DpopProofError::MissingClaim("iat"))?;

    if htm != ctx.method {
        return Err(DpopProofError::MethodMismatch);
    }
    let proof_uri = Url::parse(&htu).map_err(|_| DpopProofError::UriMismatch)?;
    if normalize_htu(&proof_uri) != normalize_htu(ctx.uri) {
        return Err(DpopProofError::UriMismatch);
    }

    if iat.abs_diff(ctx.now) > ctx.max_skew_secs {
        return Err(DpopProofError::Expired);
    }

    match (ctx.access_token, claims.ath.as_deref()) {
        (Some(token), Some(ath)) => {
            let expected = access_token_hash(token);
            if !bool::from(expected.as_bytes().ct_eq(ath.as_bytes())) {
                return Err(DpopProofError::AccessTokenHashMismatch);
            }
        }
        (Some(_), None) => return Err(DpopProofError::AccessTokenHashMismatch),
        (None, Some(_)) => return Err(DpopProofError::UnexpectedAccessTokenHash),
        (None, None) => {}
    }

    if let Some(accepted) = ctx.accepted_nonces {
        // Nonces are fixed-length server values; `ct_eq` of unequal lengths
        // is false, so an absent nonce never matches.
        let nonce = claims.nonce.as_deref().unwrap_or_default().as_bytes();
        if !accepted
            .iter()
            .any(|expected| bool::from(expected.as_bytes().ct_eq(nonce)))
        {
            return Err(DpopProofError::NonceRequired);
        }
    }

    let message = &proof[..header_b64.len() + 1 + payload_b64.len()];
    match crypto::verify(signature, message.as_bytes(), &decoding_key, alg) {
        Ok(true) => {}
        _ => return Err(DpopProofError::InvalidSignature),
    }

    Ok(VerifiedDpopProof { jkt, jti, iat })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, crypto};
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    use p256::pkcs8::DecodePrivateKey as _;
    use rsa::pkcs8::DecodePrivateKey as RsaDecodePrivateKey;
    use rsa::traits::PublicKeyParts as _;
    use serde_json::json;

    const NOW: i64 = 1_760_000_000;

    const EC_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0mBL+Hphh8GGUGdi
gmBwdXtr0cZMOm/ZXd7WQelR3umhRANCAASxIa1qgs06aj9LNbZGgn5Mf+pjqf/q
u9kjxPUBs14LLJlWTBwQxPJ6GLO+UoZswTJWTmawRuC2EyKWhJaSPxwA
-----END PRIVATE KEY-----
";

    const RSA2048_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCK5NLTKlQCgc0E
bZ/mU/6HzHHXY14okIfgGJy3+w9LbDh9k0KpRyLcyDoCSjaAG9m5Gqal/uEI/g7/
mOAa+W7FGc9gRzzVZQCzWujYtWFBUe2Ig2qVNwzFFYDw5OsB/FIJNgjzXV2pxfqe
gBfScat1u4NndEUQKNmAhQYmYAh4OgfkAJzo/CwpHYnyTY+dRG0yNtyPh/WdMtJZ
Iq4ADgHf9Wuj43ED6k03qCRQtzPcarhp8FZQ/iW/WfEv2hDwZtAxz8fW6qdzb15s
9DzpqACgfLaiTjk1jb4eHELNf+9QU7gXyEwsa/PJrmEZCk9nNYNAcPcc1YRyvE8N
KLR/rhnxAgMBAAECggEAARplJEEzTpvKTY0zVmh3Xou8obnLzyWqtphrcjifu/kd
j73CK0cB22AJueft++F8vrAb/7iBAAnIg7YqnXw6qX0VfQ3DyWwWb9Y6gDIcliC4
8rscdxfrVYtgrUkcJrViz2jq9EfbDRSh821QAx9c/b/iAMnXHJQ+eftUe6yKlK3a
UFpsQLEmcpEL6slh3S2B/yrYRqiv6ccDRZkV1dZnfm/JvzbppflPI61ZgdVyvxGg
1vJGJY2r1sXYm3Sy1waGW73K+ASj034lPyclPlDQlu4uXcNfSOabygGLKqt2/X1y
biw87w7G6oaEJRPyq64D8yWbHIFezKSnNFZR67AMoQKBgQC+1JXHQeyOc6rO0MVn
D0H4lNGJ36s4SN/C7RJFcnrSHiIp4lZnanHNt9ICWJyKnJNCOTnEZc/qS+ZD2LBO
X7BRB9mDdk/l3VdwbhD0DS21xOyJVBEy6C9Qwg2dJL+v356kS7Vkou+pCKfv1uOp
C43RFZvarvvHUp3pUtS0XhtFCQKBgQC6U6p5n3w+L6wJqSGJaqkaB/S4frJoA3Q8
H+ZjrDJgxd38punQ2S8osoA3hQloUZv+o0E4vEzHZ81+9aEhYRJH8o5i9s55tpGK
f44/iRVEV90/xt3UvRFclLNTqep3iBmyWt54upC3TPxGqxyw3qM0q2t8SDv0sjeO
TxibjBIPqQKBgQCdTRMhqt/aFNJppIH0EAmrZNDMu8ihnsCEJ3N2N4WyihBTQjVD
DeU9VBcSxARV5fclEZLip6IZWfM3XfkGwa3PPY845F+79RZMoQ3sfqh9OxRXpyp+
MhI+mZcrP82apdRZTeb6S60OQwpbk2EaSWHfRdaxDqiQhzOPzy1yeFg2MQKBgQCl
goJQ7QlpF+Gi5zjiHvu9IsoQRILngAH1EoUNjr1lVv4cWowht3p7lSvtpWA46R0/
cPcTlbhB/QP+PeR2iQq7HEu8vu2kEjdwJmROLc/VWJMw/s64FYZhjblJnQqoSR5C
XxN1fIvmNx11DLQ8rFefBpJA4M1ZTCGraLk8Go1EmQKBgFhqAcpI6hcB5d6yaFDU
0uFFdEmfsCXWvdR8pt0hTmwsUXQAj3+XdvF51bStgLl/3lzC6qF8UVOI/yUKxZT8
3j1EVDCii6sEkIHXUkjbQqae6TLBKunxswvP85yTFPM35Icxt+Vc2ksfJ9266LKb
Y3xxNa+DAtj4nYbGHfsq7GAU
-----END PRIVATE KEY-----
";

    const RSA1024_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAOFk9o/66HaRKUF6
+E/0y6k9vo5EjUtUOJ8zNBRATzz+n4AQ7+/nkumKjfc5enZa2JeUPzCo4qSK4ny0
L+0gz0oyTYkVF4QNloFfUd4AKtyhjW9HIYpCCu0DNa07pjbaD/mEjQ30Ttj9lxCt
WyQqAg1M1Qqn98NkvDhD61vXAgfvAgMBAAECgYB0XJVWG6jrnWF5Jq0PSkfiZbf8
5rMzUpWwytR2KAVAbguWKChW6GzWGOvV2Fy6wYfUKXq9+lKXtAPdcYDUoP2iTmU/
FEguPnaIrFEo5ggRjbvIDEKCb0+NZ5HGYStZraOL7kE178KhQSF3JAKpkHHmFDkz
iNMG8nQ2v0ttkakaAQJBAPVfavYcbuCeVpV4E8boW4ZtlTdbFOD+wvJlrjMBj+Nw
G+I17WyRnYfW3YmGo9rURduMNydp3Sz09mDf+ope14ECQQDrKAjVNuX4zRNjCldy
vdqprfb2+8+phKVApzbGh8mnunjpj7TxyO/zFuxaZm3aqTpMgJePsqiKeEVLo/EF
hhdvAkEAuuA9/UzwYSAWf2XhYhcrRbmF8I/s2eMNpEEup+gjpyuGAQXjWlGYsZFC
TnB9sLcEsU4b32ewLIIwdt1+2g2bgQJATnvJHug4ruY7DzYXY5tLzI/cOihm8Yvs
33wvguk0+3739fPZj0ziEL7Y2X8QMQeEBp5wdyxIphZoAkvQGGjdjwJBANiQCqLx
r1sFIIOnzKdETW1ImrFa85I1b/H+WJeTA6j5zRcr6gA1NdVeQdLXoW+9r2L/9HsI
iInRUT3PWlw/HKU=
-----END PRIVATE KEY-----
";

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn ec_jwk() -> Map<String, Value> {
        let secret = p256::SecretKey::from_pkcs8_pem(EC_PEM).unwrap();
        let point = secret.public_key().to_sec1_point(false);
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64(point.x().unwrap()),
            "y": b64(point.y().unwrap()),
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn rsa_jwk(pem: &str) -> Map<String, Value> {
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem).unwrap();
        json!({
            "kty": "RSA",
            "n": b64(&key.n().to_bytes_be()),
            "e": b64(&key.e().to_bytes_be()),
        })
        .as_object()
        .unwrap()
        .clone()
    }

    /// Sign arbitrary header and claims; the tests control every field.
    fn sign(alg: Algorithm, pem: &str, header: Value, claims: Value) -> String {
        openstack_keystone_jwt_crypto::install();
        let key = match alg {
            Algorithm::ES256 => EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
            _ => EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
        };
        let message = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        // `ring` refuses to load RSA keys below 2048 bits, which the short-key
        // tests rely on; a garbage signature exercises the same rejection
        // paths, as the key is checked before the signature.
        let signature =
            crypto::sign(message.as_bytes(), &key, alg).unwrap_or_else(|_| b64(&[0x5a; 128]));
        format!("{message}.{signature}")
    }

    fn es256_header() -> Value {
        json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": ec_jwk()})
    }

    fn claims() -> Value {
        json!({
            "jti": "proof-1",
            "htm": "POST",
            "htu": "https://ks.example/v4/oauth2/d/token",
            "iat": NOW,
        })
    }

    fn token_url() -> Url {
        Url::parse("https://ks.example/v4/oauth2/d/token").unwrap()
    }

    fn ctx(uri: &Url) -> DpopProofContext<'_> {
        DpopProofContext {
            method: "POST",
            uri,
            access_token: None,
            accepted_nonces: None,
            now: NOW,
            max_skew_secs: 60,
        }
    }

    fn es256_proof(header: Value, claims: Value) -> String {
        sign(Algorithm::ES256, EC_PEM, header, claims)
    }

    #[test]
    fn test_valid_es256_proof() {
        let uri = token_url();
        let proof = es256_proof(es256_header(), claims());
        let verified = verify_dpop_proof(&proof, &ctx(&uri)).unwrap();
        assert_eq!(verified.jti, "proof-1");
        assert_eq!(verified.iat, NOW);
        assert_eq!(verified.jkt, jwk_thumbprint(&ec_jwk()).unwrap());
    }

    #[test]
    fn test_valid_rs256_proof() {
        let uri = token_url();
        let header = json!({"typ": "dpop+jwt", "alg": "RS256", "jwk": rsa_jwk(RSA2048_PEM)});
        let proof = sign(Algorithm::RS256, RSA2048_PEM, header, claims());
        let verified = verify_dpop_proof(&proof, &ctx(&uri)).unwrap();
        assert_eq!(verified.jkt, jwk_thumbprint(&rsa_jwk(RSA2048_PEM)).unwrap());
    }

    /// RFC 7638 §3.1 example key and thumbprint.
    #[test]
    fn test_rfc7638_thumbprint_vector() {
        let jwk = json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29",
        });
        assert_eq!(
            jwk_thumbprint(jwk.as_object().unwrap()).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn test_ath_binds_access_token() {
        let uri = Url::parse("https://nova.example/v2.1/servers").unwrap();
        let token = "access.token.value";
        let mut c = claims();
        c["htm"] = json!("GET");
        c["htu"] = json!("https://nova.example/v2.1/servers");
        c["ath"] = json!(access_token_hash(token));
        let proof = es256_proof(es256_header(), c);
        let mut context = ctx(&uri);
        context.method = "GET";
        context.access_token = Some(token);
        assert!(verify_dpop_proof(&proof, &context).is_ok());

        context.access_token = Some("other.token");
        assert_eq!(
            verify_dpop_proof(&proof, &context).unwrap_err(),
            DpopProofError::AccessTokenHashMismatch
        );
    }

    #[test]
    fn test_missing_ath_on_resource_request_rejected() {
        let uri = token_url();
        let proof = es256_proof(es256_header(), claims());
        let mut context = ctx(&uri);
        context.access_token = Some("tok");
        assert_eq!(
            verify_dpop_proof(&proof, &context).unwrap_err(),
            DpopProofError::AccessTokenHashMismatch
        );
    }

    #[test]
    fn test_ath_on_token_endpoint_rejected() {
        let uri = token_url();
        let mut c = claims();
        c["ath"] = json!("x");
        let proof = es256_proof(es256_header(), c);
        assert_eq!(
            verify_dpop_proof(&proof, &ctx(&uri)).unwrap_err(),
            DpopProofError::UnexpectedAccessTokenHash
        );
    }

    #[test]
    fn test_method_mismatch() {
        let uri = token_url();
        let mut c = claims();
        c["htm"] = json!("GET");
        let proof = es256_proof(es256_header(), c);
        assert_eq!(
            verify_dpop_proof(&proof, &ctx(&uri)).unwrap_err(),
            DpopProofError::MethodMismatch
        );
    }

    #[test]
    fn test_uri_mismatch() {
        let uri = token_url();
        let mut c = claims();
        c["htu"] = json!("https://evil.example/v4/oauth2/d/token");
        let proof = es256_proof(es256_header(), c);
        assert_eq!(
            verify_dpop_proof(&proof, &ctx(&uri)).unwrap_err(),
            DpopProofError::UriMismatch
        );
    }

    #[test]
    fn test_htu_normalised_query_fragment_case_and_port() {
        let uri = Url::parse("https://KS.example:443/v4/oauth2/d/token?x=1#f").unwrap();
        let proof = es256_proof(es256_header(), claims());
        assert!(verify_dpop_proof(&proof, &ctx(&uri)).is_ok());

        let mut c = claims();
        c["htu"] = json!("https://ks.example/v4/oauth2/d/token?a=b#frag");
        let proof = es256_proof(es256_header(), c);
        assert!(verify_dpop_proof(&proof, &ctx(&token_url())).is_ok());
    }

    #[test]
    fn test_iat_window_both_directions() {
        let uri = token_url();
        for (delta, ok) in [
            (0, true),
            (60, true),
            (-60, true),
            (61, false),
            (-61, false),
        ] {
            let mut c = claims();
            c["iat"] = json!(NOW + delta);
            let proof = es256_proof(es256_header(), c);
            let res = verify_dpop_proof(&proof, &ctx(&uri));
            assert_eq!(res.is_ok(), ok, "delta {delta}");
            if !ok {
                assert_eq!(res.unwrap_err(), DpopProofError::Expired);
            }
        }
    }

    /// `iat` is attacker-controlled; extreme values must be rejected as
    /// `Expired`, not overflow the window arithmetic.
    #[test]
    fn test_iat_extreme_values_rejected() {
        let uri = token_url();
        for iat in [i64::MIN, i64::MAX] {
            let mut c = claims();
            c["iat"] = json!(iat);
            let proof = es256_proof(es256_header(), c);
            assert_eq!(
                verify_dpop_proof(&proof, &ctx(&uri)).unwrap_err(),
                DpopProofError::Expired
            );
        }
    }

    #[test]
    fn test_jti_too_long_rejected() {
        let uri = token_url();
        let mut c = claims();
        c["jti"] = json!("x".repeat(MAX_JTI_LEN + 1));
        let proof = es256_proof(es256_header(), c);
        assert_eq!(
            verify_dpop_proof(&proof, &ctx(&uri)).unwrap_err(),
            DpopProofError::JtiTooLong
        );
    }

    #[test]
    fn test_missing_claims() {
        let uri = token_url();
        for name in ["jti", "htm", "htu", "iat"] {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(name);
            let proof = es256_proof(es256_header(), c);
            assert!(matches!(
                verify_dpop_proof(&proof, &ctx(&uri)).unwrap_err(),
                DpopProofError::MissingClaim(n) if n == name
            ));
        }
    }

    #[test]
    fn test_nonce() {
        let uri = token_url();
        let mut context = ctx(&uri);
        let accepted = ["n-1".to_string(), "n-0".to_string()];
        context.accepted_nonces = Some(&accepted);

        let without = es256_proof(es256_header(), claims());
        assert_eq!(
            verify_dpop_proof(&without, &context).unwrap_err(),
            DpopProofError::NonceRequired
        );

        let mut c = claims();
        c["nonce"] = json!("stale");
        let stale = es256_proof(es256_header(), c);
        assert_eq!(
            verify_dpop_proof(&stale, &context).unwrap_err(),
            DpopProofError::NonceRequired
        );

        for nonce in ["n-1", "n-0"] {
            let mut c = claims();
            c["nonce"] = json!(nonce);
            let good = es256_proof(es256_header(), c);
            assert!(verify_dpop_proof(&good, &context).is_ok());
        }
    }

    #[test]
    fn test_wrong_typ() {
        let uri = token_url();
        for typ in [json!("JWT"), json!(null)] {
            let mut h = es256_header();
            h["typ"] = typ;
            let proof = es256_proof(h, claims());
            assert_eq!(
                verify_dpop_proof(&proof, &ctx(&uri)).unwrap_err(),
                DpopProofError::InvalidType
            );
        }
        let mut h = es256_header();
        h.as_object_mut().unwrap().remove("typ");
        assert_eq!(
            verify_dpop_proof(&es256_proof(h, claims()), &ctx(&uri)).unwrap_err(),
            DpopProofError::InvalidType
        );
    }

    #[test]
    fn test_disallowed_algorithms() {
        let uri = token_url();
        for alg in ["none", "HS256", "ES384", "PS256"] {
            let mut h = es256_header();
            h["alg"] = json!(alg);
            let msg = format!(
                "{}.{}.",
                b64(h.to_string().as_bytes()),
                b64(claims().to_string().as_bytes())
            );
            assert!(matches!(
                verify_dpop_proof(&msg, &ctx(&uri)).unwrap_err(),
                DpopProofError::UnsupportedAlgorithm(_)
            ));
        }
    }

    #[test]
    fn test_missing_jwk() {
        let uri = token_url();
        let mut h = es256_header();
        h.as_object_mut().unwrap().remove("jwk");
        assert_eq!(
            verify_dpop_proof(&es256_proof(h, claims()), &ctx(&uri)).unwrap_err(),
            DpopProofError::MissingKey
        );
    }

    #[test]
    fn test_private_and_certificate_members_rejected() {
        let uri = token_url();
        for (member, value) in [
            ("d", json!("AAAA")),
            ("p", json!("AAAA")),
            ("k", json!("AAAA")),
            ("x5c", json!(["AAAA"])),
            ("x5u", json!("https://evil.example/c")),
        ] {
            let mut h = es256_header();
            h["jwk"][member] = value;
            assert!(
                matches!(
                    verify_dpop_proof(&es256_proof(h, claims()), &ctx(&uri)).unwrap_err(),
                    DpopProofError::InvalidKey(_)
                ),
                "{member}"
            );
        }
    }

    #[test]
    fn test_kty_crv_must_match_alg() {
        let uri = token_url();
        // ES256 with an RSA key.
        let mut h = es256_header();
        h["jwk"] = Value::Object(rsa_jwk(RSA2048_PEM));
        assert!(matches!(
            verify_dpop_proof(&es256_proof(h, claims()), &ctx(&uri)).unwrap_err(),
            DpopProofError::InvalidKey(_)
        ));
        // ES256 with another curve.
        let mut h = es256_header();
        h["jwk"]["crv"] = json!("P-384");
        assert!(matches!(
            verify_dpop_proof(&es256_proof(h, claims()), &ctx(&uri)).unwrap_err(),
            DpopProofError::InvalidKey(_)
        ));
        // RS256 with an EC key.
        let h = json!({"typ": "dpop+jwt", "alg": "RS256", "jwk": ec_jwk()});
        let proof = sign(Algorithm::RS256, RSA2048_PEM, h, claims());
        assert!(matches!(
            verify_dpop_proof(&proof, &ctx(&uri)).unwrap_err(),
            DpopProofError::InvalidKey(_)
        ));
    }

    #[test]
    fn test_short_rsa_key_rejected() {
        let uri = token_url();
        let h = json!({"typ": "dpop+jwt", "alg": "RS256", "jwk": rsa_jwk(RSA1024_PEM)});
        let proof = sign(Algorithm::RS256, RSA1024_PEM, h, claims());
        assert!(matches!(
            verify_dpop_proof(&proof, &ctx(&uri)).unwrap_err(),
            DpopProofError::InvalidKey(_)
        ));
    }

    #[test]
    fn test_rsa_bit_length_is_measured_not_byte_count() {
        // `e` is 65537; the closure avoids moving the `String` into two
        // `json!`s.
        let e = || b64(&[0x01, 0x00, 0x01]);
        // A 256-byte `n` whose top byte is 0x01 is only 2041 bits: rejected.
        let mut n = vec![0u8; 256];
        n[0] = 0x01;
        let jwk = json!({ "kty": "RSA", "n": b64(&n), "e": e() });
        assert!(matches!(
            validate_key(Algorithm::RS256, jwk.as_object().unwrap()),
            Err(DpopProofError::InvalidKey(_))
        ));
        // Same length but top byte 0x80: exactly 2048 bits, the minimum.
        let mut n = vec![0u8; 256];
        n[0] = 0x80;
        let jwk = json!({ "kty": "RSA", "n": b64(&n), "e": e() });
        assert!(validate_key(Algorithm::RS256, jwk.as_object().unwrap()).is_ok());
    }

    #[test]
    fn test_signature_from_other_key_rejected() {
        let uri = token_url();
        // Header advertises the EC key but the proof is signed with another.
        let other = {
            // RSA key advertised as RS256, signed by a different RSA key.
            let h = json!({"typ": "dpop+jwt", "alg": "RS256", "jwk": rsa_jwk(RSA2048_PEM)});
            sign(Algorithm::RS256, RSA1024_PEM, h, claims())
        };
        assert_eq!(
            verify_dpop_proof(&other, &ctx(&uri)).unwrap_err(),
            DpopProofError::InvalidSignature
        );
    }

    #[test]
    fn test_tampered_claims_rejected() {
        let uri = token_url();
        let proof = es256_proof(es256_header(), claims());
        let mut parts: Vec<&str> = proof.split('.').collect();
        let forged = b64(claims()
            .to_string()
            .replace("proof-1", "proof-2")
            .as_bytes());
        parts[1] = &forged;
        assert_eq!(
            verify_dpop_proof(&parts.join("."), &ctx(&uri)).unwrap_err(),
            DpopProofError::InvalidSignature
        );
    }

    #[test]
    fn test_malformed_proofs() {
        let uri = token_url();
        for proof in ["", "a.b", "a.b.c.d", "!!!.b.c", "e30.b.c"] {
            assert!(
                matches!(
                    verify_dpop_proof(proof, &ctx(&uri)).unwrap_err(),
                    DpopProofError::Malformed(_) | DpopProofError::InvalidType
                ),
                "{proof}"
            );
        }
    }

    #[test]
    fn test_thumbprint_is_canonical() {
        let jwk = rsa_jwk(RSA2048_PEM);
        let expected = jwk_thumbprint(&jwk).unwrap();
        let mut padded = jwk.clone();
        let mut n = vec![0u8, 0];
        n.extend(URL_SAFE_NO_PAD.decode(jwk["n"].as_str().unwrap()).unwrap());
        padded.insert("n".into(), json!(b64(&n)));
        padded.insert("e".into(), json!(b64(&[0, 1, 0, 1])));
        assert_eq!(jwk_thumbprint(&padded).unwrap(), expected);
    }

    #[test]
    fn test_bad_rsa_exponent_rejected() {
        for e in [vec![3u8], vec![1, 0, 0], vec![1, 0, 2], vec![1, 0, 0, 0, 1]] {
            let mut jwk = rsa_jwk(RSA2048_PEM);
            jwk.insert("e".into(), json!(b64(&e)));
            assert!(matches!(
                validate_key(Algorithm::RS256, &jwk),
                Err(DpopProofError::InvalidKey(_))
            ));
        }
    }

    #[test]
    fn test_key_usage_members_enforced() {
        let uri = token_url();
        for (member, value) in [
            ("use", json!("enc")),
            ("key_ops", json!(["encrypt"])),
            ("alg", json!("RS256")),
        ] {
            let mut h = es256_header();
            h["jwk"][member] = value;
            assert!(matches!(
                verify_dpop_proof(&es256_proof(h, claims()), &ctx(&uri)).unwrap_err(),
                DpopProofError::InvalidKey(_)
            ));
        }
        let mut h = es256_header();
        h["jwk"]["use"] = json!("sig");
        h["jwk"]["key_ops"] = json!(["verify"]);
        h["jwk"]["alg"] = json!("ES256");
        assert!(verify_dpop_proof(&es256_proof(h, claims()), &ctx(&uri)).is_ok());
    }

    #[test]
    fn test_crit_header_rejected() {
        let uri = token_url();
        let mut h = es256_header();
        h["crit"] = json!(["exp"]);
        assert!(matches!(
            verify_dpop_proof(&es256_proof(h, claims()), &ctx(&uri)).unwrap_err(),
            DpopProofError::Malformed(_)
        ));
    }

    #[test]
    fn test_oversized_proof_rejected() {
        let uri = token_url();
        let proof = "a".repeat(MAX_PROOF_LEN + 1);
        assert!(matches!(
            verify_dpop_proof(&proof, &ctx(&uri)).unwrap_err(),
            DpopProofError::Malformed(_)
        ));
    }

    /// Cheap claim checks run before the signature: a bad claim in a proof
    /// with a garbage signature is reported as the claim error.
    #[test]
    fn test_claims_checked_before_signature() {
        let uri = token_url();
        let mut c = claims();
        c["htm"] = json!("GET");
        let proof = es256_proof(es256_header(), c);
        let mut parts: Vec<&str> = proof.split('.').collect();
        parts[2] = "AAAA";
        assert_eq!(
            verify_dpop_proof(&parts.join("."), &ctx(&uri)).unwrap_err(),
            DpopProofError::MethodMismatch
        );
    }

    #[test]
    fn test_htu_percent_encoding_and_userinfo_normalised() {
        let uri = Url::parse("https://u:p@ks.example/v4/%7eoauth2/a%2fb/token").unwrap();
        let mut c = claims();
        c["htu"] = json!("https://ks.example/v4/~oauth2/a%2Fb/token");
        assert!(verify_dpop_proof(&es256_proof(es256_header(), c), &ctx(&uri)).is_ok());
    }

    #[test]
    fn test_supported_algorithms_are_all_accepted() {
        for name in SUPPORTED_ALGORITHMS {
            let alg = Algorithm::from_str(name).unwrap();
            assert_eq!(alg_name(alg), name);
        }
    }

    #[test]
    fn test_confirmation_matches() {
        let cnf = Confirmation { jkt: "abc".into() };
        assert!(cnf.matches("abc"));
        assert!(!cnf.matches("xyz"));
        assert!(!Confirmation { jkt: String::new() }.matches(""));
    }
}
