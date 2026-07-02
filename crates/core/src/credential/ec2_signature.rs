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
//! EC2 signature verification (ADR 0019 §5).
//!
//! Pure, DB-free re-implementation of
//! `keystoneclient.contrib.ec2.utils.Ec2Signer` and
//! `EC2TokensResource._check_signature()`. Given the same secret and the
//! same `credentials` payload, this module must produce the identical
//! signature Python Keystone would produce, for every signature version
//! (v0/v1/v2/v4), since the two services validate the same EC2 credentials
//! against the same shared `credential` table.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use hmac::{Hmac, KeyInit, Mac};
use sha1::{Digest as _, Sha1};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use openstack_keystone_core_types::auth::AuthenticationError;
use openstack_keystone_core_types::credential::Ec2SignatureRequest;

type HmacSha256 = Hmac<Sha256>;

/// Manual HMAC-SHA1 (RFC 2104), since the workspace's `sha1` crate (pinned
/// to the `digest` 0.10 line for compatibility with other consumers) cannot
/// satisfy the `hmac` crate's `digest` 0.11 bound. SHA-1's 64-byte block
/// size is fixed by the algorithm, so this is a direct, dependency-free
/// implementation rather than a workaround with hidden edge cases.
fn hmac_sha1_raw(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        key_block[..20].copy_from_slice(&Sha1::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Sha1::new();
    inner.update(ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

/// The four EC2 request-signing algorithms Keystone has ever supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ec2SignatureVersion {
    /// Keystone-legacy, HMAC-SHA1 over `Action` + `Timestamp`.
    V0,
    /// Keystone-extended, HMAC-SHA1 over sorted `key+value` params.
    V1,
    /// AWS Query signing, HMAC-SHA256 (preferred) / HMAC-SHA1 (fallback).
    V2,
    /// AWS SigV4, HMAC-SHA256 throughout.
    V4,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Case-insensitive lookup into a `{header/param name: value}` map, as
/// required for HTTP header names (which are case-insensitive on the wire
/// even though the JSON `headers` object preserves whatever case the client
/// sent).
fn get_ci<'a>(map: &'a std::collections::HashMap<String, String>, name: &str) -> Option<&'a str> {
    map.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Determine the signature version via the same ordered decision procedure
/// as `Ec2Signer.generate()` (ADR 0019 §5): `SignatureVersion` is
/// authoritative for v0/v1/v2, but v4 (SigV4) never carries it, so v4 is
/// detected from the `Authorization` header or `X-Amz-Algorithm` param
/// instead.
pub fn detect_signature_version(
    req: &Ec2SignatureRequest,
) -> Result<Ec2SignatureVersion, AuthenticationError> {
    match req.params.get("SignatureVersion").map(String::as_str) {
        Some("0") => return Ok(Ec2SignatureVersion::V0),
        Some("1") => return Ok(Ec2SignatureVersion::V1),
        Some("2") => return Ok(Ec2SignatureVersion::V2),
        _ => {}
    }
    if let Some(auth) = get_ci(&req.headers, "Authorization")
        && auth.starts_with("AWS4-HMAC-SHA256")
    {
        return Ok(Ec2SignatureVersion::V4);
    }
    if req.params.get("X-Amz-Algorithm").map(String::as_str) == Some("AWS4-HMAC-SHA256") {
        return Ok(Ec2SignatureVersion::V4);
    }
    Err(AuthenticationError::Ec2UnknownSignatureVersion)
}

/// Percent-encode `s`, leaving unreserved characters (`A-Za-z0-9_.-~`) and
/// `/` untouched. Matches Python's `urllib.parse.quote(s)` (default
/// `safe='/'`).
fn uri_encode_default(s: &str) -> String {
    uri_encode(s, true)
}

/// Percent-encode `s`, leaving only the unreserved characters
/// (`A-Za-z0-9_.-~`) untouched — `/` is escaped. Matches Python's
/// `urllib.parse.quote(s, safe='-_~')`, and is also the encoding AWS SigV4
/// mandates for canonical query strings.
fn uri_encode_strict(s: &str) -> String {
    uri_encode(s, false)
}

fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        let is_unreserved =
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'~');
        if is_unreserved || (keep_slash && byte == b'/') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// v0: `HMAC-SHA1(secret, params["Action"] + params["Timestamp"])`, Base64.
fn generate_v0(secret: &str, req: &Ec2SignatureRequest) -> Result<String, AuthenticationError> {
    let action = req.params.get("Action").cloned().unwrap_or_default();
    let timestamp = req.params.get("Timestamp").cloned().unwrap_or_default();
    let string_to_sign = format!("{action}{timestamp}");
    hmac_sha1_base64(secret, &string_to_sign)
}

/// v1: `HMAC-SHA1(secret, concat(key+value for sorted(params, key=str.lower)))`, Base64.
fn generate_v1(secret: &str, req: &Ec2SignatureRequest) -> Result<String, AuthenticationError> {
    let mut pairs: Vec<(&String, &String)> = req.params.iter().collect();
    pairs.sort_by_key(|(k, _)| k.to_lowercase());
    let string_to_sign: String = pairs.into_iter().map(|(k, v)| format!("{k}{v}")).collect();
    hmac_sha1_base64(secret, &string_to_sign)
}

/// v2: AWS Query signing. Canonical query string, HMAC-SHA256 (preferred, when
/// `params["SignatureMethod"] == "HmacSHA256"`) or HMAC-SHA1 fallback, Base64.
fn generate_v2(secret: &str, req: &Ec2SignatureRequest) -> Result<String, AuthenticationError> {
    let mut pairs: Vec<(&String, &String)> = req.params.iter().collect();
    pairs.sort();
    let canonical_qs: String = pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", uri_encode_default(k), uri_encode_strict(v)))
        .collect::<Vec<_>>()
        .join("&");
    let string_to_sign = format!("{}\n{}\n{}\n{}", req.verb, req.host, req.path, canonical_qs);
    if req.params.get("SignatureMethod").map(String::as_str) == Some("HmacSHA256") {
        hmac_sha256_base64(secret, &string_to_sign)
    } else {
        hmac_sha1_base64(secret, &string_to_sign)
    }
}

/// v4: AWS SigV4. See ADR 0019 §5 "Version 4 (SigV4, HMAC-SHA256
/// throughout)" for the four-step derivation this mirrors exactly.
fn generate_v4(secret: &str, req: &Ec2SignatureRequest) -> Result<String, AuthenticationError> {
    let auth_header =
        get_ci(&req.headers, "Authorization").filter(|v| v.starts_with("AWS4-HMAC-SHA256"));

    let auth_component = |name: &str| -> Option<String> {
        if let Some(auth) = auth_header {
            parse_auth_component(auth, name)
        } else {
            req.params.get(&format!("X-Amz-{name}")).cloned()
        }
    };

    let credential =
        auth_component("Credential").ok_or(AuthenticationError::Ec2UnknownSignatureVersion)?;
    let credential_split: Vec<&str> = credential.split('/').collect();
    if credential_split.len() < 5 {
        return Err(AuthenticationError::Ec2UnknownSignatureVersion);
    }
    let cred_date = credential_split[1];
    let region = credential_split[2];
    let service = credential_split[3];
    let credential_scope = credential_split[1..5].join("/");

    let signed_headers_raw =
        auth_component("SignedHeaders").ok_or(AuthenticationError::Ec2UnknownSignatureVersion)?;

    let param_date = get_ci(&req.headers, "X-Amz-Date")
        .map(str::to_string)
        .or_else(|| req.params.get("X-Amz-Date").cloned())
        .ok_or(AuthenticationError::Ec2TimestampMissing)?;

    if !param_date.starts_with(cred_date) {
        return Err(AuthenticationError::Ec2CredentialScopeDateMismatch);
    }

    // Boto < 2.9.3 strips the port from `Host` when signing.
    let boto_legacy = get_ci(&req.headers, "User-Agent")
        .map(is_legacy_boto_user_agent)
        .unwrap_or(false);

    let mut canonical_headers = String::new();
    for header_name in signed_headers_raw.split(';') {
        let mut value = get_ci(&req.headers, header_name).unwrap_or("").trim();
        let stripped;
        if boto_legacy
            && header_name.eq_ignore_ascii_case("host")
            && let Some(idx) = value.find(':')
        {
            stripped = &value[..idx];
            value = stripped;
        }
        canonical_headers.push_str(&format!("{}:{}\n", header_name.to_lowercase(), value));
    }

    let canonical_qs = if req.verb.eq_ignore_ascii_case("POST") {
        String::new()
    } else {
        let mut pairs: Vec<(&String, &String)> = req
            .params
            .iter()
            .filter(|(k, _)| !k.eq_ignore_ascii_case("X-Amz-Signature"))
            .collect();
        pairs.sort();
        pairs
            .into_iter()
            .map(|(k, v)| format!("{}={}", uri_encode_strict(k), uri_encode_strict(v)))
            .collect::<Vec<_>>()
            .join("&")
    };

    let body_hash = req.body_hash.clone().unwrap_or_else(empty_sha256_hex);

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.verb.to_uppercase(),
        req.path,
        canonical_qs,
        canonical_headers,
        signed_headers_raw,
        body_hash
    );

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        param_date,
        credential_scope,
        to_hex(&Sha256::digest(canonical_request.as_bytes()))
    );

    let k_date = hmac_sha256_raw(format!("AWS4{secret}").as_bytes(), cred_date)?;
    let k_region = hmac_sha256_raw(&k_date, region)?;
    let k_service = hmac_sha256_raw(&k_region, service)?;
    let k_signing = hmac_sha256_raw(&k_service, "aws4_request")?;

    let signature = hmac_sha256_raw(&k_signing, &string_to_sign)?;
    Ok(to_hex(&signature))
}

/// Detects the boto < 2.9.3 `User-Agent` marker (`Boto/2.x.y` where `y` is
/// `0`, `1`, or `2`).
fn is_legacy_boto_user_agent(ua: &str) -> bool {
    for token in ua.split(|c: char| c.is_whitespace()) {
        if let Some(rest) = token.strip_prefix("Boto/2.") {
            let mut parts = rest.splitn(2, '.');
            let minor_ok = parts.next().is_some_and(|m| m.parse::<u32>().is_ok());
            let patch_ok = parts
                .next()
                .and_then(|p| p.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|p| p.parse::<u32>().ok())
                .is_some_and(|p| p <= 2);
            if minor_ok && patch_ok {
                return true;
            }
        }
    }
    false
}

fn parse_auth_component(auth_header: &str, name: &str) -> Option<String> {
    // `AWS4-HMAC-SHA256 Credential=.../..., SignedHeaders=..., Signature=...`
    // The first component is prefixed by the algorithm name and a space
    // (not just a comma), so trim to the last whitespace-separated token
    // before matching — a no-op for the other, space-free components.
    let prefix = format!("{name}=");
    auth_header
        .split(',')
        .map(str::trim)
        .map(|part| part.rsplit(' ').next().unwrap_or(part))
        .find_map(|part| part.strip_prefix(prefix.as_str()))
        .map(str::to_string)
}

fn empty_sha256_hex() -> String {
    to_hex(&Sha256::digest(b""))
}

fn hmac_sha1_base64(secret: &str, message: &str) -> Result<String, AuthenticationError> {
    Ok(BASE64.encode(hmac_sha1_raw(secret.as_bytes(), message.as_bytes())))
}

fn hmac_sha256_base64(secret: &str, message: &str) -> Result<String, AuthenticationError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| AuthenticationError::Ec2SignatureInvalid)?;
    mac.update(message.as_bytes());
    Ok(BASE64.encode(mac.finalize().into_bytes()))
}

fn hmac_sha256_raw(key: &[u8], message: &str) -> Result<Vec<u8>, AuthenticationError> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .map_err(|_| AuthenticationError::Ec2SignatureInvalid)?;
    mac.update(message.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Generate the expected signature for `req` under the given version.
pub fn generate_signature(
    secret: &str,
    version: Ec2SignatureVersion,
    req: &Ec2SignatureRequest,
) -> Result<String, AuthenticationError> {
    match version {
        Ec2SignatureVersion::V0 => generate_v0(secret, req),
        Ec2SignatureVersion::V1 => generate_v1(secret, req),
        Ec2SignatureVersion::V2 => generate_v2(secret, req),
        Ec2SignatureVersion::V4 => generate_v4(secret, req),
    }
}

/// Full signature verification flow, mirroring
/// `EC2TokensResource._check_signature()` (ADR 0019 §5):
///
/// 1. Detect the signing version.
/// 2. Generate the expected signature and compare (constant-time) against
///    `req.signature`.
/// 3. If that fails and `req.host` carries a port, strip it and retry once
///    (a fresh HMAC instance is used — HMAC state must not be reused across
///    attempts).
pub fn verify_signature(
    secret: &str,
    req: &Ec2SignatureRequest,
) -> Result<(), AuthenticationError> {
    let Some(client_signature) = req.signature.as_deref() else {
        return Err(AuthenticationError::Ec2SignatureMissing);
    };

    let version = detect_signature_version(req)?;
    let expected = generate_signature(secret, version, req)?;
    if bool::from(client_signature.as_bytes().ct_eq(expected.as_bytes())) {
        return Ok(());
    }

    if let Some(idx) = req.host.find(':') {
        let mut retry_req = req.clone();
        retry_req.host = req.host[..idx].to_string();
        let expected_retry = generate_signature(secret, version, &retry_req)?;
        if bool::from(client_signature.as_bytes().ct_eq(expected_retry.as_bytes())) {
            return Ok(());
        }
    }

    Err(AuthenticationError::Ec2SignatureInvalid)
}

/// Timestamp validation for replay-attack prevention (CVE-2020-12692).
///
/// - v0/v1/v2: `params["Timestamp"]`, ISO 8601.
/// - v4: `X-Amz-Date` header or param, `YYYYMMDDTHHMMSSZ`.
pub fn validate_timestamp(
    req: &Ec2SignatureRequest,
    ttl_seconds: i64,
) -> Result<(), AuthenticationError> {
    let version = detect_signature_version(req)?;
    let ts: DateTime<Utc> = match version {
        Ec2SignatureVersion::V4 => {
            let raw = get_ci(&req.headers, "X-Amz-Date")
                .map(str::to_string)
                .or_else(|| req.params.get("X-Amz-Date").cloned())
                .ok_or(AuthenticationError::Ec2TimestampMissing)?;
            let naive = NaiveDateTime::parse_from_str(&raw, "%Y%m%dT%H%M%SZ")
                .map_err(|e| AuthenticationError::Ec2TimestampInvalid(e.to_string()))?;
            Utc.from_utc_datetime(&naive)
        }
        _ => {
            let raw = req
                .params
                .get("Timestamp")
                .cloned()
                .ok_or(AuthenticationError::Ec2TimestampMissing)?;
            DateTime::parse_from_rfc3339(&raw)
                .map_err(|e| AuthenticationError::Ec2TimestampInvalid(e.to_string()))?
                .with_timezone(&Utc)
        }
    };

    let now = Utc::now();
    let delta = (now - ts).num_seconds().abs();
    if delta > ttl_seconds {
        return Err(AuthenticationError::Ec2TimestampExpired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base_req() -> Ec2SignatureRequest {
        Ec2SignatureRequest {
            access: "AKIAIOSFODNN7EXAMPLE".into(),
            signature: None,
            host: "identity.example.com:5000".into(),
            verb: "GET".into(),
            path: "/".into(),
            params: HashMap::new(),
            headers: HashMap::new(),
            body_hash: None,
        }
    }

    // --- Version detection -------------------------------------------------

    #[test]
    fn test_detect_version_0_1_2() {
        for (v, expected) in [
            ("0", Ec2SignatureVersion::V0),
            ("1", Ec2SignatureVersion::V1),
            ("2", Ec2SignatureVersion::V2),
        ] {
            let mut req = base_req();
            req.params.insert("SignatureVersion".into(), v.into());
            assert_eq!(detect_signature_version(&req).unwrap(), expected);
        }
    }

    #[test]
    fn test_detect_version_4_via_authorization_header() {
        let mut req = base_req();
        req.headers.insert(
            "Authorization".into(),
            "AWS4-HMAC-SHA256 Credential=AKID/20260611/RegionOne/ec2/aws4_request".into(),
        );
        assert_eq!(
            detect_signature_version(&req).unwrap(),
            Ec2SignatureVersion::V4
        );
    }

    #[test]
    fn test_detect_version_4_via_x_amz_algorithm_param() {
        let mut req = base_req();
        req.params
            .insert("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into());
        assert_eq!(
            detect_signature_version(&req).unwrap(),
            Ec2SignatureVersion::V4
        );
    }

    #[test]
    fn test_detect_version_unknown() {
        let req = base_req();
        assert!(matches!(
            detect_signature_version(&req),
            Err(AuthenticationError::Ec2UnknownSignatureVersion)
        ));
    }

    #[test]
    fn test_signature_version_takes_precedence_over_v4_hints() {
        // SignatureVersion is authoritative for v0/v1/v2 even if v4 hints
        // are also present (ADR 0019 §5, ordered decision procedure).
        let mut req = base_req();
        req.params.insert("SignatureVersion".into(), "2".into());
        req.params
            .insert("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into());
        assert_eq!(
            detect_signature_version(&req).unwrap(),
            Ec2SignatureVersion::V2
        );
    }

    // --- v0 ------------------------------------------------------------
    // Cross-checked against Python:
    //   import hmac, hashlib, base64
    //   base64.b64encode(hmac.new(b"secret", b"DescribeInstances2026-06-11T12:00:00Z", hashlib.sha1).digest())

    #[test]
    fn test_v0_known_vector() {
        let mut req = base_req();
        req.params.insert("SignatureVersion".into(), "0".into());
        req.params
            .insert("Action".into(), "DescribeInstances".into());
        req.params
            .insert("Timestamp".into(), "2026-06-11T12:00:00Z".into());
        let sig =
            generate_signature("secret", detect_signature_version(&req).unwrap(), &req).unwrap();
        assert_eq!(sig, "DB6FXh9rU95Mj1IwFBsfl9htRzg=");
    }

    // --- v1 ------------------------------------------------------------
    // Cross-checked against Python:
    //   pairs sorted by key.lower(): Action, AWSAccessKeyId, SignatureVersion, Timestamp
    //   msg = "ActionDescribeInstancesAWSAccessKeyIdAKIDSignatureVersion1Timestamp2026-06-11T12:00:00Z"
    //   base64.b64encode(hmac.new(b"secret", msg.encode(), hashlib.sha1).digest())

    #[test]
    fn test_v1_known_vector() {
        let mut req = base_req();
        req.params.insert("SignatureVersion".into(), "1".into());
        req.params
            .insert("Action".into(), "DescribeInstances".into());
        req.params.insert("AWSAccessKeyId".into(), "AKID".into());
        req.params
            .insert("Timestamp".into(), "2026-06-11T12:00:00Z".into());
        let sig =
            generate_signature("secret", detect_signature_version(&req).unwrap(), &req).unwrap();
        assert_eq!(sig, "HTnU/K7Hr/h0YAyrgNdJAqdeYjo=");
    }

    #[test]
    fn test_v1_sorts_case_insensitively() {
        // A case-sensitive byte sort would place "B" before "a" (uppercase
        // sorts first in ASCII); Ec2Signer.generate() sorts by `key.lower()`,
        // so "a" must come first regardless of the recorded case.
        let mut req = base_req();
        req.params.insert("SignatureVersion".into(), "1".into());
        req.params.insert("B".into(), "2".into());
        req.params.insert("a".into(), "1".into());
        let sig_lower_first = generate_signature("secret", Ec2SignatureVersion::V1, &req).unwrap();

        let mut req_case_sensitive_order = base_req();
        req_case_sensitive_order
            .params
            .insert("SignatureVersion".into(), "1".into());
        req_case_sensitive_order
            .params
            .insert("a".into(), "1".into());
        req_case_sensitive_order
            .params
            .insert("B".into(), "2".into());
        let sig_same =
            generate_signature("secret", Ec2SignatureVersion::V1, &req_case_sensitive_order)
                .unwrap();
        // Insertion order into the HashMap must not affect the result; only
        // case-insensitive key order does.
        assert_eq!(sig_lower_first, sig_same);
    }

    // --- v2 ------------------------------------------------------------
    // Cross-checked against Python:
    //   from urllib.parse import quote
    //   canonical = "&".join(quote(k) + "=" + quote(v, safe="-_~") for k, v in sorted(params.items()))
    //   msg = "GET\nidentity.example.com\n/\n" + canonical
    //   base64.b64encode(hmac.new(b"secret", msg.encode(), hashlib.sha256).digest())

    #[test]
    fn test_v2_known_vector_hmac_sha256() {
        let mut req = base_req();
        req.host = "identity.example.com".into();
        req.params.insert("SignatureVersion".into(), "2".into());
        req.params
            .insert("SignatureMethod".into(), "HmacSHA256".into());
        req.params
            .insert("Action".into(), "DescribeInstances".into());
        req.params.insert("AWSAccessKeyId".into(), "AKID".into());
        req.params
            .insert("Timestamp".into(), "2026-06-11T12:00:00Z".into());
        let sig =
            generate_signature("secret", detect_signature_version(&req).unwrap(), &req).unwrap();
        assert_eq!(sig, "iRihZQtFVKKJVN6+iK/pT17g8ip9xTPMDt1ZvVzWjWA=");
    }

    #[test]
    fn test_v2_falls_back_to_hmac_sha1_without_signature_method() {
        let mut req = base_req();
        req.host = "identity.example.com".into();
        req.params.insert("SignatureVersion".into(), "2".into());
        req.params
            .insert("Action".into(), "DescribeInstances".into());
        let sig_sha1 =
            generate_signature("secret", detect_signature_version(&req).unwrap(), &req).unwrap();
        req.params
            .insert("SignatureMethod".into(), "HmacSHA256".into());
        let sig_sha256 =
            generate_signature("secret", detect_signature_version(&req).unwrap(), &req).unwrap();
        assert_ne!(sig_sha1, sig_sha256);
    }

    // --- v4 --------------------------------------------------------------
    // Cross-checked against Python (manual SigV4 derivation replicating the
    // canonical request / string-to-sign / signing-key-chain steps).

    fn v4_req() -> Ec2SignatureRequest {
        let mut req = base_req();
        req.verb = "GET".into();
        req.path = "/".into();
        req.headers.insert(
            "Authorization".into(),
            "AWS4-HMAC-SHA256 Credential=AKID/20260611/RegionOne/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=unused".into(),
        );
        req.headers
            .insert("Host".into(), "identity.example.com:5000".into());
        req.headers
            .insert("X-Amz-Date".into(), "20260611T120000Z".into());
        req.body_hash = Some(empty_sha256_hex());
        req
    }

    #[test]
    fn test_v4_detected_and_signable() {
        let req = v4_req();
        assert_eq!(
            detect_signature_version(&req).unwrap(),
            Ec2SignatureVersion::V4
        );
        let sig = generate_signature("secret", Ec2SignatureVersion::V4, &req).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(
            sig.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn test_v4_known_vector() {
        // Independently re-derived in Python via hashlib/hmac following the
        // same four steps as generate_v4.
        let req = v4_req();
        let sig = generate_signature("secret", Ec2SignatureVersion::V4, &req).unwrap();
        assert_eq!(
            sig,
            "3326c587f334ae319b36fa1798f8755aca74869f0cebd40504c0d43af2e2e5dc"
        );
    }

    #[test]
    fn test_v4_date_mismatch_rejected() {
        let mut req = v4_req();
        req.headers
            .insert("X-Amz-Date".into(), "20260101T000000Z".into());
        assert!(matches!(
            generate_signature("secret", Ec2SignatureVersion::V4, &req),
            Err(AuthenticationError::Ec2CredentialScopeDateMismatch)
        ));
    }

    #[test]
    fn test_v4_boto_legacy_strips_host_port() {
        let mut req = v4_req();
        req.headers
            .insert("User-Agent".into(), "Boto/2.9.1 Python/2.7".into());
        let stripped_sig = generate_signature("secret", Ec2SignatureVersion::V4, &req).unwrap();
        let normal_sig = generate_signature("secret", Ec2SignatureVersion::V4, &v4_req()).unwrap();
        assert_ne!(stripped_sig, normal_sig);
    }

    #[test]
    fn test_boto_legacy_ua_detection() {
        assert!(is_legacy_boto_user_agent("Boto/2.9.0 Python/2.7.5"));
        assert!(is_legacy_boto_user_agent("Boto/2.9.2"));
        assert!(!is_legacy_boto_user_agent("Boto/2.9.3"));
        assert!(!is_legacy_boto_user_agent("Boto/3.0.0"));
        assert!(!is_legacy_boto_user_agent("aws-sdk-go/1.0"));
    }

    // --- verify_signature (end-to-end + port stripping) -------------------

    #[test]
    fn test_verify_signature_success() {
        let mut req = base_req();
        req.host = "identity.example.com".into();
        req.params.insert("SignatureVersion".into(), "2".into());
        req.params
            .insert("Action".into(), "DescribeInstances".into());
        let expected =
            generate_signature("secret", detect_signature_version(&req).unwrap(), &req).unwrap();
        req.signature = Some(expected);
        assert!(verify_signature("secret", &req).is_ok());
    }

    #[test]
    fn test_verify_signature_missing() {
        let mut req = base_req();
        req.params.insert("SignatureVersion".into(), "2".into());
        req.signature = None;
        assert!(matches!(
            verify_signature("secret", &req),
            Err(AuthenticationError::Ec2SignatureMissing)
        ));
    }

    #[test]
    fn test_verify_signature_invalid() {
        let mut req = base_req();
        req.params.insert("SignatureVersion".into(), "2".into());
        req.signature = Some("bogus".into());
        assert!(matches!(
            verify_signature("secret", &req),
            Err(AuthenticationError::Ec2SignatureInvalid)
        ));
    }

    #[test]
    fn test_verify_signature_port_stripping_fallback() {
        // Sign against the bare hostname (as if the client's original
        // request never had a port), but the server-side `host` carries a
        // port (e.g. added by a proxy) — the retry must recover this.
        let mut signing_req = base_req();
        signing_req.host = "identity.example.com".into();
        signing_req
            .params
            .insert("SignatureVersion".into(), "2".into());
        signing_req
            .params
            .insert("Action".into(), "DescribeInstances".into());
        let expected = generate_signature(
            "secret",
            detect_signature_version(&signing_req).unwrap(),
            &signing_req,
        )
        .unwrap();

        let mut req = signing_req.clone();
        req.host = "identity.example.com:5000".into();
        req.signature = Some(expected);
        assert!(verify_signature("secret", &req).is_ok());
    }

    // --- timestamp validation ----------------------------------------------

    #[test]
    fn test_validate_timestamp_v2_within_ttl() {
        let mut req = base_req();
        req.params.insert("SignatureVersion".into(), "2".into());
        req.params
            .insert("Timestamp".into(), Utc::now().to_rfc3339());
        assert!(validate_timestamp(&req, 300).is_ok());
    }

    #[test]
    fn test_validate_timestamp_v2_expired() {
        let mut req = base_req();
        req.params.insert("SignatureVersion".into(), "2".into());
        req.params.insert(
            "Timestamp".into(),
            (Utc::now() - chrono::Duration::seconds(600)).to_rfc3339(),
        );
        assert!(matches!(
            validate_timestamp(&req, 300),
            Err(AuthenticationError::Ec2TimestampExpired)
        ));
    }

    #[test]
    fn test_validate_timestamp_v2_missing() {
        let mut req = base_req();
        req.params.insert("SignatureVersion".into(), "2".into());
        assert!(matches!(
            validate_timestamp(&req, 300),
            Err(AuthenticationError::Ec2TimestampMissing)
        ));
    }

    #[test]
    fn test_validate_timestamp_v4_within_ttl() {
        let mut req = v4_req();
        let now = Utc::now();
        req.headers.insert(
            "X-Amz-Date".into(),
            now.format("%Y%m%dT%H%M%SZ").to_string(),
        );
        // Keep the Authorization header's credential scope date consistent.
        req.headers.insert(
            "Authorization".into(),
            format!(
                "AWS4-HMAC-SHA256 Credential=AKID/{}/RegionOne/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=unused",
                now.format("%Y%m%d")
            ),
        );
        assert!(validate_timestamp(&req, 300).is_ok());
    }

    #[test]
    fn test_validate_timestamp_v4_expired() {
        let mut req = v4_req();
        req.headers
            .insert("X-Amz-Date".into(), "20200101T000000Z".into());
        req.headers.insert(
            "Authorization".into(),
            "AWS4-HMAC-SHA256 Credential=AKID/20200101/RegionOne/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=unused".into(),
        );
        assert!(matches!(
            validate_timestamp(&req, 300),
            Err(AuthenticationError::Ec2TimestampExpired)
        ));
    }

    #[test]
    fn test_uri_encode_default_keeps_slash() {
        assert_eq!(uri_encode_default("a/b c"), "a/b%20c");
    }

    #[test]
    fn test_uri_encode_strict_escapes_slash() {
        assert_eq!(uri_encode_strict("a/b c"), "a%2Fb%20c");
    }
}
