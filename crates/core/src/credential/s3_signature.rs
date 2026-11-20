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
// Crypto inventory: EC2-1; see doc/src/contributor/crypto-inventory.md
//! S3 string-to-sign signature verification (ADR 0019 §5).
//!
//! Re-implementation of Python Keystone's `s3tokens` verification
//! (`EC2_S3_Resource._check_signature`): the S3 gateway sends the already
//! built string-to-sign (urlsafe base64) together with the client signature.
//!
//! * v1 (SigV2 style): `base64(HMAC-SHA1(secret, string_to_sign))`.
//! * SigV4 (`AWS4-HMAC-SHA256`): hex HMAC-SHA256 with the derived signing key.

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use subtle::ConstantTimeEq;

use openstack_keystone_core_types::auth::AuthenticationError;

use super::ec2_signature::{hmac_sha1_raw, hmac_sha256_raw, to_hex};

const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";
const SIGV4_SERVICES: [&str; 3] = ["s3", "iam", "sts"];

/// Decode the base64 `token` field into the string-to-sign.
///
/// The urlsafe alphabet is expected, but the standard alphabet (`+`, `/`) is
/// accepted as well, like Python's `base64.urlsafe_b64decode`.
pub fn decode_string_to_sign(token: &str) -> Result<String, AuthenticationError> {
    let token = token.trim_end_matches('=');
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .or_else(|_| STANDARD_NO_PAD.decode(token))
        .map_err(|_| AuthenticationError::Ec2SignatureInvalid)?;
    String::from_utf8(raw).map_err(|_| AuthenticationError::Ec2SignatureInvalid)
}

/// Compute the signature expected for `string_to_sign`.
pub fn generate_signature(
    secret: &str,
    string_to_sign: &str,
) -> Result<String, AuthenticationError> {
    if !string_to_sign.starts_with("AWS4") {
        return Ok(BASE64.encode(hmac_sha1_raw(secret.as_bytes(), string_to_sign.as_bytes())));
    }
    let lines: Vec<&str> = string_to_sign.split('\n').collect();
    if lines.len() != 4 || lines[0] != SIGV4_ALGORITHM {
        return Err(AuthenticationError::Ec2SignatureInvalid);
    }
    let scope: Vec<&str> = lines[2].split('/').collect();
    if scope.len() != 4 || scope[3] != "aws4_request" || !SIGV4_SERVICES.contains(&scope[2]) {
        return Err(AuthenticationError::Ec2SignatureInvalid);
    }
    let mut key = hmac_sha256_raw(format!("AWS4{secret}").as_bytes(), scope[0])?;
    for part in &scope[1..] {
        key = hmac_sha256_raw(&key, part)?;
    }
    Ok(to_hex(&hmac_sha256_raw(&key, string_to_sign)?))
}

/// Verify `client_signature` over `string_to_sign` in constant time.
pub fn verify_signature(
    secret: &str,
    string_to_sign: &str,
    client_signature: &str,
) -> Result<(), AuthenticationError> {
    let expected = generate_signature(secret, string_to_sign)?;
    if bool::from(client_signature.as_bytes().ct_eq(expected.as_bytes())) {
        Ok(())
    } else {
        Err(AuthenticationError::Ec2SignatureInvalid)
    }
}

fn parse_date(raw: &str) -> Result<DateTime<Utc>, AuthenticationError> {
    let raw = raw.trim();
    if let Ok(naive) = NaiveDateTime::parse_from_str(raw, "%Y%m%dT%H%M%SZ") {
        return Ok(Utc.from_utc_datetime(&naive));
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = DateTime::parse_from_rfc2822(raw) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(secs) = raw.parse::<i64>()
        && let Some(dt) = DateTime::from_timestamp(secs, 0)
    {
        return Ok(dt);
    }
    Err(AuthenticationError::Ec2TimestampInvalid(
        "unrecognized date format".to_string(),
    ))
}

/// Extract the request timestamp from the (signature-verified)
/// string-to-sign.
///
/// SigV4: line 1. SigV2: line 3 (`Date`, or the epoch `Expires` for query
/// auth); with an empty line 3 the `x-amz-date:` header line is used.
pub fn extract_timestamp(string_to_sign: &str) -> Result<DateTime<Utc>, AuthenticationError> {
    let lines: Vec<&str> = string_to_sign.split('\n').collect();
    let raw = if string_to_sign.starts_with("AWS4") {
        lines.get(1).copied()
    } else {
        match lines.get(3).copied().filter(|l| !l.trim().is_empty()) {
            Some(l) => Some(l),
            None => lines.iter().find_map(|l| {
                l.get(..11)
                    .filter(|p| p.eq_ignore_ascii_case("x-amz-date:"))
                    .map(|_| &l[11..])
            }),
        }
    };
    parse_date(raw.ok_or(AuthenticationError::Ec2TimestampMissing)?)
}

/// Replay-window check against `[credential] auth_ttl` (passed in seconds).
///
/// Same window as Python Keystone applies to `/v3/s3tokens`. Presigned
/// requests carry the original signing time, so they are only accepted
/// within this window; the per-request `X-Amz-Expires` is enforced by the S3
/// gateway.
pub fn validate_timestamp(
    string_to_sign: &str,
    ttl_seconds: i64,
) -> Result<(), AuthenticationError> {
    let ts = extract_timestamp(string_to_sign)?;
    if (Utc::now() - ts).num_seconds().abs() > ttl_seconds {
        return Err(AuthenticationError::Ec2TimestampExpired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sigv4_sts(date: &str, scope: &str) -> String {
        format!("AWS4-HMAC-SHA256\n{date}\n{scope}\nabcdef")
    }

    #[test]
    fn test_v1_roundtrip() {
        let sts = "GET\n\n\n1700000000\n/bucket/key";
        let sig = generate_signature("secret", sts).unwrap();
        assert!(verify_signature("secret", sts, &sig).is_ok());
        assert!(verify_signature("other", sts, &sig).is_err());
    }

    #[test]
    fn test_v4_roundtrip_and_known_vector() {
        let sts = sigv4_sts("20260101T000000Z", "20260101/us-east-1/s3/aws4_request");
        let sig = generate_signature("secret", &sts).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(verify_signature("secret", &sts, &sig).is_ok());
        assert!(verify_signature("secret", &sts, "deadbeef").is_err());
    }

    /// Published AWS SigV4 example (IAM `ListUsers`, 2015-08-30).
    #[test]
    fn test_v4_aws_known_vector() {
        let sts = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\n\
                   f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";
        assert_eq!(
            generate_signature("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", sts).unwrap(),
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn test_v4_bad_layout() {
        for sts in [
            "AWS4-HMAC-SHA256\n20260101T000000Z\nscope".to_string(),
            "AWS4-HMAC-SHA512\nd\n20260101/r/s3/aws4_request\nx".to_string(),
            sigv4_sts("d", "20260101/us-east-1/s3"),
            sigv4_sts("d", "20260101/us-east-1/s3/aws5_request"),
            sigv4_sts("d", "20260101/us-east-1/ec2/aws4_request"),
        ] {
            assert!(generate_signature("s", &sts).is_err(), "{sts}");
        }
    }

    #[test]
    fn test_decode() {
        assert_eq!(decode_string_to_sign("YT9i").unwrap(), "a?b");
        assert_eq!(decode_string_to_sign("YQ==").unwrap(), "a");
        // standard alphabet
        assert_eq!(decode_string_to_sign("YT8/").unwrap(), "a??");
        assert_eq!(decode_string_to_sign("Pj4+").unwrap(), ">>>");
        assert!(decode_string_to_sign("!!!").is_err());
    }

    #[test]
    fn test_extract_timestamp() {
        let sts = sigv4_sts("20260101T000000Z", "20260101/r/s3/aws4_request");
        assert_eq!(extract_timestamp(&sts).unwrap().timestamp(), 1767225600);
        let v2 = "GET\n\n\n1700000000\n/b";
        assert_eq!(extract_timestamp(v2).unwrap().timestamp(), 1700000000);
        let v2_hdr = "GET\n\n\n\nx-amz-date:20260101T000000Z\n/b";
        assert_eq!(extract_timestamp(v2_hdr).unwrap().timestamp(), 1767225600);
        assert!(matches!(
            extract_timestamp("GET\n\n\n\n/b"),
            Err(AuthenticationError::Ec2TimestampMissing)
        ));
        assert!(matches!(
            extract_timestamp("GET\n\n\nnot-a-date\n/b"),
            Err(AuthenticationError::Ec2TimestampInvalid(_))
        ));
    }

    #[test]
    fn test_validate_timestamp_window() {
        let now = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let ok = sigv4_sts(&now, "20260101/r/s3/aws4_request");
        assert!(validate_timestamp(&ok, 300).is_ok());
        let stale = sigv4_sts("20200101T000000Z", "20200101/r/s3/aws4_request");
        assert!(matches!(
            validate_timestamp(&stale, 300),
            Err(AuthenticationError::Ec2TimestampExpired)
        ));
    }
}
