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
//! EC2 (AWS Signature Version 2) signing and `POST /v3/ec2tokens` helpers.
//!
//! The signer here is a deliberately **independent** implementation of the
//! AWS SigV2 query-signing algorithm, written from the public AWS
//! specification and validated against the published AWS documentation
//! golden vector (see the unit test below) — it does NOT reuse the
//! server's `openstack_keystone_core::credential::ec2_signature`, so a
//! canonicalization defect on the server cannot be masked by sharing the
//! same code on both sides of the wire.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use eyre::Result;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::{Response, StatusCode};
use sha2::Sha256;

use crate::common::raw_request;

/// Percent-encode per RFC 3986 with the AWS unreserved set
/// (`A-Za-z0-9`, `-`, `_`, `.`, `~`), uppercase hex digits.
fn aws_uri_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// AWS Signature Version 2 with `SignatureMethod=HmacSHA256`:
///
/// ```text
/// StringToSign = VERB + "\n" + Host + "\n" + Path + "\n" + CanonicalQuery
/// CanonicalQuery = join("&", sorted("<enc(k)>=<enc(v)>" by byte order))
/// Signature = base64(HMAC-SHA256(secret, StringToSign))
/// ```
pub fn sign_v2_hmac_sha256(
    secret: &str,
    verb: &str,
    host: &str,
    path: &str,
    params: &HashMap<String, String>,
) -> Result<String> {
    let mut pairs: Vec<(&String, &String)> = params.iter().collect();
    pairs.sort();
    let canonical_query = pairs
        .into_iter()
        .map(|(key, value)| format!("{}={}", aws_uri_encode(key), aws_uri_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let string_to_sign = format!("{verb}\n{host}\n{path}\n{canonical_query}");

    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
        .map_err(|e| eyre::eyre!("HMAC key error: {e}"))?;
    mac.update(string_to_sign.as_bytes());
    Ok(BASE64.encode(mac.finalize().into_bytes()))
}

/// Build a signed `POST /v3/ec2tokens` request body for the given EC2
/// credential. `timestamp` defaults to now (RFC 3339); pass an old value
/// to exercise the stale-timestamp rejection. `signature_override`
/// replaces the correctly computed signature to exercise the
/// bad-signature rejection.
pub fn ec2_token_request_body(
    access: &str,
    secret: &str,
    timestamp: Option<String>,
    signature_override: Option<&str>,
) -> Result<serde_json::Value> {
    let host = "identity.example.com";
    let verb = "GET";
    let path = "/";
    let mut params = HashMap::from([
        ("SignatureVersion".to_string(), "2".to_string()),
        ("SignatureMethod".to_string(), "HmacSHA256".to_string()),
        (
            "Timestamp".to_string(),
            timestamp.unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
        ),
    ]);
    params.insert("AWSAccessKeyId".to_string(), access.to_string());

    let signature = match signature_override {
        Some(sig) => sig.to_string(),
        None => sign_v2_hmac_sha256(secret, verb, host, path, &params)?,
    };

    Ok(serde_json::json!({
        "credentials": {
            "access": access,
            "signature": signature,
            "host": host,
            "verb": verb,
            "path": path,
            "params": params,
        }
    }))
}

/// POST the signed body to `/v3/ec2tokens` with the given caller token
/// (`None` = unauthenticated). Returns the raw response.
pub async fn post_ec2_token(
    caller_token: Option<&str>,
    body: serde_json::Value,
) -> Result<Response> {
    raw_request(http::Method::POST, "v3/ec2tokens", caller_token, Some(body)).await
}

/// POST to `/v3/ec2tokens` and extract `(status, subject_token, body)`.
pub async fn post_ec2_token_extract(
    caller_token: Option<&str>,
    body: serde_json::Value,
) -> Result<(StatusCode, Option<String>, serde_json::Value)> {
    let rsp = post_ec2_token(caller_token, body).await?;
    let status = rsp.status();
    let subject_token = rsp
        .headers()
        .get("X-Subject-Token")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = rsp.json().await.unwrap_or(serde_json::Value::Null);
    Ok((status, subject_token, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published AWS "Signature Version 2 signing process" golden
    /// vector (the `DescribeJobFlows` example from the AWS General
    /// Reference): a known secret, host, and parameter set with the
    /// documented expected signature. An independent SigV2 implementation
    /// must reproduce it exactly.
    #[test]
    fn aws_documentation_golden_vector() -> Result<()> {
        let params = HashMap::from([
            (
                "AWSAccessKeyId".to_string(),
                "AKIAIOSFODNN7EXAMPLE".to_string(),
            ),
            ("Action".to_string(), "DescribeJobFlows".to_string()),
            ("SignatureMethod".to_string(), "HmacSHA256".to_string()),
            ("SignatureVersion".to_string(), "2".to_string()),
            ("Timestamp".to_string(), "2011-10-03T15:19:30".to_string()),
            ("Version".to_string(), "2009-03-31".to_string()),
        ]);
        let signature = sign_v2_hmac_sha256(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "GET",
            "elasticmapreduce.amazonaws.com",
            "/",
            &params,
        )?;
        assert_eq!(signature, "i91nKc4PWAt0JJIdXwz9HxZCJDdiy6cf/Mj6vPxyYIs=");
        Ok(())
    }

    #[test]
    fn uri_encoding_matches_aws_rules() {
        assert_eq!(
            aws_uri_encode("2011-10-03T15:19:30"),
            "2011-10-03T15%3A19%3A30"
        );
        assert_eq!(aws_uri_encode("a b/c~d_e.f-g"), "a%20b%2Fc~d_e.f-g");
    }
}
