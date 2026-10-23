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
//! HTTP-level DPoP rules shared by the `/token` endpoint and the resource
//! endpoints (RFC 9449, ADR 0043): reading the proof header, charging a
//! per-key throttle and classifying the refusals of the replay cache. Keeping
//! them in one place stops the two sides from drifting apart in what they
//! accept and how they report it.

use axum::http::HeaderMap;
use governor::{DefaultKeyedRateLimiter, clock::Clock as _};

use openstack_keystone_core::oauth2_client::dpop_replay::DpopReplayError;

/// Name of the proof header.
const DPOP_HEADER: &str = "dpop";

/// Why the `DPoP` header of a request cannot be used.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum HeaderRefusal {
    /// More than one `DPoP` header.
    Multiple,
    /// The value is not text.
    NotText,
}

impl HeaderRefusal {
    /// Description for the error response.
    pub(super) fn description(&self) -> &'static str {
        match self {
            Self::Multiple => "exactly one DPoP header is allowed",
            Self::NotText => "the DPoP header is not valid text",
        }
    }
}

/// The proof of a request: `None` when there is no `DPoP` header, an error
/// when there is more than one or the value is not text.
pub(super) fn proof_header(headers: &HeaderMap) -> Result<Option<&str>, HeaderRefusal> {
    let mut proofs = headers.get_all(DPOP_HEADER).iter();
    let Some(proof) = proofs.next() else {
        return Ok(None);
    };
    if proofs.next().is_some() {
        return Err(HeaderRefusal::Multiple);
    }
    proof.to_str().map(Some).map_err(|_| HeaderRefusal::NotText)
}

/// Charge `key`, the verified thumbprint of a proof key, against `limiter`.
/// On refusal the number of seconds to wait is returned.
pub(super) fn charge_key(limiter: &DefaultKeyedRateLimiter<String>, key: &str) -> Result<(), u64> {
    limiter.check_key(&key.to_string()).map_err(|not_until| {
        not_until
            .wait_time_from(limiter.clock().now())
            .as_secs()
            .max(1)
    })
}

/// Seconds to wait before retrying when the replay cache refused a proof
/// for lack of room, `None` when the proof was a replay.
///
/// A replay is the client's fault. A full cache or an exhausted per-key
/// share is not: it clears once the entries age out, which takes at most one
/// proof lifetime, so the caller is told to retry after that instead of
/// being sent a final-looking `invalid_dpop_proof`.
pub(super) fn replay_retry_after(error: &DpopReplayError, proof_lifetime_secs: u64) -> Option<u64> {
    match error {
        DpopReplayError::Replayed => None,
        DpopReplayError::CacheFull | DpopReplayError::KeyQuotaExceeded => {
            tracing::warn!(%error, "DPoP replay cache refused a proof");
            Some(proof_lifetime_secs.max(1))
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use governor::{Quota, RateLimiter};

    use super::*;

    #[test]
    fn test_proof_header() {
        let mut headers = HeaderMap::new();
        assert_eq!(proof_header(&headers), Ok(None));
        headers.append("dpop", HeaderValue::from_static("a.b.c"));
        assert_eq!(proof_header(&headers), Ok(Some("a.b.c")));
        headers.append("DPoP", HeaderValue::from_static("d.e.f"));
        assert_eq!(proof_header(&headers), Err(HeaderRefusal::Multiple));
    }

    #[test]
    fn test_proof_header_must_be_text() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "dpop",
            HeaderValue::from_bytes(&[0xff, 0xfe]).expect("opaque bytes are a valid value"),
        );
        assert_eq!(proof_header(&headers), Err(HeaderRefusal::NotText));
    }

    #[test]
    fn test_replay_is_no_retry_but_exhaustion_is() {
        assert_eq!(replay_retry_after(&DpopReplayError::Replayed, 60), None);
        for exhausted in [
            DpopReplayError::CacheFull,
            DpopReplayError::KeyQuotaExceeded,
        ] {
            assert_eq!(replay_retry_after(&exhausted, 60), Some(60));
        }
        assert_eq!(replay_retry_after(&DpopReplayError::CacheFull, 0), Some(1));
    }

    #[test]
    fn test_charge_key_is_per_key_and_reports_a_wait() {
        let limiter: DefaultKeyedRateLimiter<String> =
            RateLimiter::keyed(Quota::per_minute(std::num::NonZeroU32::MIN));
        assert_eq!(charge_key(&limiter, "k1"), Ok(()));
        assert!(matches!(charge_key(&limiter, "k1"), Err(wait) if wait >= 1));
        // Another key has a bucket of its own.
        assert_eq!(charge_key(&limiter, "k2"), Ok(()));
    }
}
