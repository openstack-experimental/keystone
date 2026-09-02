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
//! SCIM resource write rate limiter (ADR 0024 §11 `scim_realm_write_rate_
//! limit`).
//!
//! A second, independent tier from the per-`lookup_hash` authentication
//! limiter (ADR 0021 §6.A) that already covers every SCIM ingress request:
//! this one is checked inside each write handler (`POST`/`PUT`/`PATCH`/
//! `DELETE` on `/Users` or `/Groups`), keyed on the realm's `provider_id`,
//! to bound bulk provisioning bursts from a single compromised or
//! misconfigured realm specifically.
use governor::clock::Clock as _;

use openstack_keystone_core::api::KeystoneApiError;
use openstack_keystone_core::keystone::ServiceState;

/// Checks the SCIM write rate limiter for `provider_id`, returning
/// `429 Too Many Requests` if the bucket is exhausted.
pub(super) fn check_write_rate_limit(
    state: &ServiceState,
    provider_id: &str,
) -> Result<(), KeystoneApiError> {
    if let Err(not_until) = state
        .scim_realm_write_rate_limiter
        .check_key(&provider_id.to_string())
    {
        let retry_after = not_until
            .wait_time_from(state.scim_realm_write_rate_limiter.clock().now())
            .as_secs()
            .max(1);
        return Err(KeystoneApiError::TooManyRequests { retry_after });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::tests::get_mocked_state;
    use crate::provider::Provider;

    #[tokio::test]
    async fn test_check_write_rate_limit_allows_under_burst() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        assert!(check_write_rate_limit(&state, "provider-1").is_ok());
    }

    #[tokio::test]
    async fn test_check_write_rate_limit_rejects_once_exhausted() {
        let state = get_mocked_state(Provider::mocked_builder(), true, None).await;
        // Burn through the configured burst for this key; the mocked state
        // uses the default config (burst 50), so exhaust it deterministically
        // rather than assuming a specific count.
        let mut rejected = false;
        for _ in 0..1000 {
            if check_write_rate_limit(&state, "provider-1").is_err() {
                rejected = true;
                break;
            }
        }
        assert!(rejected, "rate limiter never rejected after 1000 calls");

        // A different `provider_id` is an independent bucket, unaffected.
        assert!(check_write_rate_limit(&state, "provider-2").is_ok());
    }
}
