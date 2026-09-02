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
//! # Nova HTTP client implementation (SPIRE integration plan, Phase 2, Fix 1)
//!
//! `reqwest`-backed implementation of
//! [`openstack_keystone_core::nova_client::NovaHttpClient`], mirroring the
//! existing `crates/keystone/src/k8s_auth_client.rs` split (trait in
//! `crates/core`, which stays free of any HTTP client dependency; the
//! concrete implementation lives here in the `keystone` binary crate).

use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};

use openstack_keystone_core::nova_client::{NovaHttpClient, NovaServerRecord};
use openstack_keystone_core_types::vendordata::VendordataProviderError;

/// Production implementation of [`NovaHttpClient`] using `reqwest`.
///
/// A single shared client with a tight timeout and bounded connection pool
/// (default 2s / 10 max idle per host / 30s idle timeout) -- see the plan's
/// "Auth deadlock prevention": keystone-rs calling Nova, which may itself
/// call back into keystone-rs via keystonemiddleware, must never let a
/// burst of concurrent boot requests grow this pool unboundedly.
pub struct KeystoneNovaHttpClient {
    client: Client,
    base_url: Option<String>,
}

impl KeystoneNovaHttpClient {
    /// Build a new client. `base_url` is `None` when `[vendordata]` was not
    /// configured with a Nova endpoint -- `get_server` then fails closed
    /// with [`VendordataProviderError::NovaUnavailable`] rather than the
    /// constructor itself being fallible on missing config.
    pub fn new(
        base_url: Option<String>,
        request_timeout: Duration,
    ) -> Result<Self, VendordataProviderError> {
        let client = Client::builder()
            .timeout(request_timeout)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| VendordataProviderError::NovaUnavailable(e.to_string()))?;
        Ok(Self { client, base_url })
    }
}

#[async_trait]
impl NovaHttpClient for KeystoneNovaHttpClient {
    async fn get_server(
        &self,
        instance_id: &str,
        admin_token: &SecretString,
    ) -> Result<NovaServerRecord, VendordataProviderError> {
        let base_url = self.base_url.as_ref().ok_or_else(|| {
            VendordataProviderError::NovaUnavailable(
                "[vendordata] nova_api_base_url is not configured".to_string(),
            )
        })?;

        let url = format!("{}/servers/{instance_id}", base_url.trim_end_matches('/'));
        let response = self
            .client
            .get(&url)
            .header("X-Auth-Token", admin_token.expose_secret())
            .send()
            .await
            .map_err(|e| VendordataProviderError::NovaUnavailable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(VendordataProviderError::NovaUnavailable(format!(
                "nova returned HTTP {}",
                response.status()
            )));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| VendordataProviderError::NovaUnavailable(e.to_string()))?;

        let tenant_id = body["server"]["tenant_id"]
            .as_str()
            .ok_or_else(|| {
                VendordataProviderError::NovaUnavailable(
                    "nova server response missing tenant_id".to_string(),
                )
            })?
            .to_string();
        let hypervisor_hostname = body["server"]["OS-EXT-SRV-ATTR:hypervisor_hostname"]
            .as_str()
            .map(str::to_string);

        Ok(NovaServerRecord {
            tenant_id,
            hypervisor_hostname,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_builds_client_without_config() {
        let client = KeystoneNovaHttpClient::new(None, Duration::from_secs(2)).unwrap();
        assert!(client.base_url.is_none());
    }

    #[tokio::test]
    async fn test_get_server_fails_closed_without_base_url() {
        let client = KeystoneNovaHttpClient::new(None, Duration::from_secs(2)).unwrap();
        let token = SecretString::from("token".to_string());
        let result = client.get_server("instance-1", &token).await;
        assert!(matches!(
            result,
            Err(VendordataProviderError::NovaUnavailable(_))
        ));
    }
}
