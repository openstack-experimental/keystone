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
//! # Nova ownership verification (SPIRE integration plan, Phase 2, Fix 1)
//!
//! Before `POST /v4/vendordata` signs an attestation JWT, it must confirm
//! the calling compute host actually owns the instance/project it claims
//! -- otherwise any compute host's shared-per-host SVID could request a
//! signed attestation for an instance it doesn't run. `crates/core` has no
//! `reqwest` dependency (deliberately, so it stays free of any one HTTP
//! client implementation -- see `crates/core/src/auth_plugin_http.rs`),
//! so this module only defines the trait; the `reqwest`-backed
//! implementation lives in `crates/keystone/src/nova_client_impl.rs`,
//! mirroring the existing [`crate::k8s_auth::K8sHttpClient`] /
//! `KeystoneK8sHttpClient` split.
use async_trait::async_trait;

use openstack_keystone_core_types::vendordata::VendordataProviderError;

use crate::keystone::ServiceState;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockNovaClientProvider;

/// The fields of a Nova server record this check needs. Deliberately not
/// the full Nova API response shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NovaServerRecord {
    /// `server.tenant_id`.
    pub tenant_id: String,
    /// `server.OS-EXT-SRV-ATTR:hypervisor_hostname`, gated behind
    /// `os-extended-server-attributes` (admin-only).
    pub hypervisor_hostname: Option<String>,
}

/// Raw HTTP transport to the Nova API. Implemented with `reqwest` in
/// `crates/keystone/src/nova_client_impl.rs`.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait NovaHttpClient: Send + Sync {
    /// Fetch the server record for `instance_id` from Nova, using
    /// keystone-rs's own admin/system-scoped service credentials.
    async fn get_server(
        &self,
        instance_id: &str,
    ) -> Result<NovaServerRecord, VendordataProviderError>;
}

/// Provider-level API consulted by the `POST /v4/vendordata` handler.
/// Mocked centrally in [`crate::mocks`] as `MockNovaClientProvider`,
/// matching every other top-level provider trait in this crate.
#[async_trait]
pub trait NovaClientApi: Send + Sync {
    /// Returns `Ok(true)` when Nova confirms `instance_id` belongs to
    /// `project_id` and runs on `host`; `Ok(false)` on an explicit
    /// mismatch (handler maps this to `403`); `Err` when the check itself
    /// could not be completed (handler fails closed with `503`).
    async fn verify_ownership(
        &self,
        state: &ServiceState,
        project_id: &str,
        instance_id: &str,
        host: &str,
    ) -> Result<bool, VendordataProviderError>;
}

/// Default [`NovaClientApi`] implementation: delegates the actual HTTP
/// call to an injected [`NovaHttpClient`], then compares the returned
/// record against the caller's claims.
pub struct NovaClientService {
    http_client: std::sync::Arc<dyn NovaHttpClient>,
}

impl NovaClientService {
    /// Create a new `NovaClientService` wrapping `http_client`.
    pub fn new(http_client: std::sync::Arc<dyn NovaHttpClient>) -> Self {
        Self { http_client }
    }
}

#[async_trait]
impl NovaClientApi for NovaClientService {
    async fn verify_ownership(
        &self,
        _state: &ServiceState,
        project_id: &str,
        instance_id: &str,
        host: &str,
    ) -> Result<bool, VendordataProviderError> {
        let record = self.http_client.get_server(instance_id).await?;
        Ok(record.tenant_id == project_id && record.hypervisor_hostname.as_deref() == Some(host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_verify_ownership_matches_project_and_host() {
        let mut mock = MockNovaHttpClient::new();
        mock.expect_get_server().returning(|_| {
            Ok(NovaServerRecord {
                tenant_id: "project-1".into(),
                hypervisor_hostname: Some("compute-1".into()),
            })
        });
        let service = NovaClientService::new(std::sync::Arc::new(mock));
        let state = crate::tests::get_mocked_state(None, None).await;

        let result = service
            .verify_ownership(&state, "project-1", "instance-1", "compute-1")
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_verify_ownership_rejects_host_mismatch() {
        let mut mock = MockNovaHttpClient::new();
        mock.expect_get_server().returning(|_| {
            Ok(NovaServerRecord {
                tenant_id: "project-1".into(),
                hypervisor_hostname: Some("compute-2".into()),
            })
        });
        let service = NovaClientService::new(std::sync::Arc::new(mock));
        let state = crate::tests::get_mocked_state(None, None).await;

        let result = service
            .verify_ownership(&state, "project-1", "instance-1", "compute-1")
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_verify_ownership_rejects_project_mismatch() {
        let mut mock = MockNovaHttpClient::new();
        mock.expect_get_server().returning(|_| {
            Ok(NovaServerRecord {
                tenant_id: "other-project".into(),
                hypervisor_hostname: Some("compute-1".into()),
            })
        });
        let service = NovaClientService::new(std::sync::Arc::new(mock));
        let state = crate::tests::get_mocked_state(None, None).await;

        let result = service
            .verify_ownership(&state, "project-1", "instance-1", "compute-1")
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_verify_ownership_propagates_nova_unavailable() {
        let mut mock = MockNovaHttpClient::new();
        mock.expect_get_server()
            .returning(|_| Err(VendordataProviderError::NovaUnavailable("timeout".into())));
        let service = NovaClientService::new(std::sync::Arc::new(mock));
        let state = crate::tests::get_mocked_state(None, None).await;

        let result = service
            .verify_ownership(&state, "project-1", "instance-1", "compute-1")
            .await;
        assert!(matches!(
            result,
            Err(VendordataProviderError::NovaUnavailable(_))
        ));
    }
}
