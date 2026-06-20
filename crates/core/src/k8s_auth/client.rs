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
//! # Kubernetes HTTP client abstraction.

use async_trait::async_trait;
use serde_json::Value;

use crate::k8s_auth::K8sAuthProviderError;
use openstack_keystone_core_types::k8s_auth::K8sAuthInstance;

/// Abstraction for HTTP communication with the Kubernetes API.
///
/// The implementation handles JWT decoding, audience/expiration validation,
/// and the TokenReview HTTP call.
#[async_trait]
pub trait K8sHttpClient: Send + Sync {
    /// Decode JWT, validate audience and expiration, then query the K8s
    /// TokenReview endpoint.
    ///
    /// # Arguments
    /// * `instance` - K8s auth instance configuration (host, CA cert, etc).
    /// * `jwt` - The JWT service account token.
    /// * `bound_audience` - Optional audience to validate against.
    ///
    /// # Returns
    /// * `Ok(Value)` with the TokenReview response.
    /// * `K8sAuthProviderError` on JWT decode, validation, or HTTP failure.
    async fn query_token_review(
        &self,
        instance: &K8sAuthInstance,
        jwt: &str,
        bound_audience: Option<&str>,
    ) -> Result<Value, K8sAuthProviderError>;
}
