use async_trait::async_trait;
use serde_json::Value;

use crate::k8s_auth::K8sAuthProviderError;
use openstack_keystone_core_types::k8s_auth::K8sAuthInstance;

/// Abstraction for HTTP communication with the Kubernetes API.
///
/// The implementation handles JWT decoding, expiration validation,
/// and the TokenReview HTTP call.
#[async_trait]
pub trait K8sHttpClient: Send + Sync {
    /// Decode JWT, validate expiration, then query the K8s TokenReview
    /// endpoint.
    ///
    /// # Arguments
    /// * `instance` - K8s auth instance configuration (host, CA cert, etc).
    /// * `jwt` - The JWT service account token.
    ///
    /// # Returns
    /// * `Ok(Value)` with the TokenReview response.
    /// * `K8sAuthProviderError` on JWT decode, validation, or HTTP failure.
    async fn query_token_review(
        &self,
        instance: &K8sAuthInstance,
        jwt: &str,
    ) -> Result<Value, K8sAuthProviderError>;
}
