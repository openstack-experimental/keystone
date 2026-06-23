use async_trait::async_trait;

use crate::k8s_auth::K8sAuthProviderError;
use openstack_keystone_core_types::k8s_auth::{K8sAuthInstance, QueryTokenReviewResult};

/// Abstraction for HTTP communication with the Kubernetes API.
///
/// The implementation handles JWT decoding, expiration validation,
/// and the TokenReview HTTP call.
#[async_trait]
pub trait K8sHttpClient: Send + Sync {
    /// Decode JWT, validate expiration, then query the K8s TokenReview
    /// endpoint.
    ///
    /// Returns a [`QueryTokenReviewResult`] containing the TokenReview
    /// response alongside the decoded JWT claims (`aud`, `exp`, `sub`)
    /// so the caller can propagate `aud` into the flattened claims map
    /// for the mapping engine.
    ///
    /// # Arguments
    /// * `instance` - K8s auth instance configuration (host, CA cert, etc).
    /// * `jwt` - The JWT service account token.
    ///
    /// # Returns
    /// * `Ok(QueryTokenReviewResult)` on success.
    /// * `K8sAuthProviderError` on JWT decode, validation, or HTTP failure.
    async fn query_token_review(
        &self,
        instance: &K8sAuthInstance,
        jwt: &str,
    ) -> Result<QueryTokenReviewResult, K8sAuthProviderError>;
}
