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
//! # Kubernetes authentication.

use std::collections::HashMap;

use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;

use openstack_keystone_core_types::auth::AuthenticationResult;
use openstack_keystone_core_types::k8s_auth::{K8sAuthInstance, K8sAuthRequest};
use openstack_keystone_core_types::mapping::auth::MappingAuthRequest;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;

use super::K8sAuthApi;
use crate::k8s_auth::{K8sAuthProviderError, service::K8sAuthService};
use crate::keystone::ServiceState;

impl K8sAuthService {
    /// Query the K8s Token Review endpoint.
    ///
    /// JWT decoding and validation is delegated to the [`K8sHttpClient`]
    /// implementation.
    ///
    /// # Arguments
    /// * `token` - [`SecretString`] with the JWT token.
    /// * `instance` - reference to the [`K8sAuthInstance`].
    ///
    /// # Returns
    /// * Success with the TokenReview response as `Value`.
    /// * `K8sAuthProviderError` if the token is invalid.
    pub(super) async fn query_k8s_token_review(
        &self,
        token: &SecretString,
        instance: &K8sAuthInstance,
    ) -> Result<Value, K8sAuthProviderError> {
        let token_review_json = self
            .http_client
            .query_token_review(instance, token.expose_secret(), None)
            .await?;

        Ok(token_review_json)
    }

    /// Validate K8s Token Review response and extract service account info.
    ///
    /// Returns `(namespace, service_account_name)` parsed from the username.
    ///
    /// # Arguments
    /// * `token_review_data` - JSON representation of the TokenReview response.
    ///
    /// # Returns
    /// * Success with `(namespace, service_account_name)`.
    /// * `K8sAuthProviderError` when the token was not authenticated or the
    ///   username format is invalid.
    pub(super) fn extract_k8s_service_account(
        &self,
        token_review_data: &Value,
    ) -> Result<(String, String), K8sAuthProviderError> {
        if !token_review_data["status"]["authenticated"]
            .as_bool()
            .unwrap_or(false)
        {
            return Err(K8sAuthProviderError::InvalidToken);
        }

        let username = token_review_data["status"]["user"]["username"]
            .as_str()
            .ok_or(K8sAuthProviderError::InvalidTokenReviewResponse)?;

        let parts: Vec<&str> = username.split(':').collect();

        match parts.as_slice() {
            ["system", "serviceaccount", ns, sa] => Ok((ns.to_string(), sa.to_string())),
            _ => Err(K8sAuthProviderError::InvalidTokenReviewResponse),
        }
    }

    /// Flatten TokenReview response into a claims map for the mapping engine.
    ///
    /// Per ADR-0020 §11.2, produces claims with keys:
    /// - `k8s.serviceaccount.name`
    /// - `k8s.serviceaccount.namespace`
    /// - `k8s.aud` (from `sub` claim of the service account token).
    ///
    /// # Arguments
    /// * `token_review_data` - TokenReview JSON response.
    ///
    /// # Returns
    /// A flattened claims map.
    pub(super) fn flatten_k8s_claims(
        &self,
        token_review_data: &Value,
    ) -> Result<HashMap<String, Vec<String>>, K8sAuthProviderError> {
        let (namespace, sa_name) = self.extract_k8s_service_account(token_review_data)?;

        let mut claims = HashMap::new();
        claims.insert("k8s.serviceaccount.name".to_string(), vec![sa_name.clone()]);
        claims.insert(
            "k8s.serviceaccount.namespace".to_string(),
            vec![namespace.clone()],
        );

        Ok(claims)
    }

    /// Authenticate via K8s TokenReview + mapping engine.
    ///
    /// Validates the JWT through the K8s TokenReview API, flattens the
    /// response into claims, and delegates to the unified mapping engine
    /// for identity resolution and shadow registry upsert.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `req` - A reference to the [`K8sAuthRequest`].
    ///
    /// # Returns
    /// * Success with [`AuthenticationResult`] via mapping engine.
    /// * `K8sAuthProviderError` if authentication fails.
    pub(super) async fn authenticate_by_mapping(
        &self,
        state: &ServiceState,
        req: &K8sAuthRequest,
    ) -> Result<AuthenticationResult, K8sAuthProviderError> {
        // Fetch k8s auth instance.
        let instance = self
            .get_auth_instance(state, &req.auth_instance_id)
            .await?
            .ok_or(K8sAuthProviderError::AuthInstanceNotFound(
                req.auth_instance_id.clone(),
            ))?;
        if !instance.enabled {
            return Err(K8sAuthProviderError::AuthInstanceNotActive(
                req.auth_instance_id.clone(),
            ));
        }

        // Call the TokenReview.
        let token_review_data = self.query_k8s_token_review(&req.jwt, &instance).await?;

        // Flatten TokenReview response into claims.
        let claims = self.flatten_k8s_claims(&token_review_data)?;

        // Derive unique workload ID from claims: "<sa>:<ns>" per ADR-0020 §11.2.
        let sa_name = &claims["k8s.serviceaccount.name"][0];
        let namespace = &claims["k8s.serviceaccount.namespace"][0];
        let unique_workload_id = format!("{sa_name}:{namespace}");

        // Delegate to the unified mapping engine.
        let mapping_req = MappingAuthRequest {
            domain_id: Some(instance.domain_id.clone()),
            source: IdentitySource::K8s {
                cluster_id: instance.id.clone(),
            },
            unique_workload_id,
            claims,
            rule_name: req.rule_name.clone(),
        };

        let auth_result = state
            .provider
            .get_mapping_provider()
            .authenticate_by_mapping(state, &mapping_req)
            .await
            .map_err(|e| K8sAuthProviderError::MappingEngine(e.to_string()))?;

        Ok(auth_result)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use serde_json::json;

    use super::*;
    use crate::k8s_auth::K8sHttpClient;
    use crate::k8s_auth::backend::MockK8sAuthBackend;
    use crate::tests::get_mocked_state;

    struct TestK8sHttpClient;

    #[async_trait]
    impl K8sHttpClient for TestK8sHttpClient {
        async fn query_token_review(
            &self,
            _instance: &K8sAuthInstance,
            _jwt: &str,
            _bound_audience: Option<&str>,
        ) -> Result<serde_json::Value, K8sAuthProviderError> {
            Ok(json!({}))
        }
    }

    fn make_service(backend: MockK8sAuthBackend) -> K8sAuthService {
        K8sAuthService {
            backend_driver: Arc::new(backend),
            http_client: Arc::new(TestK8sHttpClient),
        }
    }

    #[test]
    fn test_extract_k8s_service_account_not_authenticated() {
        let provider = make_service(MockK8sAuthBackend::default());

        if let Err(K8sAuthProviderError::InvalidToken) =
            provider.extract_k8s_service_account(&json!({"status": {"authenticated": false}}))
        {
        } else {
            panic!("not authenticated token should result in InvalidToken");
        }
    }

    #[test]
    fn test_extract_k8s_service_account_no_user() {
        let provider = make_service(MockK8sAuthBackend::default());

        if let Err(K8sAuthProviderError::InvalidTokenReviewResponse) =
            provider.extract_k8s_service_account(&json!({"status": {"authenticated": true}}))
        {
        } else {
            panic!("no user should result in InvalidTokenReviewResponse");
        }
    }

    #[test]
    fn test_extract_k8s_service_account_wrong_pattern() {
        let provider = make_service(MockK8sAuthBackend::default());

        if let Err(K8sAuthProviderError::InvalidTokenReviewResponse) = provider
            .extract_k8s_service_account(
                &json!({"status": {"authenticated": true, "user": {"username": "system"}}}),
            )
        {
        } else {
            panic!("wrong username pattern should result in InvalidTokenReviewResponse");
        }
    }

    #[test]
    fn test_extract_k8s_service_account_valid() {
        let provider = make_service(MockK8sAuthBackend::default());

        let (ns, sa) = provider
            .extract_k8s_service_account(&json!({
                "status": {"authenticated": true, "user": {"username": "system:serviceaccount:my_ns:my_sa"}}
            }))
            .expect("valid token should succeed");

        assert_eq!(ns, "my_ns");
        assert_eq!(sa, "my_sa");
    }

    #[tokio::test]
    async fn test_auth_instance_not_found() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockK8sAuthBackend::default();
        backend
            .expect_get_auth_instance()
            .returning(|_, _| Ok(None));

        let service = make_service(backend);
        let result = service
            .authenticate_by_mapping(
                &state,
                &K8sAuthRequest {
                    auth_instance_id: "missing".into(),
                    jwt: SecretString::new("jwt".into()),
                    rule_name: Some("rule".into()),
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(K8sAuthProviderError::AuthInstanceNotFound(x)) if x == "missing"
        ));
    }

    #[tokio::test]
    async fn test_auth_instance_disabled() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockK8sAuthBackend::default();
        backend.expect_get_auth_instance().returning(|_, _| {
            Ok(Some(K8sAuthInstance {
                ca_cert: None,
                disable_local_ca_jwt: true,
                domain_id: "did".into(),
                enabled: false,
                host: "http://localhost:6443".into(),
                id: "cid".into(),
                name: Some("t".into()),
            }))
        });

        let service = make_service(backend);
        let result = service
            .authenticate_by_mapping(
                &state,
                &K8sAuthRequest {
                    auth_instance_id: "cid".into(),
                    jwt: SecretString::new("jwt".into()),
                    rule_name: Some("r".into()),
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(K8sAuthProviderError::AuthInstanceNotActive(x)) if x == "cid"
        ));
    }
}
