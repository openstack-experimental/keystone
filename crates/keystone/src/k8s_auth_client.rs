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
//! # Kubernetes HTTP client implementation.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use jsonwebtoken::dangerous::insecure_decode;
use reqwest::{Certificate, Client, StatusCode};
use serde_json::Value;
use tokio::fs;
use tracing::debug;

use openstack_keystone_core::k8s_auth::K8sAuthProviderError;
pub use openstack_keystone_core::k8s_auth::K8sHttpClient;
use openstack_keystone_core_types::k8s_auth::{K8sAuthInstance, K8sClaims};

static SERVICE_ACCOUNT_CERT_PATH_STR: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
static SERVICE_ACCOUNT_CERT_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Production implementation of [`K8sHttpClient`] using `reqwest`.
#[derive(Default)]
pub struct KeystoneK8sHttpClient {
    clients: DashMap<String, Arc<Client>>,
}

impl KeystoneK8sHttpClient {
    pub fn new() -> Self {
        Self {
            clients: DashMap::new(),
        }
    }
}

#[async_trait]
impl K8sHttpClient for KeystoneK8sHttpClient {
    async fn query_token_review(
        &self,
        instance: &K8sAuthInstance,
        jwt: &str,
        bound_audience: Option<&str>,
    ) -> Result<Value, K8sAuthProviderError> {
        // Pre-flight JWT decode to fail fast on invalid tokens
        let _claims = self.validate_jwt(jwt, bound_audience)?;

        let client = self.get_or_create_client(instance).await?;

        let body = serde_json::json!({
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "spec": {
                "token": jwt,
            },
        });

        let response = client
            .post(format!(
                "{}/apis/authentication.k8s.io/v1/tokenreviews",
                instance.host
            ))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", jwt))
            .json(&body)
            .send()
            .await
            .map_err(K8sAuthProviderError::http)?;

        match response.status() {
            StatusCode::OK | StatusCode::CREATED => {
                Ok(response.json().await.map_err(K8sAuthProviderError::http)?)
            }
            _ => {
                debug!("Kubernetes returned {:?}", response);
                Err(K8sAuthProviderError::InvalidToken)
            }
        }
    }
}

impl KeystoneK8sHttpClient {
    fn validate_jwt(
        &self,
        jwt: &str,
        bound_audience: Option<&str>,
    ) -> Result<K8sClaims, K8sAuthProviderError> {
        let token_data =
            insecure_decode::<K8sClaims>(jwt).map_err(|_| K8sAuthProviderError::InvalidToken)?;
        let claims = token_data.claims;

        if let Some(expected_aud) = bound_audience {
            if !claims.aud.iter().any(|a| a == expected_aud) {
                return Err(K8sAuthProviderError::AudienceMismatch);
            }
        }

        if claims.exp < Utc::now().timestamp() as u64 {
            return Err(K8sAuthProviderError::ExpiredToken);
        }

        Ok(claims)
    }

    async fn get_or_create_client(
        &self,
        instance: &K8sAuthInstance,
    ) -> Result<Arc<Client>, K8sAuthProviderError> {
        if let Some(client) = self.clients.get(&instance.id) {
            return Ok(Arc::clone(client.value()));
        }

        let mut builder = Client::builder()
            .gzip(true)
            .pool_idle_timeout(std::time::Duration::from_secs(90));

        if let Some(ca) = &instance.ca_cert {
            builder = builder.add_root_certificate(
                Certificate::from_pem(ca.as_bytes()).map_err(K8sAuthProviderError::http)?,
            );
        } else if !instance.disable_local_ca_jwt {
            builder = builder.add_root_certificate(
                Certificate::from_pem(
                    fs::read_to_string(
                        SERVICE_ACCOUNT_CERT_PATH
                            .get_or_init(|| PathBuf::from(SERVICE_ACCOUNT_CERT_PATH_STR)),
                    )
                    .await
                    .map_err(|_| K8sAuthProviderError::CaCertificateUnknown)?
                    .as_bytes(),
                )
                .map_err(K8sAuthProviderError::http)?,
            );
        }

        let shared = Arc::new(builder.build().map_err(K8sAuthProviderError::http)?);
        self.clients
            .insert(instance.id.clone(), Arc::clone(&shared));
        Ok(shared)
    }
}

/// Mock implementation of [`K8sHttpClient`] for tests.
/// Performs JWT decode + audience/expiration validation, then returns
/// a pre-configured response.
pub struct MockK8sHttpClient {
    response: Mutex<Option<Result<Value, K8sAuthProviderError>>>,
}

impl Default for MockK8sHttpClient {
    fn default() -> Self {
        Self {
            response: Mutex::new(None),
        }
    }
}

impl MockK8sHttpClient {
    pub fn with_response(response: Result<Value, K8sAuthProviderError>) -> Self {
        Self {
            response: Mutex::new(Some(response)),
        }
    }
}

#[async_trait]
impl K8sHttpClient for MockK8sHttpClient {
    async fn query_token_review(
        &self,
        _instance: &K8sAuthInstance,
        jwt: &str,
        bound_audience: Option<&str>,
    ) -> Result<Value, K8sAuthProviderError> {
        // JWT decode without signature verification, using typed claims
        let token_data = jsonwebtoken::dangerous::insecure_decode::<K8sClaims>(jwt)
            .map_err(|_| K8sAuthProviderError::InvalidToken)?;
        let claims = token_data.claims;

        // Validate audience
        if let Some(expected_aud) = bound_audience {
            if !claims.aud.iter().any(|a| a == expected_aud) {
                return Err(K8sAuthProviderError::AudienceMismatch);
            }
        }

        // Validate expiration
        if claims.exp < Utc::now().timestamp() as u64 {
            return Err(K8sAuthProviderError::ExpiredToken);
        }

        // Return pre-configured response or default authenticated response
        let response = self.response.lock().unwrap().take();
        match response {
            Some(r) => r,
            None => Ok(serde_json::json!({
                "status": {
                    "authenticated": true,
                    "user": {"username": "system:serviceaccount:ns:sa"}
                }
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, Utc};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use openstack_keystone_core_types::k8s_auth::{K8sAuthInstance, K8sClaims};

    use super::*;

    fn make_token(aud: &str, exp_offset: i64) -> String {
        let claims = K8sClaims {
            aud: vec![aud.into()],
            exp: (Utc::now() + TimeDelta::seconds(exp_offset)).timestamp() as u64,
            sub: "system:serviceaccount:ns:sa".into(),
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("secret".as_ref()),
        )
        .expect("encode token")
    }

    fn make_instance() -> K8sAuthInstance {
        K8sAuthInstance {
            ca_cert: None,
            disable_local_ca_jwt: true,
            domain_id: "d".into(),
            enabled: true,
            host: "http://localhost:6443".into(),
            id: "i".into(),
            name: Some("t".into()),
        }
    }

    #[tokio::test]
    async fn mock_audience_mismatch() {
        let mock = MockK8sHttpClient::default();
        let jwt = make_token("correct_aud", 60);
        let result = mock
            .query_token_review(&make_instance(), &jwt, Some("wrong_aud"))
            .await;
        assert!(matches!(
            result,
            Err(K8sAuthProviderError::AudienceMismatch)
        ));
    }

    #[tokio::test]
    async fn mock_expiration_valid() {
        let mock = MockK8sHttpClient::default();
        let jwt = make_token("aud", 60);
        let result = mock
            .query_token_review(&make_instance(), &jwt, Some("aud"))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_expiration_expired() {
        let mock = MockK8sHttpClient::default();
        let jwt = make_token("aud", -60);
        let result = mock
            .query_token_review(&make_instance(), &jwt, Some("aud"))
            .await;
        assert!(matches!(result, Err(K8sAuthProviderError::ExpiredToken)));
    }

    #[tokio::test]
    async fn mock_no_bound_audience_skips_check() {
        let mock = MockK8sHttpClient::default();
        let jwt = make_token("any_aud", 60);
        let result = mock.query_token_review(&make_instance(), &jwt, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_invalid_jwt() {
        let mock = MockK8sHttpClient::default();
        let result = mock
            .query_token_review(&make_instance(), "not-a-jwt", None)
            .await;
        assert!(matches!(result, Err(K8sAuthProviderError::InvalidToken)));
    }

    #[tokio::test]
    async fn mock_custom_response() {
        let resp = serde_json::json!({
            "status": {
                "authenticated": true,
                "user": {"username": "system:serviceaccount:test:sa"}
            }
        });
        let mock = MockK8sHttpClient::with_response(Ok(resp));
        let jwt = make_token("aud", 60);
        let result = mock
            .query_token_review(&make_instance(), &jwt, Some("aud"))
            .await
            .expect("should be ok");
        assert!(result["status"]["authenticated"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn mock_response_used_once() {
        let resp = serde_json::json!({"custom": true});
        let mock = MockK8sHttpClient::with_response(Ok(resp));
        let jwt = make_token("aud", 60);

        let r1 = mock
            .query_token_review(&make_instance(), &jwt, None)
            .await
            .unwrap();
        assert!(r1["custom"].as_bool().unwrap());

        // Second call returns default (response was consumed by take)
        let r2 = mock
            .query_token_review(&make_instance(), &jwt, None)
            .await
            .unwrap();
        assert!(r2["custom"].is_null());
        assert!(r2["status"]["authenticated"].as_bool().unwrap());
    }

    // Production client pre-flight validation tests
    #[test]
    fn prod_validate_audience_mismatch() {
        let client = KeystoneK8sHttpClient::new();
        let jwt = make_token("correct", 60);
        let result = client.validate_jwt(&jwt, Some("wrong"));
        assert!(matches!(
            result,
            Err(K8sAuthProviderError::AudienceMismatch)
        ));
    }

    #[test]
    fn prod_validate_expired() {
        let client = KeystoneK8sHttpClient::new();
        let jwt = make_token("aud", -60);
        let result = client.validate_jwt(&jwt, Some("aud"));
        assert!(matches!(result, Err(K8sAuthProviderError::ExpiredToken)));
    }

    #[test]
    fn prod_validate_valid() {
        let client = KeystoneK8sHttpClient::new();
        let jwt = make_token("aud", 60);
        let result = client.validate_jwt(&jwt, Some("aud"));
        assert!(result.is_ok());
    }

    #[test]
    fn prod_validate_no_audience_check() {
        let client = KeystoneK8sHttpClient::new();
        let jwt = make_token("any", 60);
        let result = client.validate_jwt(&jwt, None);
        assert!(result.is_ok());
    }

    #[test]
    fn prod_validate_invalid_jwt() {
        let client = KeystoneK8sHttpClient::new();
        let result = client.validate_jwt("not-a-jwt", None);
        assert!(matches!(result, Err(K8sAuthProviderError::InvalidToken)));
    }
}
