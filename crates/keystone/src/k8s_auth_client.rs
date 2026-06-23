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

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use jsonwebtoken::dangerous::insecure_decode;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use tokio::fs;
use tracing::debug;

use openstack_keystone_core::k8s_auth::K8sAuthProviderError;
pub use openstack_keystone_core::k8s_auth::K8sHttpClient;
use openstack_keystone_core_types::k8s_auth::{K8sAuthInstance, K8sClaims, QueryTokenReviewResult};

/// Path to the service account CA cert mounted in a K8s pod.
const SERVICE_ACCOUNT_CERT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

/// Production implementation of [`K8sHttpClient`] using `reqwest`.
pub struct KeystoneK8sHttpClient {
    clients: DashMap<String, Arc<Client>>,
}

impl Default for KeystoneK8sHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl KeystoneK8sHttpClient {
    pub fn new() -> Self {
        Self {
            clients: DashMap::new(),
        }
    }

    /// Decode and validate a K8s JWT token (signature-less decode +
    /// expiration).
    pub fn validate_jwt(jwt: &str) -> Result<K8sClaims, K8sAuthProviderError> {
        let token_data =
            insecure_decode::<K8sClaims>(jwt).map_err(|_| K8sAuthProviderError::InvalidToken)?;
        let claims = token_data.claims;

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

        let mut builder = reqwest::Client::builder()
            .gzip(true)
            .pool_idle_timeout(std::time::Duration::from_secs(90));

        if let Some(ca) = &instance.ca_cert {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(ca.as_bytes())
                    .map_err(K8sAuthProviderError::http)?,
            );
        } else if !instance.disable_local_ca_jwt {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(
                    fs::read_to_string(SERVICE_ACCOUNT_CERT_PATH)
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

#[async_trait]
impl K8sHttpClient for KeystoneK8sHttpClient {
    async fn query_token_review(
        &self,
        instance: &K8sAuthInstance,
        jwt: &str,
    ) -> Result<QueryTokenReviewResult, K8sAuthProviderError> {
        let claims = Self::validate_jwt(jwt)?;
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
            StatusCode::OK | StatusCode::CREATED => Ok(QueryTokenReviewResult {
                claims,
                token_review: response.json().await.map_err(K8sAuthProviderError::http)?,
            }),
            status if status.is_client_error() => {
                debug!("Kubernetes returned {:?}", response);
                Err(K8sAuthProviderError::InvalidToken)
            }
            status => {
                debug!("Kubernetes returned {:?}", response);
                Err(K8sAuthProviderError::Http {
                    source: Box::new(K8sServerResponseError(status)),
                })
            }
        }
    }
}

/// Mock implementation of [`K8sHttpClient`] for tests.
///
/// Performs JWT decode + expiration validation (shared with production impl),
/// then returns a pre-configured response.
pub struct MockK8sHttpClient {
    response: Mutex<Option<Result<QueryTokenReviewResult, K8sAuthProviderError>>>,
}

impl Default for MockK8sHttpClient {
    fn default() -> Self {
        Self {
            response: Mutex::new(None),
        }
    }
}

impl MockK8sHttpClient {
    pub fn with_response(response: Result<QueryTokenReviewResult, K8sAuthProviderError>) -> Self {
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
    ) -> Result<QueryTokenReviewResult, K8sAuthProviderError> {
        let claims = KeystoneK8sHttpClient::validate_jwt(jwt)?;

        let response = self.response.lock().unwrap().take();
        match response {
            Some(r) => r,
            None => Ok(QueryTokenReviewResult {
                claims,
                token_review: serde_json::json!({
                    "status": {
                        "authenticated": true,
                        "user": {"username": "system:serviceaccount:ns:sa"}
                    }
                }),
            }),
        }
    }
}

/// Error returned when K8s API responds with a server error status.
#[derive(Debug)]
struct K8sServerResponseError(StatusCode);

impl std::fmt::Display for K8sServerResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "k8s server returned {}: {}", self.0.as_u16(), self.0)
    }
}

impl std::error::Error for K8sServerResponseError {}

#[cfg(test)]
mod tests {
    use httpmock::{Method, MockServer};
    use openstack_keystone_core_types::k8s_auth::{
        K8sAuthInstance, K8sClaims, QueryTokenReviewResult,
    };

    use super::*;

    /// Test CA cert valid till 2036.
    static CA_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIBeDCCAR2gAwIBAgIBADAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhrM3Mtc2Vy
dmVyLWNhQDE3NjgyOTE3MTEwHhcNMjYwMTEzMDgwODMxWhcNMzYwMTExMDgwODMx
WjAjMSEwHwYDVQQDDBhrM3Mtc2VydmVyLWNhQDE3NjgyOTE3MTEwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAARfFhTMwYXJNZrhtG3vYSYEuhkObCg46+WyGR1N/UWm
WWbNsc/lv1CWf/ys6enoOfAZs9k/UZzq7ILzHAk6wfOfo0IwQDAOBgNVHQ8BAf8E
BAMCAqQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU1FJnrnJcSrNHUxh1pyJO
gPLqX1cwCgYIKoZIzj0EAwIDSQAwRgIhAO0kyD4tHt+hITHoBDrAspO3AmUNDX3v
FPrC1HpT3dzIAiEAtEB0so+KoJb/2Opn1RycVzxke1CQrWgjS8ySnnFK5ok=
-----END CERTIFICATE-----
"#;

    fn make_token(jwt_exp_offset: i64) -> String {
        let exp = (Utc::now() + chrono::TimeDelta::seconds(jwt_exp_offset)).timestamp() as u64;
        let claims = K8sClaims {
            aud: vec!["aud".into()],
            exp,
            sub: "system:serviceaccount:ns:sa".into(),
        };
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret("secret".as_ref()),
        )
        .expect("encode token")
    }

    fn make_instance_with_ca() -> K8sAuthInstance {
        K8sAuthInstance {
            ca_cert: Some(CA_CERT.to_string()),
            disable_local_ca_jwt: true,
            domain_id: "did".into(),
            enabled: true,
            host: "test".into(),
            id: "cid".into(),
            name: Some("foo".into()),
        }
    }

    fn make_instance_no_ca() -> K8sAuthInstance {
        K8sAuthInstance {
            ca_cert: None,
            disable_local_ca_jwt: true,
            domain_id: "did".into(),
            enabled: true,
            host: "test".into(),
            id: "cid".into(),
            name: Some("foo".into()),
        }
    }

    // --- get_or_create_client tests ---

    #[tokio::test]
    async fn test_get_or_create_client_with_ca() {
        let client = KeystoneK8sHttpClient::new();
        let instance = make_instance_with_ca();

        let c1 = client
            .get_or_create_client(&instance)
            .await
            .expect("client creation with CA cert should succeed");

        let c2 = client
            .get_or_create_client(&instance)
            .await
            .expect("cached client should be returned");

        assert!(Arc::ptr_eq(&c1, &c2), "cache should return the same client");
    }

    #[tokio::test]
    async fn test_get_or_create_client_no_ca() {
        let client = KeystoneK8sHttpClient::new();
        let instance = make_instance_no_ca();

        assert!(
            client.get_or_create_client(&instance).await.is_ok(),
            "client should be created without CA"
        );
    }

    // --- pre-flight JWT validation tests ---

    #[test]
    fn validate_valid_jwt() {
        let jwt = make_token(60);
        assert!(KeystoneK8sHttpClient::validate_jwt(&jwt).is_ok());
    }

    #[test]
    fn validate_expired_jwt() {
        let jwt = make_token(-60);
        assert!(matches!(
            KeystoneK8sHttpClient::validate_jwt(&jwt),
            Err(K8sAuthProviderError::ExpiredToken)
        ));
    }

    #[test]
    fn validate_invalid_jwt() {
        assert!(matches!(
            KeystoneK8sHttpClient::validate_jwt("not-a-jwt"),
            Err(K8sAuthProviderError::InvalidToken)
        ));
    }

    // --- MockK8sHttpClient tests ---

    #[tokio::test]
    async fn mock_expiration_valid() {
        let mock = MockK8sHttpClient::default();
        let jwt = make_token(60);
        let instance = make_instance_no_ca();
        assert!(mock.query_token_review(&instance, &jwt).await.is_ok());
    }

    #[tokio::test]
    async fn mock_expiration_expired() {
        let mock = MockK8sHttpClient::default();
        let jwt = make_token(-60);
        let instance = make_instance_no_ca();
        assert!(matches!(
            mock.query_token_review(&instance, &jwt).await,
            Err(K8sAuthProviderError::ExpiredToken)
        ));
    }

    #[tokio::test]
    async fn mock_invalid_jwt() {
        let mock = MockK8sHttpClient::default();
        let instance = make_instance_no_ca();
        assert!(matches!(
            mock.query_token_review(&instance, "not-a-jwt").await,
            Err(K8sAuthProviderError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn mock_custom_response() {
        let resp = serde_json::json!({
            "status": {
                "authenticated": true,
                "user": {"username": "system:serviceaccount:test:sa"}
            }
        });
        let mock = MockK8sHttpClient::with_response(Ok(QueryTokenReviewResult {
            claims: K8sClaims {
                aud: vec![],
                exp: 0,
                sub: String::new(),
            },
            token_review: resp,
        }));
        let jwt = make_token(60);
        let instance = make_instance_no_ca();
        let review = mock
            .query_token_review(&instance, &jwt)
            .await
            .expect("should be ok");
        assert!(
            review.token_review["status"]["authenticated"]
                .as_bool()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn mock_response_used_once() {
        let resp = serde_json::json!({"custom": true});
        let mock = MockK8sHttpClient::with_response(Ok(QueryTokenReviewResult {
            claims: K8sClaims {
                aud: vec![],
                exp: 0,
                sub: String::new(),
            },
            token_review: resp,
        }));
        let jwt = make_token(60);
        let instance = make_instance_no_ca();

        let r1 = mock.query_token_review(&instance, &jwt).await.unwrap();
        assert!(r1.token_review["custom"].as_bool().unwrap());

        let r2 = mock.query_token_review(&instance, &jwt).await.unwrap();
        assert!(r2.token_review["custom"].is_null());
        assert!(
            r2.token_review["status"]["authenticated"]
                .as_bool()
                .unwrap()
        );
    }

    // --- Full HTTP round-trip tests ---

    #[tokio::test]
    async fn test_query_token_review_ok() {
        let mock_srv = MockServer::start();
        let jwt = make_token(60);

        let _mock = mock_srv.mock(|when, then| {
            when.method(Method::POST)
                .path("/apis/authentication.k8s.io/v1/tokenreviews")
                .header("authorization", format!("Bearer {}", jwt))
                .json_body(serde_json::json!({
                    "apiVersion": "authentication.k8s.io/v1",
                    "kind": "TokenReview",
                    "spec": { "token": jwt },
                }));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!({
                    "status": {
                        "authenticated": true,
                        "user": {"username": "system:serviceaccount:test_ns:test_sa"}
                    }
                }));
        });

        let client = KeystoneK8sHttpClient::new();
        let instance = K8sAuthInstance {
            ca_cert: None,
            disable_local_ca_jwt: true,
            domain_id: "d".into(),
            enabled: true,
            host: format!("http://{}:{}", mock_srv.host(), mock_srv.port()),
            id: "i".into(),
            name: Some("t".into()),
        };

        let body = client.query_token_review(&instance, &jwt).await.unwrap();
        assert!(
            body.token_review["status"]["authenticated"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(
            body.token_review["status"]["user"]["username"]
                .as_str()
                .unwrap(),
            "system:serviceaccount:test_ns:test_sa"
        );
        assert_eq!(body.claims.aud, vec!["aud".to_string()]);
    }

    #[tokio::test]
    async fn test_query_token_review_401() {
        let mock_srv = MockServer::start();
        let jwt = make_token(60);

        let mock = mock_srv.mock(|when, then| {
            when.method(Method::POST)
                .path("/apis/authentication.k8s.io/v1/tokenreviews")
                .header("authorization", format!("Bearer {}", jwt));
            then.status(401);
        });

        let client = KeystoneK8sHttpClient::new();
        let instance = K8sAuthInstance {
            ca_cert: None,
            disable_local_ca_jwt: true,
            domain_id: "d".into(),
            enabled: true,
            host: format!("http://{}:{}", mock_srv.host(), mock_srv.port()),
            id: "i".into(),
            name: Some("t".into()),
        };

        let result = client.query_token_review(&instance, &jwt).await;
        assert!(matches!(result, Err(K8sAuthProviderError::InvalidToken)));
        mock.assert();
    }

    #[tokio::test]
    async fn test_query_token_review_500() {
        let mock_srv = MockServer::start();
        let jwt = make_token(60);

        let mock = mock_srv.mock(|when, then| {
            when.method(Method::POST)
                .path("/apis/authentication.k8s.io/v1/tokenreviews")
                .header("authorization", format!("Bearer {}", jwt));
            then.status(500);
        });

        let client = KeystoneK8sHttpClient::new();
        let instance = K8sAuthInstance {
            ca_cert: None,
            disable_local_ca_jwt: true,
            domain_id: "d".into(),
            enabled: true,
            host: format!("http://{}:{}", mock_srv.host(), mock_srv.port()),
            id: "i".into(),
            name: Some("t".into()),
        };

        let result = client.query_token_review(&instance, &jwt).await;
        assert!(matches!(result, Err(K8sAuthProviderError::Http { .. })));
        mock.assert();
    }
}
