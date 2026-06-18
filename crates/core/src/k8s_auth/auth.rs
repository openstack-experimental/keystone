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
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use chrono::Utc;
use jsonwebtoken::dangerous::insecure_decode;
use reqwest::{Certificate, Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tokio::fs;
use tracing::{debug, trace};

use openstack_keystone_core_types::auth::AuthenticationResult;
use openstack_keystone_core_types::k8s_auth::*;
use openstack_keystone_core_types::mapping::auth::MappingAuthRequest;
use openstack_keystone_core_types::mapping::resolution::IdentitySource;

use super::K8sAuthApi;
use super::types::K8sClaims;
use crate::k8s_auth::{K8sAuthProviderError, service::K8sAuthService};
use crate::keystone::ServiceState;
use crate::mapping::MappingApi;

/// Kubernetes cluster CA certificate location.
static SERVICE_ACCOUNT_CERT_PATH_STR: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
static SERVICE_ACCOUNT_CERT_PATH: OnceLock<PathBuf> = OnceLock::new();

impl K8sAuthService {
    /// Get the [`Client`] for communication with the K8s.
    ///
    /// # Arguments
    /// * `instance` - reference to the [`K8sAuthInstance`].
    /// * `ca_path` - optional reference to the CA_CERT location.
    ///
    /// # Returns
    /// * Success `Client` with the injected root CA certificate.
    /// * `K8sAuthProviderError` when neither `ca_cert`, nor the `ca_path` (or
    ///   the default certificate location
    ///   (`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`) contain the
    ///   certificate content while the `disable_local_ca_jwt` of the
    ///   `AuthProvider` is not `true`.
    async fn get_or_create_client(
        &self,
        instance: &K8sAuthInstance,
        ca_path: Option<PathBuf>,
    ) -> Result<Arc<Client>, K8sAuthProviderError> {
        // Check if we already have a pooled client
        if let Some(client) = self.http_client_pool.get_client(&instance.id).await {
            return Ok(client);
        }

        // Create a new one
        let mut client_builder = Client::builder()
            .gzip(true)
            // Optional: Set pool idle timeout or max connections
            .pool_idle_timeout(std::time::Duration::from_secs(90));

        // Determine the CA certificate for the K8 cluster
        if let Some(val) = &instance.ca_cert {
            client_builder = client_builder.add_root_certificate(
                Certificate::from_pem(val.as_bytes()).map_err(K8sAuthProviderError::http)?,
            );
        } else if !instance.disable_local_ca_jwt {
            client_builder = client_builder.add_root_certificate(
                Certificate::from_pem(
                    fs::read_to_string(ca_path.as_ref().unwrap_or_else(|| {
                        SERVICE_ACCOUNT_CERT_PATH
                            .get_or_init(|| PathBuf::from(SERVICE_ACCOUNT_CERT_PATH_STR))
                    }))
                    .await
                    .map_err(|_| K8sAuthProviderError::CaCertificateUnknown)?
                    .as_bytes(),
                )
                .map_err(K8sAuthProviderError::http)?,
            );
        };

        // Build the client
        let shared_client = Arc::new(client_builder.build().map_err(K8sAuthProviderError::http)?);

        // Store it for future use
        self.http_client_pool
            .put_client(&instance.id, Arc::clone(&shared_client))
            .await;

        Ok(shared_client)
    }

    /// Query the K8s Token Review endpoint.
    ///
    /// Validates the JWT through the K8s TokenReview API. Audience and
    /// expiry checks are performed pre-flight; namespace/name matching is
    /// delegated to the mapping engine rules.
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
        // Pre-flight: reject expired tokens early
        let claims = insecure_decode::<K8sClaims>(token.expose_secret())
            .map_err(K8sAuthProviderError::jwt)?;
        if claims.claims.exp < Utc::now().timestamp() as u64 {
            return Err(K8sAuthProviderError::ExpiredToken);
        }

        let body = json!({
            "api_version": "authentication.k8s.io/v1".to_string(),
            "kind": "TokenReview".to_string(),
            "spec": {
                "token": token.expose_secret(),
            },
        });

        let response = self
            .get_or_create_client(instance, None)
            .await?
            .post(format!(
                "{}/apis/authentication.k8s.io/v1/tokenreviews",
                instance.host
            ))
            .header("Authorization", format!("Bearer {}", token.expose_secret()))
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

    /// Validate K8s Token Review response and extract service account info.
    ///
    /// Returns `(namespace, service_account_name)` parsed from the username.
    /// Does not check role bindings — that is handled by the mapping engine.
    ///
    /// # Arguments
    /// * `token_review_data` - json representation of the TokenReview response.
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
            if let Some(val) = token_review_data["status"]["error"].as_str() {
                trace!("token validation error: {}", val);
            }
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
    /// - `k8s.aud` (from JWT claims, if present)
    ///
    /// # Arguments
    /// * `token_review_data` - TokenReview JSON response.
    /// * `jwt` - The original JWT (used to extract `aud` claim).
    ///
    /// # Returns
    /// A flattened claims map and the JWT audience claim (optional).
    pub(super) fn flatten_k8s_claims(
        &self,
        token_review_data: &Value,
        jwt: &SecretString,
    ) -> Result<(HashMap<String, Vec<String>>, Option<Vec<String>>), K8sAuthProviderError> {
        let (namespace, sa_name) = self.extract_k8s_service_account(token_review_data)?;

        let mut claims = HashMap::new();
        claims.insert("k8s.serviceaccount.name".to_string(), vec![sa_name]);
        claims.insert("k8s.serviceaccount.namespace".to_string(), vec![namespace]);

        // Extract audience from JWT for inclusion in claims
        let aud = insecure_decode::<K8sClaims>(jwt.expose_secret())
            .map(|decoded| decoded.claims.aud)
            .ok();

        if let Some(auds) = &aud
            && !auds.is_empty()
        {
            claims.insert("k8s.aud".to_string(), auds.iter().cloned().collect());
        }

        Ok((claims, aud))
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
        let (claims, _aud) = self.flatten_k8s_claims(&token_review_data, &req.jwt)?;

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
    use std::io::Write;
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use eyre::Result;
    use httpmock::{Mock, MockServer};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use tempfile::NamedTempFile;

    use super::super::backend::MockK8sAuthBackend;
    use super::*;
    use crate::common::HttpClientPool;

    /// fake cert valid till 2036
    static CA_CERT: &str = r#"
-----BEGIN CERTIFICATE-----
MIIBeDCCAR2gAwIBAgIBADAKBggqhkjOPQQDAjAjMSEwHwYDVQQDDBhrM3Mtc2Vy
dmVyLWNhQDE3NjgyOTE3MTEwHhcNMjYwMTEzMDgwODMxWhcNMzYwMTExMDgwODMx
WjAjMSEwHwYDVQQDDBhrM3Mtc2VydmVyLWNhQDE3NjgyOTE3MTEwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAARfFhTMwYXJNZrhtG3vYSYEuhkObCg46+WyGR1N/UWm
WGbNsc/lv1CWf/ys6enoOfAZs9k/UZzq7ILzHAk6wfOfo0IwQDAOBgNVHQ8BAf8E
BAMCAqQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU1FJnrnJcSrNHUxh1pyJO
gPLqX1cwCgYIKoZIzj0EAwIDSQAwRgIhAO0kyD4tHt+hITHoBDrAspO3AmUNDX3v
FPrC1HpT3dzIAiEAtEB0so+KoJb/2Opn1RycVzxke1CQrWgjS8ySnnFK5ok=
-----END CERTIFICATE-----
"#;

    #[allow(dead_code)]
    async fn get_token_review_response_mock<'a, U: Into<String>>(
        mock_server: &'a MockServer,
        token: &SecretString,
        is_authenticated: bool,
        uname: U,
    ) -> Mock<'a> {
        mock_server
            .mock_async(|when, then| {
                when.method("POST")
                    .path("/apis/authentication.k8s.io/v1/tokenreviews")
                    .header("authorization", format!("Bearer {}", token.expose_secret()))
                    .json_body(json!({
                        "api_version": "authentication.k8s.io/v1".to_string(),
                        "kind": "TokenReview".to_string(),
                        "spec": {
                            "token": token.expose_secret(),
                        },
                    }));
                if !is_authenticated {
                    then.status(200)
                        .header("content-type", "application/json")
                        .json_body(json!({"status": {"authenticated": false, "user": {}}}))
                } else {
                    then.status(201)
                        .header("content-type", "application/json")
                        .json_body(
                            json!({"status": {"authenticated": true, "user": {"username": uname.into()}}}),
                        )
                };
            })
            .await
    }

    #[tokio::test]
    async fn test_get_or_create_client_with_ca() -> Result<()> {
        let srv = K8sAuthService {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_client_pool: Box::new(HttpClientPool::default()),
        };
        let instance = K8sAuthInstance {
            ca_cert: Some(CA_CERT.into()),
            disable_local_ca_jwt: true,
            domain_id: "did".into(),
            enabled: true,
            host: "127.0.0.1:6443".into(),
            id: "cid".into(),
            name: Some("foo".into()),
        };
        srv.get_or_create_client(&instance, None).await?;
        //  Ensure the connection is present in the pool
        assert!(
            srv.http_client_pool
                .get_client(&instance.id)
                .await
                .is_some()
        );
        // Repeat the get, now it should be returned from the cache
        srv.get_or_create_client(&instance, None).await?;

        // Test with the CA and disable_local_ca_jwt
        let instance = K8sAuthInstance {
            ca_cert: Some(CA_CERT.into()),
            disable_local_ca_jwt: true,
            domain_id: "did".into(),
            enabled: true,
            host: "127.0.0.1:6443".into(),
            id: "cid1".into(),
            name: Some("foo".into()),
        };
        assert!(srv.get_or_create_client(&instance, None).await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_or_create_client_k8s_ca() -> Result<()> {
        let provider = K8sAuthService {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_client_pool: Box::new(HttpClientPool::default()),
        };
        let instance = K8sAuthInstance {
            ca_cert: None,
            disable_local_ca_jwt: false,
            domain_id: "did".into(),
            enabled: true,
            host: "127.0.0.1:6443".into(),
            id: "cid".into(),
            name: Some("foo".into()),
        };
        let mut file = NamedTempFile::new()?;
        writeln!(file, "{}", CA_CERT)?;
        assert!(
            provider
                .get_or_create_client(&instance, Some(file.path().to_path_buf()))
                .await
                .is_ok()
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_get_or_create_client_error_no_ca() -> Result<()> {
        let provider = K8sAuthService {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_client_pool: Box::new(HttpClientPool::default()),
        };
        let instance = K8sAuthInstance {
            ca_cert: None,
            disable_local_ca_jwt: false,
            domain_id: "did".into(),
            enabled: true,
            host: "127.0.0.1:6443".into(),
            id: "cid".into(),
            name: Some("foo".into()),
        };
        if let Err(K8sAuthProviderError::CaCertificateUnknown) =
            provider.get_or_create_client(&instance, None).await
        {
        } else {
            panic!("should have raised an error");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_get_or_create_client_disable_local_ca_jwt() -> Result<()> {
        let provider = K8sAuthService {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_client_pool: Box::new(HttpClientPool::default()),
        };
        let instance = K8sAuthInstance {
            ca_cert: None,
            disable_local_ca_jwt: true,
            domain_id: "did".into(),
            enabled: true,
            host: "127.0.0.1:6443".into(),
            id: "cid".into(),
            name: Some("foo".into()),
        };
        assert!(provider.get_or_create_client(&instance, None).await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_query_k8s_token_review_expired() -> Result<()> {
        let provider = K8sAuthService {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_client_pool: Box::new(HttpClientPool::default()),
        };
        let instance = K8sAuthInstance {
            ca_cert: None,
            disable_local_ca_jwt: true,
            domain_id: "did".into(),
            enabled: true,
            host: "http://127.0.0.1:6443".into(),
            id: "cid".into(),
            name: Some("foo".into()),
        };
        let claims = K8sClaims {
            aud: vec!["aud".into()],
            exp: (Utc::now() - Duration::seconds(10)).timestamp() as u64,
            sub: "system:serviceaccount:ns:san".into(),
        };
        let token = SecretString::from(encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("not_secret".as_ref()),
        )?);

        if let Err(K8sAuthProviderError::ExpiredToken) =
            provider.query_k8s_token_review(&token, &instance).await
        {
        } else {
            panic!("should have raised an error");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_query_k8s_token_review() -> Result<()> {
        let provider = K8sAuthService {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_client_pool: Box::new(HttpClientPool::default()),
        };
        let mock_srv = MockServer::start_async().await;
        let instance = K8sAuthInstance {
            ca_cert: None,
            disable_local_ca_jwt: true,
            domain_id: "did".into(),
            enabled: true,
            host: format!("http://{}:{}", mock_srv.host(), mock_srv.port()),
            id: "cid".into(),
            name: Some("foo".into()),
        };
        let claims = K8sClaims {
            aud: vec!["aud".into()],
            exp: (Utc::now() + Duration::seconds(10)).timestamp() as u64,
            sub: "system:serviceaccount:ns:san".into(),
        };
        let token = SecretString::from(encode(
            &Header {
                nonce: Some("foo".into()),
                ..Default::default()
            },
            &claims,
            &EncodingKey::from_secret("not_secret".as_ref()),
        )?);
        let token2 = SecretString::from(encode(
            &Header {
                nonce: Some("bar".into()),
                ..Default::default()
            },
            &claims,
            &EncodingKey::from_secret("not_secret".as_ref()),
        )?);
        assert!(token.expose_secret() != token2.expose_secret());
        let rsp = json!({"foo": "bar"});
        let mock_ok = mock_srv
            .mock_async(|when, then| {
                when.method("POST")
                    .path("/apis/authentication.k8s.io/v1/tokenreviews")
                    .header("authorization", format!("Bearer {}", token.expose_secret()))
                    .json_body(json!({
                        "api_version": "authentication.k8s.io/v1".to_string(),
                        "kind": "TokenReview".to_string(),
                        "spec": {
                            "token": token.expose_secret(),
                        },
                    }));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(rsp.clone());
            })
            .await;
        let mock_nok = mock_srv
            .mock_async(|when, then| {
                when.method("POST")
                    .path("/apis/authentication.k8s.io/v1/tokenreviews")
                    .header(
                        "authorization",
                        format!("Bearer {}", token2.expose_secret()),
                    )
                    .json_body(json!({
                        "api_version": "authentication.k8s.io/v1".to_string(),
                        "kind": "TokenReview".to_string(),
                        "spec": {
                            "token": token2.expose_secret(),
                        },
                    }));
                then.status(401);
            })
            .await;

        assert_eq!(
            rsp,
            provider.query_k8s_token_review(&token, &instance).await?,
            "response is just the whole json blob"
        );
        mock_ok.assert();

        if let Err(K8sAuthProviderError::InvalidToken) =
            provider.query_k8s_token_review(&token2, &instance).await
        {
            mock_nok.assert();
        } else {
            panic!("K8 returning 401 should result in InvalidToken");
        }

        Ok(())
    }

    #[test]
    fn test_extract_k8s_service_account() -> Result<()> {
        let provider = K8sAuthService {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_client_pool: Box::new(HttpClientPool::default()),
        };

        // Not authenticated
        if let Err(K8sAuthProviderError::InvalidToken) =
            provider.extract_k8s_service_account(&json!({"status": {"authenticated": false}}))
        {
        } else {
            panic!("not authenticated token should result in InvalidToken");
        }

        // No user
        if let Err(K8sAuthProviderError::InvalidTokenReviewResponse) =
            provider.extract_k8s_service_account(&json!({"status": {"authenticated": true}}))
        {
        } else {
            panic!("no user should result in InvalidTokenReviewResponse");
        }

        // Wrong username pattern
        if let Err(K8sAuthProviderError::InvalidTokenReviewResponse) = provider
            .extract_k8s_service_account(
                &json!({"status": {"authenticated": true, "user": {"username": "system"}}}),
            )
        {
        } else {
            panic!("wrong username pattern should result in InvalidTokenReviewResponse");
        }

        // Valid
        let (ns, sa) = provider.extract_k8s_service_account(&json!({"status": {"authenticated": true, "user": {"username": "system:serviceaccount:my_ns:my_sa"}}}))?;
        assert_eq!(ns, "my_ns");
        assert_eq!(sa, "my_sa");

        Ok(())
    }
}
