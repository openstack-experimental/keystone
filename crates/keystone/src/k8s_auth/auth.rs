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

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use chrono::Utc;
use jsonwebtoken::dangerous::insecure_decode;
use reqwest::{Certificate, Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tokio::fs;
use tracing::{debug, trace};

use crate::auth::AuthenticatedInfo;
use crate::identity::IdentityApi;
use crate::k8s_auth::{K8sAuthProvider, K8sAuthProviderError, types::*};
use crate::keystone::ServiceState;
use crate::token::TokenApi;

/// Kubernetes cluster CA certificate location.
static SERVICE_ACCOUNT_CERT_PATH_STR: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
static SERVICE_ACCOUNT_CERT_PATH: OnceLock<PathBuf> = OnceLock::new();
//&str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

impl K8sAuthProvider {
    /// Get the [`Client`] for communication with the K8.
    ///
    /// # Arguments
    /// * `configuration` - reference to the [`K8sAuthConfiguration`].
    /// * `ca_path` - optional reference to the CA_CERT location.
    ///
    /// # Returns
    /// * Success `Client` with the injected root CA certificate.
    /// * `K8sAuthProviderError::CaCertificateUnknown` when neither `ca_cert`,
    ///   nor the `ca_path` (or the default certificate location
    ///   (`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`) contain the
    ///   certificate content while the `disable_local_ca_jwt` of the
    ///   `K8sAuthConfiguration` is not `true`.
    #[tracing::instrument(skip(self, ca_path))]
    async fn get_or_create_client(
        &self,
        configuration: &K8sAuthConfiguration,
        ca_path: Option<PathBuf>,
    ) -> Result<Arc<Client>, K8sAuthProviderError> {
        // Check if we already have a pooled client
        {
            let read_guard = self.http_clients.read().await;
            if let Some(client) = read_guard.get(&configuration.id) {
                return Ok(Arc::clone(client));
            }
        }

        // Create a new one
        let mut client_builder = Client::builder()
            .gzip(true)
            // Optional: Set pool idle timeout or max connections
            .pool_idle_timeout(std::time::Duration::from_secs(90));

        // Determine the CA certificate for the K8 cluster
        if let Some(val) = &configuration.ca_cert {
            client_builder =
                client_builder.add_root_certificate(Certificate::from_pem(val.as_bytes())?);
        } else if !configuration.disable_local_ca_jwt {
            client_builder = client_builder.add_root_certificate(Certificate::from_pem(
                fs::read_to_string(ca_path.as_ref().unwrap_or_else(|| {
                    SERVICE_ACCOUNT_CERT_PATH
                        .get_or_init(|| PathBuf::from(SERVICE_ACCOUNT_CERT_PATH_STR))
                }))
                .await
                .map_err(|_| K8sAuthProviderError::CaCertificateUnknown)?
                .as_bytes(),
            )?);
        };

        // Build the client
        let shared_client = Arc::new(client_builder.build()?);

        // 3. Store it for future use
        let mut write_guard = self.http_clients.write().await;
        write_guard.insert(configuration.id.clone(), Arc::clone(&shared_client));

        Ok(shared_client)
    }

    /// Query the K8s Token Review endpoint.
    ///
    /// # Arguments
    /// * `token` - [`SecretString`] with the JWT token.
    /// * `configuration` - reference to the `K8sAuthConfiguration`.
    /// * `role` - reference to the `K8sAuthRole`.
    ///
    /// # Returns
    /// * Success with the TokenReview response as `Value`.
    /// * Error if the token is invalid (expired, audience mismatch, kubernetes
    ///   rejects the token).
    #[tracing::instrument(skip(self, token))]
    pub(super) async fn query_k8s_token_review(
        &self,
        token: &SecretString,
        configuration: &K8sAuthConfiguration,
        role: &K8sAuthRole,
    ) -> Result<Value, K8sAuthProviderError> {
        // Pre-flight check to fail early on expired token of wrong audience
        let claims = insecure_decode::<K8sClaims>(token.expose_secret())?;
        if let Some(aud) = &role.bound_audience
            && !claims.claims.aud.contains(&aud)
        {
            return Err(K8sAuthProviderError::AudienceMismatch);
        }
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
            .get_or_create_client(configuration, None)
            .await?
            .post(format!(
                "{}/apis/authentication.k8s.io/v1/tokenreviews",
                configuration.host
            ))
            .header("Authorization", format!("Bearer {}", token.expose_secret()))
            .json(&body)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK | StatusCode::CREATED => Ok(response.json().await?),
            _ => {
                debug!("Kubernetes returned {:?}", response);
                Err(K8sAuthProviderError::InvalidToken)
            }
        }
    }

    /// Validate K8s Token Review response.
    ///
    /// # Arguments
    /// * `token_review_data` - json representation of the TokenReview endpoint
    ///   response.
    /// * `role` - a reference to the required `K8sAuthRole`.
    ///
    /// # Returns
    /// * Success when the token data mapping is successful.
    /// * `K8sAuthProviderError::InvalidToken` when the kubernetes rejected the
    ///   token.
    /// * `K8sAuthProviderError::InvalidTokenReviewResponse` when the necessary
    ///   information cannot
    /// be retrieved from the `token_review_data`.
    /// * `K8sAuthProviderError::FailedBoundServiceAccountName` when the token
    ///   serviceaccount name does
    /// not match the `bound_service_account_names` of the role.
    /// * `K8sAuthProviderError::FailedBoundServiceAccountNamespace` when the
    ///   token namespace does
    /// not match the `bound_service_account_namespace` specified in the role.
    #[tracing::instrument(skip(self))]
    pub(super) fn check_k8s_token_review_response(
        &self,
        token_review_data: Value,
        role: &K8sAuthRole,
    ) -> Result<(), K8sAuthProviderError> {
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

        // Parse "system:serviceaccount:namespace:name"
        let parts: Vec<&str> = username.split(':').collect();

        // Validation: Username must follow the pattern:
        // "system:serviceaccount:<NS>:<SA>"
        match parts.as_slice() {
            ["system", "serviceaccount", ns, sa] => {
                // Verify role binds.
                if !role.bound_service_account_names.is_empty()
                    && !role.bound_service_account_names.iter().any(|x| x == sa)
                {
                    return Err(K8sAuthProviderError::FailedBoundServiceAccountName(
                        sa.to_string(),
                    ));
                }
                if !role.bound_service_account_namespaces.is_empty()
                    && !role
                        .bound_service_account_namespaces
                        .iter()
                        .any(|x| x == ns)
                {
                    return Err(K8sAuthProviderError::FailedBoundServiceAccountNamespace(
                        ns.to_string(),
                    ));
                }
                Ok(())
            }
            _ => Err(K8sAuthProviderError::InvalidTokenReviewResponse),
        }
    }

    /// Authenticate (exchange) the K8s Service account token.
    ///
    /// # Arguments
    /// * `state` - Service state.
    /// * `req` - A reference to the [`K8sAuthRequest`] to authenticate.
    pub(super) async fn authenticate(
        &self,
        state: &ServiceState,
        req: &K8sAuthRequest,
    ) -> Result<AuthenticatedInfo, K8sAuthProviderError> {
        // Fetch k8s configuration.
        let configuration = self
            .get_k8s_auth_configuration(state, &req.configuration_id)
            .await?
            .ok_or(K8sAuthProviderError::ConfigurationNotFound(
                req.configuration_id.clone(),
            ))?;
        if !configuration.enabled {
            return Err(K8sAuthProviderError::ConfigurationNotActive(
                req.configuration_id.clone(),
            ));
        }
        // Find the referred role.
        let role_list_params = K8sAuthRoleListParameters {
            auth_configuration_id: Some(req.configuration_id.clone()),
            domain_id: Some(configuration.domain_id.clone()),
            name: Some(req.role_name.clone()),
            ..Default::default()
        };
        let role = self
            .list_k8s_auth_roles(state, &role_list_params)
            .await?
            .first()
            .ok_or(K8sAuthProviderError::RoleNotFound(req.role_name.clone()))?
            .clone();
        if !role.enabled {
            return Err(K8sAuthProviderError::RoleNotActive(role.id.clone()));
        }
        if role.auth_configuration_id != configuration.id {
            return Err(K8sAuthProviderError::RoleConfigurationOwnershipMismatch(
                role.id.clone(),
            ));
        }

        // Call the TokenReview and check the response.
        let token_review_response = self
            .query_k8s_token_review(&req.jwt, &configuration, &role)
            .await?;
        self.check_k8s_token_review_response(token_review_response, &role)?;

        // Find the token restriction.
        let token_restriction = state
            .provider
            .get_token_provider()
            .get_token_restriction(state, &role.token_restriction_id, true)
            .await?
            .ok_or(K8sAuthProviderError::TokenRestrictionNotFound(
                role.token_restriction_id.clone(),
            ))?;
        let user_id = token_restriction
            .user_id
            .ok_or(K8sAuthProviderError::TokenRestrictionMustSpecifyUserId)?;
        let user = state
            .provider
            .get_identity_provider()
            .get_user(state, &user_id)
            .await?
            .ok_or(K8sAuthProviderError::UserNotFound(user_id.clone()))?;
        if !user.enabled {
            return Err(K8sAuthProviderError::UserDisabled(user_id.clone()));
        }

        let mut token_builder = AuthenticatedInfo::builder();
        token_builder.methods(vec!["mapped".to_string()]);
        token_builder.token_restriction_id(role.token_restriction_id.clone());
        token_builder.user_id(user_id);
        token_builder.user(user);

        Ok(token_builder.build()?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use eyre::Result;
    use httpmock::{Mock, MockServer};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use sea_orm::DatabaseConnection;
    use tempfile::NamedTempFile;
    use tokio::sync::RwLock;

    use super::super::backend::MockK8sAuthBackend;
    use super::super::tests::get_state_mock;
    use super::*;
    use crate::config::Config;
    use crate::identity::{MockIdentityProvider, types::*};
    use crate::keystone::Service;
    use crate::policy::MockPolicyFactory;
    use crate::provider::Provider;
    use crate::token::MockTokenProvider;
    use crate::token::types::TokenRestriction;

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

    // Prepare the test data for the post token-exchange validations
    async fn build_auth_test(
        token_mock: MockTokenProvider,
        identity_mock: MockIdentityProvider,
    ) -> Result<(K8sAuthProvider, Arc<Service>, SecretString, MockServer)> {
        let provider_mock = Provider::mocked_builder()
            .token(token_mock)
            .identity(identity_mock)
            .build()
            .unwrap();
        let mock_srv = MockServer::start_async().await;
        let state = Arc::new(Service::new(
            Config::default(),
            DatabaseConnection::Disconnected,
            provider_mock,
            MockPolicyFactory::default(),
        )?);
        let host = format!("http://{}:{}", mock_srv.host(), mock_srv.port());

        let mut backend = MockK8sAuthBackend::default();
        backend
            .expect_get_k8s_auth_configuration()
            .withf(|_, id: &'_ str| id == "cid")
            .returning(move |_, _| {
                Ok(Some(K8sAuthConfiguration {
                    ca_cert: None,
                    disable_local_ca_jwt: true,
                    domain_id: "did".into(),
                    enabled: true,
                    host: host.clone(),
                    id: "cid".into(),
                    name: Some("foo".into()),
                }))
            });
        backend
            .expect_list_k8s_auth_roles()
            .withf(|_, params: &K8sAuthRoleListParameters| {
                params.auth_configuration_id == Some("cid".to_string())
                    && params.domain_id == Some("did".to_string())
                    && params.name == Some("rn".to_string())
            })
            .returning(|_, _| {
                Ok(vec![K8sAuthRole {
                    auth_configuration_id: "cid".into(),
                    bound_audience: Some("aud".into()),
                    bound_service_account_names: Vec::new(),
                    bound_service_account_namespaces: Vec::new(),
                    domain_id: "did".into(),
                    enabled: true,
                    id: "rid".into(),
                    name: "foo".into(),
                    token_restriction_id: "trid".into(),
                }])
            });

        let provider = K8sAuthProvider {
            backend_driver: Arc::new(backend),
            http_clients: RwLock::new(HashMap::new()),
        };

        let token = SecretString::from(encode(
            &Header {
                nonce: Some(uuid::Uuid::new_v4().to_string()),
                ..Default::default()
            },
            &K8sClaims {
                aud: vec!["aud".into()],
                exp: (Utc::now() + Duration::seconds(10)).timestamp() as u64,
                sub: "system:serviceaccount:ns:san".into(),
            },
            &EncodingKey::from_secret("not_secret".as_ref()),
        )?);
        get_token_review_response_mock(&mock_srv, &token, true, "system:serviceaccount:ns:sa")
            .await;
        Ok((provider, state, token, mock_srv))
    }

    #[tokio::test]
    async fn test_get_or_create_client_with_ca() -> Result<()> {
        let provider = K8sAuthProvider {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_clients: RwLock::new(HashMap::new()),
        };
        let cfg = K8sAuthConfiguration {
            ca_cert: Some(CA_CERT.into()),
            disable_local_ca_jwt: false,
            domain_id: "did".into(),
            enabled: true,
            host: "127.0.0.1:6443".into(),
            id: "cid".into(),
            name: Some("foo".into()),
        };
        provider.get_or_create_client(&cfg, None).await?;
        {
            let read_guard = provider.http_clients.read().await;
            assert!(read_guard.contains_key(&cfg.id));
        }
        // Repeat the get, now it should be returned from the cache
        provider.get_or_create_client(&cfg, None).await?;

        // Test with the CA and disable_local_ca_jwt
        let cfg = K8sAuthConfiguration {
            ca_cert: Some(CA_CERT.into()),
            disable_local_ca_jwt: true,
            domain_id: "did".into(),
            enabled: true,
            host: "127.0.0.1:6443".into(),
            id: "cid1".into(),
            name: Some("foo".into()),
        };
        assert!(provider.get_or_create_client(&cfg, None).await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_or_create_client_k8s_ca() -> Result<()> {
        let provider = K8sAuthProvider {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_clients: RwLock::new(HashMap::new()),
        };
        let cfg = K8sAuthConfiguration {
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
                .get_or_create_client(&cfg, Some(file.path().to_path_buf()))
                .await
                .is_ok()
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_get_or_create_client_error_no_ca() -> Result<()> {
        let provider = K8sAuthProvider {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_clients: RwLock::new(HashMap::new()),
        };
        let cfg = K8sAuthConfiguration {
            ca_cert: None,
            disable_local_ca_jwt: false,
            domain_id: "did".into(),
            enabled: true,
            host: "127.0.0.1:6443".into(),
            id: "cid".into(),
            name: Some("foo".into()),
        };
        if let Err(K8sAuthProviderError::CaCertificateUnknown) =
            provider.get_or_create_client(&cfg, None).await
        {
        } else {
            panic!("should have raised an error");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_get_or_create_client_disable_local_ca_jwt() -> Result<()> {
        let provider = K8sAuthProvider {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_clients: RwLock::new(HashMap::new()),
        };
        let cfg = K8sAuthConfiguration {
            ca_cert: None,
            disable_local_ca_jwt: true,
            domain_id: "did".into(),
            enabled: true,
            host: "127.0.0.1:6443".into(),
            id: "cid".into(),
            name: Some("foo".into()),
        };
        assert!(provider.get_or_create_client(&cfg, None).await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_query_k8s_token_review_aud_mismatch() -> Result<()> {
        let provider = K8sAuthProvider {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_clients: RwLock::new(HashMap::new()),
        };
        let cfg = K8sAuthConfiguration {
            ca_cert: None,
            disable_local_ca_jwt: true,
            domain_id: "did".into(),
            enabled: true,
            host: "http://127.0.0.1:6443".into(),
            id: "cid".into(),
            name: Some("foo".into()),
        };
        let role = K8sAuthRole {
            auth_configuration_id: "cid".into(),
            bound_audience: Some("other_aud".into()),
            bound_service_account_names: Vec::new(),
            bound_service_account_namespaces: Vec::new(),
            domain_id: "did".into(),
            enabled: true,
            id: "rid".into(),
            name: "foo".into(),
            token_restriction_id: "trid".into(),
        };
        let claims = K8sClaims {
            aud: vec!["aud".into()],
            exp: (Utc::now() + Duration::seconds(10)).timestamp() as u64,
            sub: "system:serviceaccount:ns:san".into(),
        };
        let token = SecretString::from(encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("not_secret".as_ref()),
        )?);

        if let Err(K8sAuthProviderError::AudienceMismatch) =
            provider.query_k8s_token_review(&token, &cfg, &role).await
        {
        } else {
            panic!("should have raised an error");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_query_k8s_token_review_expired() -> Result<()> {
        let provider = K8sAuthProvider {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_clients: RwLock::new(HashMap::new()),
        };
        let cfg = K8sAuthConfiguration {
            ca_cert: None,
            disable_local_ca_jwt: true,
            domain_id: "did".into(),
            enabled: true,
            host: "http://127.0.0.1:6443".into(),
            id: "cid".into(),
            name: Some("foo".into()),
        };
        let role = K8sAuthRole {
            auth_configuration_id: "cid".into(),
            bound_audience: Some("aud".into()),
            bound_service_account_names: Vec::new(),
            bound_service_account_namespaces: Vec::new(),
            domain_id: "did".into(),
            enabled: true,
            id: "rid".into(),
            name: "foo".into(),
            token_restriction_id: "trid".into(),
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
            provider.query_k8s_token_review(&token, &cfg, &role).await
        {
        } else {
            panic!("should have raised an error");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_query_k8s_token_review() -> Result<()> {
        let provider = K8sAuthProvider {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_clients: RwLock::new(HashMap::new()),
        };
        let mock_srv = MockServer::start_async().await;
        let cfg = K8sAuthConfiguration {
            ca_cert: None,
            disable_local_ca_jwt: true,
            domain_id: "did".into(),
            enabled: true,
            host: format!("http://{}:{}", mock_srv.host(), mock_srv.port()),
            id: "cid".into(),
            name: Some("foo".into()),
        };
        let role = K8sAuthRole {
            auth_configuration_id: "cid".into(),
            bound_audience: Some("aud".into()),
            bound_service_account_names: Vec::new(),
            bound_service_account_namespaces: Vec::new(),
            domain_id: "did".into(),
            enabled: true,
            id: "rid".into(),
            name: "foo".into(),
            token_restriction_id: "trid".into(),
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
            provider.query_k8s_token_review(&token, &cfg, &role).await?,
            "response is just the whole json blob"
        );
        mock_ok.assert();

        if let Err(K8sAuthProviderError::InvalidToken) =
            provider.query_k8s_token_review(&token2, &cfg, &role).await
        {
            mock_nok.assert();
        } else {
            panic!("K8 returning 401 should result in InvalidToken");
        }

        Ok(())
    }

    #[test]
    fn test_check_k8s_token_review_response() {
        let provider = K8sAuthProvider {
            backend_driver: Arc::new(MockK8sAuthBackend::default()),
            http_clients: RwLock::new(HashMap::new()),
        };

        let role = K8sAuthRole {
            auth_configuration_id: "cid".into(),
            bound_audience: Some("aud".into()),
            bound_service_account_names: vec!["sa".to_string()],
            bound_service_account_namespaces: vec!["ns".to_string()],
            domain_id: "did".into(),
            enabled: true,
            id: "rid".into(),
            name: "foo".into(),
            token_restriction_id: "trid".into(),
        };

        if let Err(K8sAuthProviderError::InvalidToken) = provider
            .check_k8s_token_review_response(json!({"status": {"authenticated": false}}), &role)
        {
        } else {
            panic!("not authenticated token should result in InvalidToken");
        }
        if let Err(K8sAuthProviderError::InvalidTokenReviewResponse) = provider
            .check_k8s_token_review_response(json!({"status": {"authenticated": true}}), &role)
        {
        } else {
            panic!("no user should result in InvalidTokenReviewResponse");
        }
        if let Err(K8sAuthProviderError::FailedBoundServiceAccountName(x)) = provider
            .check_k8s_token_review_response(json!({"status": {"authenticated": true, "user": {"username": "system:serviceaccount:ns:sub"}}}), &role)
        {
            assert_eq!("sub", x);
        } else {
            panic!("mismatching bound_service_account_names should result in FailedBoundServiceAccountName");
        }
        if let Err(K8sAuthProviderError::FailedBoundServiceAccountNamespace(x)) = provider
            .check_k8s_token_review_response(json!({"status": {"authenticated": true, "user": {"username": "system:serviceaccount:other_ns:sa"}}}), &role)
        {
            assert_eq!("other_ns", x);
        } else {
            panic!("mismatching bound_service_account_namespaces should result in FailedBoundServiceAccountNamespace");
        }
        if let Err(K8sAuthProviderError::InvalidTokenReviewResponse) = provider
            .check_k8s_token_review_response(
                json!({"status": {"authenticated": true, "user": {"username": "system"}}}),
                &role,
            )
        {
        } else {
            panic!("wrong username pattern should result in FailedBoundServiceAccountName");
        }
        assert!(provider
            .check_k8s_token_review_response(
                json!({"status": {"authenticated": true, "user": {"username": "system:serviceaccount:ns:sa"}}}),
                &K8sAuthRole {
                    auth_configuration_id: "cid".into(),
                    bound_audience: Some("aud".into()),
                    bound_service_account_names: Vec::new(),
                    bound_service_account_namespaces: Vec::new(),
                    domain_id: "did".into(),
                    enabled: true,
                    id: "rid".into(),
                    name: "foo".into(),
                    token_restriction_id: "trid".into(),
                }
            ).is_ok(), "role without binds should be ok");
        assert!(provider
            .check_k8s_token_review_response(
                json!({"status": {"authenticated": true, "user": {"username": "system:serviceaccount:ns:sa"}}}),
                &K8sAuthRole {
                    auth_configuration_id: "cid".into(),
                    bound_audience: Some("aud".into()),
                    bound_service_account_names: Vec::new(),
                    bound_service_account_namespaces: vec!["ns".to_string()],
                    domain_id: "did".into(),
                    enabled: true,
                    id: "rid".into(),
                    name: "foo".into(),
                    token_restriction_id: "trid".into(),
                }
            ).is_ok(), "role without bound_service_account_names should be ok");
        assert!(provider
            .check_k8s_token_review_response(
                json!({"status": {"authenticated": true, "user": {"username": "system:serviceaccount:ns:sa"}}}),
                &K8sAuthRole {
                    auth_configuration_id: "cid".into(),
                    bound_audience: Some("aud".into()),
                    bound_service_account_names: vec!["sa".to_string()],
                    bound_service_account_namespaces: Vec::new(),
                    domain_id: "did".into(),
                    enabled: true,
                    id: "rid".into(),
                    name: "foo".into(),
                    token_restriction_id: "trid".into(),
                }
            ).is_ok(), "role without bound_service_account_namespaces should be ok");
    }

    #[tokio::test]
    async fn test_auth_conf_not_found() {
        let state = get_state_mock();
        let mut backend = MockK8sAuthBackend::default();
        backend
            .expect_get_k8s_auth_configuration()
            .withf(|_, id: &'_ str| id == "cid")
            .returning(|_, _| Ok(None));
        let provider = K8sAuthProvider {
            backend_driver: Arc::new(backend),
            http_clients: RwLock::new(HashMap::new()),
        };

        if let Err(K8sAuthProviderError::ConfigurationNotFound(x)) = provider
            .authenticate_by_k8s_sa_token(
                &state,
                &K8sAuthRequest {
                    configuration_id: "cid".into(),
                    jwt: SecretString::from("secret"),
                    role_name: "rn".into(),
                },
            )
            .await
        {
            assert_eq!("cid", x);
        } else {
            panic!("ConfigurationNotFound expected");
        };
    }

    #[tokio::test]
    async fn test_auth_role_not_found() {
        let state = get_state_mock();
        let mut backend = MockK8sAuthBackend::default();
        backend
            .expect_get_k8s_auth_configuration()
            .withf(|_, id: &'_ str| id == "cid")
            .returning(|_, _| {
                Ok(Some(K8sAuthConfiguration {
                    ca_cert: None,
                    disable_local_ca_jwt: true,
                    domain_id: "did".into(),
                    enabled: true,
                    host: "http://foo:6443".into(),
                    id: "cid".into(),
                    name: Some("foo".into()),
                }))
            });
        backend
            .expect_list_k8s_auth_roles()
            .withf(|_, params: &K8sAuthRoleListParameters| {
                params.auth_configuration_id == Some("cid".to_string())
                    && params.domain_id == Some("did".to_string())
                    && params.name == Some("rn".to_string())
            })
            .returning(|_, _| Ok(vec![]));

        let provider = K8sAuthProvider {
            backend_driver: Arc::new(backend),
            http_clients: RwLock::new(HashMap::new()),
        };

        if let Err(K8sAuthProviderError::RoleNotFound(x)) = provider
            .authenticate_by_k8s_sa_token(
                &state,
                &K8sAuthRequest {
                    configuration_id: "cid".into(),
                    jwt: SecretString::from("secret"),
                    role_name: "rn".into(),
                },
            )
            .await
        {
            assert_eq!("rn", x);
        } else {
            panic!("ConfigurationNotFound expected");
        };
    }

    #[tokio::test]
    async fn test_auth_conf_or_role_disabled() {
        let state = get_state_mock();
        let mut backend = MockK8sAuthBackend::default();
        backend
            .expect_get_k8s_auth_configuration()
            .withf(|_, id: &'_ str| id == "cid")
            .returning(|_, _| {
                Ok(Some(K8sAuthConfiguration {
                    ca_cert: None,
                    disable_local_ca_jwt: true,
                    domain_id: "did".into(),
                    enabled: true,
                    host: "http://foo:6443".into(),
                    id: "cid".into(),
                    name: Some("foo".into()),
                }))
            });
        backend
            .expect_get_k8s_auth_configuration()
            .withf(|_, id: &'_ str| id == "cid_disabled")
            .returning(|_, _| {
                Ok(Some(K8sAuthConfiguration {
                    ca_cert: None,
                    disable_local_ca_jwt: true,
                    domain_id: "did".into(),
                    enabled: false,
                    host: "http://foo:6443".into(),
                    id: "cid_disabled".into(),
                    name: Some("foo".into()),
                }))
            });
        backend
            .expect_list_k8s_auth_roles()
            .withf(|_, params: &K8sAuthRoleListParameters| {
                params.auth_configuration_id == Some("cid".to_string())
                    && params.domain_id == Some("did".to_string())
                    && params.name == Some("rn".to_string())
            })
            .returning(|_, _| {
                Ok(vec![K8sAuthRole {
                    auth_configuration_id: "cid_other".into(),
                    bound_audience: Some("aud".into()),
                    bound_service_account_names: vec!["sa".to_string()],
                    bound_service_account_namespaces: Vec::new(),
                    domain_id: "did".into(),
                    enabled: true,
                    id: "rid".into(),
                    name: "foo".into(),
                    token_restriction_id: "trid".into(),
                }])
            });
        backend
            .expect_list_k8s_auth_roles()
            .withf(|_, params: &K8sAuthRoleListParameters| {
                params.auth_configuration_id == Some("cid".to_string())
                    && params.domain_id == Some("did".to_string())
                    && params.name == Some("rn_disabled".to_string())
            })
            .returning(|_, _| {
                Ok(vec![K8sAuthRole {
                    auth_configuration_id: "cid".into(),
                    bound_audience: Some("aud".into()),
                    bound_service_account_names: vec!["sa".to_string()],
                    bound_service_account_namespaces: Vec::new(),
                    domain_id: "did".into(),
                    enabled: false,
                    id: "rid_disabled".into(),
                    name: "foo".into(),
                    token_restriction_id: "trid".into(),
                }])
            });

        let provider = K8sAuthProvider {
            backend_driver: Arc::new(backend),
            http_clients: RwLock::new(HashMap::new()),
        };

        // verify disabled configuration is checked
        if let Err(K8sAuthProviderError::ConfigurationNotActive(x)) = provider
            .authenticate_by_k8s_sa_token(
                &state,
                &K8sAuthRequest {
                    configuration_id: "cid_disabled".into(),
                    jwt: SecretString::from("secret"),
                    role_name: "rn".into(),
                },
            )
            .await
        {
            assert_eq!("cid_disabled", x);
        } else {
            panic!("ConfigurationNotActive expected");
        };
        // verify disabled role is checked
        if let Err(K8sAuthProviderError::RoleNotActive(x)) = provider
            .authenticate_by_k8s_sa_token(
                &state,
                &K8sAuthRequest {
                    configuration_id: "cid".into(),
                    jwt: SecretString::from("secret"),
                    role_name: "rn_disabled".into(),
                },
            )
            .await
        {
            assert_eq!("rid_disabled", x);
        } else {
            panic!("RoleNotActive expected");
        };
        // verify role.configuration_id = configuration.id is checked
        if let Err(K8sAuthProviderError::RoleConfigurationOwnershipMismatch(x)) = provider
            .authenticate_by_k8s_sa_token(
                &state,
                &K8sAuthRequest {
                    configuration_id: "cid".into(),
                    jwt: SecretString::from("secret"),
                    role_name: "rn".into(),
                },
            )
            .await
        {
            assert_eq!("rid", x);
        } else {
            panic!("RoleConfigurationOwnershipMismatch expected");
        };
    }

    #[tokio::test]
    async fn test_auth() -> Result<()> {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_get_token_restriction()
            .withf(|_, id: &'_ str, expand: &bool| id == "trid" && *expand)
            .returning(|_, _, _| {
                Ok(Some(TokenRestriction {
                    id: "trid".into(),
                    domain_id: "did".into(),
                    project_id: Some("pid".into()),
                    user_id: Some("uid".into()),
                    ..Default::default()
                }))
            });

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(move |_, id: &'_ str| id == "uid")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .domain_id("did")
                        .enabled(true)
                        .name("name")
                        .id("uid")
                        .build()?,
                ))
            });

        let (provider, state, token, _mock_server) =
            build_auth_test(token_mock, identity_mock).await?;
        let auth_info = provider
            .authenticate_by_k8s_sa_token(
                &state,
                &K8sAuthRequest {
                    configuration_id: "cid".into(),
                    jwt: token.clone(),
                    role_name: "rn".into(),
                },
            )
            .await?;
        assert_eq!("uid", auth_info.user_id);
        assert_eq!(vec!["mapped".to_string()], auth_info.methods);
        assert_eq!("trid".to_string(), auth_info.token_restriction_id.unwrap());

        Ok(())
    }

    #[tokio::test]
    async fn test_auth_tr_not_found() -> Result<()> {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_get_token_restriction()
            .withf(|_, id: &'_ str, expand: &bool| id == "trid" && *expand)
            .returning(|_, _, _| Ok(None));

        let identity_mock = MockIdentityProvider::default();
        let (provider, state, token, _mock_server) =
            build_auth_test(token_mock, identity_mock).await?;

        match provider
            .authenticate_by_k8s_sa_token(
                &state,
                &K8sAuthRequest {
                    configuration_id: "cid".into(),
                    jwt: token.clone(),
                    role_name: "rn".into(),
                },
            )
            .await
        {
            Err(K8sAuthProviderError::TokenRestrictionNotFound(x)) => {
                assert_eq!("trid", x);
            }
            other => {
                panic!(
                    "token restriction not found should return error and not {:?}",
                    other
                );
            }
        };

        Ok(())
    }

    #[tokio::test]
    async fn test_auth_trid_user_unset() -> Result<()> {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_get_token_restriction()
            .withf(|_, id: &'_ str, expand: &bool| id == "trid" && *expand)
            .returning(|_, _, _| {
                Ok(Some(TokenRestriction {
                    id: "trid".into(),
                    domain_id: "did".into(),
                    project_id: Some("pid".into()),
                    user_id: None,
                    ..Default::default()
                }))
            });
        let identity_mock = MockIdentityProvider::default();

        let (provider, state, token, _mock_server) =
            build_auth_test(token_mock, identity_mock).await?;

        match provider
            .authenticate_by_k8s_sa_token(
                &state,
                &K8sAuthRequest {
                    configuration_id: "cid".into(),
                    jwt: token.clone(),
                    role_name: "rn".into(),
                },
            )
            .await
        {
            Err(K8sAuthProviderError::TokenRestrictionMustSpecifyUserId) => {}
            _ => {
                panic!("user must be specified in the TokenRestriction and");
            }
        };

        Ok(())
    }

    #[tokio::test]
    async fn test_auth_user_not_found() -> Result<()> {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_get_token_restriction()
            .withf(|_, id: &'_ str, expand: &bool| id == "trid" && *expand)
            .returning(|_, _, _| {
                Ok(Some(TokenRestriction {
                    id: "trid".into(),
                    domain_id: "did".into(),
                    project_id: Some("pid".into()),
                    user_id: Some("uid".into()),
                    ..Default::default()
                }))
            });

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(|_, id: &'_ str| id == "uid")
            .returning(|_, _| Ok(None));

        let (provider, state, token, _mock_server) =
            build_auth_test(token_mock, identity_mock).await?;

        match provider
            .authenticate_by_k8s_sa_token(
                &state,
                &K8sAuthRequest {
                    configuration_id: "cid".into(),
                    jwt: token.clone(),
                    role_name: "rn".into(),
                },
            )
            .await
        {
            Err(K8sAuthProviderError::UserNotFound(x)) => {
                assert_eq!("uid", x);
            }
            other => {
                panic!("user not found should return error and not {:?}", other);
            }
        };

        Ok(())
    }

    #[tokio::test]
    async fn test_auth_user_disabled() -> Result<()> {
        let mut token_mock = MockTokenProvider::default();
        token_mock
            .expect_get_token_restriction()
            .withf(|_, id: &'_ str, expand: &bool| id == "trid" && *expand)
            .returning(|_, _, _| {
                Ok(Some(TokenRestriction {
                    id: "trid".into(),
                    domain_id: "did".into(),
                    project_id: Some("pid".into()),
                    user_id: Some("uid".into()),
                    ..Default::default()
                }))
            });

        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user()
            .withf(move |_, id: &'_ str| id == "uid")
            .returning(|_, _| {
                Ok(Some(
                    UserResponseBuilder::default()
                        .domain_id("did")
                        .enabled(false)
                        .name("name")
                        .id("uid")
                        .build()?,
                ))
            });
        let (provider, state, token, _mock_server) =
            build_auth_test(token_mock, identity_mock).await?;

        match provider
            .authenticate_by_k8s_sa_token(
                &state,
                &K8sAuthRequest {
                    configuration_id: "cid".into(),
                    jwt: token.clone(),
                    role_name: "rn".into(),
                },
            )
            .await
        {
            Err(K8sAuthProviderError::UserDisabled(x)) => {
                assert_eq!("uid", x);
            }
            _ => {
                panic!("disabled user should not be allowed to login");
            }
        };

        Ok(())
    }
}
