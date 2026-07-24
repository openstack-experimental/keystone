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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use config::{Value, ValueKind};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use thiserror::Error;
use tokio::time::Instant;
use url::Url;
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

const DEFAULT_REFRESH_INTERVAL_SECONDS: u64 = 60;

fn default_refresh_interval_seconds() -> u64 {
    DEFAULT_REFRESH_INTERVAL_SECONDS
}

/// Bootstrap configuration for direct Vault access.
#[derive(Clone, Debug, Deserialize)]
pub struct VaultSection {
    /// Vault server URL.
    pub address: Url,
    /// Vault token. Prefer setting this through `OS_VAULT__TOKEN`.
    pub token: SecretString,
    /// Optional Vault Enterprise namespace.
    #[serde(default)]
    pub namespace: Option<String>,
    /// How often KV v2 metadata is polled for a newer version.
    #[serde(default = "default_refresh_interval_seconds")]
    pub refresh_interval_seconds: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SecretPath {
    mount: String,
    path: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct VaultReference {
    secret: SecretPath,
    key: String,
}

#[derive(Debug, Error)]
pub(crate) enum VaultConfigError {
    #[error("invalid Vault reference")]
    InvalidReference,
    #[error("Vault references require a [vault] configuration section")]
    MissingConfiguration,
    #[error("invalid [vault] configuration")]
    InvalidConfiguration,
    #[error("Vault token must not be empty")]
    EmptyToken,
    #[error("Vault refresh_interval_seconds must be greater than zero")]
    InvalidRefreshInterval,
    #[error("failed to initialize Vault client")]
    ClientInitialization,
    #[error("Vault token authentication failed")]
    Authentication,
    #[error("failed to read referenced Vault secret")]
    SecretRead,
    #[error("referenced Vault key was not found")]
    MissingKey,
    #[error("referenced Vault value must be a string")]
    NonStringValue,
    #[error("failed to poll Vault secret metadata")]
    MetadataRead,
    #[error("Vault token renewal failed")]
    TokenRenewal,
    #[error("Vault token revocation failed")]
    TokenRevocation,
    #[error("configuration is invalid after resolving Vault references")]
    ResolvedConfigurationInvalid,
}

#[derive(Debug)]
struct RenewalState {
    next: Instant,
    ttl: Duration,
}

/// Runtime state retained by the configuration manager.
pub(crate) struct VaultRuntime {
    client: Arc<VaultClient>,
    secret_versions: HashMap<SecretPath, u64>,
    refresh_interval: Duration,
    next_poll: Instant,
    renewal: Option<RenewalState>,
}

impl VaultRuntime {
    pub(crate) fn next_deadline(&self) -> Instant {
        self.renewal
            .as_ref()
            .map(|renewal| renewal.next.min(self.next_poll))
            .unwrap_or(self.next_poll)
    }

    /// Revoke the Vault token via `auth/token/revoke-self`.
    ///
    /// Called during graceful shutdown to invalidate the token (and any
    /// leases created with it) immediately, rather than leaving it valid
    /// until its TTL expires. Best-effort: the process is stopping, so a
    /// failure is surfaced to the caller for logging but cannot be retried.
    pub(crate) async fn revoke(&self) -> Result<(), VaultConfigError> {
        self.client
            .revoke()
            .await
            .map_err(|_| VaultConfigError::TokenRevocation)
    }

    pub(crate) async fn renew_if_due(&mut self) -> Result<(), VaultConfigError> {
        let Some(renewal) = &self.renewal else {
            return Ok(());
        };
        if Instant::now() < renewal.next {
            return Ok(());
        }

        let previous_ttl = renewal.ttl;
        match self.client.renew(None).await {
            Ok(auth) => {
                let ttl = Duration::from_secs(auth.lease_duration.max(1));
                self.renewal = auth.renewable.then(|| RenewalState {
                    next: Instant::now() + half_ttl(ttl),
                    ttl,
                });
                Ok(())
            }
            Err(_) => {
                let retry = half_ttl(previous_ttl).min(self.refresh_interval);
                if let Some(renewal) = &mut self.renewal {
                    renewal.next = Instant::now() + retry.max(Duration::from_secs(1));
                }
                Err(VaultConfigError::TokenRenewal)
            }
        }
    }

    pub(crate) async fn has_new_version(&mut self) -> Result<bool, VaultConfigError> {
        if Instant::now() < self.next_poll {
            return Ok(false);
        }
        self.next_poll = Instant::now() + self.refresh_interval;

        for (secret, current_version) in &self.secret_versions {
            let metadata = kv2::read_metadata(&*self.client, &secret.mount, &secret.path)
                .await
                .map_err(|_| VaultConfigError::MetadataRead)?;
            if metadata.current_version > *current_version {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

pub(crate) struct ResolvedVault {
    pub(crate) runtime: VaultRuntime,
}

fn half_ttl(ttl: Duration) -> Duration {
    Duration::from_secs((ttl.as_secs() / 2).max(1))
}

fn parse_reference(value: &str) -> Result<VaultReference, VaultConfigError> {
    let url = Url::parse(value).map_err(|_| VaultConfigError::InvalidReference)?;
    if url.scheme() != "vault"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
    {
        return Err(VaultConfigError::InvalidReference);
    }

    let mount = url
        .host_str()
        .filter(|mount| !mount.is_empty())
        .ok_or(VaultConfigError::InvalidReference)?;
    let path = url.path().strip_prefix('/').unwrap_or(url.path());
    let key = url
        .fragment()
        .filter(|key| !key.is_empty())
        .ok_or(VaultConfigError::InvalidReference)?;
    if path.is_empty() || path.ends_with('/') {
        return Err(VaultConfigError::InvalidReference);
    }

    Ok(VaultReference {
        secret: SecretPath {
            mount: mount.to_string(),
            path: path.to_string(),
        },
        key: key.to_string(),
    })
}

fn visit_references(
    value: &Value,
    references: &mut HashSet<VaultReference>,
    at_root: bool,
) -> Result<(), VaultConfigError> {
    match &value.kind {
        ValueKind::String(value) if value.starts_with("vault://") => {
            references.insert(parse_reference(value)?);
        }
        ValueKind::Table(table) => {
            for (key, value) in table {
                if at_root && key == "vault" {
                    continue;
                }
                visit_references(value, references, false)?;
            }
        }
        ValueKind::Array(values) => {
            for value in values {
                visit_references(value, references, false)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn contains_vault_references(value: &Value) -> Result<bool, VaultConfigError> {
    let mut references = HashSet::new();
    visit_references(value, &mut references, true)?;
    Ok(!references.is_empty())
}

fn replace_references(
    value: &mut Value,
    secrets: &HashMap<SecretPath, HashMap<String, serde_json::Value>>,
    at_root: bool,
) -> Result<(), VaultConfigError> {
    match &mut value.kind {
        ValueKind::String(current) if current.starts_with("vault://") => {
            let reference = parse_reference(current)?;
            let resolved = secrets
                .get(&reference.secret)
                .and_then(|secret| secret.get(&reference.key))
                .ok_or(VaultConfigError::MissingKey)?;
            let resolved = resolved.as_str().ok_or(VaultConfigError::NonStringValue)?;
            *current = resolved.to_string();
        }
        ValueKind::Table(table) => {
            for (key, value) in table {
                if at_root && key == "vault" {
                    continue;
                }
                replace_references(value, secrets, false)?;
            }
        }
        ValueKind::Array(values) => {
            for value in values {
                replace_references(value, secrets, false)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) async fn resolve(
    raw: &mut config::Config,
    vault: &VaultSection,
) -> Result<ResolvedVault, VaultConfigError> {
    if vault.token.expose_secret().is_empty() {
        return Err(VaultConfigError::EmptyToken);
    }
    if vault.refresh_interval_seconds == 0 {
        return Err(VaultConfigError::InvalidRefreshInterval);
    }

    let mut references = HashSet::new();
    visit_references(&raw.cache, &mut references, true)?;

    let mut settings = VaultClientSettingsBuilder::default();
    settings
        .address(vault.address.as_str())
        .token(vault.token.expose_secret());
    if let Some(namespace) = &vault.namespace {
        settings.set_namespace(namespace.clone());
    }
    let settings = settings
        .build()
        .map_err(|_| VaultConfigError::ClientInitialization)?;
    let client =
        Arc::new(VaultClient::new(settings).map_err(|_| VaultConfigError::ClientInitialization)?);

    let token = client
        .lookup()
        .await
        .map_err(|_| VaultConfigError::Authentication)?;
    let renewal = token
        .renewable
        .unwrap_or(false)
        .then_some(token.ttl)
        .filter(|ttl| *ttl > 0)
        .map(|ttl| {
            let ttl = Duration::from_secs(ttl);
            RenewalState {
                next: Instant::now() + half_ttl(ttl),
                ttl,
            }
        });

    let secret_paths: HashSet<_> = references
        .iter()
        .map(|reference| reference.secret.clone())
        .collect();
    let mut secrets = HashMap::new();
    let mut secret_versions = HashMap::new();
    for secret in secret_paths {
        let metadata = kv2::read_metadata(&*client, &secret.mount, &secret.path)
            .await
            .map_err(|_| VaultConfigError::SecretRead)?;
        let data = kv2::read_version::<HashMap<String, serde_json::Value>>(
            &*client,
            &secret.mount,
            &secret.path,
            metadata.current_version,
        )
        .await
        .map_err(|_| VaultConfigError::SecretRead)?;
        secret_versions.insert(secret.clone(), metadata.current_version);
        secrets.insert(secret, data);
    }

    replace_references(&mut raw.cache, &secrets, true)?;
    let refresh_interval = Duration::from_secs(vault.refresh_interval_seconds);
    Ok(ResolvedVault {
        runtime: VaultRuntime {
            client,
            secret_versions,
            refresh_interval,
            next_poll: Instant::now() + refresh_interval,
            renewal,
        },
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use config::{File, FileFormat};
    use httpmock::{Method::GET, Method::POST, Mock, MockServer};
    use serde_json::json;

    use super::*;

    pub(crate) fn mock_lookup(server: &MockServer, renewable: bool, ttl: u64) -> Mock<'_> {
        server.mock(|when, then| {
            when.method(GET).path("/v1/auth/token/lookup-self");
            then.status(200).json_body(json!({
                "request_id": "request",
                "lease_id": "",
                "lease_duration": 0,
                "renewable": false,
                "data": {
                    "accessor": "accessor",
                    "creation_time": 1,
                    "creation_ttl": ttl,
                    "display_name": "token",
                    "entity_id": "entity",
                    "expire_time": null,
                    "explicit_max_ttl": 0,
                    "id": "redacted",
                    "identity_policies": null,
                    "issue_time": null,
                    "meta": null,
                    "num_uses": 0,
                    "orphan": true,
                    "path": "auth/token/create",
                    "policies": ["default"],
                    "renewable": renewable,
                    "role": null,
                    "ttl": ttl
                },
                "wrap_info": null,
                "warnings": null,
                "auth": null
            }));
        })
    }

    pub(crate) fn mock_metadata(server: &MockServer, version: u64) -> Mock<'_> {
        server.mock(|when, then| {
            when.method(GET)
                .path("/v1/secret/metadata/keystone/database");
            then.status(200).json_body(json!({
                "request_id": "request",
                "lease_id": "",
                "lease_duration": 0,
                "renewable": false,
                "data": {
                    "cas_required": false,
                    "created_time": "2026-01-01T00:00:00Z",
                    "current_version": version,
                    "delete_version_after": "0s",
                    "max_versions": 0,
                    "oldest_version": 0,
                    "updated_time": "2026-01-01T00:00:00Z",
                    "custom_metadata": null,
                    "versions": {}
                },
                "wrap_info": null,
                "warnings": null,
                "auth": null
            }));
        })
    }

    pub(crate) fn mock_secret(
        server: &MockServer,
        version: u64,
        data: serde_json::Value,
    ) -> Mock<'_> {
        server.mock(|when, then| {
            when.method(GET)
                .path("/v1/secret/data/keystone/database")
                .query_param("version", version.to_string());
            then.status(200).json_body(json!({
                "request_id": "request",
                "lease_id": "",
                "lease_duration": 0,
                "renewable": false,
                "data": {
                    "data": data,
                    "metadata": {
                        "created_time": "2026-01-01T00:00:00Z",
                        "deletion_time": "",
                        "destroyed": false,
                        "version": version
                    }
                },
                "wrap_info": null,
                "warnings": null,
                "auth": null
            }));
        })
    }

    pub(crate) fn mock_renew(server: &MockServer, ttl: u64) -> Mock<'_> {
        server.mock(|when, then| {
            when.method(POST).path("/v1/auth/token/renew-self");
            then.status(200).json_body(json!({
                "request_id": "request",
                "lease_id": "",
                "lease_duration": 0,
                "renewable": false,
                "data": null,
                "wrap_info": null,
                "warnings": null,
                "auth": {
                    "client_token": "redacted",
                    "accessor": "accessor",
                    "policies": ["default"],
                    "token_policies": ["default"],
                    "metadata": null,
                    "lease_duration": ttl,
                    "renewable": true,
                    "entity_id": "entity",
                    "token_type": "service",
                    "orphan": true
                }
            }));
        })
    }

    pub(crate) fn mock_revoke(server: &MockServer) -> Mock<'_> {
        server.mock(|when, then| {
            when.method(POST).path("/v1/auth/token/revoke-self");
            then.status(204);
        })
    }

    fn test_vault(server: &MockServer, refresh_interval_seconds: u64) -> VaultSection {
        VaultSection {
            address: Url::parse(&server.base_url()).unwrap(),
            token: SecretString::from("test-token"),
            namespace: None,
            refresh_interval_seconds,
        }
    }

    #[test]
    fn parses_complete_reference() {
        let reference = parse_reference("vault://secret/keystone/database#password").unwrap();
        assert_eq!(reference.secret.mount, "secret");
        assert_eq!(reference.secret.path, "keystone/database");
        assert_eq!(reference.key, "password");
    }

    #[test]
    fn rejects_incomplete_or_ambiguous_references() {
        for value in [
            "vault:///path#key",
            "vault://mount#key",
            "vault://mount/path",
            "vault://mount/path#",
            "vault://user@mount/path#key",
            "vault://mount:8200/path#key",
            "vault://mount/path?version=1#key",
            "vault://mount/path/#key",
        ] {
            assert!(parse_reference(value).is_err(), "accepted {value}");
        }
    }

    #[tokio::test]
    async fn recursively_resolves_and_deduplicates_secret_reads() {
        let server = MockServer::start();
        let lookup = mock_lookup(&server, false, 60);
        let metadata = mock_metadata(&server, 3);
        let secret = mock_secret(
            &server,
            3,
            json!({"password": "db-secret", "username": "keystone"}),
        );
        let mut raw = config::Config::builder()
            .add_source(File::from_str(
                r#"
                    [nested]
                    connection = "main"
                    values = ["ordinary", "vault://secret/keystone/database#username"]
                "#,
                FileFormat::Toml,
            ))
            .add_source(File::from_str(
                r#"
                    [nested]
                    connection = "site"
                "#,
                FileFormat::Toml,
            ))
            .add_source(File::from_str(
                r#"
                    [nested]
                    connection = "vault://secret/keystone/database#password"
                "#,
                FileFormat::Toml,
            ))
            .build()
            .unwrap();

        resolve(&mut raw, &test_vault(&server, 60)).await.unwrap();

        assert_eq!(raw.get_string("nested.connection").unwrap(), "db-secret");
        assert_eq!(
            raw.get_array("nested.values").unwrap()[1]
                .clone()
                .into_string()
                .unwrap(),
            "keystone"
        );
        lookup.assert_calls(1);
        metadata.assert_calls(1);
        secret.assert_calls(1);
    }

    #[tokio::test]
    async fn rejects_missing_and_non_string_values_without_disclosing_them() {
        for (data, expected) in [
            (json!({"other": "SUPERSECRET"}), "not found"),
            (json!({"password": 12345}), "must be a string"),
        ] {
            let server = MockServer::start();
            let _lookup = mock_lookup(&server, false, 60);
            let _metadata = mock_metadata(&server, 1);
            let _secret = mock_secret(&server, 1, data);
            let mut raw = config::Config::builder()
                .add_source(File::from_str(
                    "value = 'vault://secret/keystone/database#password'",
                    FileFormat::Toml,
                ))
                .build()
                .unwrap();

            let error = resolve(&mut raw, &test_vault(&server, 60))
                .await
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains(expected), "{error}");
            assert!(!error.contains("SUPERSECRET"));
            assert!(!error.contains("12345"));
        }
    }

    #[tokio::test]
    async fn authentication_failure_is_redacted() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/v1/auth/token/lookup-self");
            then.status(403)
                .json_body(json!({"errors": ["test-token SUPERSECRET"]}));
        });
        let mut raw = config::Config::builder()
            .add_source(File::from_str(
                "value = 'vault://secret/keystone/database#password'",
                FileFormat::Toml,
            ))
            .build()
            .unwrap();

        let error = resolve(&mut raw, &test_vault(&server, 60))
            .await
            .err()
            .unwrap()
            .to_string();
        assert_eq!(error, "Vault token authentication failed");
        assert!(!error.contains("test-token"));
        assert!(!error.contains("SUPERSECRET"));
    }
}
