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
//! Vault resolution through [`ConfigManager`] against a mocked Vault server.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::time::Duration;

use httpmock::MockServer;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use serial_test::{parallel, serial};
use tempfile::NamedTempFile;
use tokio::time::{sleep, timeout};

use super::vault::tests::{mock_lookup, mock_metadata, mock_renew, mock_revoke, mock_secret};
use super::*;

#[derive(Debug, Default, Deserialize)]
struct Core {
    #[serde(rename = "DEFAULT", default)]
    #[allow(dead_code)]
    default: CoreDefault,
    database: CoreDatabase,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct CoreDefault {
    #[serde(default)]
    debug: bool,
}

#[derive(Debug, Deserialize)]
struct CoreDatabase {
    connection: SecretString,
}

impl Default for CoreDatabase {
    fn default() -> Self {
        Self {
            connection: SecretString::from(String::new()),
        }
    }
}

impl CoreSchema for Core {
    fn source() -> SourceSpec {
        SourceSpec {
            env_prefix: "OSLOVAULT",
            env_prefix_separator: "_",
            env_separator: "__",
            site_vars_env: "OSLOVAULT_SITE_VARS_FILE",
        }
    }

    fn reserved_sections() -> &'static [&'static str] {
        &["DEFAULT", "database"]
    }
}

fn write_vault_config(
    file: &mut NamedTempFile,
    server: &MockServer,
    refresh_interval_seconds: u64,
) {
    write!(
        file,
        r#"
[vault]
address = {}
token = test-token
refresh_interval_seconds = {}



[database]
connection = "vault://secret/keystone/database#password"
        "#,
        server.base_url(),
        refresh_interval_seconds
    )
    .unwrap();
    file.flush().unwrap();
}

#[tokio::test]
#[parallel]
async fn test_async_loader_resolves_vault_reference() {
    let server = MockServer::start();
    let lookup = mock_lookup(&server, false, 60);
    let metadata = mock_metadata(&server, 4);
    let secret = mock_secret(
        &server,
        4,
        json!({
            "password": "environment-value"
        }),
    );
    let mut config_file = NamedTempFile::with_suffix(".conf").unwrap();
    write!(
        config_file,
        r#"
[vault]
address = {}
token = test-token



[database]
connection = "vault://secret/keystone/database#password"
        "#,
        server.base_url()
    )
    .unwrap();

    let config = load_all::<Core>(config_file.path().to_path_buf())
        .await
        .unwrap();

    assert_eq!(
        config.database.connection.expose_secret(),
        "environment-value"
    );
    lookup.assert_calls(1);
    metadata.assert_calls(1);
    secret.assert_calls(1);
}

#[tokio::test]
#[parallel]
async fn test_resolved_configuration_error_is_redacted() {
    let server = MockServer::start();
    let _lookup = mock_lookup(&server, false, 60);
    let _metadata = mock_metadata(&server, 1);
    let _secret = mock_secret(&server, 1, json!({"password": "SUPERSECRET"}));
    let mut config_file = NamedTempFile::with_suffix(".conf").unwrap();
    write!(
        config_file,
        r#"
[vault]
address = {}
token = test-token

[DEFAULT]
debug = "vault://secret/keystone/database#password"



[database]
connection = ordinary
        "#,
        server.base_url()
    )
    .unwrap();

    let error = load_all::<Core>(config_file.path().to_path_buf())
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "configuration is invalid after resolving Vault references"
    );
    assert!(!error.contains("SUPERSECRET"));
    assert!(!error.contains("test-token"));
}

#[tokio::test]
#[parallel]
async fn test_async_loader_fails_closed_without_vault_configuration() {
    let mut config_file = NamedTempFile::with_suffix(".conf").unwrap();
    write!(
        config_file,
        r#"

[database]
connection = "vault://secret/keystone/database#password"
        "#
    )
    .unwrap();

    let error = load_all::<Core>(config_file.path().to_path_buf())
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "Vault references require a [vault] configuration section"
    );
}

#[tokio::test]
#[parallel]
async fn test_vault_token_revoked_on_shutdown() {
    let server = MockServer::start();
    let _lookup = mock_lookup(&server, false, 60);
    let _metadata = mock_metadata(&server, 1);
    let _secret = mock_secret(&server, 1, json!({"password": "version-one"}));
    let revoke = mock_revoke(&server);
    let mut config_file = NamedTempFile::with_suffix(".conf").unwrap();
    write_vault_config(&mut config_file, &server, 60);

    let manager = ConfigManager::<Core>::watched(config_file.path())
        .await
        .unwrap();
    manager.shutdown().await;

    assert_eq!(revoke.calls(), 1);
}

#[tokio::test]
#[serial]
async fn test_shutdown_without_vault_is_noop() {
    let mut config_file = NamedTempFile::with_suffix(".conf").unwrap();
    writeln!(config_file, "[database]\nconnection = sqlite://\n").unwrap();

    let manager = ConfigManager::<Core>::watched(config_file.path())
        .await
        .unwrap();
    // #[serial] prevents other config tests' notify watchers from firing
    // spurious parent-directory events that queue into sync_rx, triggering
    // repeated 500ms debounce sleeps. The biased select! prioritizes
    // sync_rx.recv() over shutdown.cancelled(), so a flood of events can
    // delay the shutdown break indefinitely.
    timeout(Duration::from_secs(10), manager.shutdown())
        .await
        .expect("shutdown should not hang for a non-Vault configuration");
}

#[tokio::test]
#[parallel]
async fn test_vault_version_reload_and_last_known_good_retention() {
    let server = MockServer::start();
    let _lookup = mock_lookup(&server, false, 60);
    let mut metadata = mock_metadata(&server, 1);
    let mut secret = mock_secret(&server, 1, json!({"password": "version-one"}));
    let mut config_file = NamedTempFile::with_suffix(".conf").unwrap();
    write_vault_config(&mut config_file, &server, 1);

    let manager = ConfigManager::<Core>::watched(config_file.path())
        .await
        .unwrap();
    let mut reloads = manager.notify_tx.subscribe();
    metadata.delete();
    secret.delete();
    let mut metadata = mock_metadata(&server, 2);
    let mut secret = mock_secret(&server, 2, json!({"password": "version-two"}));

    timeout(Duration::from_secs(4), reloads.recv())
        .await
        .expect("Vault version change should trigger a reload")
        .unwrap();
    assert_eq!(
        manager
            .config
            .read()
            .await
            .database
            .connection
            .expose_secret(),
        "version-two"
    );

    metadata.delete();
    secret.delete();
    let _metadata = mock_metadata(&server, 3);
    let invalid_secret = mock_secret(&server, 3, json!({"password": 12345}));
    timeout(Duration::from_secs(4), async {
        while invalid_secret.calls() == 0 {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("invalid Vault version should be attempted");
    sleep(Duration::from_millis(100)).await;

    assert!(reloads.try_recv().is_err());
    assert_eq!(
        manager
            .config
            .read()
            .await
            .database
            .connection
            .expose_secret(),
        "version-two"
    );
}

#[tokio::test]
#[serial]
async fn test_renewable_vault_token_is_renewed_halfway_through_ttl() {
    let server = MockServer::start();
    let _lookup = mock_lookup(&server, true, 2);
    let _metadata = mock_metadata(&server, 1);
    let _secret = mock_secret(&server, 1, json!({"password": "value"}));
    let renewal = mock_renew(&server, 2);
    let mut config_file = NamedTempFile::with_suffix(".conf").unwrap();
    write_vault_config(&mut config_file, &server, 60);

    let _manager = ConfigManager::<Core>::watched(config_file.path())
        .await
        .unwrap();
    // The renewal deadline (half_ttl of the 2s lookup TTL = 1s) is set as
    // an absolute Instant during vault::resolve(), before the
    // spawned watch-loop task has entered its select!. We need the
    // task to:
    // 1. Start and reach its select! loop
    // 2. Have sleep_until() fire when the 1s deadline passes
    // 3. Get picked by select! (biased — sync_rx.recv() wins if a notify
    //    event is queued from spawn-time filesystem activity)
    //
    // yield_now() is insufficient on loaded CI runners because it only
    // gives one scheduling opportunity. A short sleep gives the
    // executor repeated chances to run the spawned task.
    // #[serial] prevents other config tests' notify watchers from firing
    // spurious directory events that fill sync_rx and starve vault_tick via
    // select! bias.
    sleep(Duration::from_millis(100)).await;

    timeout(Duration::from_secs(10), async {
        while renewal.calls() == 0 {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("renewable token should be renewed");
    assert!(renewal.calls() >= 1);
}
