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
//! The `[distributed_storage]` section loaded through the configuration
//! engine (ADR 0039): registration, env override, validation and reload.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::time::Duration;

use secrecy::ExposeSecret;
use serial_test::serial;
use tempfile::NamedTempFile;

use openstack_keystone_config::{Config, ConfigManager};
use openstack_keystone_distributed_storage::config::{
    DistributedStorageConfiguration, RaftTlsConfiguration,
};

const CORE: &str = r#"
[auth]
methods = []
[database]
connection = "foo"
"#;

fn write_config(extra: &str) -> NamedTempFile {
    let mut file = NamedTempFile::with_suffix(".conf").unwrap();
    write!(file, "{CORE}{extra}").unwrap();
    file.flush().unwrap();
    file
}

#[tokio::test]
#[serial]
async fn section_is_absent_when_not_configured() {
    let file = write_config("");
    let loaded = oslo_config::load_snapshot_from::<Config>(file.path().to_path_buf())
        .await
        .unwrap();
    assert!(
        loaded
            .view()
            .section::<DistributedStorageConfiguration>()
            .is_none()
    );
    assert!(
        loaded
            .view()
            .require::<DistributedStorageConfiguration>()
            .is_err()
    );
}

#[tokio::test]
#[serial]
async fn section_is_registered_and_loaded() {
    let file = write_config(
        r#"
[distributed_storage]
node_id = 5
node_cluster_addr = http://foo:8300
path = /foo
dev_mode = true
"#,
    );
    let loaded = oslo_config::load_snapshot_from::<Config>(file.path().to_path_buf())
        .await
        .unwrap();
    let ds = loaded
        .view()
        .require::<DistributedStorageConfiguration>()
        .unwrap();
    assert_eq!(5, ds.node_id);
}

#[test]
#[serial]
fn section_honours_env_override() {
    let file = write_config(
        r#"
[distributed_storage]
node_id = 5
path = /foo
dev_mode = true
"#,
    );
    let path = file.path().to_path_buf();
    // The loader is async, but `temp_env::with_vars` is a synchronous
    // closure API, so run it to completion on a local runtime.
    let loaded = temp_env::with_vars(
        [(
            "OS_DISTRIBUTED_STORAGE__NODE_CLUSTER_ADDR",
            Some("http://test/"),
        )],
        || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(oslo_config::load_snapshot_from::<Config>(path))
        },
    )
    .unwrap();
    let ds = loaded
        .view()
        .require::<DistributedStorageConfiguration>()
        .unwrap();
    assert_eq!("http://test/", ds.node_cluster_addr.to_string());
}

#[tokio::test]
#[serial]
async fn section_is_validated_at_load() {
    // The default KEK provider is `env`, which is rejected outside `dev_mode`.
    let file = write_config(
        r#"
[distributed_storage]
node_id = 1
node_cluster_addr = http://foo:8300
path = /foo
"#,
    );
    let err = oslo_config::load_snapshot_from::<Config>(file.path().to_path_buf())
        .await
        .err()
        .expect("must be rejected");
    assert!(
        format!("{err:?}").contains("distributed_storage"),
        "unexpected error: {err:?}"
    );
}

#[tokio::test]
#[serial]
async fn section_reloads_on_cert_change() {
    let mut ca_file = NamedTempFile::new().unwrap();
    write!(ca_file, "ca").unwrap();
    let mut cert_file = NamedTempFile::new().unwrap();
    write!(cert_file, "cert").unwrap();
    let mut key_file = NamedTempFile::new().unwrap();
    write!(key_file, "key").unwrap();
    let file = write_config(&format!(
        r#"
[distributed_storage]
node_cluster_addr = https://localhost:8310
node_id = 1
path = /keystone/storage
dev_mode = true
tls_key_file = {:?}
tls_cert_file = {:?}
tls_client_ca_file = {:?}
"#,
        key_file.path(),
        cert_file.path(),
        ca_file.path()
    ));
    // A tiny delay for a higher probability that FS operations are really
    // complete.
    tokio::time::sleep(Duration::from_millis(10)).await;

    let mgr = ConfigManager::watched(file.path())
        .await
        .expect("Should initialize");

    // Another delay to let the watch thread start before the file changes.
    tokio::time::sleep(Duration::from_millis(10)).await;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(cert_file.path())
        .unwrap();
    f.write_all("another cert".as_bytes()).unwrap();

    // Wait for notify + debounce; check a few times for the change to
    // propagate.
    let mut success = false;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let updated = mgr.config.read().await;
        if let Some(ds) = updated.view().section::<DistributedStorageConfiguration>()
            && let RaftTlsConfiguration::Tls(data) = &ds.tls_configuration
            && data.tls_cert_content.as_ref().map(|x| x.expose_secret())
                == Some("another cert".as_bytes())
        {
            success = true;
            break;
        }
    }
    mgr.shutdown().await;
    assert!(success, "Section did not update after file change");
}
