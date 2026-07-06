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
#![cfg(feature = "pkcs11")]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
//! SoftHSM2-backed end-to-end integration test (ADR 0016-v2 §2.5.1,
//! implementation plan step 6).
//!
//! `crates/storage-crypto-pkcs11/tests/softhsm.rs` already covers
//! `Pkcs11Kek::wrap_dek`/`unwrap_dek` in isolation. This file instead boots a
//! real single-node cluster through `init_storage` with
//! `kek_provider = "pkcs11"`, exercising the whole path config -> `build_kek`
//! -> `Pkcs11Kek` -> the Raft state machine's DEK wrap/unwrap, and does an
//! end-to-end write/read of sensitive-tier data plus a restart that reopens
//! the same real token.
//!
//! Requires a SoftHSM2 module to be installed (`apt-get install softhsm2`,
//! same install step CI already runs for SPIRE). The module path is taken
//! from `TEST_PKCS11_MODULE` if set, otherwise the common Debian/Ubuntu path
//! is tried; tests skip (rather than fail) when no module is found.

use std::path::PathBuf;
use std::time::Duration;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use eyre::Result;
use openraft::type_config::TypeConfigExt;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};

use openstack_keystone_config::{
    Config, ConfigManager, DistributedStorageConfiguration, KekProvider, Pkcs11KekConfiguration,
    RaftTlsConfiguration, TlsConfiguration, TlsConfigurationBuilder,
};
use openstack_keystone_distributed_storage::TypeConfig;
use openstack_keystone_distributed_storage::app::init_storage;
use openstack_keystone_distributed_storage::{
    DataTier, Metadata, StorageApi, StoreDataEnvelope, StoreError,
};
use openstack_keystone_storage_crypto_pkcs11::{Pkcs11Kek, Pkcs11KekParams, SlotSelector};

const SO_PIN: &str = "1234567890";
const USER_PIN: &str = "fedcba0987";
const TOKEN_LABEL: &str = "keystone-storage-test";
const KEY_LABEL: &str = "keystone-kek";

fn make_sensitive_env<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<StoreDataEnvelope<Vec<u8>>, StoreError> {
    Ok(StoreDataEnvelope {
        data: rmp_serde::to_vec(value)?,
        metadata: Metadata::with_tier(DataTier::Sensitive),
    })
}

fn module_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("TEST_PKCS11_MODULE") {
        return Some(PathBuf::from(p));
    }
    [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

/// `Result::unwrap()`/`expect()` are denied by the crate's clippy lints for
/// `#[test]`-attributed functions, but these setup helpers aren't themselves
/// `#[test]` functions, so clippy doesn't recognize them as test code.
/// Panicking on setup failure is still exactly what's wanted here — this
/// just spells it without the denied methods.
fn ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(v) => v,
        Err(e) => panic!("{context}: {e}"),
    }
}

fn skip_without_softhsm() -> bool {
    if module_path().is_none() {
        eprintln!(
            "skipping: no SoftHSM2 module found (set TEST_PKCS11_MODULE or `apt-get install softhsm2`)"
        );
        return true;
    }
    false
}

/// Initialize a fresh SoftHSM2 token and provision the AES-256 KEK key
/// object on it. `build_pkcs11_kek` (`crates/storage/src/app.rs`) always
/// opens with `auto_generate: false` — first-run key creation must not
/// happen implicitly in-process (ADR 0016-v2 review decision, see
/// `doc/plans/0016-v2-pkcs11-tpm-kek.md`) — so the key must already exist
/// before `init_storage` runs, exactly as an operator's out-of-band key
/// ceremony would provision it.
fn provision_token(module: &PathBuf) {
    // SoftHSM only tolerates one live `C_Initialize`'d context per process
    // for a given module, so the admin context used for token/PIN setup is
    // scoped to this block and dropped (finalizing it) before `Pkcs11Kek`
    // opens its own context to provision the AES key below.
    {
        let pkcs11 = ok(Pkcs11::new(module), "load module");
        ok(
            pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)),
            "initialize",
        );
        let slot = ok(pkcs11.get_slots_with_token(), "slots")[0];
        ok(
            pkcs11.init_token(slot, &AuthPin::new(SO_PIN.into()), TOKEN_LABEL),
            "init token",
        );
        let session = ok(pkcs11.open_rw_session(slot), "so session");
        ok(
            session.login(UserType::So, Some(&AuthPin::new(SO_PIN.into()))),
            "so login",
        );
        ok(
            session.init_pin(&AuthPin::new(USER_PIN.into())),
            "init user pin",
        );
    }

    // Provision the AES key itself, as an operator's out-of-band ceremony
    // would; `init_storage` will only ever open it with `auto_generate: false`.
    ok(
        Pkcs11Kek::open(Pkcs11KekParams {
            module_path: module,
            slot: SlotSelector::Label(TOKEN_LABEL.into()),
            key_label: KEY_LABEL,
            pin: USER_PIN.as_bytes(),
            auto_generate: true,
        }),
        "provision KEK key",
    );
}

fn make_certificates() -> Result<TlsConfiguration> {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];

    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "CA");
    ca_params.distinguished_name = ca_dn;

    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca = Issuer::new(ca_params, ca_key);

    let mut peer_cert_params = CertificateParams::default();
    let now = time::OffsetDateTime::now_utc();
    peer_cert_params.not_before = now - time::Duration::days(1);
    peer_cert_params.not_after = now + time::Duration::days(28);

    let client_ip: std::net::IpAddr = "127.0.0.1".parse()?;
    peer_cert_params.subject_alt_names = vec![SanType::IpAddress(client_ip)];
    peer_cert_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    peer_cert_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let peer_key = KeyPair::generate()?;
    let peer_cert = peer_cert_params.signed_by(&peer_key, &ca)?;

    Ok(TlsConfigurationBuilder::default()
        .tls_client_ca_content(ca_cert.pem().as_bytes().to_vec())
        .tls_cert_content(peer_cert.pem().as_bytes().to_vec())
        .tls_key_content(peer_key.serialize_pem().as_bytes().to_vec())
        .build()?)
}

/// Config for a single, unnetworked node backed by the real SoftHSM2 token
/// at `module`. No gRPC server is started — as in `test_cluster.rs`'s
/// `test_quarantine_committed_via_raft`, the Raft handle is exercised
/// directly, which is enough to drive the state machine's DEK wrap/unwrap
/// path without needing a live network listener.
fn pkcs11_ds_config(
    node_id: u64,
    db_path: PathBuf,
    tls_config: TlsConfiguration,
    module: PathBuf,
) -> DistributedStorageConfiguration {
    let addr = format!("127.0.0.1:{}", 22000 + node_id as u16);
    DistributedStorageConfiguration {
        node_cluster_addr: format!("https://{addr}").parse().expect("valid address"),
        node_listener_addr: addr.parse().expect("valid address"),
        node_id,
        path: db_path,
        tls_configuration: RaftTlsConfiguration::Tls(tls_config),
        dev_mode: false,
        retry_join_nodes: vec![],
        kek_provider: KekProvider::Pkcs11,
        pkcs11: Some(Pkcs11KekConfiguration {
            pkcs11_key_label: KEY_LABEL.to_string(),
            pkcs11_module_path: module,
            pkcs11_pin_content: Some(USER_PIN.as_bytes().to_vec().into()),
            // Unused: `build_pkcs11_kek` reads `pkcs11_pin_content` (already
            // populated above), not this file — `Config::load_all` is the
            // only caller that reads `pkcs11_pin_file`, and this test builds
            // `Config` directly, bypassing it.
            pkcs11_pin_file: PathBuf::new(),
            pkcs11_slot_id: None,
            pkcs11_slot_label: Some(TOKEN_LABEL.to_string()),
        }),
        tpm: None,
    }
}

/// Set up an isolated SoftHSM2 token directory/config, provision the KEK key
/// on it, and run `f` — a synchronous closure that may itself block on an
/// async runtime via [`TypeConfig::run`] — with `SOFTHSM2_CONF` pointed at
/// the token for the duration. `temp_env::with_var` requires a synchronous
/// closure, so `f` must fully block on any async work itself rather than
/// return a `Future`; this mirrors every other test in this crate, which
/// calls `TypeConfig::run` directly from a plain `#[test]` fn rather than
/// nesting async runtimes. Returns `None` if no SoftHSM2 module is available
/// (caller should treat that as a skipped test).
fn with_provisioned_token<R>(f: impl FnOnce(&PathBuf) -> R) -> Option<R> {
    let module = module_path()?;
    let dir = ok(tempfile::TempDir::new(), "tempdir");
    let token_dir = dir.path().join("tokens");
    ok(std::fs::create_dir_all(&token_dir), "mkdir tokens");
    let conf_path = dir.path().join("softhsm2.conf");
    ok(
        std::fs::write(
            &conf_path,
            format!("directories.tokendir = {}\n", token_dir.display()),
        ),
        "write conf",
    );

    let result = temp_env::with_var("SOFTHSM2_CONF", Some(conf_path.as_os_str()), || {
        provision_token(&module);
        f(&module)
    });
    Some(result)
}

/// Boots a single-node cluster with `kek_provider = "pkcs11"` and does an
/// end-to-end write/read of sensitive-tier data — the DEK that encrypts the
/// value is itself wrapped/unwrapped by the real `Pkcs11Kek` against a real
/// SoftHSM2 token, not the dev-mode `EnvKek`.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_pkcs11_backed_cluster_write_read() {
    if skip_without_softhsm() {
        return;
    }
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    with_provisioned_token(|module| {
        TypeConfig::run(test_pkcs11_backed_cluster_write_read_inner(module.clone())).unwrap();
    });
}

async fn test_pkcs11_backed_cluster_write_read_inner(module: PathBuf) -> Result<()> {
    let storage_dir = tempfile::TempDir::new().unwrap();
    let tls_configuration = make_certificates()?;
    let ds_config = pkcs11_ds_config(
        301,
        storage_dir.path().to_path_buf(),
        tls_configuration,
        module,
    );
    let config = Config {
        distributed_storage: Some(ds_config),
        ..Default::default()
    };

    let storage = init_storage(&ConfigManager::not_watched(config))
        .await
        .expect("init_storage with a real SoftHSM2-backed KEK");

    storage
        .initialize(
            [(
                301u64,
                openstack_keystone_storage_api::Node {
                    node_id: 301,
                    rpc_addr: "127.0.0.1:0".to_string(),
                },
            )]
            .into_iter()
            .collect(),
        )
        .await?;
    for _ in 0..50 {
        if storage.current_leader() == Some(301) {
            break;
        }
        TypeConfig::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(storage.current_leader(), Some(301));

    let key = "pkcs11-e2e-key".to_string();
    let value = "pkcs11-e2e-value".to_string();
    storage
        .set_value(key.clone(), make_sensitive_env(&value)?, None, None)
        .await?;

    let got = storage
        .get_by_key(key.as_bytes(), None)
        .await?
        .expect("value should be readable back through the real PKCS#11 KEK");
    assert_eq!(
        value,
        got.try_deserialize::<String>()?.data,
        "round-tripped value must match what was written"
    );

    storage.raft.shutdown().await.ok();
    Ok(())
}

/// A wrapped DEK persisted while the token was open must still unwrap after
/// a full storage shutdown and restart that reopens the same SoftHSM2 token
/// from scratch — proving the wrapped-DEK-on-disk format doesn't depend on
/// anything beyond the token itself (no in-memory session state leaking
/// into what gets persisted).
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_pkcs11_backed_cluster_restart_reopens_token() {
    if skip_without_softhsm() {
        return;
    }
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    with_provisioned_token(|module| {
        TypeConfig::run(test_pkcs11_backed_cluster_restart_reopens_token_inner(
            module.clone(),
        ))
        .unwrap();
    });
}

async fn test_pkcs11_backed_cluster_restart_reopens_token_inner(module: PathBuf) -> Result<()> {
    let storage_dir = tempfile::TempDir::new().unwrap();
    let tls_configuration = make_certificates()?;
    let key = "pkcs11-restart-key".to_string();
    let value = "pkcs11-restart-value".to_string();

    {
        let ds_config = pkcs11_ds_config(
            302,
            storage_dir.path().to_path_buf(),
            tls_configuration.clone(),
            module.clone(),
        );
        // Unlike the single-shot quarantine/rotation tests, this test
        // restarts against the same config, so the registered rpc_addr must
        // match `node_cluster_addr` (mod scheme) for
        // `check_node_id_uniqueness` to recognize the restart as the same
        // node rather than a conflicting one — a bare "127.0.0.1:0"
        // placeholder (fine for a test that never restarts) would not.
        let rpc_addr = ds_config.node_listener_addr.to_string();
        let config = Config {
            distributed_storage: Some(ds_config),
            ..Default::default()
        };
        let storage = init_storage(&ConfigManager::not_watched(config))
            .await
            .expect("first init_storage");

        storage
            .initialize(
                [(
                    302u64,
                    openstack_keystone_storage_api::Node {
                        node_id: 302,
                        rpc_addr,
                    },
                )]
                .into_iter()
                .collect(),
            )
            .await?;
        for _ in 0..50 {
            if storage.current_leader() == Some(302) {
                break;
            }
            TypeConfig::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(storage.current_leader(), Some(302));

        storage
            .set_value(key.clone(), make_sensitive_env(&value)?, None, None)
            .await?;

        // Fjall's file lock is only released once RaftCore's background
        // task actually stops (its Drop impl doesn't do this for us) — same
        // requirement documented on
        // `test_node_restart_with_address_format_change`.
        storage.raft.shutdown().await.ok();
    }
    TypeConfig::sleep(Duration::from_millis(200)).await;

    let ds_config_restart = pkcs11_ds_config(
        302,
        storage_dir.path().to_path_buf(),
        tls_configuration,
        module,
    );
    let config_restart = Config {
        distributed_storage: Some(ds_config_restart),
        ..Default::default()
    };
    let storage_restart = init_storage(&ConfigManager::not_watched(config_restart))
        .await
        .expect("restart must reopen the same SoftHSM2 token and unwrap the persisted DEK");

    assert!(
        storage_restart.is_initialized().await?,
        "storage should detect persisted cluster state"
    );

    let got = storage_restart
        .get_by_key(key.as_bytes(), None)
        .await?
        .expect("value written before restart should still be readable after it");
    assert_eq!(value, got.try_deserialize::<String>()?.data);

    storage_restart.raft.shutdown().await.ok();
    Ok(())
}
