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
//! KEK provider gating by deployment mode.

use super::harness::*;
use super::*;

/// `init_storage` must refuse to start with `kek_provider = "env"` (the
/// default) when `dev_mode = false`: the dev-mode `EnvKek` is never a valid
/// production KEK source, so falling back to it would silently violate ADR
/// 0016-v2 §2.1 / invariant 6. Production deployments select `"pkcs11"` or
/// `"tpm"` instead (`test_pkcs11_cluster.rs` covers that path end-to-end).
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_kek_gating_production_mode_rejected() {
    TypeConfig::run(test_kek_gating_production_mode_rejected_inner()).unwrap();
}

#[allow(unsafe_code)]
async fn test_kek_gating_production_mode_rejected_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let storage_dir = tempfile::TempDir::new().unwrap();
    let tls_configuration = make_certificates()?;
    let mut ds_config = get_ds_config(101, storage_dir.path().to_path_buf(), tls_configuration);
    ds_config.dev_mode = false;

    let config = ds_config;

    // SAFETY: no concurrent env readers; test is `#[serial_test::serial]`.
    unsafe {
        std::env::remove_var("KEYSTONE_DEV_KEK");
        std::env::remove_var("KEYSTONE_ALLOW_ENV_KEK");
    }

    let result = init_storage(&config_manager(config)).await;
    assert!(
        result.is_err(),
        "init_storage must refuse to start with dev_mode=false (no production KekProvider exists)"
    );
    Ok(())
}

/// `init_storage` must refuse to start with `dev_mode = true` unless
/// `KEYSTONE_ALLOW_ENV_KEK=1` is explicitly set (ADR 0016-v2 §2.1, invariant
/// 6), even when `KEYSTONE_DEV_KEK` is present.
#[serial_test::serial]
#[tracing_test::traced_test]
#[test]
fn test_kek_gating_dev_mode_requires_allow_env_kek() {
    TypeConfig::run(test_kek_gating_dev_mode_requires_allow_env_kek_inner()).unwrap();
}

#[allow(unsafe_code)]
async fn test_kek_gating_dev_mode_requires_allow_env_kek_inner() -> Result<()> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);

    let storage_dir = tempfile::TempDir::new().unwrap();
    let tls_configuration = make_certificates()?;
    let ds_config = get_ds_config(102, storage_dir.path().to_path_buf(), tls_configuration);
    // dev_mode is true via get_ds_config, but KEYSTONE_ALLOW_ENV_KEK is unset.

    let config = ds_config;

    // SAFETY: no concurrent env readers; test is `#[serial_test::serial]`.
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::remove_var("KEYSTONE_ALLOW_ENV_KEK");
    }

    let result = init_storage(&config_manager(config)).await;
    assert!(
        result.is_err(),
        "init_storage must refuse to start with dev_mode=true but KEYSTONE_ALLOW_ENV_KEK unset"
    );
    Ok(())
}
