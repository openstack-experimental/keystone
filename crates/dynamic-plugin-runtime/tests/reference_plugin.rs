//! Integration tests against the real reference plugin (ADR 0025 PR 0.3 /
//! PR 0.4), compiled to `wasm32-unknown-unknown` on the fly - see
//! `tests/fixtures/reference-plugin`. This is the "equivalent" of a
//! `cargo xtask build-test-plugin` step described in
//! `doc/src/adr/0025-implementation-plan.md`: rather than a separate CI
//! step that can drift out of sync with the fixture source, every run of
//! this test suite rebuilds the fixture itself (cargo no-ops if nothing
//! changed) and hashes the artifact it just produced, so a test can never
//! run against a stale `.wasm`/`sha256` pair.
#![cfg(test)]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use config::{Config, File, FileFormat};
use openstack_keystone_config::{DynamicPluginConfig, DynamicPluginsSection};
use openstack_keystone_dynamic_plugin_runtime::{InvokeError, WasmPluginRegistry};
use sha2::{Digest, Sha256};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/reference-plugin")
}

/// Builds the reference plugin for `wasm32-unknown-unknown` and returns the
/// path to the resulting `.wasm` artifact plus its SHA-256.
fn build_reference_plugin() -> (PathBuf, String) {
    let dir = fixture_dir();
    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
        .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
        .current_dir(&dir)
        .status()
        .expect("failed to spawn cargo to build the reference plugin fixture");
    assert!(
        status.success(),
        "building tests/fixtures/reference-plugin for wasm32-unknown-unknown failed"
    );

    let wasm_path = dir.join("target/wasm32-unknown-unknown/release/reference_plugin.wasm");
    assert!(
        wasm_path.is_file(),
        "expected build artifact at {}",
        wasm_path.display()
    );
    let bytes = std::fs::read(&wasm_path).unwrap();
    let sha256 = {
        use std::fmt::Write;
        Sha256::digest(&bytes)
            .iter()
            .fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
    };
    (wasm_path, sha256)
}

fn config_for(path: &Path, sha256: &str, extra: &str) -> DynamicPluginConfig {
    #[derive(Debug, serde::Deserialize)]
    struct Wrapper {
        dynamic_plugin: HashMap<String, DynamicPluginConfig>,
    }

    let ini = format!(
        "[dynamic_plugin.p]\npath = {}\nsha256 = {}\nmode = full_auth\ncapabilities = provision_user\nprovision_domain_id = d\n{extra}\n",
        path.display(),
        sha256,
    );
    let c = Config::builder()
        .add_source(File::from_str(&ini, FileFormat::Ini))
        .build()
        .unwrap();
    let wrapper: Wrapper = c.try_deserialize().unwrap();
    wrapper.dynamic_plugin.into_iter().next().unwrap().1
}

fn section() -> DynamicPluginsSection {
    DynamicPluginsSection {
        plugins: vec!["p".to_string()],
    }
}

#[test]
fn test_load_and_invoke_authenticate() {
    let (path, sha256) = build_reference_plugin();
    let config = config_for(&path, &sha256, "");

    let mut configs = HashMap::new();
    configs.insert("p".to_string(), config);
    let (registry, errors) = WasmPluginRegistry::load(&section(), &configs);
    assert!(errors.is_empty(), "unexpected load errors: {errors:?}");

    let plugin = registry.get("p").expect("plugin should have loaded");
    let out = plugin
        .invoke("authenticate", br#"{"external_id":"alice","deny":false}"#)
        .expect("authenticate call should succeed");
    let out: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(out["decision"], "allow");
    assert_eq!(out["external_id"], "alice");

    let out = plugin
        .invoke("authenticate", br#"{"external_id":"bob","deny":true}"#)
        .expect("authenticate call should succeed");
    let out: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(out["decision"], "deny");
}

#[test]
fn test_fuel_exhaustion_fails_closed() {
    let (path, sha256) = build_reference_plugin();
    // Generous timeout, tiny fuel budget: the `spin` export must exhaust
    // fuel long before any wall-clock bound could plausibly fire.
    let config = config_for(&path, &sha256, "timeout_ms = 60000\nfuel_limit = 100000\n");

    let mut configs = HashMap::new();
    configs.insert("p".to_string(), config);
    let (registry, errors) = WasmPluginRegistry::load(&section(), &configs);
    assert!(errors.is_empty(), "unexpected load errors: {errors:?}");

    let plugin = registry.get("p").unwrap();
    let err = plugin
        .invoke("spin", b"")
        .expect_err("spin should not return");
    assert!(
        matches!(err, InvokeError::FuelExhausted),
        "expected FuelExhausted, got {err:?}"
    );
}

#[test]
fn test_timeout_fails_closed() {
    let (path, sha256) = build_reference_plugin();
    // Generous fuel budget, tiny timeout: the `spin` export must hit the
    // wall-clock bound long before it could exhaust that much fuel.
    let config = config_for(
        &path,
        &sha256,
        "timeout_ms = 50\nfuel_limit = 500000000000\n",
    );

    let mut configs = HashMap::new();
    configs.insert("p".to_string(), config);
    let (registry, errors) = WasmPluginRegistry::load(&section(), &configs);
    assert!(errors.is_empty(), "unexpected load errors: {errors:?}");

    let plugin = registry.get("p").unwrap();
    let err = plugin
        .invoke("spin", b"")
        .expect_err("spin should not return");
    assert!(
        matches!(err, InvokeError::Timeout),
        "expected Timeout, got {err:?}"
    );
}

#[test]
fn test_memory_limit_fails_closed() {
    let (path, sha256) = build_reference_plugin();
    // Generous fuel/timeout, tiny memory cap: `allocate_memory` must trip
    // the guest allocator well before either other bound.
    let config = config_for(
        &path,
        &sha256,
        "timeout_ms = 60000\nfuel_limit = 500000000000\nmemory_limit_mb = 1\n",
    );

    let mut configs = HashMap::new();
    configs.insert("p".to_string(), config);
    let (registry, errors) = WasmPluginRegistry::load(&section(), &configs);
    assert!(errors.is_empty(), "unexpected load errors: {errors:?}");

    let plugin = registry.get("p").unwrap();
    let err = plugin
        .invoke("allocate_memory", b"")
        .expect_err("allocate_memory should not return");
    assert!(
        matches!(err, InvokeError::Trap(_)),
        "expected Trap (guest allocator failure), got {err:?}"
    );
}

#[test]
fn test_invocations_are_isolated_between_calls() {
    let (path, sha256) = build_reference_plugin();
    let config = config_for(&path, &sha256, "timeout_ms = 60000\nfuel_limit = 100000\n");

    let mut configs = HashMap::new();
    configs.insert("p".to_string(), config);
    let (registry, errors) = WasmPluginRegistry::load(&section(), &configs);
    assert!(errors.is_empty(), "unexpected load errors: {errors:?}");
    let plugin = registry.get("p").unwrap();

    // A call that exhausts its fuel budget must not poison subsequent
    // calls against the same loaded (compiled) plugin - each invocation
    // gets a fresh Store and so a fresh fuel budget (ADR §7).
    assert!(matches!(
        plugin.invoke("spin", b""),
        Err(InvokeError::FuelExhausted)
    ));
    let out = plugin
        .invoke("authenticate", br#"{"external_id":"carol","deny":false}"#)
        .expect("a fresh invocation after a fuel-exhausted one should still succeed");
    let out: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(out["decision"], "allow");
}
