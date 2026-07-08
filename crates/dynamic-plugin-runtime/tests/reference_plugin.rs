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
use std::sync::{Arc, Mutex};

use config::{Config, File, FileFormat};
use openstack_keystone_config::{DynamicPluginConfig, DynamicPluginsSection};
use openstack_keystone_dynamic_plugin_runtime::{
    AssignRoleRequest, GuestUserCreate, HostFunctions, HttpFetchRequest, HttpFetchResponse,
    InvokeError, ProvisionUserRequest, ResolvedIdentityHandle, RoleAssignmentTarget,
    WasmPluginRegistry,
};
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
        ..Default::default()
    }
}

/// Like [`config_for`] but with an explicit `capabilities` list, for tests
/// that need something other than the `provision_user`-only default.
fn config_with_capabilities(
    path: &Path,
    sha256: &str,
    capabilities: &str,
    extra: &str,
) -> DynamicPluginConfig {
    #[derive(Debug, serde::Deserialize)]
    struct Wrapper {
        dynamic_plugin: HashMap<String, DynamicPluginConfig>,
    }

    let ini = format!(
        "[dynamic_plugin.p]\npath = {}\nsha256 = {}\nmode = full_auth\ncapabilities = {capabilities}\nprovision_domain_id = d\n{extra}\n",
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

#[test]
fn test_load_and_invoke_authenticate() {
    let (path, sha256) = build_reference_plugin();
    let config = config_for(&path, &sha256, "");

    let mut configs = HashMap::new();
    configs.insert("p".to_string(), config);
    let host_functions: Option<Arc<dyn HostFunctions>> =
        Some(Arc::new(MockHostFunctions::default()));
    let (registry, errors) =
        WasmPluginRegistry::load(&section(), &configs, host_functions.as_ref());
    assert!(errors.is_empty(), "unexpected load errors: {errors:?}");

    let plugin = registry.get("p").expect("plugin should have loaded");
    let out = plugin
        .invoke(
            "authenticate",
            br#"{"payload":{"external_id":"alice","deny":false,"domain_id":"allowed-domain"},"headers":{},"remote_addr":null}"#,
        )
        .expect("authenticate call should succeed");
    let out: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(out["decision"], "allow");
    assert_eq!(out["resolved_identity"], "handle-for-alice");
    assert_eq!(out["claims"]["source"], "reference-plugin");

    let out = plugin
        .invoke(
            "authenticate",
            br#"{"payload":{"external_id":"bob","deny":true},"headers":{},"remote_addr":null}"#,
        )
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
    let host_functions: Option<Arc<dyn HostFunctions>> =
        Some(Arc::new(MockHostFunctions::default()));
    let (registry, errors) =
        WasmPluginRegistry::load(&section(), &configs, host_functions.as_ref());
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
    let host_functions: Option<Arc<dyn HostFunctions>> =
        Some(Arc::new(MockHostFunctions::default()));
    let (registry, errors) =
        WasmPluginRegistry::load(&section(), &configs, host_functions.as_ref());
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
    let host_functions: Option<Arc<dyn HostFunctions>> =
        Some(Arc::new(MockHostFunctions::default()));
    let (registry, errors) =
        WasmPluginRegistry::load(&section(), &configs, host_functions.as_ref());
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
    let host_functions: Option<Arc<dyn HostFunctions>> =
        Some(Arc::new(MockHostFunctions::default()));
    let (registry, errors) =
        WasmPluginRegistry::load(&section(), &configs, host_functions.as_ref());
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
        .invoke(
            "authenticate",
            br#"{"payload":{"external_id":"carol","deny":false,"domain_id":"allowed-domain"},"headers":{},"remote_addr":null}"#,
        )
        .expect("a fresh invocation after a fuel-exhausted one should still succeed");
    let out: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(out["decision"], "allow");
}

/// In-memory [`HostFunctions`] double: the real identity-backed
/// implementation lives in `openstack-keystone-core`, which this crate must
/// never depend on (see `src/host_functions.rs`'s doc comment) - this mock
/// exercises the `extism::Function` registration/marshalling wiring itself
/// (JSON round-trip through guest memory, capability-gated import table)
/// without pulling in a database.
#[derive(Default)]
struct MockHostFunctions {
    // (plugin_name, external_id) -> handle
    provisioned: Mutex<HashMap<(String, String), String>>,
}

impl HostFunctions for MockHostFunctions {
    fn provision_user(
        &self,
        plugin_name: &str,
        request: ProvisionUserRequest,
    ) -> Result<ResolvedIdentityHandle, String> {
        if request.user.domain_id != "allowed-domain" {
            return Err(format!(
                "domain {} is outside this plugin's provisioning domain",
                request.user.domain_id
            ));
        }
        let handle = format!("handle-for-{}", request.external_id);
        self.provisioned.lock().unwrap().insert(
            (plugin_name.to_string(), request.external_id.clone()),
            handle.clone(),
        );
        Ok(ResolvedIdentityHandle(handle))
    }

    fn find_user(
        &self,
        plugin_name: &str,
        external_id: String,
    ) -> Result<Option<ResolvedIdentityHandle>, String> {
        Ok(self
            .provisioned
            .lock()
            .unwrap()
            .get(&(plugin_name.to_string(), external_id))
            .cloned()
            .map(ResolvedIdentityHandle))
    }

    fn assign_role(&self, _plugin_name: &str, request: AssignRoleRequest) -> Result<(), String> {
        if request.role != "reader" {
            return Err(format!("role {} is not allowed", request.role));
        }
        match &request.target {
            RoleAssignmentTarget::Project { project_id } if project_id == "forbidden-project" => {
                Err("target project is outside this plugin's provisioning domain".to_string())
            }
            _ => Ok(()),
        }
    }

    fn http_fetch(
        &self,
        _plugin_name: &str,
        request: HttpFetchRequest,
    ) -> Result<HttpFetchResponse, String> {
        if !request.url.starts_with("https://risk.acme.example.com") {
            return Err(format!("{} is not an allowed host", request.url));
        }
        Ok(HttpFetchResponse {
            status: 200,
            headers: HashMap::new(),
            body: format!("fetched:{}", request.url),
        })
    }
}

/// A plugin whose config doesn't grant `find_user` can never successfully
/// call it, even though the reference plugin fixture declares it as a
/// guest import unconditionally (`wasmtime` requires every declared import
/// to resolve at instantiation - see `src/host_functions.rs`'s
/// `HostFnContext::granted` doc comment for why the registered
/// `find_user`/`provision_user` closures themselves reject a call their
/// plugin's `capabilities` didn't grant, rather than the import being
/// selectively omitted). The call still fails closed (a trap), exactly as
/// ADR §6 requires - only the layer at which the boundary is enforced
/// differs from a literal "does not exist in the import table".
#[test]
fn test_ungranted_capability_call_is_rejected() {
    let (path, sha256) = build_reference_plugin();
    // Only `provision_user` granted; the fixture also imports `find_user`.
    let config = config_with_capabilities(&path, &sha256, "provision_user", "");

    let mut configs = HashMap::new();
    configs.insert("p".to_string(), config);
    let host_functions: Option<Arc<dyn HostFunctions>> =
        Some(Arc::new(MockHostFunctions::default()));
    let (registry, errors) =
        WasmPluginRegistry::load(&section(), &configs, host_functions.as_ref());
    assert!(errors.is_empty(), "unexpected load errors: {errors:?}");
    let plugin = registry.get("p").unwrap();

    let err = plugin
        .invoke("call_find_user", br#""dave""#)
        .expect_err("find_user was not granted to this plugin");
    assert!(matches!(err, InvokeError::Trap(_)));

    // The granted capability still works on the same loaded plugin.
    let request = ProvisionUserRequest {
        external_id: "dave".to_string(),
        user: GuestUserCreate {
            domain_id: "allowed-domain".to_string(),
            name: "Dave".to_string(),
            enabled: Some(true),
            extra: HashMap::new(),
        },
    };
    plugin
        .invoke(
            "call_provision_user",
            serde_json::to_string(&request).unwrap().as_bytes(),
        )
        .expect("provision_user is granted and should still succeed");
}

#[test]
fn test_provision_user_capability_round_trips_through_guest_memory() {
    let (path, sha256) = build_reference_plugin();
    let config = config_with_capabilities(&path, &sha256, "provision_user,find_user", "");

    let mut configs = HashMap::new();
    configs.insert("p".to_string(), config);
    let host_functions: Option<Arc<dyn HostFunctions>> =
        Some(Arc::new(MockHostFunctions::default()));
    let (registry, errors) =
        WasmPluginRegistry::load(&section(), &configs, host_functions.as_ref());
    assert!(errors.is_empty(), "unexpected load errors: {errors:?}");
    let plugin = registry.get("p").unwrap();

    let request = ProvisionUserRequest {
        external_id: "dave".to_string(),
        user: GuestUserCreate {
            domain_id: "allowed-domain".to_string(),
            name: "Dave".to_string(),
            enabled: Some(true),
            extra: HashMap::new(),
        },
    };
    let request_json = serde_json::to_string(&request).unwrap();
    let out = plugin
        .invoke("call_provision_user", request_json.as_bytes())
        .expect("provision_user call should succeed");
    // `call_provision_user`'s guest export returns a raw `String` (already
    // JSON-serialized `ResolvedIdentityHandle`), so `out` is that JSON
    // text's UTF-8 bytes.
    let handle: ResolvedIdentityHandle = serde_json::from_slice(&out).unwrap();
    assert_eq!(handle.0, "handle-for-dave");

    // A subsequent `find_user` for the same external_id resolves the
    // identity `provision_user` just recorded (idempotent lookup).
    let out = plugin
        .invoke("call_find_user", br#""dave""#)
        .expect("find_user call should succeed");
    let found: ResolvedIdentityHandle = serde_json::from_slice(&out).unwrap();
    assert_eq!(found, handle);
}

#[test]
fn test_provision_user_domain_violation_fails_closed() {
    let (path, sha256) = build_reference_plugin();
    let config = config_with_capabilities(&path, &sha256, "provision_user,find_user", "");

    let mut configs = HashMap::new();
    configs.insert("p".to_string(), config);
    let host_functions: Option<Arc<dyn HostFunctions>> =
        Some(Arc::new(MockHostFunctions::default()));
    let (registry, errors) =
        WasmPluginRegistry::load(&section(), &configs, host_functions.as_ref());
    assert!(errors.is_empty(), "unexpected load errors: {errors:?}");
    let plugin = registry.get("p").unwrap();

    let request = ProvisionUserRequest {
        external_id: "eve".to_string(),
        user: GuestUserCreate {
            domain_id: "some-other-domain".to_string(),
            name: "Eve".to_string(),
            enabled: Some(true),
            extra: HashMap::new(),
        },
    };
    let err = plugin
        .invoke(
            "call_provision_user",
            serde_json::to_string(&request).unwrap().as_bytes(),
        )
        .expect_err("a domain violation must fail the whole invocation closed");
    assert!(matches!(err, InvokeError::Trap(_)));
}

#[test]
fn test_assign_role_capability_round_trips_and_enforces_role_allowlist() {
    let (path, sha256) = build_reference_plugin();
    let config = config_with_capabilities(&path, &sha256, "provision_user,assign_role", "");

    let mut configs = HashMap::new();
    configs.insert("p".to_string(), config);
    let host_functions: Option<Arc<dyn HostFunctions>> =
        Some(Arc::new(MockHostFunctions::default()));
    let (registry, errors) =
        WasmPluginRegistry::load(&section(), &configs, host_functions.as_ref());
    assert!(errors.is_empty(), "unexpected load errors: {errors:?}");
    let plugin = registry.get("p").unwrap();

    let request = AssignRoleRequest {
        resolved_identity: ResolvedIdentityHandle("irrelevant-for-this-mock".to_string()),
        role: "reader".to_string(),
        target: RoleAssignmentTarget::Project {
            project_id: "proj-1".to_string(),
        },
    };
    plugin
        .invoke(
            "call_assign_role",
            serde_json::to_string(&request).unwrap().as_bytes(),
        )
        .expect("an allowed role should succeed");

    let disallowed = AssignRoleRequest {
        resolved_identity: ResolvedIdentityHandle("irrelevant-for-this-mock".to_string()),
        role: "admin".to_string(),
        target: RoleAssignmentTarget::Domain {
            domain_id: "dom-1".to_string(),
        },
    };
    let err = plugin
        .invoke(
            "call_assign_role",
            serde_json::to_string(&disallowed).unwrap().as_bytes(),
        )
        .expect_err("a disallowed role must fail closed");
    assert!(matches!(err, InvokeError::Trap(_)));
}

#[test]
fn test_assign_role_ungranted_capability_is_rejected() {
    let (path, sha256) = build_reference_plugin();
    // Only provision_user granted; the fixture also imports assign_role.
    let config = config_with_capabilities(&path, &sha256, "provision_user", "");

    let mut configs = HashMap::new();
    configs.insert("p".to_string(), config);
    let host_functions: Option<Arc<dyn HostFunctions>> =
        Some(Arc::new(MockHostFunctions::default()));
    let (registry, errors) =
        WasmPluginRegistry::load(&section(), &configs, host_functions.as_ref());
    assert!(errors.is_empty(), "unexpected load errors: {errors:?}");
    let plugin = registry.get("p").unwrap();

    let request = AssignRoleRequest {
        resolved_identity: ResolvedIdentityHandle("h".to_string()),
        role: "reader".to_string(),
        target: RoleAssignmentTarget::Project {
            project_id: "proj-1".to_string(),
        },
    };
    let err = plugin
        .invoke(
            "call_assign_role",
            serde_json::to_string(&request).unwrap().as_bytes(),
        )
        .expect_err("assign_role was not granted to this plugin");
    assert!(matches!(err, InvokeError::Trap(_)));
}

#[test]
fn test_http_fetch_capability_round_trips_and_enforces_allowed_hosts() {
    let (path, sha256) = build_reference_plugin();
    let config = config_with_capabilities(&path, &sha256, "provision_user,http_fetch", "");

    let mut configs = HashMap::new();
    configs.insert("p".to_string(), config);
    let host_functions: Option<Arc<dyn HostFunctions>> =
        Some(Arc::new(MockHostFunctions::default()));
    let (registry, errors) =
        WasmPluginRegistry::load(&section(), &configs, host_functions.as_ref());
    assert!(errors.is_empty(), "unexpected load errors: {errors:?}");
    let plugin = registry.get("p").unwrap();

    let request = HttpFetchRequest {
        method: "GET".to_string(),
        url: "https://risk.acme.example.com/score".to_string(),
        headers: HashMap::new(),
        body: None,
    };
    let out = plugin
        .invoke(
            "call_http_fetch",
            serde_json::to_string(&request).unwrap().as_bytes(),
        )
        .expect("an allowed host should succeed");
    let response: HttpFetchResponse = serde_json::from_slice(&out).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "fetched:https://risk.acme.example.com/score");

    let disallowed = HttpFetchRequest {
        method: "GET".to_string(),
        url: "http://169.254.169.254/latest/meta-data".to_string(),
        headers: HashMap::new(),
        body: None,
    };
    let err = plugin
        .invoke(
            "call_http_fetch",
            serde_json::to_string(&disallowed).unwrap().as_bytes(),
        )
        .expect_err("a disallowed host must fail closed");
    assert!(matches!(err, InvokeError::Trap(_)));
}
