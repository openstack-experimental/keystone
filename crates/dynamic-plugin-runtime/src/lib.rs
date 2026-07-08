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
//! # Dynamic auth plugin runtime (ADR 0025)
//!
//! Loads WebAssembly auth plugins from local disk at process startup,
//! verifies each against its pinned SHA-256 checksum, and compiles it via
//! [`extism`]/`wasmtime` with each plugin's configured resource bounds
//! (`fuel_limit`, `timeout_ms`, `memory_limit_mb`, ADR §7) baked into the
//! compiled module. Host functions [`HostFunctions::provision_user`]/
//! [`HostFunctions::find_user`] (ADR §6 B/C) are registered per plugin,
//! gated by that plugin's configured `capabilities` - `http_fetch` (§6.A)
//! and `assign_role` (§6.D) are not implemented yet, and this crate does
//! not dispatch real `authenticate`/`mapping`/`route` requests from an auth
//! method - that's Phase 1's PR 1.2+
//! (`doc/plans/0025-implementation-plan.md`).
//!
//! No WASI imports are ever registered on a loaded plugin, matching ADR
//! 0025 §6.F ("Sandbox Baseline: No WASI"). Every call to
//! [`LoadedPlugin::invoke`] instantiates a fresh [`extism::Plugin`] (and so
//! a fresh `wasmtime::Store`) from the cached compiled module, matching ADR
//! §7 "Isolation between requests" - no state or resource budget survives
//! from one invocation to the next.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use extism::{CompiledPlugin, Manifest, Plugin, PluginBuilder, Wasm};
use openstack_keystone_config::{DynamicPluginConfig, DynamicPluginsSection};
use sha2::{Digest, Sha256};
use thiserror::Error;

mod host_functions;
pub use host_functions::{
    AssignRoleRequest, GuestUserCreate, HostFunctions, HttpFetchRequest, HttpFetchResponse,
    ProvisionUserRequest, ResolvedIdentityHandle, RoleAssignmentTarget,
};

/// WebAssembly linear memory page size, per the Wasm spec (64 KiB).
const WASM_PAGE_BYTES: u64 = 64 * 1024;

/// Why a single configured plugin failed to load. Per ADR 0025 §5, this is
/// never fatal to the process - it only means *this* plugin is not
/// registered as an auth method; every other plugin and every builtin auth
/// method still start normally.
#[derive(Debug, Error)]
pub enum PluginLoadError {
    #[error("reading plugin file {path}: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "checksum mismatch for plugin: configured sha256 {expected} does not match \
         computed sha256 {actual} of {path}"
    )]
    ChecksumMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("compiling wasm module {path}: {source}")]
    Compile {
        path: String,
        #[source]
        source: extism::Error,
    },
}

/// Why a single invocation of a loaded plugin failed. Per ADR 0025 §7,
/// exceeding any bound fails only that invocation - the plugin stays
/// loaded and registered for the next call.
#[derive(Debug, Error)]
pub enum InvokeError {
    /// The plugin's `fuel_limit` (instruction budget) was exhausted before
    /// the call returned.
    #[error("plugin exceeded its fuel_limit and was aborted")]
    FuelExhausted,
    /// The plugin's `timeout_ms` wall-clock budget elapsed before the call
    /// returned.
    #[error("plugin exceeded its timeout_ms and was aborted")]
    Timeout,
    /// Any other guest-side failure: a trap (e.g. an allocation past
    /// `memory_limit_mb`, an explicit panic/abort in the guest), a
    /// malformed call, or an instantiation failure.
    #[error("plugin invocation failed: {0}")]
    Trap(String),
}

impl InvokeError {
    /// Extism/wasmtime don't expose a typed distinction between "ran out of
    /// fuel" and "hit the epoch deadline" versus an ordinary trap - both
    /// surface as an [`extism::Error`] whose message is produced by
    /// wasmtime. Classify on the (stable, wasmtime-owned) message text
    /// rather than leaving every resource-limit violation as an
    /// undifferentiated [`InvokeError::Trap`].
    fn classify(err: extism::Error) -> Self {
        let msg = err.to_string();
        if msg.contains("fuel") {
            InvokeError::FuelExhausted
        } else if msg.contains("timeout")
            || msg.contains("epoch deadline")
            || msg.contains("interrupt")
        {
            InvokeError::Timeout
        } else {
            InvokeError::Trap(msg)
        }
    }
}

/// A plugin that loaded and checksum-verified successfully. Holds a
/// *compiled* module - including whichever host functions its
/// `capabilities` config granted it (ADR §6) - plus its resource-limit
/// configuration; no `wasmtime::Store` is created (and so no guest memory
/// allocated, no fuel budget started) until [`LoadedPlugin::invoke`] is
/// called.
pub struct LoadedPlugin {
    pub name: String,
    pub sha256: String,
    compiled: CompiledPlugin,
}

impl LoadedPlugin {
    /// Instantiate a fresh [`extism::Plugin`] from the cached compiled
    /// module and call `function` with `input`, returning the raw output
    /// bytes. A new `wasmtime::Store` (and so a fresh fuel budget, timeout
    /// clock, and linear memory) is created for this call only - nothing
    /// carries over between invocations (ADR §7 "Isolation between
    /// requests").
    pub fn invoke(&self, function: &str, input: &[u8]) -> Result<Vec<u8>, InvokeError> {
        let mut plugin = Plugin::new_from_compiled(&self.compiled)
            .map_err(|e| InvokeError::Trap(e.to_string()))?;
        plugin
            .call::<&[u8], Vec<u8>>(function, input)
            .map_err(InvokeError::classify)
    }
}

/// Registry of successfully loaded dynamic auth plugins, keyed by plugin
/// name. Plugins that failed to load (missing file, checksum mismatch,
/// compile error) are not present here - see [`WasmPluginRegistry::load`]
/// for the per-plugin errors raised along the way.
#[derive(Default)]
pub struct WasmPluginRegistry {
    plugins: HashMap<String, LoadedPlugin>,
}

impl WasmPluginRegistry {
    /// Load and checksum-verify every plugin named in `section`, looking up
    /// each one's `[dynamic_plugin.<name>]` entry in `configs`. Returns the
    /// registry of plugins that loaded successfully, plus one
    /// [`PluginLoadError`] per plugin that did not - the caller (process
    /// startup) is expected to log each error at `CRITICAL` and continue,
    /// per ADR 0025 §5's "cross-node divergence is an accepted trade-off"
    /// posture: a load failure disables only that plugin, never the node.
    pub fn load(
        section: &DynamicPluginsSection,
        configs: &HashMap<String, DynamicPluginConfig>,
        host_functions: Option<&Arc<dyn HostFunctions>>,
    ) -> (Self, Vec<(String, PluginLoadError)>) {
        let mut registry = Self::default();
        let mut errors = Vec::new();

        for name in &section.plugins {
            // Config-shape validation (missing section, reserved names, ...)
            // is `DynamicPluginsSection::validate_semantics`'s job and is
            // assumed to have already run and succeeded before `load` is
            // called - a name with no config entry here is a programming
            // error in the caller, not a runtime condition to recover from.
            let Some(config) = configs.get(name) else {
                continue;
            };

            match Self::load_one(name, config, host_functions) {
                Ok(loaded) => {
                    registry.plugins.insert(name.clone(), loaded);
                }
                Err(err) => {
                    tracing::error!(
                        target: "keystone_dynamic_plugin_load_failure",
                        plugin_name = %name,
                        error = %err,
                        "dynamic auth plugin failed to load; this plugin is disabled, \
                         all other auth methods start normally"
                    );
                    errors.push((name.clone(), err));
                }
            }
        }

        (registry, errors)
    }

    fn load_one(
        name: &str,
        config: &DynamicPluginConfig,
        host_functions: Option<&Arc<dyn HostFunctions>>,
    ) -> Result<LoadedPlugin, PluginLoadError> {
        let bytes = std::fs::read(&config.path).map_err(|source| PluginLoadError::ReadFile {
            path: config.path.display().to_string(),
            source,
        })?;

        let actual = hex::encode(Sha256::digest(&bytes));
        if !actual.eq_ignore_ascii_case(&config.sha256) {
            return Err(PluginLoadError::ChecksumMismatch {
                path: config.path.display().to_string(),
                expected: config.sha256.clone(),
                actual,
            });
        }

        // Round up so a `memory_limit_mb` that isn't an exact multiple of
        // the 64 KiB page size still gets at least the requested budget,
        // and clamp to `[1, u32::MAX]` pages: never zero (a 0-page cap
        // would make every plugin call fail instantiation instead of
        // failing the way ADR §7 intends: a specific over-budget call
        // traps) and never silently wrapped by the `u32` cast for a large
        // `memory_limit_mb` (e.g. `268435456` MB is exactly 2^32 pages,
        // which would otherwise truncate to 0).
        let max_pages = (u64::from(config.memory_limit_mb) * 1024 * 1024)
            .div_ceil(WASM_PAGE_BYTES)
            .clamp(1, u64::from(u32::MAX)) as u32;
        let manifest = Manifest::new([Wasm::data(bytes)])
            .with_memory_max(max_pages)
            .with_timeout(Duration::from_millis(config.timeout_ms));

        // Host functions are baked into the *compiled* module (extism has
        // no per-invocation function-registration hook - see
        // `host_functions::build_functions`'s doc comment) - only the
        // capabilities this plugin's config actually lists are registered,
        // so an unlisted host function is structurally absent from the
        // guest's import table (ADR 0025 §6 preamble).
        let functions = host_functions::build_functions(name, &config.capabilities, host_functions);

        // `wasi(false)` is the `PluginBuilder` default - stated explicitly
        // here so this stays true even if that default ever changes
        // upstream (ADR 0025 §6.F: no WASI imports, ever).
        let compiled = PluginBuilder::new(manifest)
            .with_wasi(false)
            .with_fuel_limit(config.fuel_limit)
            .with_functions(functions)
            .compile()
            .map_err(|source| PluginLoadError::Compile {
                path: config.path.display().to_string(),
                source,
            })?;

        Ok(LoadedPlugin {
            name: name.to_string(),
            sha256: actual,
            compiled,
        })
    }

    /// Number of plugins currently loaded and available.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Look up a loaded plugin by name (its `[auth] methods` entry).
    pub fn get(&self, name: &str) -> Option<&LoadedPlugin> {
        self.plugins.get(name)
    }

    /// True if `name` was loaded and checksum-verified successfully.
    pub fn contains(&self, name: &str) -> bool {
        self.plugins.contains_key(name)
    }
}

// Minimal local hex-encoding helper so this crate doesn't need to pull in
// a dedicated `hex` dependency for a single call site.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        use std::fmt::Write;
        bytes.as_ref().iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{:02x}", b);
            acc
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::Path;

    use openstack_keystone_config::PluginMode;
    use sha2::{Digest, Sha256};
    use tempfile::NamedTempFile;

    use super::*;

    // The smallest valid WASM module: `(module)`.
    const EMPTY_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    fn write_wasm(bytes: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    fn config_for(path: &Path, sha256: String) -> DynamicPluginConfig {
        // Constructed via a throwaway INI parse since `DynamicPluginConfig`
        // has no public constructor by design (its fields are meant to
        // come from `keystone.conf`, not be hand-built by application
        // code).
        use config::{Config, File, FileFormat};

        #[derive(Debug, serde::Deserialize)]
        struct Wrapper {
            dynamic_plugin: HashMap<String, DynamicPluginConfig>,
        }

        let ini = format!(
            "[dynamic_plugin.p]\npath = {}\nsha256 = {}\nmode = full_auth\ncapabilities = provision_user\nprovision_domain_id = d\n",
            path.display(),
            sha256
        );
        let c = Config::builder()
            .add_source(File::from_str(&ini, FileFormat::Ini))
            .build()
            .unwrap();
        let wrapper: Wrapper = c.try_deserialize().unwrap();
        wrapper.dynamic_plugin.into_iter().next().unwrap().1
    }

    fn section(name: &str) -> DynamicPluginsSection {
        DynamicPluginsSection {
            plugins: vec![name.to_string()],
        }
    }

    #[test]
    fn test_load_valid_plugin_succeeds() {
        let f = write_wasm(EMPTY_WASM);
        let sha256 = hex::encode(Sha256::digest(EMPTY_WASM));
        let config = config_for(f.path(), sha256.clone());
        assert_eq!(config.mode, PluginMode::FullAuth);

        let mut configs = HashMap::new();
        configs.insert("p".to_string(), config);
        let (registry, errors) = WasmPluginRegistry::load(&section("p"), &configs, None);

        assert!(errors.is_empty(), "unexpected load errors: {errors:?}");
        assert_eq!(registry.len(), 1);
        assert!(registry.contains("p"));
        assert_eq!(registry.get("p").unwrap().sha256, sha256);
    }

    #[test]
    fn test_checksum_mismatch_disables_only_that_plugin() {
        let f = write_wasm(EMPTY_WASM);
        // Deliberately wrong, but well-formed (64 hex chars), checksum.
        let wrong_sha256 = "0".repeat(64);
        let config = config_for(f.path(), wrong_sha256);

        let mut configs = HashMap::new();
        configs.insert("p".to_string(), config);
        let (registry, errors) = WasmPluginRegistry::load(&section("p"), &configs, None);

        assert!(registry.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(matches!(
            errors[0].1,
            PluginLoadError::ChecksumMismatch { .. }
        ));
    }

    #[test]
    fn test_missing_file_disables_only_that_plugin() {
        let config = config_for(Path::new("/nonexistent/path/plugin.wasm"), "0".repeat(64));

        let mut configs = HashMap::new();
        configs.insert("p".to_string(), config);
        let (registry, errors) = WasmPluginRegistry::load(&section("p"), &configs, None);

        assert!(registry.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(matches!(errors[0].1, PluginLoadError::ReadFile { .. }));
    }

    #[test]
    fn test_multiple_plugins_one_bad_one_good() {
        let good_file = write_wasm(EMPTY_WASM);
        let good_sha256 = hex::encode(Sha256::digest(EMPTY_WASM));
        let good_config = config_for(good_file.path(), good_sha256);
        let bad_config = config_for(Path::new("/nonexistent/plugin.wasm"), "0".repeat(64));

        let mut configs = HashMap::new();
        configs.insert("good".to_string(), good_config);
        configs.insert("bad".to_string(), bad_config);
        let section = DynamicPluginsSection {
            plugins: vec!["good".to_string(), "bad".to_string()],
        };
        let (registry, errors) = WasmPluginRegistry::load(&section, &configs, None);

        assert_eq!(registry.len(), 1);
        assert!(registry.contains("good"));
        assert!(!registry.contains("bad"));
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, "bad");
    }
}
