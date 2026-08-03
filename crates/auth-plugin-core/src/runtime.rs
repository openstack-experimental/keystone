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
//! The seam between `openstack-keystone-core` and the extism-backed
//! `openstack-keystone-auth-plugin-runtime` crate: [`AuthPluginRuntime`] is
//! the trait `core` holds as `Arc<dyn AuthPluginRuntime>` state and calls
//! from its live auth-dispatch code
//! (`openstack_keystone_core::auth_plugin_auth`), so `core` itself never
//! names `extism` or the concrete `WasmPluginRegistry`/`LoadedPlugin` types
//! that implement it - those stay in `auth-plugin-runtime`, which depends on
//! this crate, not the other way around.
use thiserror::Error;

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

/// `core`'s view of a loaded set of dynamic auth plugins - implemented by
/// `openstack_keystone_auth_plugin_runtime::WasmPluginRegistry` (backed by
/// real `extism`/`wasmtime` execution) and by [`EmptyAuthPluginRuntime`]
/// (used before any plugins are loaded, and in tests that don't need a real
/// wasm runtime at all).
pub trait AuthPluginRuntime: Send + Sync {
    /// True if `name` was loaded and checksum-verified successfully.
    fn contains(&self, name: &str) -> bool;

    /// Instantiate and call `function` (`"authenticate"`/`"mapping"`/
    /// `"route"`) on the plugin named `name`, with `input` as its raw
    /// request bytes, returning the raw response bytes.
    fn invoke(&self, name: &str, function: &str, input: &[u8]) -> Result<Vec<u8>, InvokeError>;

    /// Number of plugins currently loaded and available.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An [`AuthPluginRuntime`] with no plugins loaded - `core`'s default state
/// before `load_auth_plugins` runs, and a stand-in for tests that don't
/// exercise real plugin execution (avoids pulling in the extism-backed
/// `auth-plugin-runtime` crate just to construct an empty registry).
#[derive(Debug, Default, Clone, Copy)]
pub struct EmptyAuthPluginRuntime;

impl AuthPluginRuntime for EmptyAuthPluginRuntime {
    fn contains(&self, _name: &str) -> bool {
        false
    }

    fn invoke(&self, name: &str, _function: &str, _input: &[u8]) -> Result<Vec<u8>, InvokeError> {
        Err(InvokeError::Trap(format!(
            "plugin {name} is not loaded (empty auth plugin runtime)"
        )))
    }

    fn len(&self) -> usize {
        0
    }
}
