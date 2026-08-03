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
//! Host functions §6 A-D (`http_fetch`, `provision_user`, `find_user`,
//! `assign_role`) - ADR 0025 Phase 1 (PR 1.1).
//!
//! The actual identity-backing logic (namespace-scoped storage, domain
//! restriction, CADF audit) lives in `openstack-keystone-core`, which
//! depends on this crate - not the other way around (this crate must never
//! depend on `core`, per the Phase 0 plan). [`HostFunctions`] is the seam:
//! `core` implements it and hands an `Arc<dyn HostFunctions>` to
//! [`crate::WasmPluginRegistry::load`], which uses it to build the
//! `extism::Function`s registered into each plugin. Every function is
//! registered whenever a [`HostFunctions`] provider is configured at all,
//! but each closure independently rejects a call its plugin's
//! `capabilities` config didn't grant - see
//! [`HostFnContext::granted`](self::HostFnContext) for why `wasmtime`'s
//! all-imports-must-resolve-at-instantiation requirement rules out
//! per-capability import omission for a single compiled module.
use std::sync::Arc;

use extism::convert::Json;
use extism::{CurrentPlugin, Function, PTR, UserData, Val};
use openstack_keystone_auth_plugin_core::{
    AssignRoleRequest, HostFunctions, HttpFetchRequest, ProvisionUserRequest,
};

#[derive(Clone)]
struct HostFnContext {
    plugin_name: String,
    /// This plugin's config-granted capability set, snapshotted at load
    /// time. `wasmtime` requires every guest-declared import to resolve at
    /// instantiation regardless of whether the plugin's compiled module
    /// happens to call it (an unresolved import fails *every* invocation
    /// of that module, not just calls to the missing function) - so a
    /// `Function` is always registered here whenever a
    /// [`HostFunctions`] provider exists at all, and the actual §6
    /// capability grant is enforced inside the closure instead of by
    /// selectively omitting the registration. From the guest's
    /// perspective the result is identical either way: an ungranted
    /// capability can never be successfully exercised, structurally or
    /// otherwise.
    granted: Arc<[String]>,
    host: Arc<dyn HostFunctions>,
}

fn provision_user_fn(
    plugin: &mut CurrentPlugin,
    inputs: &[Val],
    outputs: &mut [Val],
    user_data: UserData<HostFnContext>,
) -> Result<(), extism::Error> {
    let Json(request): Json<ProvisionUserRequest> = plugin.memory_get_val(&inputs[0])?;
    let data = user_data.get()?;
    let ctx = data
        .lock()
        .map_err(|_| extism::Error::msg("provision_user: host context poisoned"))?;
    if !ctx.granted.iter().any(|c| c == "provision_user") {
        return Err(extism::Error::msg(
            "provision_user: not granted to this plugin",
        ));
    }
    let handle = ctx
        .host
        .provision_user(&ctx.plugin_name, request)
        .map_err(|reason| extism::Error::msg(format!("provision_user denied: {reason}")))?;
    let mem = plugin.memory_new(Json(handle))?;
    outputs[0] = plugin.memory_to_val(mem);
    Ok(())
}

fn find_user_fn(
    plugin: &mut CurrentPlugin,
    inputs: &[Val],
    outputs: &mut [Val],
    user_data: UserData<HostFnContext>,
) -> Result<(), extism::Error> {
    let Json(external_id): Json<String> = plugin.memory_get_val(&inputs[0])?;
    let data = user_data.get()?;
    let ctx = data
        .lock()
        .map_err(|_| extism::Error::msg("find_user: host context poisoned"))?;
    if !ctx.granted.iter().any(|c| c == "find_user") {
        return Err(extism::Error::msg("find_user: not granted to this plugin"));
    }
    let result = ctx
        .host
        .find_user(&ctx.plugin_name, external_id)
        .map_err(|reason| extism::Error::msg(format!("find_user failed: {reason}")))?;
    let mem = plugin.memory_new(Json(result))?;
    outputs[0] = plugin.memory_to_val(mem);
    Ok(())
}

fn assign_role_fn(
    plugin: &mut CurrentPlugin,
    inputs: &[Val],
    outputs: &mut [Val],
    user_data: UserData<HostFnContext>,
) -> Result<(), extism::Error> {
    let Json(request): Json<AssignRoleRequest> = plugin.memory_get_val(&inputs[0])?;
    let data = user_data.get()?;
    let ctx = data
        .lock()
        .map_err(|_| extism::Error::msg("assign_role: host context poisoned"))?;
    if !ctx.granted.iter().any(|c| c == "assign_role") {
        return Err(extism::Error::msg(
            "assign_role: not granted to this plugin",
        ));
    }
    ctx.host
        .assign_role(&ctx.plugin_name, request)
        .map_err(|reason| extism::Error::msg(format!("assign_role denied: {reason}")))?;
    let mem = plugin.memory_new(Json(()))?;
    outputs[0] = plugin.memory_to_val(mem);
    Ok(())
}

fn http_fetch_fn(
    plugin: &mut CurrentPlugin,
    inputs: &[Val],
    outputs: &mut [Val],
    user_data: UserData<HostFnContext>,
) -> Result<(), extism::Error> {
    let Json(request): Json<HttpFetchRequest> = plugin.memory_get_val(&inputs[0])?;
    let data = user_data.get()?;
    let ctx = data
        .lock()
        .map_err(|_| extism::Error::msg("http_fetch: host context poisoned"))?;
    if !ctx.granted.iter().any(|c| c == "http_fetch") {
        return Err(extism::Error::msg("http_fetch: not granted to this plugin"));
    }
    let response = ctx
        .host
        .http_fetch(&ctx.plugin_name, request)
        .map_err(|reason| extism::Error::msg(format!("http_fetch failed: {reason}")))?;
    let mem = plugin.memory_new(Json(response))?;
    outputs[0] = plugin.memory_to_val(mem);
    Ok(())
}

/// Build the `extism::Function`s to register for a plugin. All four host
/// functions are always registered whenever a [`HostFunctions`] provider is
/// configured at all - see [`HostFnContext::granted`]'s doc comment for why
/// an unresolved import isn't a viable per-capability gating mechanism
/// against a single wasm module - and each closure independently rejects a
/// call its plugin's `capabilities` config didn't grant (ADR 0025 §6: an
/// ungranted capability can never be successfully exercised).
pub(crate) fn build_functions(
    plugin_name: &str,
    capabilities: &[String],
    host_functions: Option<&Arc<dyn HostFunctions>>,
) -> Vec<Function> {
    let Some(host) = host_functions else {
        return Vec::new();
    };
    let ctx = HostFnContext {
        plugin_name: plugin_name.to_string(),
        granted: capabilities.to_vec().into(),
        host: host.clone(),
    };
    vec![
        Function::new(
            "provision_user",
            [PTR],
            [PTR],
            UserData::new(ctx.clone()),
            provision_user_fn,
        ),
        Function::new(
            "find_user",
            [PTR],
            [PTR],
            UserData::new(ctx.clone()),
            find_user_fn,
        ),
        Function::new(
            "assign_role",
            [PTR],
            [PTR],
            UserData::new(ctx.clone()),
            assign_role_fn,
        ),
        Function::new(
            "http_fetch",
            [PTR],
            [PTR],
            UserData::new(ctx),
            http_fetch_fn,
        ),
    ]
}
