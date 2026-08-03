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
//! `openstack_keystone_auth_plugin_runtime::WasmPluginRegistry::load`, which
//! uses it to build the `extism::Function`s registered into each plugin -
//! that extism-facing glue lives in the `auth-plugin-runtime` crate, not
//! here, so this crate (and everything that only needs the trait/DTOs, like
//! `core`) never pulls in `extism`.
use serde::{Deserialize, Serialize};

/// Guest-facing, host-sanitized subset of user-creation fields a
/// `provision_user`-capable plugin may supply (ADR 0025 §6.B "Field
/// sanitization"). Deliberately narrower than the host's internal
/// `UserCreate`: no `id` (host-generated, always), no `password`, no
/// `options` - an allowlist, so a field added to the internal type in the
/// future is excluded here by default rather than silently reachable from
/// guest code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestUserCreate {
    /// Checked host-side against the plugin's configured
    /// `provision_domain_id`/`allowed_provision_domains` before being
    /// accepted (ADR §6.B "Domain restriction") - not trusted verbatim.
    pub domain_id: String,
    pub name: String,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionUserRequest {
    /// Plugin-derived identifier for the external identity, never a
    /// Keystone `user_id` (ADR §4 "Identity Binding").
    pub external_id: String,
    pub user: GuestUserCreate,
}

/// Opaque, host-issued handle a plugin can present back via
/// `Allow.resolved_identity` (ADR 0025 §4 "Identity Binding") - never a raw
/// `user_id`. Structurally, the only way to obtain one is a prior
/// `provision_user`/`find_user` call that resolved within this exact
/// plugin's own `(plugin_name, external_id)` namespace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedIdentityHandle(pub String);

/// Where an `assign_role` grant lands - never system scope, structurally
/// (ADR 0025 §6.D "Which scope type" - there is no `System` variant here at
/// all, so a plugin invocation has no code path to request one).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "scope")]
pub enum RoleAssignmentTarget {
    Project { project_id: String },
    Domain { domain_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignRoleRequest {
    /// Must be a handle this exact plugin's own `provision_user`/
    /// `find_user` call produced (ADR §6.D: "the same anti-impersonation
    /// constraint applies here").
    pub resolved_identity: ResolvedIdentityHandle,
    /// Checked host-side against the plugin's `assign_role_allowed` list.
    pub role: String,
    pub target: RoleAssignmentTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFetchRequest {
    pub method: String,
    /// Checked host-side against `allowed_hosts` plus connect-time IP
    /// re-validation (ADR §6.A) - not trusted verbatim.
    pub url: String,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// UTF-8 request body. Binary bodies are out of scope for this
    /// implementation - a plugin needing one must encode it (e.g. base64)
    /// at the application layer.
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFetchResponse {
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    /// UTF-8 (lossy) response body - see [`HttpFetchRequest::body`]'s note
    /// on binary payloads.
    pub body: String,
}

/// Host functions §6 A-D, implemented by `openstack-keystone-core`.
///
/// Every method is synchronous because `extism::Function` closures are
/// synchronous FFI callbacks invoked from inside `wasmtime`. An
/// implementation backed by async I/O (a database call) must bridge
/// internally - e.g. `tokio::task::block_in_place` +
/// `Handle::current().block_on(..)` - and callers of
/// `openstack_keystone_auth_plugin_runtime::LoadedPlugin::invoke` are
/// expected to run it somewhere blocking briefly is acceptable (a
/// `spawn_blocking` task), never directly on an async executor's reactor
/// thread.
pub trait HostFunctions: Send + Sync + 'static {
    /// ADR 0025 §6.B. Must be idempotent and atomic on
    /// `(plugin_name, external_id)` - a repeat call with the same
    /// `external_id` returns the same provisioned identity rather than
    /// creating a duplicate.
    ///
    /// `Err` traps the whole invocation, failing the login closed (ADR §7);
    /// a plugin never receives a granular reason (e.g. "wrong domain"), so
    /// it cannot use the failure to probe its own capability boundary.
    fn provision_user(
        &self,
        plugin_name: &str,
        request: ProvisionUserRequest,
    ) -> Result<ResolvedIdentityHandle, String>;

    /// ADR 0025 §6.C. Read-only lookup within the same
    /// `(plugin_name, external_id)` namespace `provision_user` writes to.
    /// `Ok(None)` is a legitimate outcome (no such identity yet); only a
    /// genuine host-side failure uses `Err`.
    fn find_user(
        &self,
        plugin_name: &str,
        external_id: String,
    ) -> Result<Option<ResolvedIdentityHandle>, String>;

    /// ADR 0025 §6.D. Grants `request.role` to the identity
    /// `request.resolved_identity` names, bounded on the three axes §6.D
    /// requires: role allowlist, target-domain restriction (reusing
    /// `provision_user`'s `provision_domain_id`/`allowed_provision_domains`
    /// config), and scope type (no `System` variant exists in
    /// [`RoleAssignmentTarget`] at all).
    fn assign_role(&self, plugin_name: &str, request: AssignRoleRequest) -> Result<(), String>;

    /// ADR 0025 §6.A. SSRF-hardened outbound HTTP: `request.url`'s host
    /// must be in the plugin's `allowed_hosts`, and the connection is made
    /// to a connect-time-revalidated IP address, not a hostname handed to
    /// the HTTP client to resolve a second time (closes the standard
    /// DNS-rebinding bypass of a hostname-only allowlist).
    fn http_fetch(
        &self,
        plugin_name: &str,
        request: HttpFetchRequest,
    ) -> Result<HttpFetchResponse, String>;
}
