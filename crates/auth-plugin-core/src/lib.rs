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
//! # Dynamic auth plugin wire contracts and host-facing traits (ADR 0025)
//!
//! Extism-free half of the dynamic (WebAssembly) auth plugin support split
//! out of `openstack-keystone-auth-plugin-runtime`: the wasm wire-boundary
//! contracts (`authenticate`/`mapping`/`route` request/response shapes and
//! their response-bounds validation) and the [`HostFunctions`]/
//! [`AuthPluginRuntime`] traits that let `openstack-keystone-core` implement
//! and consume dynamic auth plugins without ever depending on `extism`
//! itself. The extism-backed execution (`WasmPluginRegistry`,
//! `LoadedPlugin`, the `extism::Function` host-function glue) lives in
//! `openstack-keystone-auth-plugin-runtime`, which depends on this crate.
mod auth_contract;
mod host_functions;
mod mapping_contract;
mod route_contract;
mod runtime;

pub use auth_contract::{
    AuthPluginRequest, AuthPluginResponse, MAX_CLAIM_KEY_BYTES, MAX_CLAIM_VALUE_BYTES, MAX_CLAIMS,
    MAX_RESPONSE_BYTES, RESERVED_ENVELOPE_KEY, RESERVED_KEY_PREFIX, ResponseBoundsError,
    decode_and_validate_response,
};
pub use host_functions::{
    AssignRoleRequest, GuestUserCreate, HostFunctions, HttpFetchRequest, HttpFetchResponse,
    ProvisionUserRequest, ResolvedIdentityHandle, RoleAssignmentTarget,
};
pub use mapping_contract::{
    MappingResponse, MappingResponseBoundsError, WORKLOAD_ID_CLAIM_KEY,
    decode_and_validate_mapping_response,
};
pub use route_contract::{
    RouteRequest, RouteResponse, RouteResponseBoundsError, decode_and_validate_route_response,
};
pub use runtime::{AuthPluginRuntime, EmptyAuthPluginRuntime, InvokeError};
