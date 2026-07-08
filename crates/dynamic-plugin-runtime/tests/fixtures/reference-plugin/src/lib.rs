//! ADR 0025 reference dynamic auth plugin.
//!
//! Minimal fixture used only by `openstack-keystone-dynamic-plugin-runtime`'s
//! test suite (see PR 0.3 in `doc/src/adr/0025-implementation-plan.md`). It
//! is not a production plugin and its wire shapes are intentionally simple
//! placeholders - Phase 1-3 of the implementation plan define the real
//! `AuthPluginRequest`/`AuthPluginResponse` etc. contracts these entry
//! points will grow into.
//!
//! A third-party plugin author following the same pattern needs only:
//! `extism-pdk` as a dependency, `crate-type = ["cdylib"]`, and to compile
//! for the `wasm32-unknown-unknown` target (`rustup target add
//! wasm32-unknown-unknown`, then `cargo build --release --target
//! wasm32-unknown-unknown`).
use extism_pdk::{host_fn, plugin_fn, FnResult, Json};
use serde::{Deserialize, Serialize};

// Host functions §6 A-D (ADR 0025 Phase 1, PR 1.1). Declared as raw
// `String` in/out (JSON text) rather than `Json<T>` here so this guest
// never needs to depend on the host's own request/response types - it just
// forwards/parses JSON text, exactly as a genuinely third-party plugin
// author would since they can't import the host's Rust structs either.
#[host_fn]
extern "ExtismHost" {
    fn provision_user(request_json: String) -> String;
    fn find_user(external_id_json: String) -> String;
    fn assign_role(request_json: String) -> String;
    fn http_fetch(request_json: String) -> String;
}

/// Test-only entry point (not part of the ADR's guest contract) proving the
/// `provision_user` host function is reachable and round-trips JSON
/// correctly when this plugin's config grants the `provision_user`
/// capability.
#[plugin_fn]
pub fn call_provision_user(request_json: String) -> FnResult<String> {
    let handle = unsafe { provision_user(request_json)? };
    Ok(handle)
}

/// Test-only entry point mirroring [`call_provision_user`] for `find_user`.
#[plugin_fn]
pub fn call_find_user(external_id_json: String) -> FnResult<String> {
    let handle = unsafe { find_user(external_id_json)? };
    Ok(handle)
}

/// Test-only entry point mirroring [`call_provision_user`] for
/// `assign_role`.
#[plugin_fn]
pub fn call_assign_role(request_json: String) -> FnResult<String> {
    let result = unsafe { assign_role(request_json)? };
    Ok(result)
}

/// Test-only entry point mirroring [`call_provision_user`] for
/// `http_fetch`.
#[plugin_fn]
pub fn call_http_fetch(request_json: String) -> FnResult<String> {
    let result = unsafe { http_fetch(request_json)? };
    Ok(result)
}

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub external_id: String,
    #[serde(default)]
    pub deny: bool,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub decision: &'static str,
    pub external_id: String,
}

/// Stand-in for the eventual `authenticate` guest entry point (`full_auth`
/// mode). Allows unless the caller asks to be denied, echoing back the
/// external id it was given - just enough behavior for Phase 0 tests to
/// prove a real Rust-compiled `.wasm` module loads and round-trips JSON
/// through Extism.
#[plugin_fn]
pub fn authenticate(req: Json<AuthRequest>) -> FnResult<Json<AuthResponse>> {
    let req = req.0;
    let decision = if req.deny { "deny" } else { "allow" };
    Ok(Json(AuthResponse {
        decision,
        external_id: req.external_id,
    }))
}

#[derive(Debug, Deserialize)]
pub struct MappingRequest {
    #[serde(default)]
    pub deny: bool,
}

#[derive(Debug, Serialize)]
pub struct MappingResponse {
    pub decision: &'static str,
}

/// Stand-in for the eventual `mapping` guest entry point (`mapping` mode).
#[plugin_fn]
pub fn mapping(req: Json<MappingRequest>) -> FnResult<Json<MappingResponse>> {
    let decision = if req.0.deny { "deny" } else { "claims" };
    Ok(Json(MappingResponse { decision }))
}

#[derive(Debug, Deserialize)]
pub struct RouteRequest {
    pub target_method: String,
}

#[derive(Debug, Serialize)]
pub struct RouteResponse {
    pub decision: &'static str,
    pub target_method: String,
}

/// Stand-in for the eventual `route` guest entry point (`route` mode).
#[plugin_fn]
pub fn route(req: Json<RouteRequest>) -> FnResult<Json<RouteResponse>> {
    Ok(Json(RouteResponse {
        decision: "route",
        target_method: req.0.target_method,
    }))
}

/// Resource-limit fixture (PR 0.4): burns CPU without ever returning,
/// tripping either the host's fuel limit or its wall-clock timeout
/// depending on which bound the caller configured tighter for a given
/// test - the loop body itself is identical either way.
#[plugin_fn]
pub fn spin() -> FnResult<()> {
    let mut x: u64 = 0;
    loop {
        x = x.wrapping_add(1).wrapping_mul(2654435761);
        std::hint::black_box(x);
    }
}

/// Resource-limit fixture (PR 0.4): grows a buffer without bound until the
/// guest allocator fails, tripping the host's `memory_limit_mb`.
#[plugin_fn]
pub fn allocate_memory() -> FnResult<()> {
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    loop {
        chunks.push(vec![0xAAu8; 1024 * 1024]);
        std::hint::black_box(&chunks);
    }
}
