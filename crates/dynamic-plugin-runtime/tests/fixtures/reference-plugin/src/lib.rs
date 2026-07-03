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
use extism_pdk::{plugin_fn, FnResult, Json};
use serde::{Deserialize, Serialize};

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
