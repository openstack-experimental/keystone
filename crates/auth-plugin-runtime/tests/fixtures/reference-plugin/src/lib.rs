//! ADR 0025 reference dynamic auth plugin.
//!
//! Minimal fixture used only by `openstack-keystone-auth-plugin-runtime`'s
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
use extism_pdk::{FnResult, Json, host_fn, plugin_fn};
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

// `AuthPluginRequest`/`AuthPluginResponse` mirror
// `openstack_keystone_auth_plugin_runtime::auth_contract`'s wire shape
// (ADR 0025 §4 "Guest Contract - full_auth Mode") - defined locally rather
// than imported, keeping this fixture crate dependency-free from
// `auth-plugin-runtime`'s Rust types, exactly as a genuinely third-party
// plugin author (who cannot import the host's Rust structs) would have to.

#[derive(Debug, Deserialize)]
pub struct AuthPluginRequest {
    pub payload: AuthPayload,
    #[serde(default)]
    #[allow(dead_code)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub remote_addr: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthPayload {
    pub external_id: String,
    #[serde(default)]
    pub deny: bool,
    /// Defaults to the domain this fixture's own `[auth_plugin.p]`
    /// config grants in tests (`provision_domain_id = d`).
    #[serde(default = "default_domain_id")]
    pub domain_id: String,
    /// Test-only hook: skip the real `provision_user` call and return a
    /// self-fabricated `resolved_identity` instead - simulates a
    /// compromised/buggy plugin trying to hand back a handle it was never
    /// actually issued, proving the host's identity-binding verification
    /// (ADR §4 step 3) rejects it rather than trusting it.
    #[serde(default)]
    pub bad_handle: bool,
}

fn default_domain_id() -> String {
    "d".to_string()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum AuthPluginResponse {
    Allow {
        resolved_identity: String,
        claims: std::collections::HashMap<String, serde_json::Value>,
    },
    Deny {
        reason: String,
    },
}

/// `full_auth` mode's `authenticate` guest entry point (ADR 0025 §4). Denies
/// if the caller asked to be denied; otherwise calls the host's
/// `provision_user` (idempotent - a repeat call with the same `external_id`
/// resolves the same identity, PR 1.1) and returns the resulting handle,
/// with a small claim proving the plugin's own claims-namespacing
/// (`plugin_claims.<plugin_name>.*`) round-trips end to end.
#[plugin_fn]
pub fn authenticate(req: Json<AuthPluginRequest>) -> FnResult<Json<AuthPluginResponse>> {
    let payload = req.0.payload;
    if payload.deny {
        return Ok(Json(AuthPluginResponse::Deny {
            reason: "reference-plugin: deny requested".to_string(),
        }));
    }
    if payload.bad_handle {
        return Ok(Json(AuthPluginResponse::Allow {
            resolved_identity: "forged-handle-never-issued-by-the-host".to_string(),
            claims: std::collections::HashMap::new(),
        }));
    }

    let provision_request = serde_json::json!({
        "external_id": payload.external_id,
        "user": {
            "domain_id": payload.domain_id,
            "name": payload.external_id,
            "enabled": true,
            "extra": {},
        },
    });
    let handle_json = unsafe { provision_user(provision_request.to_string())? };
    let resolved_identity: String = serde_json::from_str(&handle_json)?;

    let mut claims = std::collections::HashMap::new();
    claims.insert(
        "source".to_string(),
        serde_json::Value::String("reference-plugin".to_string()),
    );

    Ok(Json(AuthPluginResponse::Allow {
        resolved_identity,
        claims,
    }))
}

#[derive(Debug, Deserialize)]
pub struct MappingPayload {
    pub external_id: String,
    #[serde(default)]
    pub deny: bool,
}

#[derive(Debug, Deserialize)]
pub struct MappingPluginRequest {
    pub payload: MappingPayload,
    #[serde(default)]
    #[allow(dead_code)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub remote_addr: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum MappingResponse {
    Claims {
        claims: std::collections::HashMap<String, serde_json::Value>,
    },
    Deny {
        reason: String,
    },
}

/// `mapping` mode's `mapping` guest entry point (ADR 0025 §4). Denies if the
/// caller asked to be denied; otherwise returns claims feeding the host's
/// Mapping Engine, including the reserved `__keystone_workload_id` claim
/// every `mapping`-mode plugin must supply
/// (`openstack_keystone_auth_plugin_runtime::mapping_contract`).
#[plugin_fn]
pub fn mapping(req: Json<MappingPluginRequest>) -> FnResult<Json<MappingResponse>> {
    let payload = req.0.payload;
    if payload.deny {
        return Ok(Json(MappingResponse::Deny {
            reason: "reference-plugin: deny requested".to_string(),
        }));
    }

    let mut claims = std::collections::HashMap::new();
    claims.insert(
        "__keystone_workload_id".to_string(),
        serde_json::Value::String(payload.external_id.clone()),
    );
    claims.insert(
        "external_id".to_string(),
        serde_json::Value::String(payload.external_id),
    );

    Ok(Json(MappingResponse::Claims { claims }))
}

#[derive(Debug, Deserialize)]
pub struct RouteRequest {
    pub methods: Vec<String>,
    #[serde(default)]
    pub payloads: std::collections::HashMap<String, serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub remote_addr: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum RouteResponse {
    Passthrough,
    Route {
        target_method: String,
        payload: serde_json::Value,
    },
    Deny {
        reason: String,
    },
}

/// `route` mode's `route` guest entry point (ADR 0025 §4). Inspects the
/// `application_credential` payload block (the ADR's own motivating
/// example): an `application_credential_id` of `"deny-me"` denies outright,
/// one prefixed `tf-` is rerouted to `hacked_appcred_handler` with the rest of
/// the id relabeled into an `external_id` field (so this fixture composes
/// end-to-end with the `authenticate` export above in integration tests -
/// a real router would shape its `payload` however its actual target
/// method's contract requires), and anything else passes through
/// unmodified - mirrors the ADR's own reference router example (§5 config
/// example).
#[plugin_fn]
pub fn route(req: Json<RouteRequest>) -> FnResult<Json<RouteResponse>> {
    let payload = req.0.payloads.get("application_credential");
    let cred_id = payload.and_then(|p| p.get("application_credential_id"));

    let Some(serde_json::Value::String(cred_id)) = cred_id else {
        return Ok(Json(RouteResponse::Passthrough));
    };

    if cred_id == "deny-me" {
        return Ok(Json(RouteResponse::Deny {
            reason: "reference-plugin: deny requested".to_string(),
        }));
    }

    if let Some(rest) = cred_id.strip_prefix("tf-") {
        return Ok(Json(RouteResponse::Route {
            target_method: "hacked_appcred_handler".to_string(),
            payload: serde_json::json!({"external_id": rest}),
        }));
    }

    Ok(Json(RouteResponse::Passthrough))
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
