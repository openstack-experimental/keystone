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
//! # Per-domain assignment driver dispatch (ADR 0034)
//!
//! Exercises `[assignment] domain_specific_drivers_enabled` end to end through
//! the full `Provider` stack: `AssignmentService` builds a real
//! `DomainConfigResolver`, `reload` / `refresh_bindings` enumerate the bound
//! domains with the SQL domain-config driver's `list_domains_with_option` and
//! rebuild the routing bundle through the real backend factories
//! (`build_global_assignment_backend` / `build_named_assignment_backend`), and
//! `DomainConfigService` enforces the write-time binding validation (§3).
//!
//! A stub OpenFGA HTTP server ([`openfga_stub`]) stands in for a real store, so
//! a domain bound to a named `[assignment.backends.*]` OpenFGA block exercises
//! the driver crate end to end: `create_grant` writes a tuple over real HTTP,
//! the target-scoped listing reads it back, and the grant stays disjoint from
//! the global SQL backend. The reload reactor building that named instance
//! through `inventory` (the driver crates are not linked into the
//! `openstack-keystone-core` test binary), the fan-out union / de-dup over
//! several live backends, and the config-API rejection path are covered here
//! too.

use eyre::Result;
use serde_json::{Value, json};
use tracing_test::traced_test;

use openstack_keystone_config::{AssignmentBackendConfig, Config, OpenFGAAssignmentDriver};
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::domain_config::DomainConfigProviderError;
use openstack_keystone_core_types::assignment::*;
use openstack_keystone_core_types::domain_config::{DomainConfig, DomainConfigCreate};

use crate::common::get_state_with_config;
use crate::{create_domain, create_role, create_user};

/// Turn per-domain assignment dispatch on with the database as the config
/// source. The resolver is fixed at construction, so this must run before the
/// `Provider` is built (hence the `get_state_with_config` mutator).
fn enable_assignment_dispatch(cfg: &mut Config) {
    cfg.assignment.domain_specific_drivers_enabled = true;
    cfg.domain_config.from_database = Some(true);
}

/// [`enable_assignment_dispatch`] plus a named `[assignment.backends.<name>]`
/// block, so that block's driver name becomes bindable (§3) and a bound domain
/// mapped to it drives the named backend factory on reload.
fn enable_with_block(name: &str, block: AssignmentBackendConfig) -> impl FnOnce(&mut Config) + '_ {
    move |cfg| {
        enable_assignment_dispatch(cfg);
        cfg.assignment.backends.insert(name.to_string(), block);
    }
}

/// A named OpenFGA block pointing at `api_url` / `store_id`, with the given
/// Keystone-role-id -> OpenFGA-relation map (`Value::Null` for none).
fn openfga_block_at(
    api_url: &str,
    store_id: &str,
    role_to_relation: Value,
) -> AssignmentBackendConfig {
    let driver: OpenFGAAssignmentDriver = serde_json::from_value(json!({
        "api_url": api_url,
        "store_id": store_id,
        "model_id": null,
        "timeout": null,
        "role_to_relation": role_to_relation,
    }))
    .expect("valid openfga assignment block");
    AssignmentBackendConfig::Openfga(Box::new(driver))
}

/// A named OpenFGA block at a dead address. Used where the block is only there
/// to make `openfga` a bindable name and no operation routes to it: `with_config`
/// only builds a `reqwest::Client`, so constructing it does no I/O.
fn openfga_block() -> AssignmentBackendConfig {
    openfga_block_at(
        "http://127.0.0.1:59191/",
        "01JTESTSTORE000000000000",
        Value::Null,
    )
}

/// The `[assignment.backends.<name>]` OpenFGA block wired to a live stub, with
/// `role_id` mapped to the `member` relation.
fn openfga_block_for(stub: &openfga_stub::StubHandle, role_id: &str) -> AssignmentBackendConfig {
    let mut role_to_relation = serde_json::Map::new();
    role_to_relation.insert(role_id.to_string(), json!("member"));
    openfga_block_at(
        &stub.api_url(),
        "01JSTUBSTORE0000000000000",
        Value::Object(role_to_relation),
    )
}

/// A stored overlay pinning a domain to `assignment/driver = <driver>`.
fn assignment_binding(driver: &str) -> DomainConfigCreate {
    DomainConfigCreate(
        DomainConfig::from_value(json!({ "assignment": { "driver": driver } }))
            .expect("valid domain configuration"),
    )
}

/// Grant `role` to `user` on `domain` and report whether the domain-scoped
/// listing (which target-routes on `domain`) sees it.
async fn grant_and_see_on_domain(
    state: &std::sync::Arc<openstack_keystone::keystone::Service>,
    user: &str,
    domain: &str,
    role: &str,
) -> Result<bool> {
    let ctx = ExecutionContext::internal(state);
    state
        .provider
        .get_assignment_provider()
        .create_grant(
            &ctx,
            AssignmentCreate::user_domain(user, domain, role, false),
        )
        .await?;
    let seen = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            &ctx,
            &RoleAssignmentListParameters {
                domain_id: Some(domain.to_string()),
                user_id: Some(user.to_string()),
                ..Default::default()
            },
        )
        .await?;
    Ok(seen.iter().any(|a| a.role_id == role))
}

/// With dispatch on and no named block, a domain that stores
/// `assignment/driver = sql` still serves grants through the (shared) global
/// SQL backend, and a domain with no binding does too. The `refresh_bindings`
/// fired by the config write runs `rebuild` through the real `Provider` and
/// must not error.
#[tokio::test]
#[traced_test]
async fn dispatch_on_serves_the_global_sql_grant_path() -> Result<()> {
    let (state, _tmp) = get_state_with_config(enable_assignment_dispatch).await?;
    let pinned = create_domain!(state)?;
    let plain = create_domain!(state)?;
    let role = create_role!(state)?;
    let u_pinned = create_user!(state, pinned.id.clone())?;
    let u_plain = create_user!(state, plain.id.clone())?;

    state
        .provider
        .get_domain_config_provider()
        .create_domain_config(&state, &pinned.id, assignment_binding("sql"))
        .await?;

    assert!(
        grant_and_see_on_domain(&state, &u_pinned.id, &pinned.id, &role.id).await?,
        "the sql-pinned domain must serve the grant"
    );
    assert!(
        grant_and_see_on_domain(&state, &u_plain.id, &plain.id, &role.id).await?,
        "the unbound domain must serve the grant via the global backend"
    );
    Ok(())
}

/// A bound domain mapped to a named `[assignment.backends.*]` block makes
/// `reload` build that instance through the real backend factory (`inventory`)
/// and report a change; a second reload with nothing changed reports none. A
/// grant on an unrelated domain keeps working throughout.
#[tokio::test]
#[traced_test]
async fn a_named_block_is_built_by_the_reload_reactor() -> Result<()> {
    let (state, _tmp) =
        get_state_with_config(enable_with_block("central_fga", openfga_block())).await?;
    let fga_domain = create_domain!(state)?;
    let sql_domain = create_domain!(state)?;
    let role = create_role!(state)?;
    let u_fga = create_user!(state, fga_domain.id.clone())?;
    let u_sql = create_user!(state, sql_domain.id.clone())?;

    // Map the domain id (only known now) to the block, then bind it.
    state
        .config_manager
        .config
        .write()
        .await
        .assignment
        .domains
        .insert(fga_domain.id.clone(), "central_fga".to_string());

    // The config-API write fires `refresh_bindings`, which rebuilds the bundle:
    // `central_fga` is now a block a bound domain maps to, so the OpenFGA
    // backend factory runs. `with_config` does no I/O, so this succeeds.
    state
        .provider
        .get_domain_config_provider()
        .create_domain_config(&state, &fga_domain.id, assignment_binding("openfga"))
        .await?;

    // Positive proof the named instance landed in the routing bundle: a grant
    // on the mapped domain routes to `central_fga`, whose block carries no role
    // mapping and a dead `api_url`, so the OpenFGA driver rejects it. Had the
    // block not been built, the grant would have fallen back to the global SQL
    // backend and succeeded.
    let ctx = ExecutionContext::internal(&state);
    let routed = state
        .provider
        .get_assignment_provider()
        .create_grant(
            &ctx,
            AssignmentCreate::user_domain(&u_fga.id, &fga_domain.id, &role.id, false),
        )
        .await;
    assert!(
        matches!(routed, Err(AssignmentProviderError::Driver(_))),
        "the mapped domain must route to the named OpenFGA instance, got {routed:?}"
    );

    // An explicit reload with the config unchanged is a no-op.
    let changed = state
        .provider
        .get_assignment_provider()
        .reload(&state)
        .await?;
    assert!(!changed, "an unchanged configuration reloads to no change");

    // The unrelated SQL domain is untouched by the OpenFGA block.
    assert!(
        grant_and_see_on_domain(&state, &u_sql.id, &sql_domain.id, &role.id).await?,
        "a domain outside the named block still routes to the global backend"
    );
    Ok(())
}

/// A domain that resolves a non-global driver name it has no
/// `[assignment.domains]` mapping for falls back to the global backend and logs
/// the stale binding once (ADR 0034 §4 step 3). The grant still succeeds.
#[tokio::test]
#[traced_test]
async fn an_unmapped_binding_falls_back_to_global_and_warns() -> Result<()> {
    let (state, _tmp) =
        get_state_with_config(enable_with_block("central_fga", openfga_block())).await?;
    let domain = create_domain!(state)?;
    let role = create_role!(state)?;
    let user = create_user!(state, domain.id.clone())?;

    // `openfga` is bindable (a block names it) but the domain is mapped
    // nowhere, so resolution is stale -> global.
    state
        .provider
        .get_domain_config_provider()
        .create_domain_config(&state, &domain.id, assignment_binding("openfga"))
        .await?;

    assert!(
        grant_and_see_on_domain(&state, &user.id, &domain.id, &role.id).await?,
        "a stale binding must not break the grant path"
    );
    assert!(
        logs_contain("stale assignment binding"),
        "the stale binding must be logged once"
    );
    Ok(())
}

/// `DomainConfigService` rejects an `assignment/driver` binding that names no
/// configured backend (ADR 0034 §3), and the rejected write does not land.
/// `sql` is always accepted.
#[tokio::test]
#[traced_test]
async fn the_config_api_rejects_an_unbindable_driver() -> Result<()> {
    let (state, _tmp) = get_state_with_config(enable_assignment_dispatch).await?;
    let domain = create_domain!(state)?;
    let dc = state.provider.get_domain_config_provider();

    let err = dc
        .create_domain_config(&state, &domain.id, assignment_binding("openfga"))
        .await
        .expect_err("no block names `openfga`, so the binding must be rejected");
    assert!(
        matches!(err, DomainConfigProviderError::InvalidOptionValue { .. }),
        "expected InvalidOptionValue, got {err:?}"
    );
    assert!(
        dc.get_domain_config(&state, &domain.id).await?.is_none(),
        "the rejected binding must not have been stored"
    );

    dc.create_domain_config(&state, &domain.id, assignment_binding("sql"))
        .await?;
    Ok(())
}

/// An untargeted `GET /v3/role_assignments` fans out over every backend in the
/// bundle (global plus each distinct named instance) and unions the results,
/// de-duplicating (ADR 0034 §5). Two live SQL backends over the same database
/// each return every row, so without de-dup the union would double every
/// assignment.
#[tokio::test]
#[traced_test]
async fn an_untargeted_listing_unions_and_deduplicates_the_fanout() -> Result<()> {
    let (state, _tmp) =
        get_state_with_config(enable_with_block("b_sql", AssignmentBackendConfig::Sql)).await?;
    let ctx = ExecutionContext::internal(&state);
    let mapped = create_domain!(state)?;
    let other = create_domain!(state)?;
    let role = create_role!(state)?;
    let u_mapped = create_user!(state, mapped.id.clone())?;
    let u_other = create_user!(state, other.id.clone())?;

    // Make `b_sql` an active named instance: map a bound domain to it. The
    // instance is a fresh `SqlBackend` Arc, so the fan-out set is
    // [global, b_sql] — two live backends over the one database.
    state
        .config_manager
        .config
        .write()
        .await
        .assignment
        .domains
        .insert(mapped.id.clone(), "b_sql".to_string());
    state
        .provider
        .get_domain_config_provider()
        .create_domain_config(&state, &mapped.id, assignment_binding("sql"))
        .await?;

    for (user, domain) in [(&u_mapped.id, &mapped.id), (&u_other.id, &other.id)] {
        state
            .provider
            .get_assignment_provider()
            .create_grant(
                &ctx,
                AssignmentCreate::user_domain(user, domain, &role.id, false),
            )
            .await?;
    }

    let listed = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(&ctx, &RoleAssignmentListParameters::default())
        .await?;

    let distinct: std::collections::HashSet<_> = listed
        .iter()
        .map(|a| (a.actor_id.clone(), a.target_id.clone(), a.role_id.clone()))
        .collect();
    assert_eq!(
        distinct.len(),
        2,
        "two grants were created; the fan-out must union to exactly those"
    );
    assert_eq!(
        listed.len(),
        distinct.len(),
        "the fan-out over two identical SQL backends must de-duplicate"
    );
    Ok(())
}

/// The bundle's per-domain resolution is cached: repeated grants on one bound
/// domain do not re-read the stored config on every call. Observable only as
/// "no error / correct result" here; the call-count assertion is in the unit
/// suite.
#[tokio::test]
#[traced_test]
async fn repeated_grants_on_a_bound_domain_reuse_the_cached_resolution() -> Result<()> {
    let (state, _tmp) = get_state_with_config(enable_assignment_dispatch).await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;
    let role_a = create_role!(state)?;
    let role_b = create_role!(state)?;

    state
        .provider
        .get_domain_config_provider()
        .create_domain_config(&state, &domain.id, assignment_binding("sql"))
        .await?;

    let ctx = ExecutionContext::internal(&state);
    for role in [&role_a.id, &role_b.id] {
        state
            .provider
            .get_assignment_provider()
            .create_grant(
                &ctx,
                AssignmentCreate::user_domain(&user.id, &domain.id, role, false),
            )
            .await?;
    }

    let listed = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            &ctx,
            &RoleAssignmentListParameters {
                domain_id: Some(domain.id.clone()),
                user_id: Some(user.id.clone()),
                ..Default::default()
            },
        )
        .await?;
    let roles: std::collections::HashSet<_> = listed.iter().map(|a| a.role_id.clone()).collect();
    assert!(roles.contains(&role_a.id) && roles.contains(&role_b.id));
    Ok(())
}

/// Wire a domain to a named OpenFGA block backed by a live stub server: adding
/// the block plus the `[assignment.domains]` mapping, then storing the
/// `assignment/driver = openfga` binding whose write fires `refresh_bindings`,
/// which builds the named instance through the real `inventory` factory. Every
/// caller shares one `stub`; the returned tuple keeps the domains/user/role in
/// scope.
async fn bind_domain_to_openfga_stub(
    state: &std::sync::Arc<openstack_keystone::keystone::Service>,
    stub: &openfga_stub::StubHandle,
    fga_domain: &str,
    role_id: &str,
) -> Result<()> {
    {
        let mut cfg = state.config_manager.config.write().await;
        cfg.assignment
            .backends
            .insert("central_fga".to_string(), openfga_block_for(stub, role_id));
        cfg.assignment
            .domains
            .insert(fga_domain.to_string(), "central_fga".to_string());
    }
    state
        .provider
        .get_domain_config_provider()
        .create_domain_config(state, fga_domain, assignment_binding("openfga"))
        .await?;
    Ok(())
}

/// A domain bound to a named OpenFGA block routes its grants to that store over
/// real HTTP (the stub OpenFGA server), and the grant stays disjoint from the
/// global SQL backend — neither store sees the other's rows (ADR 0034 §1, §4).
#[tokio::test]
#[traced_test]
async fn openfga_bound_domain_routes_grants_to_that_store_disjoint_from_sql() -> Result<()> {
    let stub = openfga_stub::start().await;

    let (state, _tmp) = get_state_with_config(enable_assignment_dispatch).await?;
    let fga_domain = create_domain!(state)?;
    let sql_domain = create_domain!(state)?;
    let role = create_role!(state)?;
    let u_fga = create_user!(state, fga_domain.id.clone())?;
    let u_sql = create_user!(state, sql_domain.id.clone())?;

    bind_domain_to_openfga_stub(&state, &stub, &fga_domain.id, &role.id).await?;
    assert!(
        !logs_contain("assignment driver reload failed"),
        "building the named OpenFGA instance must not error"
    );

    let ctx = ExecutionContext::internal(&state);
    for (user, domain) in [(&u_fga.id, &fga_domain.id), (&u_sql.id, &sql_domain.id)] {
        state
            .provider
            .get_assignment_provider()
            .create_grant(
                &ctx,
                AssignmentCreate::user_domain(user, domain, &role.id, false),
            )
            .await?;
    }

    // Only the OpenFGA-bound domain's grant reached the OpenFGA store, in the
    // driver's canonical `type:id` tuple shape.
    assert_eq!(
        stub.tuples(),
        vec![(
            format!("user:{}", u_fga.id),
            "member".to_string(),
            format!("domain:{}", fga_domain.id),
        )],
        "only the openfga-bound domain's grant may reach the openfga store"
    );
    assert_eq!(
        stub.writes(),
        1,
        "exactly one write reached the openfga store"
    );

    // The target-scoped listing on the fga domain routes to OpenFGA and reads
    // the tuple back through the driver.
    let via_fga = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            &ctx,
            &RoleAssignmentListParameters {
                domain_id: Some(fga_domain.id.clone()),
                user_id: Some(u_fga.id.clone()),
                ..Default::default()
            },
        )
        .await?;
    assert!(
        via_fga.iter().any(|a| a.role_id == role.id),
        "the openfga-routed listing must see the grant it wrote"
    );
    assert!(
        stub.reads() >= 1,
        "the target-scoped listing must have read the openfga store"
    );

    // The SQL backend holds its own domain's grant and nothing from OpenFGA.
    let via_sql = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(
            &ctx,
            &RoleAssignmentListParameters {
                domain_id: Some(sql_domain.id.clone()),
                ..Default::default()
            },
        )
        .await?;
    assert!(
        via_sql.iter().any(|a| a.actor_id == u_sql.id),
        "the sql domain's own grant is served by sql"
    );
    assert!(
        !via_sql.iter().any(|a| a.actor_id == u_fga.id),
        "the openfga grant must not appear in the sql backend"
    );
    Ok(())
}

/// With an OpenFGA instance in the fan-out set, an untargeted
/// `list_role_assignments` fails the whole call: the OpenFGA driver cannot
/// enumerate every assignment, and ADR 0034 §5 fails the union on any backend
/// error rather than silently dropping a backend.
#[tokio::test]
#[traced_test]
async fn untargeted_fanout_fails_when_openfga_cannot_serve_it() -> Result<()> {
    let stub = openfga_stub::start().await;

    let (state, _tmp) = get_state_with_config(enable_assignment_dispatch).await?;
    let fga_domain = create_domain!(state)?;
    let role = create_role!(state)?;
    let user = create_user!(state, fga_domain.id.clone())?;

    bind_domain_to_openfga_stub(&state, &stub, &fga_domain.id, &role.id).await?;

    let ctx = ExecutionContext::internal(&state);
    state
        .provider
        .get_assignment_provider()
        .create_grant(
            &ctx,
            AssignmentCreate::user_domain(&user.id, &fga_domain.id, &role.id, false),
        )
        .await?;

    let listed = state
        .provider
        .get_assignment_provider()
        .list_role_assignments(&ctx, &RoleAssignmentListParameters::default())
        .await;
    assert!(
        matches!(listed, Err(AssignmentProviderError::NotImplemented(_))),
        "an untargeted fan-out including an openfga instance must fail the whole \
         call, not drop the backend, got {listed:?}"
    );
    Ok(())
}

/// A minimal stateful OpenFGA HTTP server for the integration suite.
///
/// Speaks just enough of the OpenFGA REST surface for the assignment driver
/// (`crates/assignment-driver-openfga`): `write` (tuple add / delete), `read`
/// (filtered tuple listing), `check` / `batch-check` (exact-tuple match) and
/// `streamed-list-objects`. Tuples live in memory; requests are counted so a
/// test can assert a grant reached this store and not the SQL one.
mod openfga_stub {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use axum::{
        Json, Router,
        extract::{Path, State},
        routing::post,
    };
    use serde_json::{Value, json};
    use tokio::net::TcpListener;

    /// `(user, relation, object)`, each an OpenFGA `type:id` string except the
    /// relation.
    type Tuple = (String, String, String);

    #[derive(Default)]
    pub struct Store {
        pub tuples: Vec<Tuple>,
        pub writes: usize,
        pub reads: usize,
    }

    /// Aborts the background `axum::serve` task once the last [`StubHandle`]
    /// clone is dropped, so a stub does not outlive its test.
    struct ServerTask(tokio::task::JoinHandle<()>);

    impl Drop for ServerTask {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    #[derive(Clone)]
    pub struct StubHandle {
        store: Arc<Mutex<Store>>,
        addr: SocketAddr,
        _task: Arc<ServerTask>,
    }

    impl StubHandle {
        /// `api_url` for an `[assignment.backends.*]` OpenFGA block: a trailing
        /// slash so the driver's relative `stores/{id}/...` paths resolve
        /// without dropping the host.
        pub fn api_url(&self) -> String {
            format!("http://{}/", self.addr)
        }

        pub fn tuples(&self) -> Vec<Tuple> {
            self.lock().tuples.clone()
        }

        pub fn writes(&self) -> usize {
            self.lock().writes
        }

        pub fn reads(&self) -> usize {
            self.lock().reads
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
            self.store.lock().expect("stub store lock")
        }
    }

    /// Bind a stub OpenFGA server on an ephemeral loopback port and serve it on
    /// a background task for the rest of the test process.
    pub async fn start() -> StubHandle {
        let store = Arc::new(Mutex::new(Store::default()));
        let app = Router::new()
            .route("/stores/{store_id}/write", post(write))
            .route("/stores/{store_id}/read", post(read))
            .route("/stores/{store_id}/check", post(check))
            .route("/stores/{store_id}/batch-check", post(batch_check))
            .route(
                "/stores/{store_id}/streamed-list-objects",
                post(list_objects),
            )
            .with_state(store.clone());
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind openfga stub");
        let addr = listener.local_addr().expect("stub local addr");
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service()).await;
        });
        StubHandle {
            store,
            addr,
            _task: Arc::new(ServerTask(task)),
        }
    }

    fn field<'a>(key: &'a Value, name: &str) -> Option<&'a str> {
        key.get(name).and_then(Value::as_str)
    }

    /// Whether every field present in `key` (`user` / `relation` / `object`)
    /// matches a stored tuple.
    fn matches(t: &Tuple, key: &Value) -> bool {
        let (u, r, o) = t;
        field(key, "user").is_none_or(|w| w == u)
            && field(key, "relation").is_none_or(|w| w == r)
            && field(key, "object").is_none_or(|w| w == o)
    }

    fn exact(tuples: &[Tuple], key: &Value) -> bool {
        matches!(
            (
                field(key, "user"),
                field(key, "relation"),
                field(key, "object")
            ),
            (Some(_), Some(_), Some(_))
        ) && tuples.iter().any(|t| matches(t, key))
    }

    async fn write(
        Path(_store_id): Path<String>,
        State(store): State<Arc<Mutex<Store>>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let mut guard = store.lock().expect("stub store lock");
        guard.writes += 1;
        if let Some(keys) = body.pointer("/writes/tuple_keys").and_then(Value::as_array) {
            for k in keys.clone() {
                if let (Some(u), Some(r), Some(o)) = (
                    field(&k, "user"),
                    field(&k, "relation"),
                    field(&k, "object"),
                ) {
                    let t = (u.to_string(), r.to_string(), o.to_string());
                    if !guard.tuples.contains(&t) {
                        guard.tuples.push(t);
                    }
                }
            }
        }
        if let Some(keys) = body
            .pointer("/deletes/tuple_keys")
            .and_then(Value::as_array)
        {
            for k in keys.clone() {
                guard.tuples.retain(|t| !matches(t, &k));
            }
        }
        Json(json!({}))
    }

    async fn read(
        Path(_store_id): Path<String>,
        State(store): State<Arc<Mutex<Store>>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let mut guard = store.lock().expect("stub store lock");
        guard.reads += 1;
        let key = body.get("tuple_key").cloned().unwrap_or(Value::Null);
        let tuples: Vec<Value> = guard
            .tuples
            .iter()
            .filter(|t| matches(t, &key))
            .map(|(u, r, o)| json!({ "key": { "user": u, "relation": r, "object": o } }))
            .collect();
        Json(json!({ "tuples": tuples, "continuation_token": null }))
    }

    async fn check(
        Path(_store_id): Path<String>,
        State(store): State<Arc<Mutex<Store>>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let guard = store.lock().expect("stub store lock");
        let allowed = exact(&guard.tuples, body.get("tuple_key").unwrap_or(&Value::Null));
        Json(json!({ "allowed": allowed }))
    }

    async fn batch_check(
        Path(_store_id): Path<String>,
        State(store): State<Arc<Mutex<Store>>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let guard = store.lock().expect("stub store lock");
        let mut result = serde_json::Map::new();
        if let Some(checks) = body.get("checks").and_then(Value::as_array) {
            for c in checks {
                let cid = field(c, "correlation_id").unwrap_or("");
                let allowed = exact(&guard.tuples, c.get("tuple_key").unwrap_or(&Value::Null));
                result.insert(cid.to_string(), json!({ "allowed": allowed }));
            }
        }
        Json(json!({ "result": result }))
    }

    async fn list_objects(
        Path(_store_id): Path<String>,
        State(store): State<Arc<Mutex<Store>>>,
        Json(body): Json<Value>,
    ) -> String {
        let guard = store.lock().expect("stub store lock");
        let want_user = body.get("user").and_then(Value::as_str);
        let want_relation = body.get("relation").and_then(Value::as_str);
        let want_type = body.get("type").and_then(Value::as_str);
        let mut out = String::new();
        for (u, r, o) in &guard.tuples {
            let type_ok = want_type.is_none_or(|t| o.starts_with(&format!("{t}:")));
            if want_user.is_none_or(|w| w == u) && want_relation.is_none_or(|w| w == r) && type_ok {
                out.push_str(&json!({ "result": { "object": o } }).to_string());
                out.push('\n');
            }
        }
        out
    }
}
