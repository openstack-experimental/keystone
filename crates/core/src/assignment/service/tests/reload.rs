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

//! [`AssignmentService::reload`] / `refresh_bindings` unit tests (ADR 0034 §9).
//!
//! These cover the bundle-rebuild paths that do **not** need a plugin-manager
//! backend build: an unchanged block is reused by `Arc::ptr_eq`, a block a
//! bound domain no longer maps to is dropped, the dispatch switch going off
//! drops every named instance, the binding cache is cleared, and an
//! unresolvable new configuration keeps the last-known-good bundle (`Ok(false)`).
//! Cases that add or mutate an `[assignment.backends.*]` block (which builds a
//! fresh instance through `inventory`) live in `tests/integration`, where the
//! driver crates are linked.

use std::collections::HashMap;

use openstack_keystone_config::{AssignmentBackendConfig, AssignmentProvider, Config};

use super::*;
use crate::domain_config::backend::{DomainConfigBackend, MockDomainConfigBackend};
use crate::domain_config::error::DomainConfigProviderError;

/// A resolver whose database source reports `bound` as the set of domains
/// carrying an `assignment/driver` binding, `Err` when `bound` is `Err`.
fn resolver_over(bound: Result<Vec<&'static str>, ()>) -> Arc<DomainConfigResolver> {
    let mut mock = MockDomainConfigBackend::new();
    mock.expect_list_domains_with_option()
        .returning(move |_, _, _| match &bound {
            Ok(domains) => Ok(domains.iter().map(|d| d.to_string()).collect()),
            Err(()) => Err(DomainConfigProviderError::Driver("boom".into())),
        });
    let source: Arc<dyn DomainConfigBackend> = Arc::new(mock);
    Arc::new(DomainConfigResolver::from_sources(None, Some(source)))
}

/// `[assignment]` with the dispatch switch `on`, one `sql` block `b_sql` and
/// `domains` mapping `d1 → b_sql`.
fn assignment_section(dispatch_on: bool, map_d1: bool) -> AssignmentProvider {
    let mut backends = HashMap::new();
    backends.insert("b_sql".to_string(), AssignmentBackendConfig::Sql);
    let mut domains = HashMap::new();
    if map_d1 {
        domains.insert("d1".to_string(), "b_sql".to_string());
    }
    AssignmentProvider {
        driver: "openfga".to_string(),
        domain_specific_drivers_enabled: dispatch_on,
        backends,
        domains,
        ..Default::default()
    }
}

fn config(section: AssignmentProvider) -> Config {
    Config {
        assignment: section,
        ..Default::default()
    }
}

/// A service whose live bundle already carries `named` as the `b_sql` instance
/// (as a first reload would have built it), wired to `resolver`.
async fn service_with_named(
    named: Arc<dyn AssignmentBackend>,
    map_d1: bool,
    resolver: Arc<DomainConfigResolver>,
) -> (AssignmentService, ServiceState) {
    let state = get_mocked_state(Some(config(assignment_section(true, map_d1))), None).await;
    let mut blocks = HashMap::new();
    blocks.insert("b_sql".to_string(), AssignmentBackendConfig::Sql);
    let mut instances = HashMap::new();
    instances.insert("b_sql".to_string(), named);
    let provider = AssignmentService::from_parts(
        "openfga",
        Arc::new(MockAssignmentBackend::default()),
        map_d1
            .then(|| ("d1".to_string(), "b_sql".to_string()))
            .into_iter()
            .collect(),
        blocks,
        instances,
        Some(resolver),
    );
    (provider, state)
}

#[tokio::test]
async fn an_unchanged_block_is_reused_by_pointer() {
    let named: Arc<dyn AssignmentBackend> = Arc::new(MockAssignmentBackend::default());
    let (provider, state) =
        service_with_named(named.clone(), true, resolver_over(Ok(vec!["d1"]))).await;

    let changed = provider.reload(&state).await.unwrap();

    assert!(!changed, "identical config must report no change");
    let bundle = provider.bundle.load_full();
    assert!(
        Arc::ptr_eq(&bundle.instances["b_sql"], &named),
        "the live instance must be the very same Arc"
    );
    assert_eq!(bundle.fanout.len(), 2);
}

#[tokio::test]
async fn a_block_no_bound_domain_maps_to_is_dropped() {
    let named: Arc<dyn AssignmentBackend> = Arc::new(MockAssignmentBackend::default());
    // Live bundle maps d1 → b_sql; the reloaded config drops the mapping.
    let (provider, state) = service_with_named(named, true, resolver_over(Ok(vec!["d1"]))).await;
    *state.config_manager.config.write().await = config(assignment_section(true, false));

    let changed = provider.reload(&state).await.unwrap();

    assert!(changed);
    let bundle = provider.bundle.load_full();
    assert!(bundle.instances.is_empty());
    assert_eq!(
        bundle.fanout.len(),
        1,
        "fan-out is the global backend alone"
    );
}

#[tokio::test]
async fn turning_the_dispatch_switch_off_drops_every_named_instance() {
    let named: Arc<dyn AssignmentBackend> = Arc::new(MockAssignmentBackend::default());
    let (provider, state) = service_with_named(named, true, resolver_over(Ok(vec!["d1"]))).await;
    *state.config_manager.config.write().await = config(assignment_section(false, true));

    let changed = provider.reload(&state).await.unwrap();

    assert!(changed);
    let bundle = provider.bundle.load_full();
    assert!(!bundle.dispatch_enabled);
    assert!(bundle.instances.is_empty());
}

#[tokio::test]
async fn reload_clears_the_binding_cache() {
    let mut named_mock = MockAssignmentBackend::default();
    named_mock.expect_create_grant().returning(|_, grant| {
        Ok(AssignmentBuilder::default()
            .actor_id(grant.actor_id)
            .role_id(grant.role_id)
            .target_id(grant.target_id)
            .r#type(grant.r#type)
            .build()
            .unwrap())
    });
    let named: Arc<dyn AssignmentBackend> = Arc::new(named_mock);
    let (provider, state) = service_with_named(named, true, resolver_over(Ok(vec!["d1"]))).await;

    // Populate the per-domain resolution cache — but the resolver mock here
    // only answers `list_domains_with_option`, so a grant that had to consult
    // `effective_config` would panic. Instead assert the cache directly.
    provider
        .binding_cache
        .write()
        .await
        .insert("d1".to_string(), "sql".to_string());

    provider.reload(&state).await.unwrap();

    assert!(
        provider.binding_cache.read().await.is_empty(),
        "the binding cache must be cleared on reload"
    );
}

#[tokio::test]
async fn an_unresolvable_new_config_keeps_the_previous_bundle() {
    let named: Arc<dyn AssignmentBackend> = Arc::new(MockAssignmentBackend::default());
    let (provider, state) = service_with_named(named.clone(), true, resolver_over(Err(()))).await;

    let changed = provider.reload(&state).await.unwrap();

    assert!(!changed, "a failed rebuild reports Ok(false)");
    let bundle = provider.bundle.load_full();
    assert!(
        Arc::ptr_eq(&bundle.instances["b_sql"], &named),
        "the last-known-good bundle stays in service"
    );
}

/// The dispatch switch flipped **on** by a config reload takes effect: the
/// resolver is re-wired from the captured backend handle, not frozen at
/// construction.
#[tokio::test]
async fn flipping_the_dispatch_switch_on_via_reload_takes_effect() {
    // Built with the switch off — no resolver, dispatch disabled.
    let state = get_mocked_state(Some(config(assignment_section(false, false))), None).await;
    let mut sql_mock = MockDomainConfigBackend::new();
    sql_mock
        .expect_list_domains_with_option()
        .returning(|_, _, _| Ok(Vec::new()));
    let sql_backend: Arc<dyn DomainConfigBackend> = Arc::new(sql_mock);
    let provider = AssignmentService::from_parts(
        "openfga",
        Arc::new(MockAssignmentBackend::default()),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        None,
    )
    .with_dc_sql_backend(sql_backend);
    assert!(!provider.bundle.load_full().dispatch_enabled);

    // Operator turns per-domain dispatch on; the config reloads.
    *state.config_manager.config.write().await = config(assignment_section(true, false));
    let changed = provider.reload(&state).await.unwrap();

    assert!(changed, "the switch flip must be observable");
    assert!(
        provider.bundle.load_full().dispatch_enabled,
        "dispatch is live after the reload without a restart"
    );
    assert!(provider.resolver.load_full().is_some());
}

/// A reload re-scans the `fs` domain-config driver before it enumerates the
/// bound domains (ADR 0034 §9), so an operator's edit to a per-domain
/// `keystone.<name>.conf` is visible without a restart.
#[tokio::test]
async fn reload_rescans_the_fs_domain_config_backend() {
    let state = get_mocked_state(Some(config(assignment_section(true, false))), None).await;

    let mut fs_mock = MockDomainConfigBackend::new();
    fs_mock.expect_reload().times(1).returning(|_| Ok(true));
    fs_mock
        .expect_list_domains_with_option()
        .returning(|_, _, _| Ok(Vec::new()));
    let fs_backend: Arc<dyn DomainConfigBackend> = Arc::new(fs_mock);

    let provider = AssignmentService::from_parts(
        "openfga",
        Arc::new(MockAssignmentBackend::default()),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        None,
    )
    .with_dc_file_backend(fs_backend);

    // One `rebuild` per `reload`, one `fs.reload` per `rebuild`: the
    // `expect_reload().times(1)` is verified when the provider (and the Arc
    // holding the mock) drop at end of test.
    provider.reload(&state).await.unwrap();
}

/// A best-effort scan failure on the `fs` driver never fails the reload; the
/// bundle rebuild carries on against the last good scan.
#[tokio::test]
async fn reload_survives_an_fs_rescan_error() {
    let state = get_mocked_state(Some(config(assignment_section(true, false))), None).await;

    let mut fs_mock = MockDomainConfigBackend::new();
    fs_mock
        .expect_reload()
        .returning(|_| Err(DomainConfigProviderError::Driver("disk gone".into())));
    fs_mock
        .expect_list_domains_with_option()
        .returning(|_, _, _| Ok(Vec::new()));
    let fs_backend: Arc<dyn DomainConfigBackend> = Arc::new(fs_mock);

    let provider = AssignmentService::from_parts(
        "openfga",
        Arc::new(MockAssignmentBackend::default()),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        None,
    )
    .with_dc_file_backend(fs_backend);

    provider
        .reload(&state)
        .await
        .expect("an fs rescan error must not fail the reload");
}

#[tokio::test]
async fn refresh_bindings_swallows_a_rebuild_error() {
    let named: Arc<dyn AssignmentBackend> = Arc::new(MockAssignmentBackend::default());
    let (provider, state) = service_with_named(named, true, resolver_over(Err(()))).await;

    // Best-effort: never surfaces the error to the domain-config write path.
    provider.refresh_bindings(&state).await.unwrap();
}
