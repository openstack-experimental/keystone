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

//! Per-domain assignment driver dispatch unit tests (ADR 0034 "Testing").
//!
//! Split out of `service.rs::tests`. Covers target-keyed routing
//! ([`AssignmentService::driver_for_target`]), the per-domain resolution cache,
//! the `system` carve-out (§1), stale-binding fallback (§4), the shared-backend
//! fast path (§4), the cross-domain grant invariant (§1) and the untargeted
//! fan-out with de-dup / pagination / fail-fast (§5).

use serde_json::json;

use openstack_keystone_core_types::domain_config::DomainConfig;
use openstack_keystone_core_types::resource::Project;

use super::*;
use crate::domain_config::backend::{DomainConfigBackend, MockDomainConfigBackend};
use crate::domain_config::error::DomainConfigProviderError;
use crate::resource::MockResourceProvider;

/// A domain-config `database` source whose `get_domain_config` answers `answer`
/// (cloned) every call, expected exactly `calls` times.
fn config_source(
    answer: Result<Option<DomainConfig>, DomainConfigProviderError>,
    calls: usize,
) -> Arc<dyn DomainConfigBackend> {
    let mut mock = MockDomainConfigBackend::new();
    mock.expect_get_domain_config()
        .times(calls)
        .returning(move |_, _| match &answer {
            Ok(maybe) => Ok(maybe.clone()),
            Err(err) => Err(DomainConfigProviderError::Driver(err.to_string())),
        });
    Arc::new(mock)
}

/// A resolver whose only active source is the database `source`.
fn resolver(source: Arc<dyn DomainConfigBackend>) -> Arc<DomainConfigResolver> {
    Arc::new(DomainConfigResolver::from_sources(None, Some(source)))
}

/// A stored overlay binding `assignment/driver = <driver>`.
fn binding(driver: &str) -> DomainConfig {
    DomainConfig::from_value(json!({ "assignment": { "driver": driver } })).expect("valid config")
}

/// An assignment backend whose `create_grant` is expected exactly `calls`
/// times and echoes a fixed assignment.
fn create_backend(calls: usize) -> Arc<dyn AssignmentBackend> {
    let mut mock = MockAssignmentBackend::default();
    mock.expect_create_grant()
        .times(calls)
        .returning(|_, grant| {
            Ok(AssignmentBuilder::default()
                .actor_id(grant.actor_id)
                .role_id(grant.role_id)
                .target_id(grant.target_id)
                .r#type(grant.r#type)
                .build()
                .unwrap())
        });
    Arc::new(mock)
}

/// An assignment backend whose `list_assignments` is expected exactly `calls`
/// times and returns `rows`.
fn list_backend(calls: usize, rows: Vec<Assignment>) -> Arc<dyn AssignmentBackend> {
    let mut mock = MockAssignmentBackend::default();
    mock.expect_list_assignments()
        .times(calls)
        .returning(move |_, _| Ok(rows.clone()));
    Arc::new(mock)
}

fn assignment(actor: &str, target: &str, role: &str, kind: AssignmentType) -> Assignment {
    AssignmentBuilder::default()
        .actor_id(actor)
        .role_id(role)
        .target_id(target)
        .r#type(kind)
        .build()
        .unwrap()
}

/// State whose resource provider resolves every project id to `Project` in
/// `domain_id`.
async fn state_with_project_domain(domain_id: &'static str) -> ServiceState {
    let mut resource = MockResourceProvider::default();
    resource
        .expect_get_project()
        .returning(move |_, project_id| {
            Ok(Some(Project {
                id: project_id.to_string(),
                name: project_id.to_string(),
                domain_id: domain_id.to_string(),
                enabled: true,
                ..Default::default()
            }))
        });
    get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_resource(resource)),
    )
    .await
}

/// One named `sql` block `b_sql` bound to `domains`, its instance, plus a
/// distinct global backend named `openfga` — so a `sql` binding is never the
/// global name.
fn service(
    global: Arc<dyn AssignmentBackend>,
    named: Arc<dyn AssignmentBackend>,
    domains: &[(&str, &str)],
    source: Arc<dyn DomainConfigBackend>,
) -> AssignmentService {
    let mut blocks = HashMap::new();
    blocks.insert("b_sql".to_string(), AssignmentBackendConfig::Sql);
    let mut instances = HashMap::new();
    instances.insert("b_sql".to_string(), named);
    AssignmentService::from_parts(
        "openfga",
        global,
        domains
            .iter()
            .map(|(d, b)| (d.to_string(), b.to_string()))
            .collect(),
        blocks,
        instances,
        Some(resolver(source)),
    )
}

#[tokio::test]
async fn a_stored_binding_routes_a_domain_grant_to_the_named_instance() {
    let state = get_mocked_state(None, None).await;
    let global = create_backend(0);
    let named = create_backend(1);
    let provider = service(
        global,
        named,
        &[("d1", "b_sql")],
        config_source(Ok(Some(binding("sql"))), 1),
    );

    provider
        .create_grant(
            &ExecutionContext::internal(&state),
            AssignmentCreate::user_domain("u", "d1", "r", false),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_domain_without_a_binding_uses_the_global_backend() {
    let state = get_mocked_state(None, None).await;
    let global = create_backend(1);
    let named = create_backend(0);
    let provider = service(
        global,
        named,
        &[("d1", "b_sql")],
        config_source(Ok(None), 1),
    );

    provider
        .create_grant(
            &ExecutionContext::internal(&state),
            AssignmentCreate::user_domain("u", "d1", "r", false),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn the_resolution_is_cached_per_domain() {
    let state = get_mocked_state(None, None).await;
    let global = create_backend(0);
    let named = create_backend(2);
    // The source is consulted exactly once for two grants on the same domain.
    let provider = service(
        global,
        named,
        &[("d1", "b_sql")],
        config_source(Ok(Some(binding("sql"))), 1),
    );

    let ctx = ExecutionContext::internal(&state);
    provider
        .create_grant(&ctx, AssignmentCreate::user_domain("u", "d1", "r", false))
        .await
        .unwrap();
    provider
        .create_grant(&ctx, AssignmentCreate::group_domain("g", "d1", "r", false))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_resolver_error_falls_back_to_the_global_backend() {
    let state = get_mocked_state(None, None).await;
    let global = create_backend(1);
    let named = create_backend(0);
    let provider = service(
        global,
        named,
        &[("d1", "b_sql")],
        config_source(Err(DomainConfigProviderError::Driver("boom".into())), 1),
    );

    provider
        .create_grant(
            &ExecutionContext::internal(&state),
            AssignmentCreate::user_domain("u", "d1", "r", false),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_system_target_never_consults_the_resolver() {
    // ADR 0034 §1: `system` targets always use the global backend and never
    // touch the domain-config source (which also bounds the §6 blast radius).
    let state = get_mocked_state(None, None).await;
    let global = create_backend(1);
    let named = create_backend(0);
    let provider = service(
        global,
        named,
        &[("d1", "b_sql")],
        config_source(Ok(Some(binding("sql"))), 0),
    );

    provider
        .create_grant(
            &ExecutionContext::internal(&state),
            AssignmentCreate::user_system("u", "all", "r", false),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_project_target_routes_on_its_owning_domain() {
    // The dispatch domain of a project grant is the project's `domain_id`,
    // fetched from the resource provider — not the actor's domain.
    let state = state_with_project_domain("d1").await;
    let global = create_backend(0);
    let named = create_backend(1);
    let provider = service(
        global,
        named,
        &[("d1", "b_sql")],
        config_source(Ok(Some(binding("sql"))), 1),
    );

    provider
        .create_grant(
            &ExecutionContext::internal(&state),
            AssignmentCreate::user_project("actor-in-another-domain", "p1", "r", false),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_stale_binding_falls_back_to_the_global_backend() {
    // A domain that resolves a non-global driver name but has no matching
    // live `[assignment.domains]` → `[assignment.backends.*]` block routes to
    // the global backend (ADR 0034 §4 step 3).
    let state = get_mocked_state(None, None).await;
    let global = create_backend(1);
    let named = create_backend(0);
    let provider = service(
        global,
        named,
        &[], // d1 is bound in the store but mapped nowhere.
        config_source(Ok(Some(binding("sql"))), 1),
    );

    provider
        .create_grant(
            &ExecutionContext::internal(&state),
            AssignmentCreate::user_domain("u", "d1", "r", false),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn two_domains_on_one_block_share_the_backend_instance() {
    // ADR 0034 §4: two domains mapped to the same block resolve to the very
    // same `Arc`, and the fan-out set counts it once.
    let state = get_mocked_state(None, None).await;
    let global = create_backend(0);
    let named = create_backend(2);
    let provider = service(
        global,
        named,
        &[("d1", "b_sql"), ("d2", "b_sql")],
        config_source(Ok(Some(binding("sql"))), 2),
    );

    let ctx = ExecutionContext::internal(&state);
    provider
        .create_grant(&ctx, AssignmentCreate::user_domain("u", "d1", "r", false))
        .await
        .unwrap();
    provider
        .create_grant(&ctx, AssignmentCreate::user_domain("u", "d2", "r", false))
        .await
        .unwrap();

    let bundle = provider.bundle.load_full();
    assert_eq!(bundle.fanout.len(), 2, "global + one shared named instance");
}

#[tokio::test]
async fn a_cross_domain_project_grant_is_written_to_and_read_from_the_target_domain() {
    // ADR 0034 §1: an actor in domain A granted a role on a project in domain
    // B is written to B's driver and shows up in B's target-scoped listing;
    // A's driver is never touched.
    let state = state_with_project_domain("d-b").await;

    let mut global_mock = MockAssignmentBackend::default();
    global_mock.expect_create_grant().times(0);
    global_mock.expect_list_assignments().times(0);
    let global: Arc<dyn AssignmentBackend> = Arc::new(global_mock);

    let row = assignment("actor-in-a", "p-in-b", "r", AssignmentType::UserProject);
    let mut named_mock = MockAssignmentBackend::default();
    named_mock
        .expect_create_grant()
        .once()
        .returning(|_, grant| {
            Ok(AssignmentBuilder::default()
                .actor_id(grant.actor_id)
                .role_id(grant.role_id)
                .target_id(grant.target_id)
                .r#type(grant.r#type)
                .build()
                .unwrap())
        });
    let row_clone = row.clone();
    named_mock
        .expect_list_assignments()
        .once()
        .returning(move |_, _| Ok(vec![row_clone.clone()]));
    let named: Arc<dyn AssignmentBackend> = Arc::new(named_mock);

    let provider = service(
        global,
        named,
        &[("d-b", "b_sql")],
        config_source(Ok(Some(binding("sql"))), 1),
    );

    let ctx = ExecutionContext::internal(&state);
    provider
        .create_grant(
            &ctx,
            AssignmentCreate::user_project("actor-in-a", "p-in-b", "r", false),
        )
        .await
        .unwrap();

    let listed = provider
        .list_role_assignments(
            &ctx,
            &RoleAssignmentListParameters {
                domain_id: Some("d-b".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(listed, vec![row]);
}

#[tokio::test]
async fn an_untargeted_listing_fans_out_and_unions_the_results() {
    let state = get_mocked_state(None, None).await;
    let g_row = assignment("u", "d-global", "r", AssignmentType::UserDomain);
    let n_row = assignment("u", "d1", "r", AssignmentType::UserDomain);
    let global = list_backend(1, vec![g_row.clone()]);
    let named = list_backend(1, vec![n_row.clone()]);
    let provider = service(
        global,
        named,
        &[("d1", "b_sql")],
        config_source(Ok(Some(binding("sql"))), 0),
    );

    let mut listed = provider
        .list_role_assignments(
            &ExecutionContext::internal(&state),
            &RoleAssignmentListParameters::default(),
        )
        .await
        .unwrap();
    listed.sort_by_key(Assignment::pagination_marker);
    let mut want = vec![g_row, n_row];
    want.sort_by_key(Assignment::pagination_marker);
    assert_eq!(listed, want);
}

#[tokio::test]
async fn an_untargeted_listing_deduplicates_across_backends() {
    let state = get_mocked_state(None, None).await;
    let row = assignment("u", "d1", "r", AssignmentType::UserDomain);
    let global = list_backend(1, vec![row.clone()]);
    let named = list_backend(1, vec![row.clone()]);
    let provider = service(
        global,
        named,
        &[("d1", "b_sql")],
        config_source(Ok(Some(binding("sql"))), 0),
    );

    let listed = provider
        .list_role_assignments(
            &ExecutionContext::internal(&state),
            &RoleAssignmentListParameters::default(),
        )
        .await
        .unwrap();
    assert_eq!(listed, vec![row]);
}

#[tokio::test]
async fn an_untargeted_listing_paginates_the_union_once() {
    let state = get_mocked_state(None, None).await;
    let global = list_backend(
        1,
        vec![
            assignment("u", "a", "r", AssignmentType::UserDomain),
            assignment("u", "c", "r", AssignmentType::UserDomain),
        ],
    );
    let named = list_backend(
        1,
        vec![assignment("u", "b", "r", AssignmentType::UserDomain)],
    );
    let provider = service(
        global,
        named,
        &[("d1", "b_sql")],
        config_source(Ok(Some(binding("sql"))), 0),
    );

    let listed = provider
        .list_role_assignments(
            &ExecutionContext::internal(&state),
            &RoleAssignmentListParameters {
                pagination: openstack_keystone_core_types::ListPagination {
                    limit: Some(1),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    // `limit + 1` rows off the sorted, deduplicated union of both backends.
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].target_id, "a");
    assert_eq!(listed[1].target_id, "b");
}

#[tokio::test]
async fn an_untargeted_listing_fails_the_whole_call_on_one_backend_error() {
    let state = get_mocked_state(None, None).await;
    let global = list_backend(
        1,
        vec![assignment("u", "d", "r", AssignmentType::UserDomain)],
    );
    let mut named_mock = MockAssignmentBackend::default();
    named_mock
        .expect_list_assignments()
        .returning(|_, _| Err(AssignmentProviderError::Driver("openfga 501".into())));
    let named: Arc<dyn AssignmentBackend> = Arc::new(named_mock);
    let provider = service(
        global,
        named,
        &[("d1", "b_sql")],
        config_source(Ok(Some(binding("sql"))), 0),
    );

    let error = provider
        .list_role_assignments(
            &ExecutionContext::internal(&state),
            &RoleAssignmentListParameters::default(),
        )
        .await
        .expect_err("one backend error must fail the whole fan-out");
    assert!(matches!(error, AssignmentProviderError::Driver(_)));
}

#[tokio::test]
async fn a_system_filtered_listing_uses_only_the_global_backend() {
    let state = get_mocked_state(None, None).await;
    let global = list_backend(1, vec![]);
    let named = list_backend(0, vec![]);
    let provider = service(
        global,
        named,
        &[("d1", "b_sql")],
        config_source(Ok(Some(binding("sql"))), 0),
    );

    provider
        .list_role_assignments(
            &ExecutionContext::internal(&state),
            &RoleAssignmentListParameters {
                system_id: Some("all".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_domain_filtered_listing_routes_to_that_domains_driver() {
    let state = get_mocked_state(None, None).await;
    let global = list_backend(0, vec![]);
    let named = list_backend(1, vec![]);
    let provider = service(
        global,
        named,
        &[("d1", "b_sql")],
        config_source(Ok(Some(binding("sql"))), 1),
    );

    provider
        .list_role_assignments(
            &ExecutionContext::internal(&state),
            &RoleAssignmentListParameters {
                domain_id: Some("d1".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn dispatch_off_routes_every_target_to_the_single_backend() {
    // `from_backend` builds a `dispatch_enabled: false` bundle with no
    // resolver: even a domain grant goes straight to the one backend.
    let state = get_mocked_state(None, None).await;
    let provider = AssignmentService::from_backend(create_backend(1));

    provider
        .create_grant(
            &ExecutionContext::internal(&state),
            AssignmentCreate::user_domain("u", "d1", "r", false),
        )
        .await
        .unwrap();
}
