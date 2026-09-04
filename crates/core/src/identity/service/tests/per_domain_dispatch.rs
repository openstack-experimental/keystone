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

//! Per-domain identity driver dispatch unit tests.
//!
//! Split out of `service.rs::tests`. Covers `DomainConfigResolver` consultation,
//! per-domain resolution caching, the id-mapping public-id lookup, the two
//! ported python-keystone guards (`is_domain_aware`/`DomainNotFound`,
//! `CrossBackendNotAllowed`), and password-auth dispatch.

use openstack_keystone_core_types::domain_config::DomainConfig;

use super::*;
use crate::domain_config::DomainConfigResolver;
use crate::domain_config::backend::MockDomainConfigBackend;
use crate::domain_config::error::DomainConfigProviderError;

/// A domain-config `sql` source whose `get_domain_config` answers
/// `answer` (cloned) every call, expected `calls` times.
fn config_source(
    answer: Result<Option<DomainConfig>, DomainConfigProviderError>,
    calls: usize,
) -> Arc<dyn crate::domain_config::backend::DomainConfigBackend> {
    let mut mock = MockDomainConfigBackend::new();
    mock.expect_get_domain_config()
        .times(calls)
        .returning(move |_, _| match &answer {
            Ok(maybe) => Ok(maybe.clone()),
            Err(err) => Err(DomainConfigProviderError::Driver(err.to_string())),
        });
    Arc::new(mock)
}

/// A resolver whose database source is `source`.
fn resolver(
    source: Arc<dyn crate::domain_config::backend::DomainConfigBackend>,
) -> Arc<DomainConfigResolver> {
    Arc::new(DomainConfigResolver::from_sources(None, Some(source)))
}

/// An identity list backend that only ever answers an empty list, and
/// only when `calls` says it should be reached.
fn identity_backend(calls: usize) -> Arc<dyn IdentityBackend> {
    let mut mock = MockIdentityBackend::default();
    mock.expect_is_domain_aware().return_const(true);
    mock.expect_list_users()
        .times(calls)
        .returning(|_, _| Ok(Vec::new()));
    Arc::new(mock)
}

fn list_params(domain_id: &str) -> UserListParameters {
    UserListParametersBuilder::default()
        .domain_id(Some(domain_id.to_owned()))
        .build()
        .unwrap()
}

#[tokio::test]
async fn resolver_absent_uses_the_global_driver() {
    // `from_driver` leaves `domain_config_resolver` `None`: even a
    // domain-scoped list must never touch a resolver.
    let state = get_mocked_state(None, None).await;
    let provider = IdentityService::from_driver(identity_backend_owned());
    provider
        .list_users(&ExecutionContext::internal(&state), &list_params("d1"))
        .await
        .unwrap();
}

fn identity_backend_owned() -> MockIdentityBackend {
    let mut mock = MockIdentityBackend::default();
    mock.expect_is_domain_aware().return_const(true);
    mock.expect_list_users().returning(|_, _| Ok(Vec::new()));
    mock
}

#[tokio::test]
async fn stored_driver_selects_the_named_backend() {
    let state = get_mocked_state(None, None).await;
    let sql = identity_backend(0);
    let ldap = identity_backend(1);
    let mut backends = HashMap::new();
    backends.insert("sql".to_string(), sql.clone());
    backends.insert("ldap".to_string(), ldap);
    let provider = IdentityService::from_backends(
        "sql",
        sql,
        backends,
        Some(resolver(config_source(
            Ok(Some(
                DomainConfig::from_value(json!({"identity": {"driver": "ldap"}}))
                    .expect("valid config"),
            )),
            1,
        ))),
    );

    provider
        .list_users(&ExecutionContext::internal(&state), &list_params("d-ldap"))
        .await
        .unwrap();
}

#[tokio::test]
async fn empty_stored_config_uses_the_global_driver() {
    let state = get_mocked_state(None, None).await;
    let sql = identity_backend(1);
    let mut backends = HashMap::new();
    backends.insert("sql".to_string(), sql.clone());
    let provider = IdentityService::from_backends(
        "sql",
        sql,
        backends,
        Some(resolver(config_source(Ok(None), 1))),
    );

    provider
        .list_users(&ExecutionContext::internal(&state), &list_params("d-none"))
        .await
        .unwrap();
}

#[tokio::test]
async fn the_resolution_is_cached_per_domain() {
    let state = get_mocked_state(None, None).await;
    let sql = identity_backend(0);
    let ldap = identity_backend(2);
    let mut backends = HashMap::new();
    backends.insert("sql".to_string(), sql.clone());
    backends.insert("ldap".to_string(), ldap);
    // The source is expected exactly once for two identical lists.
    let provider = IdentityService::from_backends(
        "sql",
        sql,
        backends,
        Some(resolver(config_source(
            Ok(Some(
                DomainConfig::from_value(json!({"identity": {"driver": "ldap"}}))
                    .expect("valid config"),
            )),
            1,
        ))),
    );

    let ctx = ExecutionContext::internal(&state);
    provider
        .list_users(&ctx, &list_params("d-ldap"))
        .await
        .unwrap();
    provider
        .list_users(&ctx, &list_params("d-ldap"))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_resolver_error_falls_back_to_the_global_driver() {
    let state = get_mocked_state(None, None).await;
    let sql = identity_backend(1);
    let mut backends = HashMap::new();
    backends.insert("sql".to_string(), sql.clone());
    let provider = IdentityService::from_backends(
        "sql",
        sql,
        backends,
        Some(resolver(config_source(
            Err(DomainConfigProviderError::Driver("boom".to_string())),
            1,
        ))),
    );

    provider
        .list_users(
            &ExecutionContext::internal(&state),
            &list_params("d-broken"),
        )
        .await
        .unwrap();
}

use openstack_keystone_core_types::idmapping::{IdMapping, IdMappingEntityType};

use crate::idmapping::MockIdMappingProvider;

/// An identity backend that only ever answers `get_user` -> `None`,
/// and only when `calls` says it should be reached.
fn get_user_backend(calls: usize) -> Arc<dyn IdentityBackend> {
    let mut mock = MockIdentityBackend::default();
    mock.expect_is_domain_aware().return_const(true);
    mock.expect_get_user()
        .times(calls)
        .returning(|_, _| Ok(None));
    Arc::new(mock)
}

/// A state whose id-mapping provider answers `get_by_public_id` with
/// `answer` (cloned) every call.
async fn state_with_idmapping(answer: Option<IdMapping>) -> ServiceState {
    let mut mock = MockIdMappingProvider::default();
    mock.expect_get_by_public_id()
        .returning(move |_, _| Ok(answer.clone()));
    get_mocked_state(None, Some(Provider::mocked_builder().mock_idmapping(mock))).await
}

#[tokio::test]
async fn an_unmapped_id_uses_the_global_driver() {
    // python-keystone `_get_domain_driver_and_entity_id`: a public id
    // with no id-mapping row is owned by the default driver. The
    // domain's stored `ldap` config must not be consulted and the
    // entity must not be re-routed by re-deriving its domain.
    let state = state_with_idmapping(None).await;
    let sql = get_user_backend(1);
    let ldap = get_user_backend(0);
    let mut backends = HashMap::new();
    backends.insert("sql".to_string(), sql.clone());
    backends.insert("ldap".to_string(), ldap);
    let provider = IdentityService::from_backends(
        "sql",
        sql,
        backends,
        Some(resolver(config_source(
            Ok(Some(
                DomainConfig::from_value(json!({"identity": {"driver": "ldap"}}))
                    .expect("valid config"),
            )),
            0,
        ))),
    );

    provider
        .get_user(&ExecutionContext::internal(&state), "u-sql")
        .await
        .unwrap();
}

#[tokio::test]
async fn a_mapped_id_uses_its_domain_driver() {
    // A public id carried in the id mapping is owned by that domain's
    // configured driver.
    let state = state_with_idmapping(Some(IdMapping {
        domain_id: "d-ldap".to_string(),
        entity_type: IdMappingEntityType::User,
        local_id: "local".to_string(),
        public_id: "pub-id".to_string(),
    }))
    .await;
    let sql = get_user_backend(0);
    let ldap = get_user_backend(1);
    let mut backends = HashMap::new();
    backends.insert("sql".to_string(), sql.clone());
    backends.insert("ldap".to_string(), ldap);
    let provider = IdentityService::from_backends(
        "sql",
        sql,
        backends,
        Some(resolver(config_source(
            Ok(Some(
                DomainConfig::from_value(json!({"identity": {"driver": "ldap"}}))
                    .expect("valid config"),
            )),
            1,
        ))),
    );

    provider
        .get_user(&ExecutionContext::internal(&state), "pub-id")
        .await
        .unwrap();
}

/// A global identity backend that is not domain aware (LDAP-like) and
/// answers `list_users` only `list_calls` times.
fn non_domain_aware_backend(list_calls: usize) -> Arc<dyn IdentityBackend> {
    let mut mock = MockIdentityBackend::default();
    mock.expect_is_domain_aware().return_const(false);
    mock.expect_list_users()
        .times(list_calls)
        .returning(|_, _| Ok(Vec::new()));
    Arc::new(mock)
}

#[tokio::test]
async fn a_foreign_domain_on_a_non_domain_aware_global_driver_is_rejected() {
    // python-keystone `_select_identity_driver`: a single non-domain
    // aware directory (LDAP) as the global driver cannot represent a
    // domain other than `default`.
    let state = get_mocked_state(None, None).await;
    let ldap = non_domain_aware_backend(0);
    let mut backends = HashMap::new();
    backends.insert("ldap".to_string(), ldap.clone());
    let provider = IdentityService::from_backends(
        "ldap",
        ldap,
        backends,
        Some(resolver(config_source(Ok(None), 1))),
    );

    let error = provider
        .list_users(&ExecutionContext::internal(&state), &list_params("d2"))
        .await
        .expect_err("a foreign domain must be rejected");
    assert!(
        matches!(
            error,
            IdentityProviderError::ResourceProvider {
                source: ResourceProviderError::DomainNotFound(_)
            }
        ),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn the_default_domain_on_a_non_domain_aware_global_driver_is_allowed() {
    let state = get_mocked_state(None, None).await;
    let ldap = non_domain_aware_backend(1);
    let mut backends = HashMap::new();
    backends.insert("ldap".to_string(), ldap.clone());
    let provider = IdentityService::from_backends(
        "ldap",
        ldap,
        backends,
        Some(resolver(config_source(Ok(None), 1))),
    );

    // `from_backends` sets `default_domain_id` to "default".
    provider
        .list_users(&ExecutionContext::internal(&state), &list_params("default"))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_cross_backend_membership_is_rejected() {
    // python-keystone `_assert_user_and_group_in_same_backend`: the
    // user resolves to LDAP (mapped), the group to the global SQL
    // driver (unmapped) -> 403 CrossBackendNotAllowed, after both
    // entities are confirmed to exist.
    let mut idmapping = MockIdMappingProvider::default();
    idmapping
        .expect_get_by_public_id()
        .returning(|_, public_id| {
            Ok((public_id == "u").then(|| IdMapping {
                domain_id: "d-ldap".to_string(),
                entity_type: IdMappingEntityType::User,
                local_id: "u".to_string(),
                public_id: "u".to_string(),
            }))
        });
    let state = get_mocked_state(
        None,
        Some(Provider::mocked_builder().mock_idmapping(idmapping)),
    )
    .await;

    let mut sql_mock = MockIdentityBackend::default();
    sql_mock.expect_is_domain_aware().return_const(true);
    sql_mock.expect_get_group().returning(|_, group_id| {
        Ok(Some(
            openstack_keystone_core_types::identity::GroupBuilder::default()
                .id(group_id)
                .domain_id("default")
                .name("g-name")
                .build()
                .expect("valid group"),
        ))
    });
    let sql: Arc<dyn IdentityBackend> = Arc::new(sql_mock);

    let mut ldap_mock = MockIdentityBackend::default();
    ldap_mock.expect_is_domain_aware().return_const(false);
    ldap_mock.expect_get_user().returning(|_, user_id| {
        Ok(Some(
            UserResponseBuilder::default()
                .id(user_id)
                .domain_id("d-ldap")
                .enabled(true)
                .name("u-name")
                .build()
                .expect("valid user"),
        ))
    });
    let ldap: Arc<dyn IdentityBackend> = Arc::new(ldap_mock);

    let mut backends = HashMap::new();
    backends.insert("sql".to_string(), sql.clone());
    backends.insert("ldap".to_string(), ldap);
    let provider = IdentityService::from_backends(
        "sql",
        sql,
        backends,
        Some(resolver(config_source(
            Ok(Some(
                DomainConfig::from_value(json!({"identity": {"driver": "ldap"}}))
                    .expect("valid config"),
            )),
            1,
        ))),
    );

    let error = provider
        .add_user_to_group(&ExecutionContext::internal(&state), "u", "g")
        .await
        .expect_err("a cross-backend membership must be rejected");
    assert!(
        matches!(error, IdentityProviderError::CrossBackendNotAllowed { .. }),
        "unexpected error: {error:?}"
    );
}

/// Build a state whose id-mapping provider answers `get_by_public_id`
/// by calling `f` with the queried public id.
async fn state_with_mapping_fn(
    f: impl Fn(&str) -> Option<IdMapping> + Send + Sync + 'static,
) -> ServiceState {
    let mut mock = MockIdMappingProvider::default();
    mock.expect_get_by_public_id()
        .returning(move |_, public_id| Ok(f(public_id)));
    get_mocked_state(None, Some(Provider::mocked_builder().mock_idmapping(mock))).await
}

/// An `IdMapping` row binding `public_id` to `domain_id`.
fn user_mapping(domain_id: &str, public_id: &str) -> IdMapping {
    IdMapping {
        domain_id: domain_id.to_string(),
        entity_type: IdMappingEntityType::User,
        local_id: public_id.to_string(),
        public_id: public_id.to_string(),
    }
}

/// A domain-config `sql` source whose overlay is `identity/driver =
/// ldap`, expected `calls` times.
fn ldap_config_source(calls: usize) -> Arc<dyn crate::domain_config::backend::DomainConfigBackend> {
    config_source(
        Ok(Some(
            DomainConfig::from_value(json!({"identity": {"driver": "ldap"}}))
                .expect("valid config"),
        )),
        calls,
    )
}

/// An identity backend that only ever answers `get_group` -> `None`,
/// and only when `calls` says it should be reached.
fn get_group_backend(calls: usize) -> Arc<dyn IdentityBackend> {
    let mut mock = MockIdentityBackend::default();
    mock.expect_is_domain_aware().return_const(true);
    mock.expect_get_group()
        .times(calls)
        .returning(|_, _| Ok(None));
    Arc::new(mock)
}

#[tokio::test]
async fn a_mapped_id_with_no_domain_driver_uses_the_global_driver() {
    // python-keystone `_get_domain_driver_and_entity_id`: a mapped id
    // whose domain carries no domain-specific `identity/driver` is
    // served by the default driver, never rejected.
    let state =
        state_with_mapping_fn(|id| (id == "seg-user").then(|| user_mapping("d-empty", "seg-user")))
            .await;
    let sql = get_user_backend(1);
    let ldap = get_user_backend(0);
    let mut backends = HashMap::new();
    backends.insert("sql".to_string(), sql.clone());
    backends.insert("ldap".to_string(), ldap);
    let provider = IdentityService::from_backends(
        "sql",
        sql,
        backends,
        Some(resolver(config_source(Ok(None), 1))),
    );

    provider
        .get_user(&ExecutionContext::internal(&state), "seg-user")
        .await
        .unwrap();
}

#[tokio::test]
async fn a_mapped_group_id_uses_its_domain_driver() {
    // Group dispatch mirrors user dispatch: a mapped group public id
    // is served by its domain's configured driver.
    let state = state_with_mapping_fn(|id| {
        (id == "grp").then(|| IdMapping {
            domain_id: "d-ldap".to_string(),
            entity_type: IdMappingEntityType::Group,
            local_id: "grp".to_string(),
            public_id: "grp".to_string(),
        })
    })
    .await;
    let sql = get_group_backend(0);
    let ldap = get_group_backend(1);
    let mut backends = HashMap::new();
    backends.insert("sql".to_string(), sql.clone());
    backends.insert("ldap".to_string(), ldap);
    let provider =
        IdentityService::from_backends("sql", sql, backends, Some(resolver(ldap_config_source(1))));

    provider
        .get_group(&ExecutionContext::internal(&state), "grp")
        .await
        .unwrap();
}

#[tokio::test]
async fn a_shared_backend_serves_membership_across_two_domains() {
    // python-keystone: two domains backed by the same driver (domain3
    // and domain4 in `test_domain_segregation`) may hold a membership
    // between them. Here the user resolves via `d-a`, the group via
    // `d-b`, both to the same `ldap` backend instance -> the
    // `Arc::ptr_eq` fast path returns without any existence probe.
    let state = state_with_mapping_fn(|id| match id {
        "u" => Some(user_mapping("d-a", "u")),
        "g" => Some(user_mapping("d-b", "g")),
        _ => None,
    })
    .await;

    let sql = identity_backend(0);
    let mut ldap_mock = MockIdentityBackend::default();
    ldap_mock.expect_is_domain_aware().return_const(true);
    ldap_mock.expect_get_user().times(0);
    ldap_mock.expect_get_group().times(0);
    ldap_mock
        .expect_add_user_to_group()
        .once()
        .returning(|_, _, _| Ok(()));
    let ldap: Arc<dyn IdentityBackend> = Arc::new(ldap_mock);

    let mut backends = HashMap::new();
    backends.insert("sql".to_string(), sql.clone());
    backends.insert("ldap".to_string(), ldap);
    let provider =
        IdentityService::from_backends("sql", sql, backends, Some(resolver(ldap_config_source(2))));

    provider
        .add_user_to_group(&ExecutionContext::internal(&state), "u", "g")
        .await
        .unwrap();
}

#[tokio::test]
async fn a_same_domain_membership_through_a_per_domain_driver_is_allowed() {
    // User and group both mapped to `d-ldap`: one resolver hit
    // (cached), both resolve to `ldap`, membership proceeds.
    let state =
        state_with_mapping_fn(|id| matches!(id, "u" | "g").then(|| user_mapping("d-ldap", id)))
            .await;

    let sql = identity_backend(0);
    let mut ldap_mock = MockIdentityBackend::default();
    ldap_mock.expect_is_domain_aware().return_const(true);
    ldap_mock.expect_get_user().times(0);
    ldap_mock.expect_get_group().times(0);
    ldap_mock
        .expect_add_user_to_group()
        .once()
        .returning(|_, _, _| Ok(()));
    let ldap: Arc<dyn IdentityBackend> = Arc::new(ldap_mock);

    let mut backends = HashMap::new();
    backends.insert("sql".to_string(), sql.clone());
    backends.insert("ldap".to_string(), ldap);
    let provider =
        IdentityService::from_backends("sql", sql, backends, Some(resolver(ldap_config_source(1))));

    provider
        .add_user_to_group(&ExecutionContext::internal(&state), "u", "g")
        .await
        .unwrap();
}

/// A provider + state for the cross-backend membership scenario: `u`
/// is mapped to `d-ldap` (LDAP), `g` is unmapped (global SQL). Both
/// entities exist. Every membership mutation must reject with
/// `CrossBackendNotAllowed`.
async fn cross_backend_fixture() -> (IdentityService, ServiceState) {
    let state = state_with_mapping_fn(|id| (id == "u").then(|| user_mapping("d-ldap", "u"))).await;

    let mut sql_mock = MockIdentityBackend::default();
    sql_mock.expect_is_domain_aware().return_const(true);
    sql_mock.expect_get_group().returning(|_, group_id| {
        Ok(Some(
            openstack_keystone_core_types::identity::GroupBuilder::default()
                .id(group_id)
                .domain_id("default")
                .name("g-name")
                .build()
                .expect("valid group"),
        ))
    });
    let sql: Arc<dyn IdentityBackend> = Arc::new(sql_mock);

    let mut ldap_mock = MockIdentityBackend::default();
    ldap_mock.expect_is_domain_aware().return_const(false);
    ldap_mock.expect_get_user().returning(|_, user_id| {
        Ok(Some(
            UserResponseBuilder::default()
                .id(user_id)
                .domain_id("d-ldap")
                .enabled(true)
                .name("u-name")
                .build()
                .expect("valid user"),
        ))
    });
    let ldap: Arc<dyn IdentityBackend> = Arc::new(ldap_mock);

    let mut backends = HashMap::new();
    backends.insert("sql".to_string(), sql.clone());
    backends.insert("ldap".to_string(), ldap);
    let provider =
        IdentityService::from_backends("sql", sql, backends, Some(resolver(ldap_config_source(1))));
    (provider, state)
}

#[tokio::test]
async fn remove_user_from_group_rejects_a_cross_backend_membership() {
    let (provider, state) = cross_backend_fixture().await;
    let error = provider
        .remove_user_from_group(&ExecutionContext::internal(&state), "u", "g")
        .await
        .expect_err("a cross-backend membership must be rejected");
    assert!(
        matches!(error, IdentityProviderError::CrossBackendNotAllowed { .. }),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn add_user_to_group_expiring_rejects_a_cross_backend_membership() {
    let (provider, state) = cross_backend_fixture().await;
    let error = provider
        .add_user_to_group_expiring(&ExecutionContext::internal(&state), "u", "g", "idp")
        .await
        .expect_err("a cross-backend membership must be rejected");
    assert!(
        matches!(error, IdentityProviderError::CrossBackendNotAllowed { .. }),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn remove_user_from_group_expiring_rejects_a_cross_backend_membership() {
    let (provider, state) = cross_backend_fixture().await;
    let error = provider
        .remove_user_from_group_expiring(&ExecutionContext::internal(&state), "u", "g", "idp")
        .await
        .expect_err("a cross-backend membership must be rejected");
    assert!(
        matches!(error, IdentityProviderError::CrossBackendNotAllowed { .. }),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn authenticate_by_password_uses_the_resolved_per_domain_driver() {
    // python-keystone `test_authenticate_to_each_domain`: password auth
    // is served by the driver the request's domain resolves to.
    let state = get_mocked_state(None, None).await;

    let mut sql_mock = MockIdentityBackend::default();
    sql_mock.expect_is_domain_aware().return_const(true);
    sql_mock.expect_authenticate_by_password().times(0);
    let sql: Arc<dyn IdentityBackend> = Arc::new(sql_mock);

    let mut ldap_mock = MockIdentityBackend::default();
    ldap_mock.expect_is_domain_aware().return_const(true);
    ldap_mock.expect_check_user_exist().times(0);
    ldap_mock
        .expect_authenticate_by_password()
        .once()
        .returning(|_, _| Err(AuthenticationError::UserNameOrPasswordWrong.into()));
    let ldap: Arc<dyn IdentityBackend> = Arc::new(ldap_mock);

    let mut backends = HashMap::new();
    backends.insert("sql".to_string(), sql.clone());
    backends.insert("ldap".to_string(), ldap);
    let provider =
        IdentityService::from_backends("sql", sql, backends, Some(resolver(ldap_config_source(1))));

    let result = provider
        .authenticate_by_password(
            &ExecutionContext::internal(&state),
            &UserPasswordAuthRequest {
                id: Some("u".into()),
                password: "pw".into(),
                domain: Some(Domain {
                    id: Some("d-ldap".into()),
                    name: None,
                }),
                ..Default::default()
            },
        )
        .await;
    assert!(
        matches!(
            result,
            Err(IdentityProviderError::Authentication {
                source: AuthenticationError::UserNameOrPasswordWrong
            })
        ),
        "unexpected result: {result:?}"
    );
}

#[tokio::test]
async fn the_non_domain_aware_guard_honours_a_custom_default_domain_id() {
    // The guard compares against `[identity] default_domain_id`, not a
    // literal "default": the configured primary domain is allowed onto
    // the non-domain-aware global driver, every other domain is not.
    let state = get_mocked_state(None, None).await;
    let ldap = non_domain_aware_backend(1);
    let mut backends = HashMap::new();
    backends.insert("ldap".to_string(), ldap.clone());
    let provider = IdentityService::from_backends(
        "ldap",
        ldap,
        backends,
        Some(resolver(config_source(Ok(None), 2))),
    )
    .with_default_domain_id("d-primary");

    let ctx = ExecutionContext::internal(&state);
    provider
        .list_users(&ctx, &list_params("d-primary"))
        .await
        .unwrap();
    let error = provider
        .list_users(&ctx, &list_params("default"))
        .await
        .expect_err("a non-primary domain must be rejected");
    assert!(
        matches!(
            error,
            IdentityProviderError::ResourceProvider {
                source: ResourceProviderError::DomainNotFound(_)
            }
        ),
        "unexpected error: {error:?}"
    );
}
