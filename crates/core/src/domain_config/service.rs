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

//! # Domain configuration provider service

use std::sync::Arc;

use async_trait::async_trait;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::domain_config::*;

use crate::domain_config::api::DomainConfigApi;
use crate::domain_config::backend::DomainConfigBackend;
use crate::domain_config::error::DomainConfigProviderError;
use crate::keystone::ServiceState;
use crate::plugin_manager::PluginManagerApi;

/// The backend source the configuration API reads and writes.
///
/// python-keystone's domain config API always targets the database, whatever
/// `[identity] domain_configurations_from_database` is set to -- that switch
/// only decides whether the *identity manager* consults the stored
/// configuration. The file source (`fs`) is operator-managed on disk and never
/// written through the API.
const API_BACKEND: &str = "sql";

/// The registration type claimed by the domain whose stored `identity/driver`
/// is `sql`. Matches python-keystone's `SQL` registration key.
const SQL_REGISTRATION: &str = "SQL";

/// Domain configuration provider service.
///
/// A near pass-through to the `sql` domain-config backend. The only logic it
/// adds is the single-domain SQL identity-driver registration lock
/// (issue #960): while `[identity] domain_configurations_from_database` is on,
/// at most one domain may have `identity/driver = sql` in its stored config.
pub struct DomainConfigService {
    backend_driver: Arc<dyn DomainConfigBackend>,
    /// `[identity] domain_configurations_from_database`. The registration lock
    /// is enforced only while this is set; otherwise the stored configuration
    /// never drives identity-backend selection and there is nothing to guard.
    domain_configurations_from_database: bool,
}

impl DomainConfigService {
    /// Create a new `DomainConfigService`.
    ///
    /// # Parameters
    /// - `config`: The service configuration; only
    ///   `[identity] domain_configurations_from_database` is read, to decide
    ///   whether the registration lock is enforced.
    /// - `plugin_manager`: The plugin manager used to resolve the backend
    ///   driver.
    ///
    /// # Returns
    /// - `Result<Self, DomainConfigProviderError>` - The initialized service,
    ///   or [`DomainConfigProviderError::UnsupportedDriver`] when the `sql`
    ///   backend is not registered.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, DomainConfigProviderError> {
        let backend_driver = plugin_manager
            .get_domain_config_backend(API_BACKEND)?
            .clone();
        Ok(Self {
            backend_driver,
            domain_configurations_from_database: config
                .identity
                .domain_configurations_from_database,
        })
    }

    /// The `identity/driver` a domain configuration sets, if any.
    fn identity_driver(config: &DomainConfig) -> Option<String> {
        config
            .clone()
            .into_group(DomainConfigGroupName::Identity)
            .and_then(|group| {
                group
                    .get("driver")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
            })
    }

    /// Claim the SQL identity-driver registration for `domain_id`, or fail the
    /// write when another domain already holds it. No-op unless
    /// configurations come from the database.
    async fn claim_sql_registration(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<(), DomainConfigProviderError> {
        if !self.domain_configurations_from_database {
            return Ok(());
        }
        let obtained = self
            .backend_driver
            .obtain_registration(state, domain_id, SQL_REGISTRATION)
            .await?;
        if !obtained
            && self
                .backend_driver
                .read_registration(state, SQL_REGISTRATION)
                .await?
                .as_deref()
                != Some(domain_id)
        {
            return Err(DomainConfigProviderError::Conflict(
                "the SQL identity driver is already registered to another domain".to_owned(),
            ));
        }
        Ok(())
    }

    /// Give up the SQL identity-driver registration `domain_id` may hold.
    /// No-op unless configurations come from the database.
    async fn release_sql_registration(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<(), DomainConfigProviderError> {
        if !self.domain_configurations_from_database {
            return Ok(());
        }
        self.backend_driver
            .release_registration(state, domain_id, Some(SQL_REGISTRATION))
            .await
    }

    /// Reconcile the SQL registration with the `identity/driver` a write is
    /// about to store: `Some("sql")` must claim it (before the write, so a
    /// conflict blocks the write), any other value releases it (after), and
    /// `None` — the write does not touch `identity/driver` — leaves it alone.
    async fn reconcile_registration_before(
        &self,
        state: &ServiceState,
        domain_id: &str,
        driver: Option<&str>,
    ) -> Result<(), DomainConfigProviderError> {
        if driver == Some("sql") {
            self.claim_sql_registration(state, domain_id).await?;
        }
        Ok(())
    }

    async fn reconcile_registration_after(
        &self,
        state: &ServiceState,
        domain_id: &str,
        driver: Option<&str>,
    ) -> Result<(), DomainConfigProviderError> {
        if let Some(driver) = driver
            && driver != "sql"
        {
            self.release_sql_registration(state, domain_id).await?;
        }
        Ok(())
    }

    /// The `assignment/driver` a domain configuration sets, if any
    /// (ADR 0034 §3). `driver` is the group's only whitelisted option, so a
    /// `Some` here also means "this write touches the `assignment` group".
    fn assignment_driver(config: &DomainConfig) -> Option<String> {
        config.resolve_assignment_driver_name()
    }

    /// Reject a write that would bind a domain to an `assignment/driver` no
    /// running backend can serve (ADR 0034 §3): the name must be `sql`, the
    /// global `[assignment] driver`, or the `driver` of some
    /// `[assignment.backends.*]` block. An unrecognised name would otherwise
    /// be stored happily and then silently fall back to the global driver at
    /// resolve time — catch it at the write instead. `None` (the write does
    /// not set `assignment/driver`) passes.
    async fn validate_assignment_binding(
        &self,
        state: &ServiceState,
        domain_id: &str,
        driver: Option<&str>,
    ) -> Result<(), DomainConfigProviderError> {
        let Some(driver) = driver else {
            return Ok(());
        };
        let config = state.config_manager.config.read().await;
        let bindable = config.assignment.bindable_driver_names();
        if !bindable.contains(driver) {
            let mut names: Vec<_> = bindable.into_iter().collect();
            names.sort();
            return Err(DomainConfigProviderError::InvalidOptionValue {
                group: "assignment".to_owned(),
                option: "driver".to_owned(),
                source: serde::de::Error::custom(format!(
                    "{driver:?} names no configured assignment backend; valid names: {names:?}"
                )),
            });
        }
        // The name is bindable, but a per-domain instance only spins up when
        // `[assignment.domains]` maps this domain to a matching backend block
        // (ADR 0034 §4). A non-global name with no such mapping is stored
        // happily and then falls straight back to the global driver at resolve
        // time -- an inert binding. Reject nothing (the operator may add the
        // mapping next), but say so loudly.
        let global = config.assignment.driver.as_str();
        if driver != "sql" && driver != global {
            let mapped = config
                .assignment
                .domains
                .get(domain_id)
                .and_then(|block| config.assignment.backends.get(block))
                .map(|block| block.driver_name());
            if mapped != Some(driver) {
                tracing::warn!(
                    domain_id,
                    driver,
                    "domain bound to assignment driver {driver:?} with no matching \
                     [assignment.domains] mapping; the binding is inert and resolves \
                     to the global {global:?} driver until the mapping is added"
                );
            }
        }
        Ok(())
    }

    /// Recompute the assignment provider's domain→driver bindings and
    /// untargeted fan-out set after a write that touched the `assignment`
    /// group (ADR 0034 §9). Best-effort: the write has already committed, so
    /// a failure here is logged and swallowed — the fan-out set self-heals on
    /// the next full config reload.
    async fn refresh_assignment_bindings(&self, state: &ServiceState, touched: bool) {
        if !touched {
            return;
        }
        if let Err(error) = state
            .provider
            .get_assignment_provider()
            .refresh_bindings(state)
            .await
        {
            tracing::warn!(
                %error,
                "assignment binding refresh after a domain-config write failed; \
                 the fan-out set self-heals on the next reload"
            );
        }
    }
}

#[async_trait]
impl DomainConfigApi for DomainConfigService {
    async fn create_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        config: DomainConfigCreate,
    ) -> Result<DomainConfig, DomainConfigProviderError> {
        let driver = Self::identity_driver(&config.0);
        let assignment_driver = Self::assignment_driver(&config.0);
        // Validate before `reconcile_registration_before`: a rejected write
        // must not leave the SQL identity-driver registration claimed.
        self.validate_assignment_binding(state, domain_id, assignment_driver.as_deref())
            .await?;
        self.reconcile_registration_before(state, domain_id, driver.as_deref())
            .await?;
        let stored = self
            .backend_driver
            .create_domain_config(state, domain_id, config)
            .await?;
        self.reconcile_registration_after(state, domain_id, driver.as_deref())
            .await?;
        self.refresh_assignment_bindings(state, assignment_driver.is_some())
            .await;
        Ok(stored)
    }

    async fn get_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<DomainConfig>, DomainConfigProviderError> {
        self.backend_driver
            .get_domain_config(state, domain_id)
            .await
    }

    async fn get_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
    ) -> Result<Option<DomainConfigGroup>, DomainConfigProviderError> {
        self.backend_driver
            .get_domain_config_group(state, domain_id, group)
            .await
    }

    async fn get_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<Option<DomainConfigOption>, DomainConfigProviderError> {
        self.backend_driver
            .get_domain_config_option(state, domain_id, group, option)
            .await
    }

    async fn update_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        config: DomainConfigUpdate,
    ) -> Result<DomainConfig, DomainConfigProviderError> {
        let driver = Self::identity_driver(&config.0);
        let assignment_driver = Self::assignment_driver(&config.0);
        self.validate_assignment_binding(state, domain_id, assignment_driver.as_deref())
            .await?;
        self.reconcile_registration_before(state, domain_id, driver.as_deref())
            .await?;
        let stored = self
            .backend_driver
            .update_domain_config(state, domain_id, config)
            .await?;
        self.reconcile_registration_after(state, domain_id, driver.as_deref())
            .await?;
        self.refresh_assignment_bindings(state, assignment_driver.is_some())
            .await;
        Ok(stored)
    }

    async fn update_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        config: DomainConfigUpdate,
    ) -> Result<DomainConfigGroup, DomainConfigProviderError> {
        let driver = (group == DomainConfigGroupName::Identity)
            .then(|| Self::identity_driver(&config.0))
            .flatten();
        let assignment_driver = (group == DomainConfigGroupName::Assignment)
            .then(|| Self::assignment_driver(&config.0))
            .flatten();
        self.validate_assignment_binding(state, domain_id, assignment_driver.as_deref())
            .await?;
        self.reconcile_registration_before(state, domain_id, driver.as_deref())
            .await?;
        let stored = self
            .backend_driver
            .update_domain_config_group(state, domain_id, group, config)
            .await?;
        self.reconcile_registration_after(state, domain_id, driver.as_deref())
            .await?;
        self.refresh_assignment_bindings(state, assignment_driver.is_some())
            .await;
        Ok(stored)
    }

    async fn update_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        option: DomainConfigOption,
    ) -> Result<DomainConfigOption, DomainConfigProviderError> {
        let driver = (option.group == DomainConfigGroupName::Identity && option.option == "driver")
            .then(|| option.value.as_value().as_str().map(str::to_owned))
            .flatten();
        let assignment_driver = (option.group == DomainConfigGroupName::Assignment
            && option.option == "driver")
            .then(|| option.value.as_value().as_str().map(str::to_owned))
            .flatten();
        self.validate_assignment_binding(state, domain_id, assignment_driver.as_deref())
            .await?;
        self.reconcile_registration_before(state, domain_id, driver.as_deref())
            .await?;
        let stored = self
            .backend_driver
            .update_domain_config_option(state, domain_id, option)
            .await?;
        self.reconcile_registration_after(state, domain_id, driver.as_deref())
            .await?;
        self.refresh_assignment_bindings(state, assignment_driver.is_some())
            .await;
        Ok(stored)
    }

    async fn delete_domain_config<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<(), DomainConfigProviderError> {
        self.backend_driver
            .delete_domain_config(state, domain_id)
            .await?;
        // A whole-config delete may have dropped an `assignment/driver`
        // binding; refresh unconditionally (ADR 0034 §9).
        self.refresh_assignment_bindings(state, true).await;
        self.release_sql_registration(state, domain_id).await
    }

    async fn delete_domain_config_group<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
    ) -> Result<(), DomainConfigProviderError> {
        self.backend_driver
            .delete_domain_config_group(state, domain_id, group)
            .await?;
        if group == DomainConfigGroupName::Identity {
            self.release_sql_registration(state, domain_id).await?;
        }
        self.refresh_assignment_bindings(state, group == DomainConfigGroupName::Assignment)
            .await;
        Ok(())
    }

    async fn delete_domain_config_option<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<(), DomainConfigProviderError> {
        self.backend_driver
            .delete_domain_config_option(state, domain_id, group, option)
            .await?;
        if group == DomainConfigGroupName::Identity && option == "driver" {
            self.release_sql_registration(state, domain_id).await?;
        }
        self.refresh_assignment_bindings(
            state,
            group == DomainConfigGroupName::Assignment && option == "driver",
        )
        .await;
        Ok(())
    }

    async fn get_default_config(
        &self,
        state: &ServiceState,
    ) -> Result<DomainConfig, DomainConfigProviderError> {
        self.backend_driver.get_default_config(state).await
    }

    async fn get_default_group(
        &self,
        state: &ServiceState,
        group: DomainConfigGroupName,
    ) -> Result<DomainConfigGroup, DomainConfigProviderError> {
        self.backend_driver.get_default_group(state, group).await
    }

    async fn get_default_option<'a>(
        &self,
        state: &ServiceState,
        group: DomainConfigGroupName,
        option: &'a str,
    ) -> Result<Option<DomainConfigOption>, DomainConfigProviderError> {
        self.backend_driver
            .get_default_option(state, group, option)
            .await
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::domain_config::backend::MockDomainConfigBackend;
    use crate::tests::get_mocked_state;

    /// A `DomainConfigService` over `backend`, with the registration lock
    /// enforced when `from_database`.
    fn service(backend: MockDomainConfigBackend, from_database: bool) -> DomainConfigService {
        DomainConfigService {
            backend_driver: Arc::new(backend),
            domain_configurations_from_database: from_database,
        }
    }

    /// A `DomainConfig` from a request-shaped body.
    fn config(body: serde_json::Value) -> DomainConfig {
        DomainConfig::from_value(body).expect("a valid domain configuration")
    }

    /// A `create_domain_config` that echoes back an `identity/driver = sql`
    /// configuration.
    fn expect_create(backend: &mut MockDomainConfigBackend) {
        backend
            .expect_create_domain_config()
            .returning(|_, _, _| Ok(config(json!({"identity": {"driver": "sql"}}))));
    }

    #[tokio::test]
    async fn the_lock_is_skipped_when_configs_do_not_come_from_the_database() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockDomainConfigBackend::new();
        backend.expect_obtain_registration().never();
        backend.expect_release_registration().never();
        expect_create(&mut backend);

        service(backend, false)
            .create_domain_config(
                &state,
                "d1",
                DomainConfigCreate(config(json!({"identity": {"driver": "sql"}}))),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_sql_driver_claims_the_free_registration_then_writes() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockDomainConfigBackend::new();
        backend
            .expect_obtain_registration()
            .withf(|_, domain_id, driver_type| domain_id == "d1" && driver_type == "SQL")
            .returning(|_, _, _| Ok(true));
        backend.expect_release_registration().never();
        expect_create(&mut backend);

        service(backend, true)
            .create_domain_config(
                &state,
                "d1",
                DomainConfigCreate(config(json!({"identity": {"driver": "sql"}}))),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_registration_held_by_another_domain_blocks_the_write() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockDomainConfigBackend::new();
        backend
            .expect_obtain_registration()
            .returning(|_, _, _| Ok(false));
        backend
            .expect_read_registration()
            .returning(|_, _| Ok(Some("other-domain".to_string())));
        backend.expect_create_domain_config().never();

        let error = service(backend, true)
            .create_domain_config(
                &state,
                "d1",
                DomainConfigCreate(config(json!({"identity": {"driver": "sql"}}))),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, DomainConfigProviderError::Conflict(_)));
    }

    #[tokio::test]
    async fn a_registration_already_held_by_this_domain_lets_the_write_through() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockDomainConfigBackend::new();
        backend
            .expect_obtain_registration()
            .returning(|_, _, _| Ok(false));
        backend
            .expect_read_registration()
            .returning(|_, _| Ok(Some("d1".to_string())));
        expect_create(&mut backend);

        service(backend, true)
            .create_domain_config(
                &state,
                "d1",
                DomainConfigCreate(config(json!({"identity": {"driver": "sql"}}))),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn switching_to_a_non_sql_driver_releases_the_registration_after_the_write() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockDomainConfigBackend::new();
        backend.expect_obtain_registration().never();
        backend
            .expect_update_domain_config()
            .returning(|_, _, _| Ok(config(json!({"identity": {"driver": "ldap"}}))));
        backend
            .expect_release_registration()
            .withf(|_, domain_id, driver_type| domain_id == "d1" && *driver_type == Some("SQL"))
            .returning(|_, _, _| Ok(()));

        service(backend, true)
            .update_domain_config(
                &state,
                "d1",
                DomainConfigUpdate(config(json!({"identity": {"driver": "ldap"}}))),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn deleting_the_configuration_releases_the_registration() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockDomainConfigBackend::new();
        backend
            .expect_delete_domain_config()
            .returning(|_, _| Ok(()));
        backend
            .expect_release_registration()
            .withf(|_, domain_id, driver_type| domain_id == "d1" && *driver_type == Some("SQL"))
            .returning(|_, _, _| Ok(()));

        service(backend, true)
            .delete_domain_config(&state, "d1")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn deleting_the_configuration_is_a_plain_passthrough_without_database_configs() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockDomainConfigBackend::new();
        backend
            .expect_delete_domain_config()
            .returning(|_, _| Ok(()));
        backend.expect_release_registration().never();

        service(backend, false)
            .delete_domain_config(&state, "d1")
            .await
            .unwrap();
    }

    /// A `Config` with one `[assignment.backends.central_fga]` block whose
    /// driver is `openfga`.
    fn config_with_openfga_backend() -> Config {
        let mut config = Config::default();
        config.assignment.backends.insert(
            "central_fga".to_string(),
            serde_json::from_value(json!({
                "driver": "openfga",
                "api_url": "http://fga.example/",
                "store_id": "s1",
            }))
            .expect("a valid openfga backend block"),
        );
        config
    }

    #[tokio::test]
    async fn an_unbacked_assignment_driver_is_rejected_before_the_registration_claim() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockDomainConfigBackend::new();
        // The reorder guarantee (ADR 0034 §3): validation fails before the SQL
        // identity-driver registration is claimed, so a rejected write leaves
        // no dangling claim behind.
        backend.expect_obtain_registration().never();
        backend.expect_create_domain_config().never();

        let error = service(backend, true)
            .create_domain_config(
                &state,
                "d1",
                DomainConfigCreate(config(json!({
                    "identity": {"driver": "sql"},
                    "assignment": {"driver": "openfga"},
                }))),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            DomainConfigProviderError::InvalidOptionValue { .. }
        ));
    }

    #[tokio::test]
    async fn an_assignment_driver_named_by_a_backend_block_is_accepted() {
        let state = get_mocked_state(Some(config_with_openfga_backend()), None).await;
        let mut backend = MockDomainConfigBackend::new();
        backend
            .expect_create_domain_config()
            .returning(|_, _, _| Ok(config(json!({"assignment": {"driver": "openfga"}}))));

        service(backend, false)
            .create_domain_config(
                &state,
                "d1",
                DomainConfigCreate(config(json!({"assignment": {"driver": "openfga"}}))),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_sql_assignment_driver_is_always_accepted() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockDomainConfigBackend::new();
        backend
            .expect_create_domain_config()
            .returning(|_, _, _| Ok(config(json!({"assignment": {"driver": "sql"}}))));

        service(backend, false)
            .create_domain_config(
                &state,
                "d1",
                DomainConfigCreate(config(json!({"assignment": {"driver": "sql"}}))),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn a_bindable_driver_with_no_domains_mapping_warns_that_the_binding_is_inert() {
        let state = get_mocked_state(Some(config_with_openfga_backend()), None).await;
        let mut backend = MockDomainConfigBackend::new();
        backend
            .expect_create_domain_config()
            .returning(|_, _, _| Ok(config(json!({"assignment": {"driver": "openfga"}}))));

        // The write is accepted (the name is bindable), but there is no
        // `[assignment.domains]` entry for `d1`, so the stored binding will
        // resolve straight back to the global driver.
        service(backend, false)
            .create_domain_config(
                &state,
                "d1",
                DomainConfigCreate(config(json!({"assignment": {"driver": "openfga"}}))),
            )
            .await
            .unwrap();
        assert!(logs_contain("the binding is inert"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn a_bindable_driver_with_a_matching_domains_mapping_does_not_warn() {
        let mut cfg = config_with_openfga_backend();
        cfg.assignment
            .domains
            .insert("d1".to_string(), "central_fga".to_string());
        let state = get_mocked_state(Some(cfg), None).await;
        let mut backend = MockDomainConfigBackend::new();
        backend
            .expect_create_domain_config()
            .returning(|_, _, _| Ok(config(json!({"assignment": {"driver": "openfga"}}))));

        service(backend, false)
            .create_domain_config(
                &state,
                "d1",
                DomainConfigCreate(config(json!({"assignment": {"driver": "openfga"}}))),
            )
            .await
            .unwrap();
        assert!(!logs_contain("the binding is inert"));
    }

    #[tokio::test]
    async fn an_unbacked_assignment_driver_is_rejected_on_the_option_path() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockDomainConfigBackend::new();
        backend.expect_update_domain_config_option().never();

        let error = service(backend, true)
            .update_domain_config_option(
                &state,
                "d1",
                DomainConfigOption::new(DomainConfigGroupName::Assignment, "driver", "openfga"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            DomainConfigProviderError::InvalidOptionValue { .. }
        ));
    }
}
