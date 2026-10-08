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

//! # IdMapping provider

use async_trait::async_trait;
use std::sync::Arc;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::idmapping::*;

use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
use crate::idmapping::{IdMappingApi, IdMappingProviderError, backend::IdMappingBackend};
use crate::plugin_manager::PluginManagerApi;

pub struct IdMappingService {
    /// Backend driver.
    backend_driver: Arc<dyn IdMappingBackend>,
}

impl IdMappingService {
    /// Create a new `IdMappingService`.
    ///
    /// # Parameters
    /// - `config`: The configuration.
    /// - `plugin_manager`: The plugin manager.
    ///
    /// # Returns
    /// - `Result<Self, IdMappingProviderError>` - The new service or an error.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, IdMappingProviderError> {
        let backend_driver = plugin_manager
            .get_idmapping_backend(config.idmapping.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

/// Build the audit event for an ID mapping change. A bulk delete carries only
/// the domain; a single mapping carries its public ID.
fn id_mapping_event(
    operation: Operation,
    domain_id: Option<&str>,
    public_id: Option<&str>,
) -> Event {
    Event::new(
        operation,
        EventPayload::IdMapping {
            domain_id: domain_id.map(str::to_string),
            public_id: public_id.map(str::to_string),
        },
    )
}

#[async_trait]
impl IdMappingApi for IdMappingService {
    /// Get the `IdMapping` by the local data.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `local_id`: The local identifier.
    /// - `domain_id`: The domain identifier.
    /// - `entity_type`: The entity type.
    ///
    /// # Returns
    /// - `Result<Option<IdMapping>, IdMappingProviderError>` - A `Result`
    ///   containing an `Option` with the `IdMapping` if found, or an `Error`.
    #[tracing::instrument(name = "provider.idmapping.get_by_local_id", level = "debug", skip_all, fields(local_id = %local_id, domain_id = %domain_id, entity_type = ?entity_type))]
    async fn get_by_local_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        local_id: &'a str,
        domain_id: &'a str,
        entity_type: IdMappingEntityType,
    ) -> Result<Option<IdMapping>, IdMappingProviderError> {
        self.backend_driver
            .get_by_local_id(ctx.state(), local_id, domain_id, entity_type)
            .await
    }

    /// Get the `IdMapping` by the public identifier.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `public_id`: The public identifier.
    ///
    /// # Returns
    /// - `Result<Option<IdMapping>, IdMappingProviderError>` - A `Result`
    ///   containing an `Option` with the `IdMapping` if found, or an `Error`.
    #[tracing::instrument(name = "provider.idmapping.get_by_public_id", level = "debug", skip_all, fields(public_id = %public_id))]
    async fn get_by_public_id<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        public_id: &'a str,
    ) -> Result<Option<IdMapping>, IdMappingProviderError> {
        self.backend_driver
            .get_by_public_id(ctx.state(), public_id)
            .await
    }

    /// Create a new `IdMapping`.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `local_id`: The local identifier.
    /// - `domain_id`: The domain identifier.
    /// - `entity_type`: The entity type.
    /// - `public_id`: The public identifier to use. If `None`, one is generated
    ///   deterministically (sha256 over `domain_id`, `entity_type`, `local_id`
    ///   — bit-compatible with python-keystone's `sha256` id generator).
    ///
    /// # Returns
    /// - `Result<IdMapping, IdMappingProviderError>` - The created (or
    ///   already-existing, on a benign race) `IdMapping`, or an `Error`.
    #[tracing::instrument(name = "provider.idmapping.create_id_mapping", level = "debug", skip_all, fields(local_id = %local_id, domain_id = %domain_id, entity_type = ?entity_type))]
    async fn create_id_mapping<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        local_id: &'a str,
        domain_id: &'a str,
        entity_type: IdMappingEntityType,
        public_id: Option<&'a str>,
    ) -> Result<IdMapping, IdMappingProviderError> {
        let generated;
        let public_id = match public_id {
            Some(public_id) => public_id,
            None => {
                generated =
                    crate::identity::generate_public_id(domain_id, local_id, entity_type.as_str());
                &generated
            }
        };
        let event = id_mapping_event(Operation::Create, Some(domain_id), Some(public_id));
        let op = async {
            self.backend_driver
                .create_id_mapping(ctx.state(), local_id, domain_id, entity_type, public_id)
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: event,
            operation: op,
            on_audit_error: |_: AuditDispatchError| IdMappingProviderError::AuditUnavailable,
        }
    }

    /// Delete the `IdMapping` by the public identifier.
    ///
    /// Silent/idempotent if no mapping is found.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `public_id`: The public identifier.
    ///
    /// # Returns
    /// - `Result<(), IdMappingProviderError>` - `Ok` on success (including when
    ///   nothing was found), or an `Error`.
    #[tracing::instrument(name = "provider.idmapping.delete_id_mapping", level = "debug", skip_all, fields(public_id = %public_id))]
    async fn delete_id_mapping<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        public_id: &'a str,
    ) -> Result<(), IdMappingProviderError> {
        let op = async {
            self.backend_driver
                .delete_id_mapping(ctx.state(), public_id)
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: id_mapping_event(Operation::Delete, None, Some(public_id)),
            operation: op,
            on_audit_error: |_: AuditDispatchError| IdMappingProviderError::AuditUnavailable,
        }
    }

    /// Delete every `IdMapping` row belonging to a domain.
    ///
    /// # Parameters
    /// - `ctx`: The execution context.
    /// - `domain_id`: The domain identifier.
    ///
    /// # Returns
    /// - `Result<(), IdMappingProviderError>` - `Ok` on success (including when
    ///   nothing was found), or an `Error`.
    #[tracing::instrument(name = "provider.idmapping.delete_mappings_for_domain", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn delete_mappings_for_domain<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        domain_id: &'a str,
    ) -> Result<(), IdMappingProviderError> {
        let op = async {
            self.backend_driver
                .delete_mappings_for_domain(ctx.state(), domain_id)
                .await
        };
        crate::audited_if_ctx! {
            ctx: ctx,
            event: id_mapping_event(Operation::Delete, Some(domain_id), None),
            operation: op,
            on_audit_error: |_: AuditDispatchError| IdMappingProviderError::AuditUnavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    // use std::sync::Arc;

    use super::*;
    use crate::idmapping::backend::MockIdMappingBackend;
    use crate::tests::get_mocked_state;

    fn create_provider(backend: MockIdMappingBackend) -> IdMappingService {
        IdMappingService {
            backend_driver: Arc::new(backend),
        }
    }

    #[tokio::test]
    async fn test_get_by_local_id() {
        let state = get_mocked_state(None, None).await;
        let sot = IdMapping {
            public_id: "pid".into(),
            local_id: "lid".into(),
            domain_id: "did".into(),
            entity_type: IdMappingEntityType::User,
        };
        let mut backend = MockIdMappingBackend::default();
        let sot_clone = sot.clone();
        backend
            .expect_get_by_local_id()
            .withf(|_, lid: &'_ str, did: &'_ str, _et: &IdMappingEntityType| {
                lid == "lid" && did == "did"
            })
            .returning(move |_, _, _, _| Ok(Some(sot_clone.clone())));
        let provider = create_provider(backend);

        let res: IdMapping = provider
            .get_by_local_id(
                &ExecutionContext::internal(&state),
                "lid",
                "did",
                IdMappingEntityType::User,
            )
            .await
            .unwrap()
            .expect("id mapping should be there");
        assert_eq!(res, sot);
    }

    #[tokio::test]
    async fn test_get_by_public_id() {
        let state = get_mocked_state(None, None).await;
        let sot = IdMapping {
            public_id: "pid".into(),
            local_id: "lid".into(),
            domain_id: "did".into(),
            entity_type: IdMappingEntityType::User,
        };
        let mut backend = MockIdMappingBackend::default();
        let sot_clone = sot.clone();
        backend
            .expect_get_by_public_id()
            .withf(|_, pid: &'_ str| pid == "pid")
            .returning(move |_, _| Ok(Some(sot_clone.clone())));
        let provider = create_provider(backend);

        let res: IdMapping = provider
            .get_by_public_id(&ExecutionContext::internal(&state), "pid")
            .await
            .unwrap()
            .expect("id mapping should be there");
        assert_eq!(res, sot);
    }

    #[tokio::test]
    async fn test_create_id_mapping_with_explicit_public_id() {
        let state = get_mocked_state(None, None).await;
        let sot = IdMapping {
            public_id: "pid".into(),
            local_id: "lid".into(),
            domain_id: "did".into(),
            entity_type: IdMappingEntityType::User,
        };
        let mut backend = MockIdMappingBackend::default();
        let sot_clone = sot.clone();
        backend
            .expect_create_id_mapping()
            .withf(
                |_, lid: &'_ str, did: &'_ str, _et: &IdMappingEntityType, pid: &'_ str| {
                    lid == "lid" && did == "did" && pid == "pid"
                },
            )
            .returning(move |_, _, _, _, _| Ok(sot_clone.clone()));
        let provider = create_provider(backend);

        let res = provider
            .create_id_mapping(
                &ExecutionContext::internal(&state),
                "lid",
                "did",
                IdMappingEntityType::User,
                Some("pid"),
            )
            .await
            .unwrap();
        assert_eq!(res, sot);
    }

    #[tokio::test]
    async fn test_create_id_mapping_generates_public_id_when_omitted() {
        let state = get_mocked_state(None, None).await;
        let expected_public_id = crate::identity::generate_public_id("did", "lid", "user");
        let sot = IdMapping {
            public_id: expected_public_id.clone(),
            local_id: "lid".into(),
            domain_id: "did".into(),
            entity_type: IdMappingEntityType::User,
        };
        let mut backend = MockIdMappingBackend::default();
        let sot_clone = sot.clone();
        let expected_public_id_clone = expected_public_id.clone();
        backend
            .expect_create_id_mapping()
            .withf(
                move |_, lid: &'_ str, did: &'_ str, _et: &IdMappingEntityType, pid: &'_ str| {
                    lid == "lid" && did == "did" && pid == expected_public_id_clone
                },
            )
            .returning(move |_, _, _, _, _| Ok(sot_clone.clone()));
        let provider = create_provider(backend);

        let res = provider
            .create_id_mapping(
                &ExecutionContext::internal(&state),
                "lid",
                "did",
                IdMappingEntityType::User,
                None,
            )
            .await
            .unwrap();
        assert_eq!(res.public_id, expected_public_id);
    }

    #[tokio::test]
    async fn test_delete_id_mapping() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockIdMappingBackend::default();
        backend
            .expect_delete_id_mapping()
            .withf(|_, pid: &'_ str| pid == "pid")
            .returning(|_, _| Ok(()));
        let provider = create_provider(backend);

        provider
            .delete_id_mapping(&ExecutionContext::internal(&state), "pid")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_delete_mappings_for_domain() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockIdMappingBackend::default();
        backend
            .expect_delete_mappings_for_domain()
            .withf(|_, did: &'_ str| did == "did")
            .returning(|_, _| Ok(()));
        let provider = create_provider(backend);

        provider
            .delete_mappings_for_domain(&ExecutionContext::internal(&state), "did")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_delete_mappings_for_domain_is_audited() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockIdMappingBackend::default();
        backend
            .expect_delete_mappings_for_domain()
            .returning(|_, _| Ok(()));
        let provider = IdMappingService {
            backend_driver: std::sync::Arc::new(backend),
        };
        let hook = crate::tests::RecordingAuditHook::new();
        state.event_dispatcher.subscribe_audit(hook.clone()).await;
        let vsc = crate::tests::test_vsc();

        provider
            .delete_mappings_for_domain(&ExecutionContext::from_auth(&state, &vsc), "domain-1")
            .await
            .unwrap();

        assert_eq!(hook.outcomes(), ["Attempt", "Success"]);
        assert!(hook.seen()[0].1.contains("IdMapping"));
    }
}
