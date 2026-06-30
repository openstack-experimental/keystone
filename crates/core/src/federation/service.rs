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
//! # Federation provider
//!
//! Federation provider implements the functionality necessary for the user
//! federation.
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::federation::*;

use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
use crate::federation::{FederationApi, FederationProviderError, backend::FederationBackend};
use crate::plugin_manager::PluginManagerApi;

pub struct FederationService {
    backend_driver: Arc<dyn FederationBackend>,
}

impl FederationService {
    /// Create new federation service.
    ///
    /// # Parameters
    /// - `config`: The configuration for the federation service.
    /// - `plugin_manager`: The plugin manager to resolve the federation
    ///   backend.
    ///
    /// # Returns
    /// - `Result<Self, FederationProviderError>` - The newly created
    ///   `FederationService` or an error.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, FederationProviderError> {
        let backend_driver = plugin_manager
            .get_federation_backend(config.federation.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl FederationApi for FederationService {
    /// Cleanup expired resources.
    ///
    /// # Parameters
    /// - `exec`: The execution context.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or a
    ///   federation provider error.
    async fn cleanup<'a>(&self, ctx: &ExecutionContext<'a>) -> Result<(), FederationProviderError> {
        self.backend_driver.cleanup(ctx.state()).await
    }

    /// Create new auth state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `auth_state`: The authentication state to create.
    ///
    /// # Returns
    /// - `Result<AuthState, FederationProviderError>` - The created `AuthState`
    ///   or an error.
    async fn create_auth_state<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        auth_state: AuthState,
    ) -> Result<AuthState, FederationProviderError> {
        let auth_state_result = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let auth_state_clone = auth_state.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::AuthState { id: auth_state.state.clone() },
                ),
                operation: async {
                    backend_driver.create_auth_state(ctx.state(), auth_state_clone).await
                },
                on_audit_error: |_: AuditDispatchError| FederationProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let auth_state_result = self
                .backend_driver
                .create_auth_state(ctx.state(), auth_state)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::AuthState {
                        id: auth_state_result.state.clone(),
                    },
                ))
                .await;
            auth_state_result
        };
        Ok(auth_state_result)
    }

    /// Create Identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `idp`: The identity provider details to create.
    ///
    /// # Returns
    /// - `Result<IdentityProvider, FederationProviderError>` - The created
    ///   `IdentityProvider` or an error.
    async fn create_identity_provider<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        idp: IdentityProviderCreate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        let mut mod_idp = idp;
        if mod_idp.id.is_none() {
            mod_idp.id = Some(Uuid::new_v4().simple().to_string());
        }
        let provider_id = mod_idp.id.clone().unwrap_or_default();
        let provider = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let mod_idp_clone = mod_idp.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::IdentityProvider { id: provider_id.clone() },
                ),
                operation: async {
                    backend_driver.create_identity_provider(ctx.state(), mod_idp_clone).await
                },
                on_audit_error: |_: AuditDispatchError| FederationProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let provider = self
                .backend_driver
                .create_identity_provider(ctx.state(), mod_idp)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::IdentityProvider {
                        id: provider.id.clone(),
                    },
                ))
                .await;
            provider
        };
        Ok(provider)
    }

    /// Delete auth state.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the auth state to delete.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or an error.
    async fn delete_auth_state<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::AuthState { id: id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_auth_state(ctx.state(), id).await?;
                    Ok::<(), FederationProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| FederationProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
                .delete_auth_state(ctx.state(), id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::AuthState { id: id.to_string() },
                ))
                .await;
        }
        Ok(())
    }

    /// Delete identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to delete.
    ///
    /// # Returns
    /// - `Result<(), FederationProviderError>` - Ok if successful, or an error.
    async fn delete_identity_provider<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::IdentityProvider { id: id.to_string() },
                ),
                operation: async {
                    self.backend_driver.delete_identity_provider(ctx.state(), id).await?;
                    Ok::<(), FederationProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| FederationProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
                .delete_identity_provider(ctx.state(), id)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::IdentityProvider { id: id.to_string() },
                ))
                .await;
        }
        Ok(())
    }

    /// Get auth state by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the auth state to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<AuthState>, FederationProviderError>` - A `Result`
    ///   containing an `Option` with the auth state if found, or an `Error`.
    async fn get_auth_state<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError> {
        self.backend_driver.get_auth_state(ctx.state(), id).await
    }

    /// Get single IDP by ID.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to retrieve.
    ///
    /// # Returns
    /// - `Result<Option<IdentityProvider>, FederationProviderError>` - A
    ///   `Result` containing an `Option` with the identity provider if found,
    ///   or an `Error`.
    async fn get_identity_provider<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError> {
        self.backend_driver
            .get_identity_provider(ctx.state(), id)
            .await
    }

    /// List IDP.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `params`: The list parameters for identity providers.
    ///
    /// # Returns
    /// - `Result<Vec<IdentityProvider>, FederationProviderError>` - A list of
    ///   identity providers or an error.
    async fn list_identity_providers<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &IdentityProviderListParameters,
    ) -> Result<Vec<IdentityProvider>, FederationProviderError> {
        self.backend_driver
            .list_identity_providers(ctx.state(), params)
            .await
    }

    /// Update Identity provider.
    ///
    /// # Parameters
    /// - `state`: The service state.
    /// - `id`: The ID of the identity provider to update.
    /// - `idp`: The update details for the identity provider.
    ///
    /// # Returns
    /// - `Result<IdentityProvider, FederationProviderError>` - The updated
    ///   `IdentityProvider` or an error.
    async fn update_identity_provider<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
        idp: IdentityProviderUpdate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        let provider = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let idp_clone = idp.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::IdentityProvider { id: id.to_string() },
                ),
                operation: async {
                    backend_driver.update_identity_provider(ctx.state(), id, idp_clone).await
                },
                on_audit_error: |_: AuditDispatchError| FederationProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let provider = self
                .backend_driver
                .update_identity_provider(ctx.state(), id, idp)
                .await?;
            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Update,
                    EventPayload::IdentityProvider { id: id.to_string() },
                ))
                .await;
            provider
        };
        Ok(provider)
    }
}
