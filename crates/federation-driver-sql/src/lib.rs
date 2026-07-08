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
//! SQL backend driver for the Keystone federation provider.
//!
//! This crate provides the database persistence layer for federation-related
//! resources managed by the
//! [`FederationBackend`](openstack_keystone_core::federation::backend::FederationBackend):
//! identity providers, federation protocols, federated users, and
//! authentication state. It uses SeaORM for query construction and migration
//! handling.
//!
//! # Entities
//!
//! - [`entity::IdentityProvider`] - identity providers (IdPs)
//! - [`entity::FederationProtocol`] -federation protocols bound to IdPs
//! - [`entity::FederatedIdentityProvider`] - federated users mapped to local
//!   identity
//! - [`entity::FederatedAuthState`] -short-lived authentication state records
//!   for federation flows
//! - [`entity::IdpRemoteIds`] - remote identifiers associated with an IdP
//!
//! # Registration
//!
//! The [`SqlBackend`] is registered with the
//! [`SqlDriver`](openstack_keystone_core::SqlDriver) plugin registry via
//! `inventory::submit!` so it is automatically discovered at runtime when the
//! SQL driver feature is enabled.
//!
//! # Authentication State
//!
//! Authentication state records are short-lived and carry an expiration
//! timestamp. The [`SqlBackend::cleanup`] method periodically removes expired
//! records to prevent unbounded growth.

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, Schema};
use sea_orm_migration::MigrationTrait;

use openstack_keystone_core::federation::{FederationProviderError, backend::FederationBackend};
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::{
    SqlDriver, SqlDriverRegistration, db::create_table, error::DatabaseError,
};
use openstack_keystone_core_types::federation::*;

mod auth_state;
pub mod entity;
mod identity_provider;
pub mod migration;

#[derive(Default)]
/// SQL backend for the federation provider.
///
/// Implements
/// [`FederationBackend`](openstack_keystone_core::federation::backend::FederationBackend)
/// for persistence and [`SqlDriver`](openstack_keystone_core::SqlDriver) for
/// schema setup and migrations.
pub struct SqlBackend {}

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

// Submit the plugin to the registry at compile-time
static PLUGIN: SqlBackend = SqlBackend {};
inventory::submit! {
    SqlDriverRegistration { driver: &PLUGIN }
}

#[async_trait]
impl FederationBackend for SqlBackend {
    /// Delete expired authentication state records.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn cleanup(&self, state: &ServiceState) -> Result<(), FederationProviderError> {
        Ok(auth_state::delete_expired(&state.db).await?)
    }

    /// Persist a new authentication state record.
    ///
    /// This is the initial step in a federation authentication flow. The record
    /// carries an expiration timestamp so it can be cleaned up by
    /// [`Self::cleanup`].
    ///
    /// # Arguments
    ///
    /// * `auth_state` - the authentication state to create.
    ///
    /// # Returns
    ///
    /// The created [`AuthState`].
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_auth_state(
        &self,
        state: &ServiceState,
        auth_state: AuthState,
    ) -> Result<AuthState, FederationProviderError> {
        Ok(auth_state::create(&state.db, auth_state).await?)
    }

    /// Create a new identity provider.
    ///
    /// # Arguments
    ///
    /// * `idp` - the identity provider details.
    ///
    /// # Returns
    ///
    /// The created [`IdentityProvider`].
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_identity_provider(
        &self,
        state: &ServiceState,
        idp: IdentityProviderCreate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        Ok(identity_provider::create(&state.db, idp).await?)
    }

    /// Delete the authentication state record identified by `id`.
    ///
    /// # Arguments
    ///
    /// * `id` - the auth state record ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        Ok(auth_state::delete(&state.db, id).await?)
    }

    /// Delete the identity provider identified by `id`.
    ///
    /// # Arguments
    ///
    /// * `id` - the identity provider ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), FederationProviderError> {
        Ok(identity_provider::delete(&state.db, id).await?)
    }

    /// Retrieve the authentication state record by ID.
    ///
    /// # Arguments
    ///
    /// * `id` - the auth state record ID.
    ///
    /// # Returns
    ///
    /// The [`AuthState`] if it exists, or `None` if the record has expired or
    /// was already consumed.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_auth_state<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<AuthState>, FederationProviderError> {
        Ok(auth_state::get(&state.db, id).await?)
    }

    /// Retrieve a single identity provider by ID.
    ///
    /// # Arguments
    ///
    /// * `id` - the identity provider ID.
    ///
    /// # Returns
    ///
    /// The [`IdentityProvider`] if it exists, or `None`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<IdentityProvider>, FederationProviderError> {
        Ok(identity_provider::get(&state.db, id).await?)
    }

    /// List identity providers matching the given filter parameters.
    ///
    /// # Arguments
    ///
    /// * `params` - name and description filters.
    ///
    /// # Returns
    ///
    /// A vector of matching [`IdentityProvider`]s.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_identity_providers(
        &self,
        state: &ServiceState,
        params: &IdentityProviderListParameters,
    ) -> Result<Vec<IdentityProvider>, FederationProviderError> {
        Ok(identity_provider::list(&state.db, params).await?)
    }

    /// Update an existing identity provider.
    ///
    /// # Arguments
    ///
    /// * `id` - the identity provider ID.
    /// * `idp` - the fields to update.
    ///
    /// # Returns
    ///
    /// The updated [`IdentityProvider`].
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_identity_provider<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        idp: IdentityProviderUpdate,
    ) -> Result<IdentityProvider, FederationProviderError> {
        Ok(identity_provider::update(&state.db, id, idp).await?)
    }
}

#[async_trait]
impl SqlDriver for SqlBackend {
    /// Create the federation-related database tables.
    ///
    /// Sets up the tables for identity providers, federation protocols,
    /// federated identity providers, IdP remote IDs, and federated auth state.
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(
            connection,
            schema,
            crate::entity::prelude::FederatedIdentityProvider,
        )
        .await?;
        create_table(connection, schema, crate::entity::prelude::IdentityProvider).await?;
        create_table(
            connection,
            schema,
            crate::entity::prelude::FederationProtocol,
        )
        .await?;
        create_table(connection, schema, crate::entity::prelude::IdpRemoteIds).await?;
        create_table(
            connection,
            schema,
            crate::entity::prelude::FederatedAuthState,
        )
        .await?;
        create_table(connection, schema, crate::entity::prelude::Mapping).await?;
        Ok(())
    }

    /// Return the ordered list of database migrations for this driver.
    fn migrations(&self) -> Vec<Box<dyn MigrationTrait>> {
        crate::migration::migrations()
    }
}

#[cfg(test)]
mod tests {}
