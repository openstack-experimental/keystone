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
//! OpenStack Keystone SQL driver for the ID Mapping provider
use async_trait::async_trait;

use sea_orm::{DatabaseConnection, Schema};

use openstack_keystone_core::identity_mapping::IdentityMappingProviderError;
use openstack_keystone_core::identity_mapping::backend::IdentityMappingBackend;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::{
    SqlDriver, SqlDriverRegistration, db::create_table, error::DatabaseError,
};
use openstack_keystone_core_types::identity_mapping::*;

pub mod entity;
mod id_mapping;

#[derive(Default)]
pub struct SqlBackend {}

// Submit the plugin to the registry at compile-time
static PLUGIN: SqlBackend = SqlBackend {};
inventory::submit! {
    SqlDriverRegistration { driver: &PLUGIN }
}

#[async_trait]
impl IdentityMappingBackend for SqlBackend {
    /// Get the `IdMapping` by the local data.
    async fn get_by_local_id<'a>(
        &self,
        state: &ServiceState,
        local_id: &'a str,
        domain_id: &'a str,
        entity_type: IdMappingEntityType,
    ) -> Result<Option<IdMapping>, IdentityMappingProviderError> {
        Ok(id_mapping::get_by_local_id(&state.db, local_id, domain_id, entity_type).await?)
    }

    /// Get the IdMapping by the public_id.
    async fn get_by_public_id<'a>(
        &self,
        state: &ServiceState,
        public_id: &'a str,
    ) -> Result<Option<IdMapping>, IdentityMappingProviderError> {
        Ok(id_mapping::get_by_public_id(&state.db, public_id).await?)
    }
}

#[async_trait]
impl SqlDriver for SqlBackend {
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(connection, schema, crate::entity::prelude::IdMapping).await?;
        Ok(())
    }
}
