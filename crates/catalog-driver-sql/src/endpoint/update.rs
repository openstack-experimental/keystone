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
//! # Update Endpoint

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::db::merge_extra;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::{Endpoint, EndpointUpdate};

use crate::entity::{endpoint as db_endpoint, prelude::Endpoint as DbEndpoint};

/// Updates an existing endpoint.
///
/// Only the fields set in `endpoint` are changed; the rest are left as-is.
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The ID of the endpoint to update.
/// - `endpoint`: The fields to change.
///
/// # Returns
/// A `Result` containing the updated `Endpoint`, or an `Error` (including
/// `EndpointNotFound` if no endpoint with that ID exists).
pub async fn update<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
    endpoint: EndpointUpdate,
) -> Result<Endpoint, CatalogProviderError> {
    let existing = DbEndpoint::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("fetching endpoint for update")?
        .ok_or_else(|| CatalogProviderError::EndpointNotFound(id.as_ref().to_string()))?;

    let existing_extra = existing.extra.clone();
    let mut update_model: db_endpoint::ActiveModel = existing.into();

    if let Some(enabled) = endpoint.enabled {
        update_model.enabled = Set(enabled);
    }
    if let Some(interface) = endpoint.interface {
        update_model.interface = Set(interface);
    }
    if let Some(region_id) = endpoint.region_id {
        update_model.region_id = Set(Some(region_id));
    }
    if let Some(service_id) = endpoint.service_id {
        update_model.service_id = Set(service_id);
    }
    if let Some(url) = endpoint.url {
        update_model.url = Set(url);
    }
    if let Some(extra) = endpoint.extra {
        update_model.extra = Set(Some(merge_extra(existing_extra.as_deref(), &extra)?));
    }

    update_model
        .update(db)
        .await
        .context("updating endpoint")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::super::tests::get_endpoint_mock;
    use super::*;

    #[tokio::test]
    async fn test_update() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // 1. fetch the existing endpoint
            .append_query_results([vec![get_endpoint_mock("1")]])
            // 2. the UPDATE returns the updated row
            .append_query_results([vec![get_endpoint_mock("1")]])
            .into_connection();

        let req = EndpointUpdate {
            enabled: Some(false),
            ..Default::default()
        };

        let result = update(&db, "1", req).await;
        assert!(result.is_ok(), "update failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_endpoint::Model>::new()])
            .into_connection();

        let result = update(&db, "missing", EndpointUpdate::default()).await;
        assert!(matches!(
            result,
            Err(CatalogProviderError::EndpointNotFound(_))
        ));
    }
}
