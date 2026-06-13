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
//! # Update Service

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::{Service, ServiceUpdate};

use crate::entity::{prelude::Service as DbService, service as db_service};

/// Updates an existing service.
///
/// Only the fields set in `service` are changed; the rest are left as-is.
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The ID of the service to update.
/// - `service`: The fields to change.
///
/// # Returns
/// A `Result` containing the updated `Service`, or an `Error` (including
/// `ServiceNotFound` if no service with that ID exists).
pub async fn update<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
    service: ServiceUpdate,
) -> Result<Service, CatalogProviderError> {
    let existing = DbService::find_by_id(id.as_ref())
        .one(db)
        .await
        .context("fetching service for update")?
        .ok_or_else(|| CatalogProviderError::ServiceNotFound(id.as_ref().to_string()))?;

    let mut update_model: db_service::ActiveModel = existing.into();

    if let Some(enabled) = service.enabled {
        update_model.enabled = Set(enabled);
    }
    if let Some(typ) = service.r#type {
        update_model.r#type = Set(Some(typ));
    }
    // The provider has already merged `extra`; the driver only persists it.
    if let Some(extra) = service.extra {
        update_model.extra = Set(Some(serde_json::to_string(&extra)?));
    }

    update_model
        .update(db)
        .await
        .context("updating service")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::super::tests::get_service_mock;
    use super::*;

    #[tokio::test]
    async fn test_update() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            // 1. fetch the existing service
            .append_query_results([vec![get_service_mock("1")]])
            // 2. the UPDATE returns the updated row
            .append_query_results([vec![get_service_mock("1")]])
            .into_connection();

        let req = ServiceUpdate {
            enabled: Some(false),
            ..Default::default()
        };

        let result = update(&db, "1", req).await;
        assert!(result.is_ok(), "update failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<db_service::Model>::new()])
            .into_connection();

        let result = update(&db, "missing", ServiceUpdate::default()).await;
        assert!(matches!(
            result,
            Err(CatalogProviderError::ServiceNotFound(_))
        ));
    }
}
