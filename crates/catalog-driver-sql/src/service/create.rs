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

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::{Service, ServiceCreate};

use crate::entity::service as db_service;

/// Creates a new service.
///
/// # Parameters
/// - `db`: The database connection.
/// - `service`: The service creation parameters.
///
/// # Returns
/// A `Result` containing the created `Service`, or an `Error`.
pub async fn create(
    db: &DatabaseConnection,
    service: ServiceCreate,
) -> Result<Service, CatalogProviderError> {
    TryInto::<db_service::ActiveModel>::try_into(service)?
        .insert(db)
        .await
        .context("creating service")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::*;

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_service::Model {
                id: "svc-1".into(),
                r#type: Some("compute".into()),
                enabled: true,
                extra: Some(r#"{"name":"nova"}"#.into()),
            }]])
            .into_connection();

        let service_create = ServiceCreate {
            enabled: true,
            extra: HashMap::new(),
            id: Some("svc-1".to_string()),
            r#type: Some("compute".to_string()),
        };

        let created = create(&db, service_create).await.unwrap();

        assert_eq!(created.id, "svc-1");
        // `name` is read back out of the `extra` blob.
        assert_eq!(created.name().as_deref(), Some("nova"));
        assert_eq!(created.r#type.as_deref(), Some("compute"));
        assert!(created.enabled);
    }
}
