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
//! # OpenStack Keystone SQL driver for the catalog provider

use async_trait::async_trait;
use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::{DatabaseConnection, Schema};

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::catalog::backend::CatalogBackend;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::{
    SqlDriver, SqlDriverRegistration, db::create_table, error::DatabaseError,
};
use openstack_keystone_core_types::catalog::*;

use crate::entity::{
    endpoint as db_endpoint,
    prelude::{Endpoint as DbEndpoint, Service as DbService},
    service as db_service,
};

mod endpoint;
pub mod entity;
mod service;

#[derive(Default)]
pub struct SqlBackend {}

// Submit the plugin to the registry at compile-time
static PLUGIN: SqlBackend = SqlBackend {};
inventory::submit! {
    SqlDriverRegistration { driver: &PLUGIN }
}

#[async_trait]
impl CatalogBackend for SqlBackend {
    /// List services.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `params`: The parameters for listing services.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Service`s, or a
    /// `CatalogProviderError`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_services(
        &self,
        state: &ServiceState,
        params: &ServiceListParameters,
    ) -> Result<Vec<Service>, CatalogProviderError> {
        Ok(service::list(&state.db, params).await?)
    }

    /// Get a single service by ID.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The ID of the service to retrieve.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Service` if found, or an
    /// `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_service<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Service>, CatalogProviderError> {
        Ok(service::get(&state.db, id).await?)
    }

    /// List endpoints.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `params`: The parameters for listing endpoints.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Endpoint`s, or a
    /// `CatalogProviderError`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_endpoints(
        &self,
        state: &ServiceState,
        params: &EndpointListParameters,
    ) -> Result<Vec<Endpoint>, CatalogProviderError> {
        Ok(endpoint::list(&state.db, params).await?)
    }

    /// Get a single endpoint by ID.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The ID of the endpoint to retrieve.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Endpoint` if found, or an
    /// `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_endpoint<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Endpoint>, CatalogProviderError> {
        Ok(endpoint::get(&state.db, id).await?)
    }

    /// Get the catalog (services with endpoints).
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `enabled`: Whether to return only enabled entries.
    ///
    /// # Returns
    /// A `Result` containing a vector of tuples of `Service` and its associated
    /// `Endpoint`s, or a `CatalogProviderError`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    /// Get the catalog.
    ///
    /// # Parameters
    /// - `db`: The database connection.
    /// - `enabled`: Whether to return only enabled entries.
    ///
    /// # Returns
    /// A `Result` containing a vector of tuples of `Service` and its associated
    /// `Endpoint`s, or a `CatalogProviderError`.
    async fn get_catalog(
        &self,
        state: &ServiceState,
        enabled: bool,
    ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError> {
        Ok(get_catalog(&state.db, enabled).await?)
    }
}

async fn get_catalog(
    db: &DatabaseConnection,
    enabled: bool,
) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError> {
    let db_entities: Vec<(db_service::Model, Vec<db_endpoint::Model>)> = DbService::find()
        .filter(db_service::Column::Enabled.eq(enabled))
        .find_with_related(DbEndpoint)
        .filter(db_endpoint::Column::Enabled.eq(enabled))
        .all(db)
        .await
        .context("fetching catalog")?;

    let mut res: Vec<(Service, Vec<Endpoint>)> = Vec::new();
    for (srv, db_endpoints) in db_entities.into_iter() {
        let service: Service = srv.try_into()?;
        let endpoints: Result<Vec<Endpoint>, _> = db_endpoints
            .into_iter()
            .map(TryInto::<Endpoint>::try_into)
            .collect();
        res.push((service, endpoints?));
    }
    Ok(res)
}

#[async_trait]
impl SqlDriver for SqlBackend {
    /// Sets up the database tables for the catalog.
    ///
    /// # Parameters
    /// - `connection`: The database connection.
    /// - `schema`: The database schema.
    ///
    /// # Returns
    /// A `Result` indicating success or a `DatabaseError`.
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(connection, schema, crate::entity::prelude::Region).await?;
        create_table(connection, schema, crate::entity::prelude::Service).await?;
        create_table(connection, schema, crate::entity::prelude::Endpoint).await?;
        create_table(connection, schema, crate::entity::prelude::EndpointGroup).await?;
        create_table(connection, schema, crate::entity::prelude::ProjectEndpoint).await?;
        create_table(
            connection,
            schema,
            crate::entity::prelude::ProjectEndpointGroup,
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};
    use serde_json::json;

    use super::*;
    use crate::endpoint::tests::get_endpoint_mock;
    use crate::service::tests::get_service_mock;

    #[tokio::test]
    async fn test_get_catalog() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                (get_service_mock("1"), get_endpoint_mock("1")),
                (get_service_mock("1"), get_endpoint_mock("2")),
            ]])
            .into_connection();
        assert_eq!(
            get_catalog(&db, false).await.unwrap(),
            vec![(
                Service {
                    id: "1".into(),
                    r#type: Some("type".into()),
                    enabled: true,
                    name: Some("srv".into()),
                    extra: Some(json!({"name": "srv"})),
                },
                vec![
                    Endpoint {
                        id: "1".into(),
                        interface: "public".into(),
                        service_id: "srv_id".into(),
                        region_id: Some("region".into()),
                        enabled: true,
                        url: "http://localhost".into(),
                        extra: None
                    },
                    Endpoint {
                        id: "2".into(),
                        interface: "public".into(),
                        service_id: "srv_id".into(),
                        region_id: Some("region".into()),
                        enabled: true,
                        url: "http://localhost".into(),
                        extra: None
                    }
                ]
            )]
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "service"."id" AS "A_id", "service"."type" AS "A_type", "service"."enabled" AS "A_enabled", "service"."extra" AS "A_extra", "endpoint"."id" AS "B_id", "endpoint"."legacy_endpoint_id" AS "B_legacy_endpoint_id", "endpoint"."interface" AS "B_interface", "endpoint"."service_id" AS "B_service_id", "endpoint"."url" AS "B_url", "endpoint"."extra" AS "B_extra", "endpoint"."enabled" AS "B_enabled", "endpoint"."region_id" AS "B_region_id" FROM "service" LEFT JOIN "endpoint" ON "service"."id" = "endpoint"."service_id" WHERE "service"."enabled" = $1 AND "endpoint"."enabled" = $2 ORDER BY "service"."id" ASC"#,
                [false.into(), false.into()]
            ),]
        );
    }
}
