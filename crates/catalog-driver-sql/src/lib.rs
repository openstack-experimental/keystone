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
mod endpoint_group;
pub mod entity;
mod project_endpoint;
mod project_endpoint_group;
mod region;
mod service;

#[derive(Default)]
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
impl CatalogBackend for SqlBackend {
    /// Associate an endpoint with a project.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn add_endpoint_to_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        endpoint_id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        Ok(project_endpoint::add(&state.db, project_id, endpoint_id).await?)
    }

    /// Associate an endpoint group with a project.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn add_endpoint_group_to_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        endpoint_group_id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        Ok(project_endpoint_group::add(&state.db, project_id, endpoint_group_id).await?)
    }

    /// Check whether an endpoint is associated with a project.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn check_endpoint_in_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        endpoint_id: &'a str,
    ) -> Result<bool, CatalogProviderError> {
        Ok(project_endpoint::check(&state.db, project_id, endpoint_id).await?)
    }

    /// Check whether an endpoint group is associated with a project.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn check_endpoint_group_in_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        endpoint_group_id: &'a str,
    ) -> Result<bool, CatalogProviderError> {
        Ok(project_endpoint_group::check(&state.db, project_id, endpoint_group_id).await?)
    }

    /// Create a new endpoint.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `endpoint_data`: The endpoint creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Endpoint`, or a
    /// `CatalogProviderError`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_endpoint(
        &self,
        state: &ServiceState,
        endpoint_data: EndpointCreate,
    ) -> Result<Endpoint, CatalogProviderError> {
        Ok(endpoint::create(&state.db, endpoint_data).await?)
    }

    /// Create a new endpoint group.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_endpoint_group(
        &self,
        state: &ServiceState,
        endpoint_group: EndpointGroupCreate,
    ) -> Result<EndpointGroup, CatalogProviderError> {
        Ok(endpoint_group::create(&state.db, endpoint_group).await?)
    }

    /// Create a new region.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `region_data`: The region creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Region`, or a `CatalogProviderError`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_region(
        &self,
        state: &ServiceState,
        region_data: RegionCreate,
    ) -> Result<Region, CatalogProviderError> {
        Ok(region::create(&state.db, region_data).await?)
    }

    /// Create a new service.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `service_data`: The service creation parameters.
    ///
    /// # Returns
    /// A `Result` containing the created `Service`, or a
    /// `CatalogProviderError`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_service(
        &self,
        state: &ServiceState,
        service_data: ServiceCreate,
    ) -> Result<Service, CatalogProviderError> {
        Ok(service::create(&state.db, service_data).await?)
    }

    /// Delete an endpoint by ID.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The ID of the endpoint to delete.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_endpoint<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        Ok(endpoint::delete(&state.db, id).await?)
    }

    /// Delete an endpoint group by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_endpoint_group<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        Ok(endpoint_group::delete(&state.db, id).await?)
    }

    /// Delete a region by ID.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The ID of the region to delete.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_region<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        Ok(region::delete(&state.db, id).await?)
    }

    /// Delete a service by ID.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The ID of the service to delete.
    ///
    /// # Returns
    /// A `Result` indicating success or a `CatalogProviderError`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_service<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        Ok(service::delete(&state.db, id).await?)
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
    async fn get_catalog(
        &self,
        state: &ServiceState,
        enabled: bool,
    ) -> Result<Vec<(Service, Vec<Endpoint>)>, CatalogProviderError> {
        Ok(get_catalog(&state.db, enabled).await?)
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

    /// Get a single endpoint group by ID.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_endpoint_group<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<EndpointGroup>, CatalogProviderError> {
        Ok(endpoint_group::get(&state.db, id).await?)
    }

    /// Get a single region by ID.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The ID of the region to retrieve.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Region` if found, or an
    /// `Error`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_region<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<Region>, CatalogProviderError> {
        Ok(region::get(&state.db, id).await?)
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

    /// List endpoint groups.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_endpoint_groups(
        &self,
        state: &ServiceState,
        params: &EndpointGroupListParameters,
    ) -> Result<Vec<EndpointGroup>, CatalogProviderError> {
        Ok(endpoint_group::list(&state.db, params).await?)
    }

    /// List the endpoints associated with a project.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_project_endpoints<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Vec<Endpoint>, CatalogProviderError> {
        Ok(project_endpoint::list_endpoints(&state.db, project_id).await?)
    }

    /// List the endpoint groups associated with a project.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_project_endpoint_groups<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Vec<EndpointGroup>, CatalogProviderError> {
        Ok(project_endpoint_group::list_endpoint_groups(&state.db, project_id).await?)
    }

    /// List regions.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `params`: The parameters for listing regions.
    ///
    /// # Returns
    /// A `Result` containing a vector of `Region`s, or a
    /// `CatalogProviderError`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_regions(
        &self,
        state: &ServiceState,
        params: &RegionListParameters,
    ) -> Result<Vec<Region>, CatalogProviderError> {
        Ok(region::list(&state.db, params).await?)
    }

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

    /// Update an existing endpoint.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The ID of the endpoint to update.
    /// - `endpoint_data`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `Endpoint`, or a
    /// `CatalogProviderError`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    /// Remove the association between an endpoint and a project.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn remove_endpoint_from_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        endpoint_id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        Ok(project_endpoint::remove(&state.db, project_id, endpoint_id).await?)
    }

    /// Remove the association between an endpoint group and a project.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn remove_endpoint_group_from_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        endpoint_group_id: &'a str,
    ) -> Result<(), CatalogProviderError> {
        Ok(project_endpoint_group::remove(&state.db, project_id, endpoint_group_id).await?)
    }

    /// Update an existing endpoint.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_endpoint<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        endpoint_data: EndpointUpdate,
    ) -> Result<Endpoint, CatalogProviderError> {
        Ok(endpoint::update(&state.db, id, endpoint_data).await?)
    }

    /// Update an existing endpoint group.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_endpoint_group<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        endpoint_group: EndpointGroupUpdate,
    ) -> Result<EndpointGroup, CatalogProviderError> {
        Ok(endpoint_group::update(&state.db, id, endpoint_group).await?)
    }

    /// Update an existing region.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The ID of the region to update.
    /// - `region_data`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `Region`, or a `CatalogProviderError`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_region<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        region_data: RegionUpdate,
    ) -> Result<Region, CatalogProviderError> {
        Ok(region::update(&state.db, id, region_data).await?)
    }

    /// Update an existing service.
    ///
    /// # Parameters
    /// - `state`: The service state containing the database connection.
    /// - `id`: The ID of the service to update.
    /// - `service_data`: The fields to change.
    ///
    /// # Returns
    /// A `Result` containing the updated `Service`, or a
    /// `CatalogProviderError`.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn update_service<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        service_data: ServiceUpdate,
    ) -> Result<Service, CatalogProviderError> {
        Ok(service::update(&state.db, id, service_data).await?)
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
                    extra: [("name".to_string(), json!("srv"))].into(),
                },
                vec![
                    Endpoint {
                        id: "1".into(),
                        interface: "public".into(),
                        service_id: "srv_id".into(),
                        region_id: Some("region".into()),
                        enabled: true,
                        url: "http://localhost".into(),
                        extra: Default::default()
                    },
                    Endpoint {
                        id: "2".into(),
                        interface: "public".into(),
                        service_id: "srv_id".into(),
                        region_id: Some("region".into()),
                        enabled: true,
                        url: "http://localhost".into(),
                        extra: Default::default()
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
