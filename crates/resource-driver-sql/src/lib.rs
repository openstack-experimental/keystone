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
//! # OpenStack Keystone SQL driver for the resource provider

use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, Schema, TransactionTrait};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core::projection_cache::ProjectionCache;
use openstack_keystone_core::resource::{ResourceProviderError, backend::ResourceBackend};
use openstack_keystone_core::table_watermark;
use openstack_keystone_core::{
    SqlDriver, SqlDriverRegistration, db::create_table, error::DatabaseError,
};
use openstack_keystone_core_types::freshness::Freshness;
use openstack_keystone_core_types::resource::*;

mod domain;
pub mod entity;
pub mod migration;
mod project;
mod project_option;
mod project_tag;
#[cfg(test)]
mod sqlite_tests;

/// Projections of the projects that readers tolerating some staleness may be
/// served from. Both depend on the `project` table only.
struct ProjectCaches {
    /// The domain of a project by project ID.
    domain_id: ProjectionCache<String>,
    /// The IDs of the parents of a project by project ID, closest first.
    parent_ids: ProjectionCache<Vec<String>>,
}

/// Entries per cache.
const CACHE_CAPACITY: usize = 10_000;

impl Default for ProjectCaches {
    fn default() -> Self {
        Self {
            domain_id: ProjectionCache::new(table_watermark::PROJECT_TABLES, CACHE_CAPACITY),
            parent_ids: ProjectionCache::new(table_watermark::PROJECT_TABLES, CACHE_CAPACITY),
        }
    }
}

impl ProjectCaches {
    /// Forget everything: this replica wrote to the project tree and must
    /// see the result immediately.
    fn invalidate(&self) {
        self.domain_id.invalidate();
        self.parent_ids.invalidate();
    }
}

#[derive(Default)]
pub struct SqlBackend {
    /// Per driver instance: it belongs to the connection it reads through.
    caches: LazyLock<ProjectCaches>,
}

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

// Submit the plugin to the registry at compile-time
static PLUGIN: SqlBackend = SqlBackend {
    caches: LazyLock::new(ProjectCaches::default),
};
inventory::submit! {
    SqlDriverRegistration { driver: &PLUGIN }
}
inventory::submit! {
    BackendRegistration::<dyn ResourceBackend> {
        name: "sql",
        selected: |_| true,
        build: |_cfg| Box::pin(async {
            Ok(Arc::new(SqlBackend::default()) as Arc<dyn ResourceBackend>)
        }),
    }
}

#[async_trait]
impl ResourceBackend for SqlBackend {
    /// Get `enabled` property of a domain.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `domain_id`: ID of the domain.
    ///
    /// # Returns
    /// A `bool` indicating if the domain is enabled.
    #[tracing::instrument(name = "driver.sql.resource.get_domain_enabled", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn get_domain_enabled<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<bool, ResourceProviderError> {
        Ok(domain::get_domain_enabled(&state.db.connection(), domain_id).await?)
    }

    /// Get the short representation of a domain by ID.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `domain_id`: ID of the domain.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `DomainRef` if found, or an
    /// `Error`.
    #[tracing::instrument(name = "driver.sql.resource.get_domain_ref", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn get_domain_ref<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<DomainRef>, ResourceProviderError> {
        Ok(domain::get_domain_ref_by_id(&state.db.connection(), domain_id).await?)
    }

    /// Create new domain.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `domain`: Domain creation parameters.
    ///
    /// # Returns
    /// The created `Domain`.
    #[tracing::instrument(name = "driver.sql.resource.create_domain", level = "debug", skip_all)]
    async fn create_domain(
        &self,
        state: &ServiceState,
        domain: DomainCreate,
    ) -> Result<Domain, ResourceProviderError> {
        let result = domain::create(&state.db.connection(), domain).await;
        self.caches.invalidate();
        Ok(result?)
    }

    /// Create new project.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project`: Project creation parameters.
    ///
    /// # Returns
    /// The created `Project`.
    #[tracing::instrument(name = "driver.sql.resource.create_project", level = "debug", skip_all)]
    async fn create_project(
        &self,
        state: &ServiceState,
        project: ProjectCreate,
    ) -> Result<Project, ResourceProviderError> {
        let txn = state
            .db
            .connection()
            .begin()
            .await
            .context("starting the project create transaction")?;
        let created = project::create(&txn, project).await?;
        let committed = txn
            .commit()
            .await
            .context("committing the project create transaction");
        self.caches.invalidate();
        committed?;
        Ok(created)
    }

    /// Update domain.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `domain_id`: ID of the domain to update.
    /// - `domain`: The fields to change.
    ///
    /// # Returns
    /// The updated `Domain`.
    #[tracing::instrument(name = "driver.sql.resource.update_domain", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn update_domain<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
        domain: DomainUpdate,
    ) -> Result<Domain, ResourceProviderError> {
        let result = domain::update(&state.db.connection(), domain_id, domain).await;
        self.caches.invalidate();
        Ok(result?)
    }

    /// Update a project.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project_id`: ID of the project to update.
    /// - `project`: The fields to change.
    ///
    /// # Returns
    /// The updated `Project`.
    #[tracing::instrument(name = "driver.sql.resource.update_project", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn update_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        project: ProjectUpdate,
    ) -> Result<Project, ResourceProviderError> {
        let txn = state
            .db
            .connection()
            .begin()
            .await
            .context("starting the project update transaction")?;
        let updated = project::update(&txn, project_id, project).await?;
        let committed = txn
            .commit()
            .await
            .context("committing the project update transaction");
        self.caches.invalidate();
        committed?;
        Ok(updated)
    }

    /// Delete domain by the ID.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `id`: ID of the domain to delete.
    #[tracing::instrument(name = "driver.sql.resource.delete_domain", level = "debug", skip_all, fields(domain_id = %id))]
    async fn delete_domain<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), ResourceProviderError> {
        let result = domain::delete(&state.db.connection(), id).await;
        self.caches.invalidate();
        Ok(result?)
    }

    /// Delete project by the ID.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `id`: ID of the project to delete.
    #[tracing::instrument(name = "driver.sql.resource.delete_project", level = "debug", skip_all, fields(project_id = %id))]
    async fn delete_project<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), ResourceProviderError> {
        let result = project::delete(&state.db.connection(), id).await;
        self.caches.invalidate();
        Ok(result?)
    }

    /// Get single domain by ID.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `domain_id`: ID of the domain.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Domain` if found, or an
    /// `Error`.
    #[tracing::instrument(name = "driver.sql.resource.get_domain", level = "debug", skip_all, fields(domain_id = %domain_id))]
    async fn get_domain<'a>(
        &self,
        state: &ServiceState,
        domain_id: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        Ok(domain::get_domain_by_id(&state.db.connection(), domain_id).await?)
    }

    /// Get single domain by Name.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `domain_name`: Name of the domain.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Domain` if found, or an
    /// `Error`.
    #[tracing::instrument(
        name = "driver.sql.resource.get_domain_by_name",
        level = "debug",
        skip_all
    )]
    async fn get_domain_by_name<'a>(
        &self,
        state: &ServiceState,
        domain_name: &'a str,
    ) -> Result<Option<Domain>, ResourceProviderError> {
        Ok(domain::get_domain_by_name(&state.db.connection(), domain_name).await?)
    }

    /// Get single project by ID.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project_id`: ID of the project.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Project` if found, or an
    /// `Error`.
    #[tracing::instrument(name = "driver.sql.resource.get_project", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn get_project<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        Ok(project::get_project(&state.db.connection(), project_id).await?)
    }

    /// Get single project by Name and Domain ID.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `name`: Name of the project.
    /// - `domain_id`: ID of the domain.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Project` if found, or an
    /// `Error`.
    #[tracing::instrument(name = "driver.sql.resource.get_project_by_name", level = "debug", skip_all, fields(name = %name, domain_id = %domain_id))]
    async fn get_project_by_name<'a>(
        &self,
        state: &ServiceState,
        name: &'a str,
        domain_id: &'a str,
    ) -> Result<Option<Project>, ResourceProviderError> {
        Ok(project::get_project_by_name(&state.db.connection(), name, domain_id).await?)
    }

    /// Get the ID of the domain a project belongs to.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the domain ID if the project
    /// exists, or an `Error`.
    #[tracing::instrument(name = "driver.sql.resource.get_project_domain_id", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn get_project_domain_id<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<String>, ResourceProviderError> {
        Ok(project::get_project_domain_id(&state.db.connection(), project_id).await?)
    }

    /// Get the ID of the domain a project belongs to, from the projection
    /// cache when `freshness` allows it. A missing project is never cached.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project_id`: The ID of the project.
    /// - `freshness`: How stale the result may be.
    #[tracing::instrument(name = "driver.sql.resource.get_project_domain_id_with_freshness", level = "debug", skip_all, fields(project_id = %project_id, freshness = ?freshness))]
    async fn get_project_domain_id_with_freshness<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        freshness: Freshness,
    ) -> Result<Option<String>, ResourceProviderError> {
        let watermarks = state.db.watermarks();
        let db = state.db.connection();
        self.caches
            .domain_id
            .get_or_load_some(&watermarks, project_id, freshness, || {
                project::get_project_domain_id(&db, project_id)
            })
            .await
    }

    /// Get the IDs of the project parents, from the projection cache when
    /// `freshness` allows it. A missing project is never cached.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project_id`: The ID of the project.
    /// - `freshness`: How stale the result may be.
    #[tracing::instrument(name = "driver.sql.resource.get_project_parent_ids_with_freshness", level = "debug", skip_all, fields(project_id = %project_id, freshness = ?freshness))]
    async fn get_project_parent_ids_with_freshness<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        freshness: Freshness,
    ) -> Result<Option<Vec<String>>, ResourceProviderError> {
        let watermarks = state.db.watermarks();
        let db = state.db.connection();
        self.caches
            .parent_ids
            .get_or_load_some(&watermarks, project_id, freshness, || {
                project::get_project_parent_ids(&db, project_id)
            })
            .await
    }

    /// Get the short representation of a project (no options and tags).
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project_id`: ID of the project.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `ProjectRef` if the project
    /// exists, or an `Error`.
    #[tracing::instrument(name = "driver.sql.resource.get_project_ref", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn get_project_ref<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<ProjectRef>, ResourceProviderError> {
        Ok(project::get_project_ref(&state.db.connection(), project_id).await?)
    }

    /// Get the IDs of the project parents.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the parent IDs, the closest
    /// first, if the project exists, or an `Error`.
    #[tracing::instrument(name = "driver.sql.resource.get_project_parent_ids", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn get_project_parent_ids<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Vec<String>>, ResourceProviderError> {
        Ok(project::get_project_parent_ids(&state.db.connection(), project_id).await?)
    }

    /// Get project parents.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project_id`: The ID of the project.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the `Vec<Project>` if found, or
    /// an `Error`.
    #[tracing::instrument(name = "driver.sql.resource.get_project_parents", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn get_project_parents<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError> {
        Ok(project::get_project_parents(&state.db.connection(), project_id).await?)
    }

    /// Get project subtree (all descendants).
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project_id`: ID of the project.
    ///
    /// # Returns
    /// A `Result` containing an `Option` with the descendants ordered breadth
    /// first if the project exists, or an `Error`.
    #[tracing::instrument(name = "driver.sql.resource.get_project_subtree", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn get_project_subtree<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Option<Vec<Project>>, ResourceProviderError> {
        Ok(project::get_project_subtree(&state.db.connection(), project_id).await?)
    }

    /// List the tags of a project.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project_id`: ID of the project.
    ///
    /// # Returns
    /// The sorted tags of the project.
    #[tracing::instrument(name = "driver.sql.resource.list_project_tags", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn list_project_tags<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
    ) -> Result<Vec<String>, ResourceProviderError> {
        let db = state.db.connection();
        project_tag::ensure_project_exists(&db, project_id).await?;
        project_tag::list_by_project_id(&db, project_id).await
    }

    /// Replace all tags of a project.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project_id`: ID of the project.
    /// - `tags`: The new set of tags.
    ///
    /// # Returns
    /// The resulting sorted tags.
    #[tracing::instrument(name = "driver.sql.resource.replace_project_tags", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn replace_project_tags<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        mut tags: Vec<String>,
    ) -> Result<Vec<String>, ResourceProviderError> {
        project_tag::ensure_project_exists(&state.db.connection(), project_id).await?;
        let txn = state
            .db
            .connection()
            .begin()
            .await
            .context("starting the project tags transaction")?;
        project_tag::replace(&txn, project_id, &tags).await?;
        txn.commit()
            .await
            .context("committing the project tags transaction")?;
        tags.sort();
        Ok(tags)
    }

    /// Add a single tag to a project.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project_id`: ID of the project.
    /// - `tag`: The tag to add.
    #[tracing::instrument(name = "driver.sql.resource.create_project_tag", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn create_project_tag<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        tag: &'a str,
    ) -> Result<(), ResourceProviderError> {
        let db = state.db.connection();
        project_tag::ensure_project_exists(&db, project_id).await?;
        let txn = db
            .begin()
            .await
            .context("starting the project tag transaction")?;
        project_tag::create(&txn, project_id, tag).await?;
        txn.commit()
            .await
            .context("committing the project tag transaction")?;
        Ok(())
    }

    /// Delete a single tag from a project.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `project_id`: ID of the project.
    /// - `tag`: The tag to delete.
    #[tracing::instrument(name = "driver.sql.resource.delete_project_tag", level = "debug", skip_all, fields(project_id = %project_id))]
    async fn delete_project_tag<'a>(
        &self,
        state: &ServiceState,
        project_id: &'a str,
        tag: &'a str,
    ) -> Result<(), ResourceProviderError> {
        let db = state.db.connection();
        project_tag::ensure_project_exists(&db, project_id).await?;
        project_tag::delete(&db, project_id, tag).await
    }

    /// List domains.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `params`: List parameters for domains.
    ///
    /// # Returns
    /// A `Vec<Domain>`.
    #[tracing::instrument(name = "driver.sql.resource.list_domains", level = "debug", skip_all, fields(params = ?params))]
    async fn list_domains(
        &self,
        state: &ServiceState,
        params: &DomainListParameters,
    ) -> Result<Vec<Domain>, ResourceProviderError> {
        Ok(domain::list(&state.db.connection(), params).await?)
    }

    /// List projects.
    ///
    /// # Parameters
    /// - `state`: Service state containing the database connection.
    /// - `params`: List parameters for projects.
    ///
    /// # Returns
    /// A `Vec<Project>`.
    #[tracing::instrument(name = "driver.sql.resource.list_projects", level = "debug", skip_all, fields(params = ?params))]
    async fn list_projects(
        &self,
        state: &ServiceState,
        params: &ProjectListParameters,
    ) -> Result<Vec<Project>, ResourceProviderError> {
        Ok(project::list(&state.db.connection(), params).await?)
    }
}

#[async_trait]
impl SqlDriver for SqlBackend {
    async fn setup(
        &self,
        connection: &DatabaseConnection,
        schema: &Schema,
    ) -> Result<(), DatabaseError> {
        create_table(connection, schema, crate::entity::prelude::Project).await?;
        create_table(connection, schema, crate::entity::prelude::ProjectOption).await?;
        create_table(connection, schema, crate::entity::prelude::ProjectTag).await?;

        if domain::get_domain_by_id(connection, domain::NULL_DOMAIN_ID)
            .await
            .map_err(|e| DatabaseError::Sql {
                message: e.to_string(),
                context: "checking for null domain during setup".to_string(),
            })?
            .is_none()
        {
            domain::create(
                connection,
                DomainCreate {
                    description: None,
                    extra: std::collections::HashMap::new(),
                    enabled: false,
                    id: Some(domain::NULL_DOMAIN_ID.into()),
                    name: domain::NULL_DOMAIN_ID.into(),
                    options: None,
                },
            )
            .await
            .map_err(|e| DatabaseError::Sql {
                message: e.to_string(),
                context: "creating null domain during setup".to_string(),
            })?;
        }
        table_watermark::install(connection, table_watermark::PROJECT_TABLES).await?;
        Ok(())
    }

    /// Return the ordered list of database migrations for this driver.
    fn migrations(&self) -> Vec<Box<dyn sea_orm_migration::MigrationTrait>> {
        crate::migration::migrations()
    }
}
