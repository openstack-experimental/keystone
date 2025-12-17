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
//

use eyre::{Result, WrapErr};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbConn, EntityTrait, entity::*,
    schema::Schema, sea_query::*,
};
use uuid::Uuid;

use openstack_keystone::db::entity::prelude::*;
use openstack_keystone::db::entity::{local_user, project, role, user};

/// Create table with the related types and indexes (when known)
async fn create_table<C, E>(conn: &C, schema: &Schema, entity: E) -> Result<()>
where
    C: ConnectionTrait,
    E: EntityTrait,
{
    // Create types before the table
    for ttype in schema.create_enum_from_entity(entity) {
        conn.execute(conn.get_database_backend().build(&ttype))
            .await?;
    }
    // Create the table
    conn.execute(
        conn.get_database_backend()
            .build(&schema.create_table_from_entity(entity)),
    )
    .await?;
    // Create related indexes
    for tidx in schema.create_index_from_entity(entity) {
        conn.execute(conn.get_database_backend().build(&tidx))
            .await?;
    }
    Ok(())
}

async fn create_index<C>(conn: &C, index: IndexCreateStatement) -> Result<()>
where
    C: ConnectionTrait,
{
    conn.execute(conn.get_database_backend().build(&index))
        .await?;
    Ok(())
}

/// Setup the database schema.
///
/// Create tables in the order of the foreign references with indexes and types.
pub async fn setup_schema(db: &DbConn) -> Result<()> {
    // TODO: with sea-orm 2.0 it can be improved
    //db.get_schema_registry("crate::db::entity::*").sync(db).await?;
    // Setup Schema helper
    let schema = Schema::new(db.get_database_backend());

    create_table(db, &schema, Project).await?;
    create_index(
        db,
        Index::create()
            .name("ixu_project_name_domain_id")
            .table(Project)
            .col(project::Column::Name)
            .col(project::Column::DomainId)
            .unique()
            .to_owned(),
    )
    .await?;
    create_table(db, &schema, User).await?;
    create_index(
        db,
        Index::create()
            .name("ixu_user_id_domain_id")
            .table(User)
            .col(user::Column::Id)
            .col(user::Column::DomainId)
            .unique()
            .to_owned(),
    )
    .await?;
    create_table(db, &schema, LocalUser).await?;
    create_index(
        db,
        Index::create()
            .name("local_user_domain_id_name")
            .table(LocalUser)
            .col(local_user::Column::Name)
            .col(local_user::Column::DomainId)
            .unique()
            .to_owned(),
    )
    .await?;
    create_table(db, &schema, Password).await?;
    create_table(db, &schema, UserOption).await?;
    create_table(db, &schema, NonlocalUser).await?;
    create_table(db, &schema, IdentityProvider).await?;
    create_table(db, &schema, FederationProtocol).await?;
    create_table(db, &schema, FederatedUser).await?;
    create_table(db, &schema, Group).await?;
    create_table(db, &schema, UserGroupMembership).await?;
    create_table(db, &schema, ExpiringUserGroupMembership).await?;

    create_table(db, &schema, Role).await?;
    create_table(db, &schema, ImpliedRole).await?;
    create_table(db, &schema, Assignment).await?;
    create_table(db, &schema, RevocationEvent).await?;

    create_table(db, &schema, AccessRule).await?;
    create_table(db, &schema, ApplicationCredential).await?;
    create_table(db, &schema, ApplicationCredentialRole).await?;
    create_table(db, &schema, ApplicationCredentialAccessRule).await?;

    Ok(())
}

pub async fn bootstrap(db: &DbConn) -> Result<()> {
    // Domain/project data
    Project::insert_many([project::ActiveModel {
        is_domain: Set(true),
        id: Set("<<keystone.domain.root>>".into()),
        name: Set("<<keystone.domain.root>>".into()),
        extra: NotSet,
        description: NotSet,
        enabled: Set(Some(true)),
        domain_id: Set("<<keystone.domain.root>>".into()),
        parent_id: NotSet,
    }])
    .exec(db)
    .await?;

    // Roles
    Role::insert_many([
        role::ActiveModel {
            id: Set("role_a".into()),
            name: Set("role_a".into()),
            extra: NotSet,
            description: NotSet,
            domain_id: Set("domain_a".into()),
        },
        role::ActiveModel {
            id: Set("role_b".into()),
            name: Set("role_b".into()),
            extra: NotSet,
            description: NotSet,
            domain_id: Set("domain_a".into()),
        },
    ])
    .exec(db)
    .await?;

    Ok(())
}

/// Prepare the isolated Database
///
/// Based on the `DATABASE_URL` environment variable prepare the database for the tests:
///
/// - `postgres` - create a unique schema
/// - `mysql` - create a unique database on the instance
/// - other - use whatever passed.
///
/// By default (when `DATABASE_URL` var is unset) use inmemory sqlite.
pub async fn get_isolated_database() -> Result<DatabaseConnection> {
    let db_conn = std::env::var("DATABASE_URL").unwrap_or("sqlite::memory:".to_string());
    let opts: ConnectOptions = ConnectOptions::new(&db_conn).sqlx_logging(false).to_owned();
    let root_db = Database::connect(opts)
        .await
        .wrap_err_with(|| format!("Failed to connect to database at {}", db_conn.clone()))?;
    let isolated_db_url = if db_conn.starts_with("postgres") {
        // Generate a unique schema name
        let schema_name = format!("test_schema_{}", Uuid::new_v4().simple());

        // Create the schema using a raw SQL driver (sqlx)
        root_db
            .execute_unprepared(&format!("CREATE SCHEMA \"{}\"", schema_name))
            .await
            .expect("Failed to create schema");

        // Create a new connection string that targets this schema specifically
        // Postgres uses 'search_path' to resolve table names
        if db_conn.contains('?') {
            format!("{}&options=-c%20search_path%3D{}", db_conn, schema_name)
        } else {
            format!("{}?options=-c%20search_path%3D{}", db_conn, schema_name)
        }
    } else if db_conn.starts_with("mysql") {
        // Generate a unique database name
        let db_name = format!("test_db_{}", Uuid::new_v4().simple());

        // Create the database
        // MySQL uses backticks for identifiers
        root_db
            .execute_unprepared(&format!("CREATE DATABASE `{}`", db_name))
            .await
            .expect("Failed to create database");

        // Build the connection string for the specific test database
        // Assuming base_url is "mysql://user:pass@localhost:3306"
        format!("{}/{}", db_conn.trim_end_matches('/'), db_name)
    } else {
        // Just use whichever URL has been passed
        db_conn
    };
    let opts = ConnectOptions::new(&isolated_db_url)
        .sqlx_logging(false)
        .to_owned();
    let db = Database::connect(opts).await.wrap_err_with(|| {
        format!(
            "Failed to connect to database at {}",
            isolated_db_url.clone()
        )
    })?;
    setup_schema(&db).await?;

    Ok(db)
}
