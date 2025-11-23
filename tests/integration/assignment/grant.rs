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

use eyre::Report;
use sea_orm::{DatabaseBackend, DbConn, query::*, schema::Schema, sea_query::*};

use openstack_keystone::db::entity::prelude::*;

mod list;

async fn setup_schema(db: &DbConn) -> Result<(), Report> {
    // TODO: with sea-orm 2.0 it can be improved
    //db.get_schema_registry("crate::db::entity::*").sync(db).await?;
    // Setup Schema helper
    let schema = Schema::new(DatabaseBackend::Sqlite);

    // Derive from Entity
    let stmts: Vec<TableCreateStatement> = vec![
        schema.create_table_from_entity(Assignment),
        schema.create_table_from_entity(Group),
        schema.create_table_from_entity(ImpliedRole),
        schema.create_table_from_entity(Project),
        schema.create_table_from_entity(Role),
        schema.create_table_from_entity(SystemAssignment),
        schema.create_table_from_entity(User),
        schema.create_table_from_entity(UserGroupMembership),
    ];

    // Execute create table statement
    for stmt in stmts.iter() {
        db.execute(db.get_database_backend().build(stmt)).await?;
    }

    Ok(())
}
