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

use eyre::Report;
use sea_orm::{DatabaseBackend, DbConn, entity::*, query::*, schema::Schema, sea_query::*};

use openstack_keystone::db::entity::prelude::*;
use openstack_keystone::db::entity::{project, role, user};

pub async fn setup_schema(db: &DbConn) -> Result<(), Report> {
    // TODO: with sea-orm 2.0 it can be improved
    //db.get_schema_registry("crate::db::entity::*").sync(db).await?;
    // Setup Schema helper
    let schema = Schema::new(DatabaseBackend::Sqlite);

    // Derive from Entity
    let stmts: Vec<TableCreateStatement> = vec![
        schema.create_table_from_entity(AccessRule),
        schema.create_table_from_entity(ApplicationCredential),
        schema.create_table_from_entity(ApplicationCredentialRole),
        schema.create_table_from_entity(ApplicationCredentialAccessRule),
        schema.create_table_from_entity(Assignment),
        schema.create_table_from_entity(Group),
        schema.create_table_from_entity(ExpiringUserGroupMembership),
        schema.create_table_from_entity(FederatedUser),
        schema.create_table_from_entity(ImpliedRole),
        schema.create_table_from_entity(LocalUser),
        schema.create_table_from_entity(NonlocalUser),
        schema.create_table_from_entity(Password),
        schema.create_table_from_entity(Project),
        schema.create_table_from_entity(RevocationEvent),
        schema.create_table_from_entity(Role),
        schema.create_table_from_entity(User),
        schema.create_table_from_entity(UserGroupMembership),
        schema.create_table_from_entity(UserOption),
    ];

    // Execute create table statement
    for stmt in stmts.iter() {
        db.execute(db.get_database_backend().build(stmt)).await?;
    }

    let idxs: Vec<IndexCreateStatement> = vec![
        Index::create()
            .name("ixu_project_name_domain_id")
            .table(Project)
            .col(project::Column::Name)
            .col(project::Column::DomainId)
            .unique()
            .to_owned(),
        Index::create()
            .name("ixu_user_id_domain_id")
            .table(User)
            .col(user::Column::Id)
            .col(user::Column::DomainId)
            .unique()
            .to_owned(),
    ];

    // Execute create index statement
    for stmt in idxs.iter() {
        db.execute(db.get_database_backend().build(stmt)).await?;
    }

    Ok(())
}

pub async fn bootstrap(db: &DbConn) -> Result<(), Report> {
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
