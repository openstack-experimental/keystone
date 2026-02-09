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
use sea_orm_migration::{prelude::*, schema::*};

use crate::db::entity::prelude::{FederatedMapping, Project, Role, User};
use crate::db::entity::{project, role, user};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(TokenRestriction::Table)
                    .if_not_exists()
                    .col(string_len(TokenRestriction::Id, 64).primary_key())
                    .col(string_len(TokenRestriction::DomainId, 64))
                    .col(string_len_null(TokenRestriction::UserId, 64))
                    .col(boolean(TokenRestriction::AllowRenew))
                    .col(boolean(TokenRestriction::AllowRescope))
                    .col(string_len_null(TokenRestriction::ProjectId, 64))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-token-restriction-domain")
                            .from(TokenRestriction::Table, TokenRestriction::DomainId)
                            .to(Project, project::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-token-restriction-user")
                            .from(TokenRestriction::Table, TokenRestriction::UserId)
                            .to(User, user::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-token-restriction-project")
                            .from(TokenRestriction::Table, TokenRestriction::ProjectId)
                            .to(Project, project::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(TokenRestrictionRoleAssociation::Table)
                    .if_not_exists()
                    .col(string_len(
                        TokenRestrictionRoleAssociation::RestrictionId,
                        64,
                    ))
                    .col(string_len(TokenRestrictionRoleAssociation::RoleId, 64))
                    .primary_key(
                        Index::create()
                            .name("fk-token-restriction-role-association-pk")
                            .col(TokenRestrictionRoleAssociation::RestrictionId)
                            .col(TokenRestrictionRoleAssociation::RoleId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-token-restriction-role-association-restriction")
                            .from(
                                TokenRestrictionRoleAssociation::Table,
                                TokenRestrictionRoleAssociation::RestrictionId,
                            )
                            .to(TokenRestriction::Table, TokenRestriction::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-token-restriction-role-association-role")
                            .from(
                                TokenRestrictionRoleAssociation::Table,
                                TokenRestrictionRoleAssociation::RoleId,
                            )
                            .to(Role, role::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(FederatedMapping)
                    .add_column(ColumnDef::new("token_restriction_id").string_len(64))
                    .drop_column("token_user_id")
                    .drop_column("token_role_ids")
                    .add_foreign_key(
                        &TableForeignKey::new()
                            .name("fk-federated-mapping-token-restriction")
                            .from_tbl(FederatedMapping)
                            .from_col("token_restriction_id")
                            .to_tbl(TokenRestriction::Table)
                            .to_col(TokenRestriction::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(FederatedMapping)
                    .drop_column("token_restriction_id")
                    .add_column(ColumnDef::new("token_restriction_id").string_len(64))
                    .add_column(ColumnDef::new("token_role_ids").string_len(128))
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(TokenRestrictionRoleAssociation::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(TokenRestriction::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum TokenRestriction {
    Table,
    Id,
    DomainId,
    UserId,
    AllowRenew,
    AllowRescope,
    ProjectId,
}

#[derive(DeriveIden)]
enum TokenRestrictionRoleAssociation {
    Table,
    RestrictionId,
    RoleId,
}
