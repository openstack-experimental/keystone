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

use crate::db::entity::prelude::User;
use crate::db::entity::user;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(WebauthnCredential::Table)
                    .if_not_exists()
                    .col(pk_auto(WebauthnCredential::Id))
                    .col(string_len(WebauthnCredential::UserId, 64))
                    .col(string_len(WebauthnCredential::CredentialId, 1024))
                    .col(string_len_null(WebauthnCredential::Description, 64))
                    .col(text(WebauthnCredential::Passkey))
                    .col(unsigned(WebauthnCredential::Counter))
                    .col(string_len(WebauthnCredential::Type, 25))
                    .col(string_len_null(WebauthnCredential::Aaguid, 36))
                    .col(date_time(WebauthnCredential::CreatedAt))
                    .col(date_time_null(WebauthnCredential::LastUsedAt))
                    .col(date_time_null(WebauthnCredential::LastUpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-user-passkey-credential")
                            .from(WebauthnCredential::Table, WebauthnCredential::UserId)
                            .to(User, user::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(WebauthnState::Table)
                    .if_not_exists()
                    .col(string_len(WebauthnCredential::UserId, 64))
                    .col(text(WebauthnState::State))
                    .col(string_len(WebauthnState::Type, 10))
                    .col(date_time(WebauthnState::CreatedAt))
                    .primary_key(Index::create().col(WebauthnState::UserId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-user-passkey-state")
                            .from(WebauthnState::Table, WebauthnState::UserId)
                            .to(User, user::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(WebauthnCredential::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(WebauthnState::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum WebauthnCredential {
    Table,
    Id,
    UserId,
    CredentialId,
    Description,
    Passkey,
    Counter,
    Type,
    Aaguid,
    CreatedAt,
    LastUsedAt,
    LastUpdatedAt,
}

#[derive(DeriveIden)]
enum WebauthnState {
    Table,
    UserId,
    State,
    CreatedAt,
    Type,
}
