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

use crate::db::entity::prelude::{Project, TokenRestriction};
use crate::db::entity::{project, token_restriction};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(KubernetesAuth::Table)
                    .if_not_exists()
                    .col(string_len(KubernetesAuth::Id, 64).primary_key())
                    .col(string_len(KubernetesAuth::DomainId, 64))
                    .col(string_len_null(KubernetesAuth::Name, 255))
                    .col(string_len(KubernetesAuth::Host, 128))
                    .col(boolean(KubernetesAuth::Enabled))
                    .col(text_null(KubernetesAuth::CaCert))
                    .col(boolean(KubernetesAuth::DisableLocalCaJwt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-k8auth-domain")
                            .from(KubernetesAuth::Table, KubernetesAuth::DomainId)
                            .to(Project, project::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .index(
                        Index::create()
                            .unique()
                            .nulls_not_distinct()
                            .name("idx-k8auth-domain-name")
                            .col(KubernetesAuth::DomainId)
                            .col(KubernetesAuth::Name),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(KubernetesAuthRole::Table)
                    .if_not_exists()
                    .col(string_len(KubernetesAuthRole::Id, 64).primary_key())
                    .col(string_len(KubernetesAuthRole::DomainId, 64))
                    .col(string_len(KubernetesAuthRole::AuthConfigurationId, 64))
                    .col(string_len(KubernetesAuthRole::Name, 255))
                    .col(boolean(KubernetesAuthRole::Enabled))
                    .col(text(KubernetesAuthRole::BoundServiceAccountNames))
                    .col(text(KubernetesAuthRole::BoundServiceAccountNamespaces))
                    .col(string_len_null(KubernetesAuthRole::BoundAudience, 128))
                    .col(string_len(KubernetesAuthRole::TokenRestrictionId, 64))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-k8role-domain")
                            .from(KubernetesAuthRole::Table, KubernetesAuthRole::DomainId)
                            .to(Project, project::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-k8role-k8")
                            .from(
                                KubernetesAuthRole::Table,
                                KubernetesAuthRole::AuthConfigurationId,
                            )
                            .to(KubernetesAuth::Table, KubernetesAuth::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-k8role-token-restriction")
                            .from(
                                KubernetesAuthRole::Table,
                                KubernetesAuthRole::TokenRestrictionId,
                            )
                            .to(TokenRestriction, token_restriction::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .index(
                        Index::create()
                            .unique()
                            .nulls_not_distinct()
                            .name("idx-k8role-domain-name")
                            .col(KubernetesAuth::DomainId)
                            .col(KubernetesAuth::Name),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(KubernetesAuthRole::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(KubernetesAuth::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum KubernetesAuth {
    Table,
    Id,
    DomainId,
    Name,
    Enabled,
    Host,
    CaCert,
    DisableLocalCaJwt,
}

#[derive(DeriveIden)]
enum KubernetesAuthRole {
    Table,
    Id,
    DomainId,
    AuthConfigurationId,
    Name,
    Enabled,
    BoundServiceAccountNames,
    BoundServiceAccountNamespaces,
    BoundAudience,
    TokenRestrictionId,
}
