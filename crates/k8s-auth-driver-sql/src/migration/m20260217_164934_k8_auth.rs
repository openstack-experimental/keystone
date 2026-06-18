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

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(KubernetesAuthInstance::Table)
                    .if_not_exists()
                    .col(string_len(KubernetesAuthInstance::Id, 64).primary_key())
                    .col(string_len(KubernetesAuthInstance::DomainId, 64))
                    .col(string_len_null(KubernetesAuthInstance::Name, 255))
                    .col(string_len(KubernetesAuthInstance::Host, 128))
                    .col(boolean(KubernetesAuthInstance::Enabled))
                    .col(text_null(KubernetesAuthInstance::CaCert))
                    .col(boolean(KubernetesAuthInstance::DisableLocalCaJwt))
                    .index(
                        Index::create()
                            .unique()
                            .nulls_not_distinct()
                            .name("idx-k8auth-provider-domain-name")
                            .col(KubernetesAuthInstance::DomainId)
                            .col(KubernetesAuthInstance::Name),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(KubernetesAuthInstance::Table)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum KubernetesAuthInstance {
    Table,
    Id,
    DomainId,
    Name,
    Enabled,
    Host,
    CaCert,
    DisableLocalCaJwt,
}
