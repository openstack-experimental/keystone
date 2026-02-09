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
#![allow(clippy::enum_variant_names)]
use sea_orm_migration::{
    prelude::{extension::postgres::Type, *},
    schema::*,
};

use crate::db::entity::prelude::Project;
use crate::db::entity::project;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db_backend = manager.get_database_backend();
        manager
            .create_table(
                Table::create()
                    .table(FederatedIdentityProvider::Table)
                    .if_not_exists()
                    .col(string_len(FederatedIdentityProvider::Id, 64).primary_key())
                    .col(string_len(FederatedIdentityProvider::Name, 255))
                    .col(string_len_null(FederatedIdentityProvider::DomainId, 64))
                    .col(boolean(FederatedIdentityProvider::Enabled))
                    .col(string_len_null(
                        FederatedIdentityProvider::OidcDiscoveryUrl,
                        255,
                    ))
                    .col(string_len_null(
                        FederatedIdentityProvider::OidcClientId,
                        255,
                    ))
                    .col(string_len_null(
                        FederatedIdentityProvider::OidcClientSecret,
                        255,
                    ))
                    .col(string_len_null(
                        FederatedIdentityProvider::OidcResponseMode,
                        64,
                    ))
                    .col(string_len_null(
                        FederatedIdentityProvider::OidcResponseTypes,
                        255,
                    ))
                    .col(text_null(FederatedIdentityProvider::JwksUrl))
                    .col(text_null(FederatedIdentityProvider::JwtValidationPubkeys))
                    .col(string_len_null(FederatedIdentityProvider::BoundIssuer, 255))
                    .col(json_null(FederatedIdentityProvider::ProviderConfig))
                    .col(string_len_null(
                        FederatedIdentityProvider::DefaultMappingName,
                        255,
                    ))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-idp-project")
                            .from(
                                FederatedIdentityProvider::Table,
                                FederatedIdentityProvider::DomainId,
                            )
                            .to(Project, project::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .index(
                        Index::create()
                            .unique()
                            .nulls_not_distinct()
                            .name("idx-idp-name-domain-discovery")
                            .col(FederatedIdentityProvider::DomainId)
                            .col(FederatedIdentityProvider::Name)
                            .col(FederatedIdentityProvider::OidcDiscoveryUrl),
                    )
                    .to_owned(),
            )
            .await?;

        if db_backend == sea_orm::DatabaseBackend::Postgres {
            manager
                .create_type(
                    Type::create()
                        .as_enum(FederatedMappingType::FederatedMappingType)
                        .values([FederatedMappingType::Oidc, FederatedMappingType::Jwt])
                        .to_owned(),
                )
                .await?;
        }

        manager
            .create_table(
                Table::create()
                    .table(FederatedMapping::Table)
                    .if_not_exists()
                    .col(string_len(FederatedMapping::Id, 64).primary_key())
                    .col(string_len(FederatedMapping::Name, 255))
                    .col(string_len(FederatedMapping::IdpId, 64))
                    .col(string_len_null(FederatedMapping::DomainId, 64))
                    .col(enumeration(
                        FederatedMapping::Type,
                        FederatedMappingType::FederatedMappingType,
                        [FederatedMappingType::Oidc, FederatedMappingType::Jwt],
                    ))
                    .col(boolean(FederatedMapping::Enabled))
                    .col(string_len_null(FederatedMapping::AllowedRedirectUris, 1024))
                    .col(string_len(FederatedMapping::UserIdClaim, 64))
                    .col(string_len(FederatedMapping::UserNameClaim, 64))
                    .col(string_len_null(FederatedMapping::DomainIdClaim, 64))
                    //.col(string_len_null(FederatedMapping::UserClaimJsonPointer, 128))
                    .col(string_len_null(FederatedMapping::GroupsClaim, 64))
                    .col(string_len_null(FederatedMapping::BoundAudiences, 1024))
                    .col(string_len_null(FederatedMapping::BoundSubject, 128))
                    .col(json_null(FederatedMapping::BoundClaims))
                    .col(string_len_null(FederatedMapping::OidcScopes, 128))
                    //.col(json_null(FederatedMapping::ClaimMappings))
                    .col(string_len_null(FederatedMapping::TokenUserId, 64))
                    .col(string_len_null(FederatedMapping::TokenRoleIds, 128))
                    .col(string_len_null(FederatedMapping::TokenProjectId, 128))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-idp-mapping-idp")
                            .from(FederatedMapping::Table, FederatedMapping::IdpId)
                            .to(
                                FederatedIdentityProvider::Table,
                                FederatedIdentityProvider::Id,
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-idp-mapping-project")
                            .from(FederatedMapping::Table, FederatedMapping::DomainId)
                            .to(Project, project::Column::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-idp-mapping-domain")
                    .table(FederatedMapping::Table)
                    .col(FederatedMapping::DomainId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(FederatedAuthState::Table)
                    .if_not_exists()
                    .col(string_len(FederatedAuthState::IdpId, 64))
                    .col(string_len(FederatedAuthState::MappingId, 64))
                    .col(string_len(FederatedAuthState::State, 64).primary_key())
                    .col(string_len(FederatedAuthState::Nonce, 64))
                    .col(string_len(FederatedAuthState::RedirectUri, 256))
                    .col(string_len(FederatedAuthState::PkceVerifier, 64))
                    .col(date_time(FederatedAuthState::ExpiresAt))
                    .col(json_null(FederatedAuthState::RequestedScope))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-idp-auth-state-idp")
                            .from(FederatedAuthState::Table, FederatedAuthState::IdpId)
                            .to(
                                FederatedIdentityProvider::Table,
                                FederatedIdentityProvider::Id,
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-idp-auth-state-mapping")
                            .from(FederatedAuthState::Table, FederatedAuthState::MappingId)
                            .to(FederatedMapping::Table, FederatedMapping::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db_backend = manager.get_database_backend();
        manager
            .drop_table(
                Table::drop()
                    .if_exists()
                    .table(FederatedAuthState::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .if_exists()
                    .table(FederatedMapping::Table)
                    .to_owned(),
            )
            .await?;

        if db_backend == sea_orm::DatabaseBackend::Postgres {
            manager
                .drop_type(
                    Type::drop()
                        .if_exists()
                        .name(FederatedMappingType::FederatedMappingType)
                        .to_owned(),
                )
                .await?;
        }

        manager
            .drop_table(
                Table::drop()
                    .table(FederatedIdentityProvider::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum FederatedIdentityProvider {
    Table,
    Id,
    DomainId,
    Name,
    Enabled,
    OidcDiscoveryUrl,
    OidcClientId,
    OidcClientSecret,
    OidcResponseMode,
    OidcResponseTypes,
    BoundIssuer,
    JwksUrl,
    JwtValidationPubkeys,
    ProviderConfig,
    DefaultMappingName,
}

#[derive(DeriveIden)]
enum FederatedMapping {
    Table,
    Id,
    DomainId,
    Name,
    IdpId,
    Type,
    Enabled,
    AllowedRedirectUris,
    UserIdClaim,
    UserNameClaim,
    DomainIdClaim,
    GroupsClaim,
    BoundAudiences,
    BoundSubject,
    BoundClaims,
    OidcScopes,
    TokenUserId,
    TokenRoleIds,
    TokenProjectId,
}

#[derive(DeriveIden)]
enum FederatedMappingType {
    FederatedMappingType,
    Oidc,
    Jwt,
}

#[derive(DeriveIden)]
enum FederatedAuthState {
    Table,
    IdpId,
    MappingId,
    State,
    Nonce,
    RedirectUri,
    PkceVerifier,
    ExpiresAt,
    RequestedScope,
}
