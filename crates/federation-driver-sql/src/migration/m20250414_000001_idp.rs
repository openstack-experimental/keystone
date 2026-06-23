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
use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
                        FederatedIdentityProvider::AllowedRedirectUris,
                        1024,
                    ))
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
                    .col(string_len_null(FederatedIdentityProvider::OidcScopes, 128))
                    .col(text_null(FederatedIdentityProvider::JwksUrl))
                    .col(text_null(FederatedIdentityProvider::JwtValidationPubkeys))
                    .col(string_len_null(FederatedIdentityProvider::BoundIssuer, 255))
                    .col(json_null(FederatedIdentityProvider::ProviderConfig))
                    .col(string_len_null(
                        FederatedIdentityProvider::DefaultMappingName,
                        255,
                    ))
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

        manager
            .create_table(
                Table::create()
                    .table(FederatedAuthState::Table)
                    .if_not_exists()
                    .col(string_len(FederatedAuthState::IdpId, 64))
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
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
    AllowedRedirectUris,
    OidcDiscoveryUrl,
    OidcClientId,
    OidcClientSecret,
    OidcResponseMode,
    OidcResponseTypes,
    OidcScopes,
    BoundIssuer,
    JwksUrl,
    JwtValidationPubkeys,
    ProviderConfig,
    DefaultMappingName,
}

#[derive(DeriveIden)]
enum FederatedAuthState {
    Table,
    IdpId,
    State,
    Nonce,
    RedirectUri,
    PkceVerifier,
    ExpiresAt,
    RequestedScope,
}
