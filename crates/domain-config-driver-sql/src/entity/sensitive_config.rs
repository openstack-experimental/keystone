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
//! `SeaORM` Entity for the write-only domain configuration options.

use sea_orm::entity::prelude::*;

/// A single sensitive configuration option of a domain.
///
/// Same shape as [`super::whitelisted_config::Model`], in a separate table so
/// that a read serving the API can never accidentally include a secret: the
/// readable endpoints simply do not query this table. Matches
/// python-keystone's `sensitive_config`.
#[derive(Clone, Debug, DeriveEntityModel, Eq, PartialEq)]
#[sea_orm(table_name = "sensitive_config")]
pub struct Model {
    /// The domain the option applies to.
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_type = "String(StringLen::N(64))"
    )]
    pub domain_id: String,

    /// The group holding the option, e.g. `ldap`.
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_type = "String(StringLen::N(255))"
    )]
    pub group: String,

    /// The option name, e.g. `password`.
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_type = "String(StringLen::N(255))"
    )]
    pub option: String,

    /// The JSON encoded option value.
    #[sea_orm(column_type = "Text")]
    pub value: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
