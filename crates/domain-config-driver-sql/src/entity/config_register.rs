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
//! `SeaORM` Entity for the domain configuration registrations.

use sea_orm::entity::prelude::*;

/// The domain holding the registration of a configuration type.
///
/// Table and columns match python-keystone's `config_register`. The
/// registration type is the primary key, which is what makes the registration
/// exclusive: a second domain claiming a type it already registered to another
/// one violates the key rather than overwriting the row.
#[derive(Clone, Debug, DeriveEntityModel, Eq, PartialEq)]
#[sea_orm(table_name = "config_register")]
pub struct Model {
    /// The registration type, e.g. `SQL`.
    ///
    /// Named `type` in the table, as python-keystone names it.
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_name = "type",
        column_type = "String(StringLen::N(64))"
    )]
    pub r#type: String,

    /// The domain holding the registration.
    #[sea_orm(column_type = "String(StringLen::N(64))")]
    pub domain_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
