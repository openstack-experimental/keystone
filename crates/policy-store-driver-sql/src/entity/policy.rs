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

//! `SeaORM` Entity for the `policy` table.
//!
//! Column types mirror python keystone's initial migration exactly, so
//! `SqlDriver::setup` produces the same schema an existing python-managed
//! database already has:
//!
//! ```text
//! id     String(64)  primary key
//! type   String(255) not null
//! blob   Text        not null   (ks_sql.JsonBlob)
//! extra  Text        null       (ks_sql.JsonBlob)
//! ```

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "policy")]
pub struct Model {
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_type = "String(StringLen::N(64))"
    )]
    pub id: String,
    #[sea_orm(column_name = "type", column_type = "String(StringLen::N(255))")]
    pub r#type: String,
    /// JSON-encoded policy document (python keystone's `JsonBlob`).
    #[sea_orm(column_type = "Text")]
    pub blob: String,
    /// JSON-encoded additional properties.
    #[sea_orm(column_type = "Text", nullable)]
    pub extra: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
