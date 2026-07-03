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
//! `SeaORM` entity for the `credential` table (ADR 0019 §1).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "credential")]
pub struct Model {
    /// Primary key. For `ec2`: `SHA-256(blob['access'])` hex-encoded.
    /// Otherwise a random UUID.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,

    /// The ID of the user who owns the credential.
    pub user_id: String,

    /// The ID of the project associated with the credential (mandatory for
    /// `ec2`).
    pub project_id: Option<String>,

    /// The Fernet-encrypted secret blob.
    #[sea_orm(column_type = "Text")]
    pub encrypted_blob: String,

    /// The credential type (`ec2`, `totp`, or a custom string).
    pub r#type: String,

    /// SHA-1 hex digest of the primary key used for encryption (ADR 0019
    /// §4, `key_hash` Specification).
    pub key_hash: String,

    /// Extensible JSON field, stored by Python as a JSON-encoded string in a
    /// `Text` column (`JsonBlob`). Modelled as `Option<String>`, matching
    /// the convention already used by `identity-driver-sql`'s `user`/`group`
    /// entities — never a native JSON/JSONB column.
    #[sea_orm(column_type = "Text", nullable)]
    pub extra: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
