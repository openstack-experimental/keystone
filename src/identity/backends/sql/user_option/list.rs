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

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use crate::db::entity::{prelude::UserOption as DbUserOptions, user_option};
use crate::identity::backends::sql::{IdentityDatabaseError, db_err};

pub async fn list_by_user_id<S: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: S,
) -> Result<impl IntoIterator<Item = user_option::Model>, IdentityDatabaseError> {
    DbUserOptions::find()
        .filter(user_option::Column::UserId.eq(user_id.as_ref()))
        .all(db)
        .await
        .map_err(|err| db_err(err, "fetching options of the user"))
}
