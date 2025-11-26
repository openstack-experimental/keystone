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

use chrono::{DateTime, Local, Utc};
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use crate::db::entity::password;
use crate::identity::backends::sql::{IdentityDatabaseError, db_err};

pub async fn create<S: AsRef<str>>(
    db: &DatabaseConnection,
    local_user_id: i32,
    password_hash: S,
    expires_at: Option<DateTime<Utc>>,
) -> Result<password::Model, IdentityDatabaseError> {
    let now = Local::now().naive_utc();
    let mut entry = password::ActiveModel {
        id: NotSet,
        local_user_id: Set(local_user_id),
        self_service: Set(false),
        expires_at: NotSet,
        password_hash: Set(Some(password_hash.as_ref().into())),
        created_at: Set(now),
        created_at_int: Set(now.and_utc().timestamp_micros()),
        expires_at_int: NotSet,
    };
    if let Some(expire) = expires_at {
        entry.expires_at = Set(Some(expire.naive_utc()));
        entry.expires_at_int = Set(Some(expire.timestamp_micros()));
    }
    let db_entry: password::Model = entry
        .insert(db)
        .await
        .map_err(|err| db_err(err, "inserting new password record"))?;
    Ok(db_entry)
}
