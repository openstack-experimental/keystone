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

use chrono::{DateTime, Utc};
use sea_orm::ConnectionTrait;
use sea_orm::entity::*;

use crate::db::entity::password;
use crate::error::DbContextExt;
use crate::identity::backend::sql::IdentityDatabaseError;

#[tracing::instrument(skip_all)]
pub async fn create<C: ConnectionTrait, S: AsRef<str>>(
    db: &C,
    local_user_id: i32,
    password_hash: S,
    expires_at: Option<DateTime<Utc>>,
) -> Result<password::Model, IdentityDatabaseError> {
    let now = Utc::now().naive_utc();
    Ok(password::ActiveModel {
        id: NotSet,
        local_user_id: Set(local_user_id),
        self_service: Set(false),
        expires_at: expires_at
            .map(|expires| Set(Some(expires.naive_utc())))
            .unwrap_or(NotSet),
        password_hash: Set(Some(password_hash.as_ref().into())),
        created_at: Set(now),
        created_at_int: Set(now.and_utc().timestamp_micros()),
        expires_at_int: expires_at
            .map(|expires| Set(Some(expires.timestamp_micros())))
            .unwrap_or(NotSet),
    }
    .insert(db)
    .await
    .context("inserting new password record")?)
}
