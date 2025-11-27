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

use crate::db::entity::local_user as db_local_user;
use crate::identity::backends::sql::{IdentityDatabaseError, db_err};

pub async fn reset_failed_auth(
    db: &DatabaseConnection,
    user: &db_local_user::Model,
) -> Result<db_local_user::Model, IdentityDatabaseError> {
    let mut update: db_local_user::ActiveModel = user.clone().into();
    update.failed_auth_count = Set(None);
    update.failed_auth_at = Set(None);
    update
        .update(db)
        .await
        .map_err(|err| db_err(err, "resetting local user failed auth counters"))
}
