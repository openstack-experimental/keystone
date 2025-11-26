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

use crate::config::Config;
use crate::db::entity::local_user;
use crate::identity::backends::sql::{IdentityDatabaseError, db_err};
use crate::identity::types::UserCreate;

pub async fn create(
    conf: &Config,
    db: &DatabaseConnection,
    user: &UserCreate,
) -> Result<local_user::Model, IdentityDatabaseError> {
    let mut entry = local_user::ActiveModel {
        id: NotSet,
        user_id: Set(user.id.clone()),
        domain_id: Set(user.domain_id.clone()),
        name: Set(user.name.clone()),
        failed_auth_count: NotSet,
        failed_auth_at: NotSet,
    };
    // Set failed_auth_count to 0 if compliance disabling is on
    if let Some(true) = &user.enabled
        && conf
            .security_compliance
            .disable_user_account_days_inactive
            .is_some()
    {
        entry.failed_auth_count = Set(Some(0));
    }

    let db_user: local_user::Model = entry
        .insert(db)
        .await
        .map_err(|err| db_err(err, "inserting new user record"))?;

    Ok(db_user)
}
