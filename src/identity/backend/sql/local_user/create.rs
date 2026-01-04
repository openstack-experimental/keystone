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

use sea_orm::ConnectionTrait;
use sea_orm::entity::*;
use uuid::Uuid;

use crate::config::Config;
use crate::db::entity::local_user;
use crate::error::DbContextExt;
use crate::identity::backend::sql::IdentityDatabaseError;
use crate::identity::types::UserCreate;

pub async fn create<C>(
    conf: &Config,
    db: &C,
    user: &UserCreate,
) -> Result<local_user::Model, IdentityDatabaseError>
where
    C: ConnectionTrait,
{
    Ok(local_user::ActiveModel {
        id: NotSet,
        user_id: Set(user
            .id
            .clone()
            .unwrap_or(Uuid::new_v4().simple().to_string())),
        domain_id: Set(user.domain_id.clone()),
        name: Set(user.name.clone()),
        failed_auth_count: if user.enabled.is_some_and(|x| x)
            && conf
                .security_compliance
                .disable_user_account_days_inactive
                .is_some()
        {
            Set(Some(0))
        } else {
            NotSet
        },
        failed_auth_at: NotSet,
    }
    .insert(db)
    .await
    .context("inserting new user record")?)
}
