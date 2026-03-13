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

use crate::config::Config;
use crate::db::entity::{local_user, user};
use crate::error::DbContextExt;
use crate::identity::{IdentityProviderError, types::UserCreate};

#[tracing::instrument(skip_all)]
pub async fn create<C>(
    conf: &Config,
    db: &C,
    main_record: &user::Model,
    user: &UserCreate,
) -> Result<local_user::Model, IdentityProviderError>
where
    C: ConnectionTrait,
{
    Ok(local_user::ActiveModel {
        id: NotSet,
        user_id: Set(main_record.id.clone()),
        domain_id: Set(main_record.domain_id.clone()),
        name: Set(user.name.clone()),
        failed_auth_count: if main_record.enabled.is_some_and(|x| x)
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
    //user
    //.to_local_user_active_model(conf, main_record)?
    .insert(db)
    .await
    .context("inserting new user record")?)
}
