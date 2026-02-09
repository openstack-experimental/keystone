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
use crate::identity::backend::sql::IdentityDatabaseError;
use crate::identity::types::UserCreate;

#[tracing::instrument(skip_all)]
pub async fn create<C>(
    conf: &Config,
    db: &C,
    main_record: &user::Model,
    user: &UserCreate,
) -> Result<local_user::Model, IdentityDatabaseError>
where
    C: ConnectionTrait,
{
    Ok(user
        .to_local_user_active_model(conf, main_record)?
        .insert(db)
        .await
        .context("inserting new user record")?)
}
