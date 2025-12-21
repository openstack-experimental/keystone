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

use super::super::local_user;
use crate::config::Config;
use crate::db::entity::{
    local_user as db_local_user, password as db_password,
    prelude::{LocalUser, User as DbUser},
    user as db_user,
};
use crate::error::DbContextExt;
use crate::identity::backends::error::IdentityDatabaseError;
use crate::identity::types::*;

pub async fn list(
    conf: &Config,
    db: &DatabaseConnection,
    params: &UserListParameters,
) -> Result<Vec<UserResponse>, IdentityDatabaseError> {
    // Prepare basic selects for users and local_users only
    let mut user_select = DbUser::find();
    let mut local_user_select = LocalUser::find();

    // Apply filters to the user table
    if let Some(domain_id) = &params.domain_id {
        user_select = user_select.filter(db_user::Column::DomainId.eq(domain_id));
    }

    // Apply filters to the local_user table
    if let Some(name) = &params.name {
        local_user_select = local_user_select.filter(db_local_user::Column::Name.eq(name));
    }

    // Fetch users from the user table
    let db_users: Vec<db_user::Model> = user_select.all(db).await.context("fetching users data")?;

    // Load related local_user data
    let local_users = db_users
        .load_one(local_user_select, db)
        .await
        .context("fetching local users data")?;

    // Load passwords for local users
    let local_users_passwords: Vec<Option<Vec<db_password::Model>>> =
        local_user::load_local_users_passwords(
            db,
            local_users.iter().cloned().map(|u| u.map(|x| x.id)),
        )
        .await?;

    let last_activity_cutof_date = conf.get_user_last_activity_cutof_date();

    let mut results: Vec<UserResponse> = Vec::new();

    // Iterate over users and build responses
    for (u, (local, passwords)) in db_users.into_iter().zip(
        local_users
            .into_iter()
            .zip(local_users_passwords.into_iter()),
    ) {
        // Skip users without local_user data
        let Some(local) = local else {
            continue;
        };

        // Build the user response
        let mut user_builder = UserResponseBuilder::default();
        user_builder.merge_user_data(
            &u,
            &UserOptions::default(), // Local users don't have user options
            last_activity_cutof_date.as_ref(),
        );
        user_builder.merge_local_user_data(&local);

        if let Some(pass) = passwords {
            user_builder.merge_passwords_data(pass.into_iter());
        }

        results.push(user_builder.build()?);
    }

    Ok(results)
}
