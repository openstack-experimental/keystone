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
    federated_user as db_federated_user, local_user as db_local_user,
    nonlocal_user as db_nonlocal_user, password as db_password,
    prelude::{FederatedUser, LocalUser, NonlocalUser, User as DbUser, UserOption},
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
    // Prepare basic selects
    let mut user_select = DbUser::find();
    let mut local_user_select = LocalUser::find();
    let mut nonlocal_user_select = NonlocalUser::find();
    let mut federated_user_select = FederatedUser::find();

    if let Some(domain_id) = &params.domain_id {
        user_select = user_select.filter(db_user::Column::DomainId.eq(domain_id));
    }
    if let Some(name) = &params.name {
        local_user_select = local_user_select.filter(db_local_user::Column::Name.eq(name));
        nonlocal_user_select = nonlocal_user_select.filter(db_nonlocal_user::Column::Name.eq(name));
        federated_user_select =
            federated_user_select.filter(db_federated_user::Column::DisplayName.eq(name));
    }

    let db_users: Vec<db_user::Model> = user_select.all(db).await.context("fetching users data")?;

    let (user_opts, local_users, nonlocal_users, federated_users) = tokio::join!(
        db_users.load_many(UserOption, db),
        db_users.load_one(local_user_select, db),
        db_users.load_one(nonlocal_user_select, db),
        db_users.load_many(federated_user_select, db)
    );

    let locals = local_users.context("fetching local users data")?;

    let local_users_passwords: Vec<Option<Vec<db_password::Model>>> =
        local_user::load_local_users_passwords(db, locals.iter().cloned().map(|u| u.map(|x| x.id)))
            .await?;

    let last_activity_cutof_date = conf.get_user_last_activity_cutof_date();

    let mut results: Vec<UserResponse> = Vec::new();
    for (u, (o, (l, (p, (n, f))))) in db_users.into_iter().zip(
        user_opts.context("fetching user options")?.into_iter().zip(
            locals.into_iter().zip(
                local_users_passwords.into_iter().zip(
                    nonlocal_users
                        .context("fetching nonlocal users data")?
                        .into_iter()
                        .zip(
                            federated_users
                                .context("fetching federated users data")?
                                .into_iter(),
                        ),
                ),
            ),
        ),
    ) {
        if l.is_none() && n.is_none() && f.is_empty() {
            continue;
        }

        let mut user_builder = UserResponseBuilder::default();
        user_builder.merge_user_data(
            &u,
            &UserOptions::from_iter(o),
            last_activity_cutof_date.as_ref(),
        );
        //user_builder.merge_options(&UserOptions::from_iter(o));
        if let Some(local) = l {
            user_builder.merge_local_user_data(&local);
            if let Some(pass) = p {
                user_builder.merge_passwords_data(pass.into_iter());
            }
        } else if let Some(nonlocal) = n {
            user_builder.merge_nonlocal_user_data(&nonlocal);
        } else if !f.is_empty() {
            user_builder.merge_federated_user_data(f);
        } else {
            return Err(IdentityDatabaseError::MalformedUser(u.id))?;
        };
        results.push(user_builder.build()?);
    }

    //let select: Vec<(String, Option<String>, )>  = DbUser::find()
    //let select = DbUser::find();
    //let select  = Prefixer::new(DbUser::find().select_only())
    //    .add_columns(DbUser)
    //    .add_columns(LocalUser)
    //    .add_columns(NonlocalUser)
    //    .selector
    //    .left_join(LocalUser)
    //    .left_join(NonlocalUser)
    //    //.left_join(FederatedUser)
    //    .into_model::<DbUserData>()
    //    .all(db)
    //    .await
    //    .unwrap();
    Ok(results)
}
