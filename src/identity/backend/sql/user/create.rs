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

use chrono::Local;
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde_json::json;

use crate::common::password_hashing;
use crate::config::Config;
use crate::db::entity::{
    federated_user as db_federated_user, password as db_password, user as db_user,
};
use crate::error::DbContextExt;
use crate::identity::backend::sql::IdentityDatabaseError;
use crate::identity::backend::sql::types::{User, UserType};
use crate::identity::types::*;

use super::super::federated_user;
use super::super::local_user;
use super::super::nonlocal_user;
use super::super::password;

async fn create_main<C>(
    conf: &Config,
    db: &C,
    user: &User,
) -> Result<db_user::Model, IdentityDatabaseError>
where
    C: ConnectionTrait,
{
    let now = Local::now().naive_utc();
    // Set last_active to now if compliance disabling is on
    let last_active_at = if user.enabled {
        if conf
            .security_compliance
            .disable_user_account_days_inactive
            .is_some()
        {
            Set(Some(now.date()))
        } else {
            NotSet
        }
    } else {
        NotSet
    };

    Ok(db_user::ActiveModel {
        id: Set(user.id.clone()),
        enabled: Set(Some(user.enabled)),
        extra: Set(Some(serde_json::to_string(
            // For keystone it is important to have at least "{}"
            &user.extra.as_ref().or(Some(&json!({}))),
        )?)),
        default_project_id: Set(user.default_project_id.clone()),
        last_active_at,
        created_at: Set(Some(now)),
        domain_id: Set(user.domain_id.clone()),
    }
    .insert(db)
    .await
    .context("inserting user entry")?)
}

pub async fn create(
    conf: &Config,
    db: &DatabaseConnection,
    user: User,
) -> Result<UserResponse, IdentityDatabaseError> {
    // Do a lot of stuff in a transaction

    let txn = db
        .begin()
        .await
        .context("starting transaction for persisting user")?;

    let main_user = create_main(conf, &txn, &user).await?;
    let mut response_builder = UserResponseBuilder::default();
    response_builder.merge_user_data(&main_user, &UserOptions::default(), None);

    match &user.type_data {
        UserType::Local(data) => {
            let local_user = local_user::create(conf, &txn, &main_user, data).await?;

            let mut passwords: Vec<db_password::Model> = Vec::new();
            if let Some(password) = &data.password {
                let password_entry = password::create(
                    &txn,
                    local_user.id,
                    password_hashing::hash_password(conf, password).await?,
                    None,
                )
                .await?;

                passwords.push(password_entry);
            }
            response_builder
                .merge_local_user_data(&local_user)
                .merge_passwords_data(passwords);
        }
        UserType::NonLocal(data) => {
            let nonlocal_user = nonlocal_user::create(&txn, &main_user, data.name.clone()).await?;
            response_builder.merge_nonlocal_user_data(&nonlocal_user);
        }
        UserType::Federated(data) => {
            let mut federated_entities: Vec<db_federated_user::Model> = Vec::new();
            for federated_user in &data.data {
                if federated_user.protocol_ids.is_empty() {
                    federated_entities.push(
                        federated_user::create(
                            &txn,
                            db_federated_user::ActiveModel {
                                id: NotSet,
                                user_id: Set(main_user.id.clone()),
                                idp_id: Set(federated_user.idp_id.clone()),
                                protocol_id: Set("oidc".into()),
                                unique_id: Set(federated_user.unique_id.clone()),
                                display_name: Set(Some(federated_user.name.clone())),
                            },
                        )
                        .await?,
                    );
                } else {
                    for proto in &federated_user.protocol_ids {
                        federated_entities.push(
                            federated_user::create(
                                &txn,
                                db_federated_user::ActiveModel {
                                    id: NotSet,
                                    user_id: Set(main_user.id.clone()),
                                    idp_id: Set(federated_user.idp_id.clone()),
                                    protocol_id: Set(proto.clone()),
                                    unique_id: Set(federated_user.unique_id.clone()),
                                    display_name: Set(Some(federated_user.name.clone())),
                                },
                            )
                            .await?,
                        );
                    }
                }
            }
            response_builder.merge_federated_user_data(federated_entities);
        }
        UserType::ServiceAccount(data) => {
            let sa = nonlocal_user::create(&txn, &main_user, data.name.clone()).await?;
            response_builder.merge_nonlocal_user_data(&sa);
        }
    }

    // TODO: user options

    txn.commit()
        .await
        .context("committing the user creation transaction")?;

    Ok(response_builder.build()?)
}

#[cfg(test)]
mod tests {
    // use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult,
    // Transaction};
}
