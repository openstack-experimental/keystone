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
use crate::identity::backends::sql::{IdentityDatabaseError, db_err};
use crate::identity::types::*;

use super::super::federated_user;
use super::super::local_user;
use super::super::password;

async fn create_main<C>(
    conf: &Config,
    db: &C,
    user: &UserCreate,
) -> Result<db_user::Model, IdentityDatabaseError>
where
    C: ConnectionTrait,
{
    let now = Local::now().naive_utc();
    // Set last_active to now if compliance disabling is on
    let last_active_at = if let Some(true) = &user.enabled {
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

    let entry: db_user::ActiveModel = db_user::ActiveModel {
        id: Set(user.id.clone()),
        enabled: Set(user.enabled),
        extra: Set(Some(serde_json::to_string(
            // For keystone it is important to have at least "{}"
            &user.extra.as_ref().or(Some(&json!({}))),
        )?)),
        default_project_id: Set(user.default_project_id.clone()),
        last_active_at,
        created_at: Set(Some(now)),
        domain_id: Set(user.domain_id.clone()),
    };
    let db_user: db_user::Model = entry
        .insert(db)
        .await
        .map_err(|err| db_err(err, "inserting user entry"))?;
    Ok(db_user)
}

pub async fn create(
    conf: &Config,
    db: &DatabaseConnection,
    user: UserCreate,
) -> Result<UserResponse, IdentityDatabaseError> {
    // Do a lot of stuff in a transaction

    let txn = db
        .begin()
        .await
        .map_err(|err| db_err(err, "starting transaction for persisting user"))?;
    let main_user = create_main(conf, &txn, &user).await?;
    let mut response_builder = UserResponseBuilder::default();
    response_builder.merge_user_data(&main_user, &UserOptions::default(), None);
    if let Some(federation_data) = &user.federated {
        let mut federated_entities: Vec<db_federated_user::Model> = Vec::new();
        for federated_user in federation_data {
            if federated_user.protocols.is_empty() {
                federated_entities.push(
                    federated_user::create(
                        conf,
                        &txn,
                        db_federated_user::ActiveModel {
                            id: NotSet,
                            user_id: Set(user.id.clone()),
                            idp_id: Set(federated_user.idp_id.clone()),
                            protocol_id: Set("oidc".into()),
                            unique_id: Set(federated_user.unique_id.clone()),
                            display_name: Set(Some(user.name.clone())),
                        },
                    )
                    .await?,
                );
            } else {
                for proto in &federated_user.protocols {
                    federated_entities.push(
                        federated_user::create(
                            conf,
                            &txn,
                            db_federated_user::ActiveModel {
                                id: NotSet,
                                user_id: Set(user.id.clone()),
                                idp_id: Set(federated_user.idp_id.clone()),
                                protocol_id: Set(proto.protocol_id.clone()),
                                unique_id: Set(proto.unique_id.clone()),
                                display_name: Set(Some(user.name.clone())),
                            },
                        )
                        .await?,
                    );
                }
            }
        }

        response_builder.merge_federated_user_data(federated_entities);
    } else {
        // Local user
        let local_user = local_user::create(conf, &txn, &user).await?;
        let mut passwords: Vec<db_password::Model> = Vec::new();
        if let Some(password) = &user.password {
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
    txn.commit()
        .await
        .map_err(|err| db_err(err, "committing the user creation transaction"))?;

    Ok(response_builder.build()?)
}

#[cfg(test)]
mod tests {
    // use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult,
    // Transaction};
}
