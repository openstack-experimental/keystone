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
use serde_json::json;

use crate::config::Config;
use crate::db::entity::{
    federated_user as db_federated_user, password as db_password, user as db_user,
};
use crate::identity::backends::sql::{IdentityDatabaseError, db_err};
use crate::identity::password_hashing;
use crate::identity::types::*;

use super::super::federated_user;
use super::super::local_user;
use super::super::password;

async fn create_main(
    conf: &Config,
    db: &DatabaseConnection,
    user: &UserCreate,
) -> Result<db_user::Model, IdentityDatabaseError> {
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
    let main_user = create_main(conf, db, &user).await?;
    if let Some(federation_data) = &user.federated {
        let mut federated_entities: Vec<db_federated_user::Model> = Vec::new();
        for federated_user in federation_data {
            if federated_user.protocols.is_empty() {
                federated_entities.push(
                    federated_user::create(
                        conf,
                        db,
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
                            db,
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

        let builder = federated_user::get_federated_user_builder(
            &main_user,
            federated_entities,
            UserOptions::default(),
        );

        Ok(builder.build()?)
    } else {
        // Local user
        let local_user = local_user::create(conf, db, &user).await?;
        let mut passwords: Vec<db_password::Model> = Vec::new();
        if let Some(password) = &user.password {
            let password_entry = password::create(
                db,
                local_user.id,
                password_hashing::hash_password(conf, password).await?,
                None,
            )
            .await?;

            passwords.push(password_entry);
        }
        Ok(local_user::get_local_user_builder(
            conf,
            &main_user,
            local_user,
            Some(passwords),
            UserOptions::default(),
        )
        .build()?)
    }
    // let ub = common::get_user_builder(&main_user, Vec::new()).build()?;

    // Ok(ub)
}

#[cfg(test)]
mod tests {
    // use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult,
    // Transaction};
}
