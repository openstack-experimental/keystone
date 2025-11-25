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

use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;
use std::collections::HashSet;
use webauthn_rs::prelude::{Passkey, PasskeyAuthentication, PasskeyRegistration};

mod common;
mod federated_user;
mod group;
mod local_user;
mod password;
mod user;
mod user_group;
mod user_option;
mod webauthn;

use super::super::types::*;
use crate::auth::{AuthenticatedInfo, AuthenticationError};
use crate::config::Config;
use crate::db::entity::{
    federated_user as db_federated_user, local_user as db_local_user,
    nonlocal_user as db_nonlocal_user, password as db_password,
    prelude::{FederatedUser, LocalUser, NonlocalUser, User as DbUser, UserOption},
    user as db_user,
};
use crate::identity::IdentityProviderError;
use crate::identity::backends::error::{IdentityDatabaseError, db_err};
use crate::identity::password_hashing;
use crate::keystone::ServiceState;

#[derive(Clone, Debug, Default)]
pub struct SqlBackend {
    pub config: Config,
}

impl SqlBackend {}

#[async_trait]
impl IdentityBackend for SqlBackend {
    /// Set config
    fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// Authenticate a user by a password
    async fn authenticate_by_password(
        &self,
        state: &ServiceState,
        auth: UserPasswordAuthRequest,
    ) -> Result<AuthenticatedInfo, IdentityProviderError> {
        let user_with_passwords = local_user::load_local_user_with_passwords(
            &state.db,
            auth.id,
            auth.name,
            auth.domain.and_then(|x| x.id),
        )
        .await?;
        if let Some((local_user, password)) = user_with_passwords {
            let passwords: Vec<db_password::Model> = password.into_iter().collect();
            if let Some(latest_password) = passwords.first()
                && let Some(expected_hash) = &latest_password.password_hash
            {
                let user_opts = user_option::get(&state.db, local_user.user_id.clone()).await?;

                if password_hashing::verify_password(&self.config, auth.password, expected_hash)
                    .await?
                {
                    if let Some(user) = user::get(&state.db, &local_user.user_id).await? {
                        // TODO: Check password is expired
                        // TODO: reset failed login attempt
                        let user_builder = common::get_local_user_builder(
                            &self.config,
                            &user,
                            local_user,
                            Some(passwords),
                            user_opts,
                        );
                        let user = user_builder.build()?;
                        return Ok(AuthenticatedInfo::builder()
                            .user_id(user.id.clone())
                            .user(user)
                            .methods(vec!["password".into()])
                            .build()
                            .map_err(AuthenticationError::from)?);
                    }
                } else {
                    return Err(IdentityProviderError::WrongUsernamePassword);
                }
            }
        }
        return Err(IdentityProviderError::WrongUsernamePassword);
    }

    /// Fetch users from the database
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_users(
        &self,
        state: &ServiceState,
        params: &UserListParameters,
    ) -> Result<Vec<UserResponse>, IdentityProviderError> {
        Ok(list_users(&self.config, &state.db, params).await?)
    }

    /// Get single user by ID
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        Ok(get_user(&self.config, &state.db, user_id).await?)
    }

    /// Find federated user by IDP and Unique ID
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn find_federated_user<'a>(
        &self,
        state: &ServiceState,
        idp_id: &'a str,
        unique_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        Ok(find_federated_user(&self.config, &state.db, idp_id, unique_id).await?)
    }

    /// Create user
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_user(
        &self,
        state: &ServiceState,
        user: UserCreate,
    ) -> Result<UserResponse, IdentityProviderError> {
        Ok(create_user(&self.config, &state.db, user).await?)
    }

    /// Delete user
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user::delete(&self.config, &state.db, user_id).await?)
    }

    /// List groups
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_groups(
        &self,
        state: &ServiceState,
        params: &GroupListParameters,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        Ok(group::list(&self.config, &state.db, params).await?)
    }

    /// Get single group by ID
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<Option<Group>, IdentityProviderError> {
        Ok(group::get(&self.config, &state.db, group_id).await?)
    }

    /// Create group
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_group(
        &self,
        state: &ServiceState,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError> {
        Ok(group::create(&self.config, &state.db, group).await?)
    }

    /// Delete group
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(group::delete(&self.config, &state.db, group_id).await?)
    }

    /// List groups a user is member of.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_groups_of_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        Ok(user_group::list_user_groups(&state.db, user_id).await?)
    }

    /// Add the user into the group.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn add_user_to_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::add_user_to_group(&state.db, user_id, group_id).await?)
    }

    /// Add user group membership relations.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn add_users_to_groups<'a>(
        &self,
        state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::add_users_to_groups(&state.db, memberships).await?)
    }

    /// Remove the user from the group.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn remove_user_from_group<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::remove_user_from_group(&state.db, user_id, group_id).await?)
    }

    /// Remove the user from multiple groups.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn remove_user_from_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::remove_user_from_groups(&state.db, user_id, group_ids).await?)
    }

    /// Set group memberships of the user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn set_user_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::set_user_groups(&state.db, user_id, group_ids).await?)
    }

    /// Create webauthn credential for the user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_user_webauthn_credential<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        credential: &Passkey,
        description: Option<&'a str>,
    ) -> Result<WebauthnCredential, IdentityProviderError> {
        Ok(webauthn::credential::create(&state.db, user_id, credential, description, None).await?)
    }

    /// List user webauthn credentials.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn list_user_webauthn_credentials<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<Passkey>, IdentityProviderError> {
        Ok(webauthn::credential::list(&state.db, user_id).await?)
    }

    /// Save webauthn credential registration state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        reg_state: PasskeyRegistration,
    ) -> Result<(), IdentityProviderError> {
        Ok(webauthn::state::create_register(&state.db, user_id, reg_state).await?)
    }

    /// Save webauthn credential auth state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn create_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        auth_state: PasskeyAuthentication,
    ) -> Result<(), IdentityProviderError> {
        Ok(webauthn::state::create_auth(&state.db, user_id, auth_state).await?)
    }

    /// Get webauthn credential registration state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<PasskeyRegistration>, IdentityProviderError> {
        Ok(webauthn::state::get_register(&state.db, user_id).await?)
    }

    /// Get webauthn credential auth state.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn get_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<PasskeyAuthentication>, IdentityProviderError> {
        Ok(webauthn::state::get_auth(&state.db, user_id).await?)
    }

    /// Delete webauthn credential registration state for the user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_user_webauthn_credential_registration_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(webauthn::state::delete(&state.db, user_id).await?)
    }

    /// Delete webauthn credential auth state for a user.
    #[tracing::instrument(level = "debug", skip(self, state))]
    async fn delete_user_webauthn_credential_authentication_state<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(webauthn::state::delete(&state.db, user_id).await?)
    }
}

async fn list_users(
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

    let db_users: Vec<db_user::Model> = user_select
        .all(db)
        .await
        .map_err(|err| db_err(err, "fetching users data"))?;

    let (user_opts, local_users, nonlocal_users, federated_users) = tokio::join!(
        db_users.load_many(UserOption, db),
        db_users.load_one(local_user_select, db),
        db_users.load_one(nonlocal_user_select, db),
        db_users.load_many(federated_user_select, db)
    );

    let locals = local_users.map_err(|err| db_err(err, "fetching local users data"))?;

    let local_users_passwords: Vec<Option<Vec<db_password::Model>>> =
        local_user::load_local_users_passwords(db, locals.iter().cloned().map(|u| u.map(|x| x.id)))
            .await?;

    let mut results: Vec<UserResponse> = Vec::new();
    for (u, (o, (l, (p, (n, f))))) in db_users.into_iter().zip(
        user_opts
            .map_err(|err| db_err(err, "fetching user options"))?
            .into_iter()
            .zip(
                locals.into_iter().zip(
                    local_users_passwords.into_iter().zip(
                        nonlocal_users
                            .map_err(|err| db_err(err, "fetching nonlocal users data"))?
                            .into_iter()
                            .zip(
                                federated_users
                                    .map_err(|err| db_err(err, "fetching federated users data"))?
                                    .into_iter(),
                            ),
                    ),
                ),
            ),
    ) {
        if l.is_none() && n.is_none() && f.is_empty() {
            continue;
        }
        let user_builder: UserResponseBuilder = if let Some(local) = l {
            common::get_local_user_builder(conf, &u, local, p.map(|x| x.into_iter()), o)
        } else if let Some(nonlocal) = n {
            common::get_nonlocal_user_builder(&u, nonlocal, o)
        } else if !f.is_empty() {
            common::get_federated_user_builder(&u, f, o)
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

pub async fn get_user(
    conf: &Config,
    db: &DatabaseConnection,
    user_id: &str,
) -> Result<Option<UserResponse>, IdentityDatabaseError> {
    let user_select = DbUser::find_by_id(user_id);

    let user_entry: Option<db_user::Model> = user_select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching the user data"))?;

    if let Some(user) = user_entry {
        let (user_opts, local_user_with_passwords) = tokio::join!(
            user.find_related(UserOption).all(db),
            local_user::load_local_user_with_passwords(
                db,
                Some(&user_id),
                None::<&str>,
                None::<&str>,
            )
        );

        let user_builder: UserResponseBuilder = match local_user_with_passwords? {
            Some(local_user_with_passwords) => common::get_local_user_builder(
                conf,
                &user,
                local_user_with_passwords.0,
                Some(local_user_with_passwords.1),
                user_opts.map_err(|err| db_err(err, "fetching user options"))?,
            ),
            _ => match user
                .find_related(NonlocalUser)
                .one(db)
                .await
                .map_err(|err| db_err(err, "fetching nonlocal user data"))?
            {
                Some(nonlocal_user) => common::get_nonlocal_user_builder(
                    &user,
                    nonlocal_user,
                    user_opts.map_err(|err| db_err(err, "fetching user options"))?,
                ),
                _ => {
                    let federated_user = user
                        .find_related(FederatedUser)
                        .all(db)
                        .await
                        .map_err(|err| db_err(err, "fetching federated user data"))?;
                    if !federated_user.is_empty() {
                        common::get_federated_user_builder(
                            &user,
                            federated_user,
                            user_opts.map_err(|err| db_err(err, "fetching user options"))?,
                        )
                    } else {
                        return Err(IdentityDatabaseError::MalformedUser(user_id.to_string()))?;
                    }
                }
            },
        };

        return Ok(Some(user_builder.build()?));
    }

    Ok(None)
}

pub async fn find_federated_user<I: AsRef<str>, U: AsRef<str>>(
    conf: &Config,
    db: &DatabaseConnection,
    idp_id: I,
    unique_id: U,
) -> Result<Option<UserResponse>, IdentityDatabaseError> {
    if let Some(federated_entry) =
        federated_user::find_by_idp_and_unique_id(conf, db, idp_id, unique_id).await?
    {
        return get_user(conf, db, &federated_entry.user_id).await;
    }
    Ok(None)
}

async fn create_user(
    conf: &Config,
    db: &DatabaseConnection,
    user: UserCreate,
) -> Result<UserResponse, IdentityDatabaseError> {
    let main_user = user::create(conf, db, &user).await?;
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

        let builder =
            common::get_federated_user_builder(&main_user, federated_entities, Vec::new());

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
        Ok(common::get_local_user_builder(
            conf,
            &main_user,
            local_user,
            Some(passwords),
            Vec::new(),
        )
        .build()?)
    }
    // let ub = common::get_user_builder(&main_user, Vec::new()).build()?;

    // Ok(ub)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::derivable_impls)]
    use chrono::Local;
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use crate::config::Config;
    use crate::db::entity::{local_user, password, user, user_option};

    use super::*;

    fn get_user_mock(user_id: String) -> user::Model {
        user::Model {
            id: user_id.clone(),
            domain_id: "foo_domain".into(),
            enabled: Some(true),
            ..Default::default()
        }
    }

    fn get_local_user_with_password_mock(
        user_id: String,
        cnt_password: usize,
    ) -> Vec<(local_user::Model, password::Model)> {
        let lu = local_user::Model {
            user_id: user_id.clone(),
            domain_id: "foo_domain".into(),
            name: "Apple Cake".to_owned(),
            ..Default::default()
        };
        let mut passwords: Vec<password::Model> = Vec::new();
        for i in 0..cnt_password {
            passwords.push(password::Model {
                id: i as i32,
                local_user_id: 1,
                expires_at: None,
                self_service: false,
                password_hash: None,
                created_at: Local::now().naive_utc(),
                created_at_int: 12345,
                expires_at_int: None,
            });
        }
        passwords
            .into_iter()
            .map(|x| (lu.clone(), x.clone()))
            .collect()
    }

    #[tokio::test]
    async fn test_get_user_local() {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result - select user itself
                vec![get_user_mock("1".into())],
            ])
            .append_query_results([
                //// Second query result - user options
                vec![user_option::Model {
                    user_id: "1".into(),
                    option_id: "1000".into(),
                    option_value: Some("true".into()),
                }],
            ])
            .append_query_results([
                // Third query result - local user with passwords
                get_local_user_with_password_mock("1".into(), 1),
            ])
            .into_connection();
        let config = Config::default();
        assert_eq!(
            get_user(&config, &db, "1").await.unwrap().unwrap(),
            UserResponse {
                id: "1".into(),
                domain_id: "foo_domain".into(),
                name: "Apple Cake".to_owned(),
                enabled: true,
                options: UserOptions {
                    ignore_change_password_upon_first_use: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            }
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user"."id", "user"."extra", "user"."enabled", "user"."default_project_id", "user"."created_at", "user"."last_active_at", "user"."domain_id" FROM "user" WHERE "user"."id" = $1 LIMIT $2"#,
                    ["1".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "user_option"."user_id", "user_option"."option_id", "user_option"."option_value" FROM "user_option" INNER JOIN "user" ON "user"."id" = "user_option"."user_id" WHERE "user"."id" = $1"#,
                    ["1".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "local_user"."id" AS "A_id", "local_user"."user_id" AS "A_user_id", "local_user"."domain_id" AS "A_domain_id", "local_user"."name" AS "A_name", "local_user"."failed_auth_count" AS "A_failed_auth_count", "local_user"."failed_auth_at" AS "A_failed_auth_at", "password"."id" AS "B_id", "password"."local_user_id" AS "B_local_user_id", "password"."self_service" AS "B_self_service", "password"."created_at" AS "B_created_at", "password"."expires_at" AS "B_expires_at", "password"."password_hash" AS "B_password_hash", "password"."created_at_int" AS "B_created_at_int", "password"."expires_at_int" AS "B_expires_at_int" FROM "local_user" LEFT JOIN "password" ON "local_user"."id" = "password"."local_user_id" WHERE "local_user"."user_id" = $1 ORDER BY "local_user"."id" ASC, "password"."created_at_int" DESC"#,
                    ["1".into()]
                ),
            ]
        );
    }
}
