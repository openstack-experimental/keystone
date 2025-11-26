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

use super::local_user;
use super::user;
use super::user_option;
use crate::auth::{AuthenticatedInfo, AuthenticationError};
use crate::config::Config;
use crate::db::entity::password as db_password;
use crate::identity::IdentityProviderError;
use crate::identity::password_hashing;
use crate::identity::types::*;

/// Authenticate a user by a password
pub async fn authenticate_by_password(
    config: &Config,
    db: &DatabaseConnection,
    auth: UserPasswordAuthRequest,
) -> Result<AuthenticatedInfo, IdentityProviderError> {
    let user_with_passwords = local_user::load_local_user_with_passwords(
        db,
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
            let user_opts = user_option::list_by_user_id(db, local_user.user_id.clone()).await?;

            if password_hashing::verify_password(config, auth.password, expected_hash).await? {
                if let Some(user) = user::get_main_entry(db, &local_user.user_id).await? {
                    // TODO: Check password is expired
                    // TODO: reset failed login attempt
                    let user_builder = local_user::get_local_user_builder(
                        config,
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
    Err(IdentityProviderError::WrongUsernamePassword)
}
