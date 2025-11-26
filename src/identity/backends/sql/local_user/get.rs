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

use crate::config::Config;
use crate::db::entity::{local_user, prelude::LocalUser};
use crate::identity::backends::sql::{IdentityDatabaseError, db_err};

pub async fn get_by_name_and_domain<N: AsRef<str>, D: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    name: N,
    domain_id: D,
) -> Result<Option<local_user::Model>, IdentityDatabaseError> {
    LocalUser::find()
        .filter(local_user::Column::Name.eq(name.as_ref()))
        .filter(local_user::Column::DomainId.eq(domain_id.as_ref()))
        .one(db)
        .await
        .map_err(|err| db_err(err, "searching user by name and domain"))
}

pub async fn get_by_user_id<U: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    user_id: U,
) -> Result<Option<local_user::Model>, IdentityDatabaseError> {
    LocalUser::find()
        .filter(local_user::Column::UserId.eq(user_id.as_ref()))
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching the user by ID"))
}
