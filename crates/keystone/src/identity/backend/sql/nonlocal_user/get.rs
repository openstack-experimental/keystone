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

use crate::db::entity::{nonlocal_user, prelude::NonlocalUser};
use crate::error::DbContextExt;
use crate::identity::backend::sql::IdentityDatabaseError;

#[allow(unused)]
#[tracing::instrument(skip_all)]
pub async fn get_by_name_and_domain<N: AsRef<str>, D: AsRef<str>>(
    db: &DatabaseConnection,
    name: N,
    domain_id: D,
) -> Result<Option<nonlocal_user::Model>, IdentityDatabaseError> {
    Ok(NonlocalUser::find()
        .filter(nonlocal_user::Column::Name.eq(name.as_ref()))
        .filter(nonlocal_user::Column::DomainId.eq(domain_id.as_ref()))
        .one(db)
        .await
        .context("searching nonlocal user by name and domain")?)
}

#[tracing::instrument(skip_all)]
pub async fn get_by_user_id<U: AsRef<str>>(
    db: &DatabaseConnection,
    user_id: U,
) -> Result<Option<nonlocal_user::Model>, IdentityDatabaseError> {
    Ok(NonlocalUser::find()
        .filter(nonlocal_user::Column::UserId.eq(user_id.as_ref()))
        .one(db)
        .await
        .context("fetching the nonlocal user by ID")?)
}
