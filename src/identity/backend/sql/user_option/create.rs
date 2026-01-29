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

use crate::db::entity::prelude::UserOption as DbUserOption;
use crate::db::entity::user_option as db_user_option;
use crate::error::DbContextExt;
use crate::identity::backend::sql::IdentityDatabaseError;

pub async fn create<C, I>(db: &C, opts: I) -> Result<(), IdentityDatabaseError>
where
    C: ConnectionTrait,
    I: IntoIterator<Item = db_user_option::Model>,
{
    DbUserOption::insert_many(
        opts.into_iter()
            .map(Into::<db_user_option::ActiveModel>::into),
    )
    .exec(db)
    .await
    .context("inserting new user options")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    // use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult,
    // Transaction};
}
