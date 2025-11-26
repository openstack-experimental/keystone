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

use crate::config::Config;
use crate::db::entity::federated_user;
use crate::identity::backends::sql::{IdentityDatabaseError, db_err};

pub async fn create<A>(
    _conf: &Config,
    db: &DatabaseConnection,
    federation: A,
) -> Result<federated_user::Model, IdentityDatabaseError>
where
    A: Into<federated_user::ActiveModel>,
{
    let db_user: federated_user::Model = federation
        .into()
        .insert(db)
        .await
        .map_err(|err| db_err(err, "persisting federated user data"))?;

    Ok(db_user)
}

#[cfg(test)]
mod tests {}
