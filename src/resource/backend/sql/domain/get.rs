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

use crate::db::entity::{prelude::Project as DbProject, project as db_project};
use crate::resource::Config;
use crate::resource::backend::error::{ResourceDatabaseError, db_err};
use crate::resource::types::Domain;

pub async fn get_domain_by_id<I: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    domain_id: I,
) -> Result<Option<Domain>, ResourceDatabaseError> {
    let domain_select =
        DbProject::find_by_id(domain_id.as_ref()).filter(db_project::Column::IsDomain.eq(true));

    let domain_entry: Option<db_project::Model> = domain_select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching domain by id"))?;
    domain_entry.map(TryInto::try_into).transpose()
}

pub async fn get_domain_by_name<N: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    domain_name: N,
) -> Result<Option<Domain>, ResourceDatabaseError> {
    let domain_select = DbProject::find()
        .filter(db_project::Column::IsDomain.eq(true))
        .filter(db_project::Column::Name.eq(domain_name.as_ref()));

    let domain_entry: Option<db_project::Model> = domain_select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching domain by name"))?;
    domain_entry.map(TryInto::try_into).transpose()
}
