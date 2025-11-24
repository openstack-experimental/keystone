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
use crate::resource::types::Project;

pub async fn get_project<I: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Project>, ResourceDatabaseError> {
    let project_select =
        DbProject::find_by_id(id.as_ref()).filter(db_project::Column::IsDomain.eq(false));

    let project_entry: Option<db_project::Model> = project_select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching project by id"))?;
    project_entry.map(TryInto::try_into).transpose()
}

pub async fn get_project_by_name<N: AsRef<str>, D: AsRef<str>>(
    _conf: &Config,
    db: &DatabaseConnection,
    name: N,
    domain_id: D,
) -> Result<Option<Project>, ResourceDatabaseError> {
    let project_select = DbProject::find()
        .filter(db_project::Column::IsDomain.eq(false))
        .filter(db_project::Column::Name.eq(name.as_ref()))
        .filter(db_project::Column::DomainId.eq(domain_id.as_ref()));

    let project_entry: Option<db_project::Model> = project_select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching project by name and domain"))?;
    project_entry.map(TryInto::try_into).transpose()
}
