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

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::limit::LimitProviderError;

use crate::entity::{limit as db_limit, prelude::Limit as DbLimit};

/// Delete all limits of the domain.
pub async fn delete_by_domain<I: AsRef<str>>(
    db: &DatabaseConnection,
    domain_id: I,
) -> Result<(), LimitProviderError> {
    DbLimit::delete_many()
        .filter(db_limit::Column::DomainId.eq(domain_id.as_ref()))
        .exec(db)
        .await
        .context("deleting limits of the domain")?;
    Ok(())
}
