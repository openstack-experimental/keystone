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

use openstack_keystone_config::Config;
use openstack_keystone_core::credential::CredentialProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::credential::*;

use crate::credential::get::to_plaintext;
use crate::entity::{credential as db_credential, prelude::Credential as DbCredential};

/// List credentials matching the given driver-level hints
/// (`user_id`/`type`).
pub async fn list(
    cfg: &Config,
    db: &DatabaseConnection,
    params: &CredentialListParameters,
) -> Result<Vec<Credential>, CredentialProviderError> {
    let mut select = DbCredential::find();
    if let Some(user_id) = &params.user_id {
        select = select.filter(db_credential::Column::UserId.eq(user_id.as_str()));
    }
    if let Some(r#type) = &params.r#type {
        select = select.filter(db_credential::Column::Type.eq(r#type.as_str()));
    }

    let models = select.all(db).await.context("listing credentials")?;

    let mut result = Vec::with_capacity(models.len());
    for model in models {
        result.push(to_plaintext(cfg, model)?);
    }
    Ok(result)
}

/// List all credentials owned by a user, optionally filtered by type.
pub async fn list_for_user<'a>(
    cfg: &Config,
    db: &DatabaseConnection,
    user_id: &'a str,
    r#type: Option<&'a str>,
) -> Result<Vec<Credential>, CredentialProviderError> {
    list(
        cfg,
        db,
        &CredentialListParameters {
            user_id: Some(user_id.to_string()),
            r#type: r#type.map(str::to_string),
        },
    )
    .await
}
