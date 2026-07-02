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

use sea_orm::ActiveValue::Set;
use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_config::Config;
use openstack_keystone_core::credential::CredentialProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::credential::*;

use crate::credential::get::to_plaintext;
use crate::entity::{credential as db_credential, prelude::Credential as DbCredential};
use crate::fernet::FernetKeyRepository;

/// Update a credential. Updating `blob` re-encrypts it with the current
/// Primary Key and updates `key_hash` (ADR 0019 §2, Update).
pub async fn update(
    cfg: &Config,
    db: &DatabaseConnection,
    id: &str,
    rec: CredentialUpdate,
) -> Result<Credential, CredentialProviderError> {
    let model = DbCredential::find()
        .filter(db_credential::Column::Id.eq(id))
        .one(db)
        .await
        .context("fetching credential for update")?
        .ok_or_else(|| CredentialProviderError::CredentialNotFound(id.to_string()))?;

    let mut active: db_credential::ActiveModel = model.into();

    if let Some(new_type) = rec.r#type {
        active.r#type = Set(new_type);
    }
    if let Some(new_project_id) = rec.project_id {
        active.project_id = Set(Some(new_project_id));
    }
    if let Some(new_blob) = rec.blob {
        let repo = FernetKeyRepository::new(cfg.credential.key_repository.clone());
        let keys = repo.load(cfg.credential.insecure_allow_null_key)?;
        active.encrypted_blob = Set(keys.multi_fernet.encrypt(new_blob.as_bytes()));
        active.key_hash = Set(keys.primary_key_hash);
    }

    let updated = active.update(db).await.context("updating credential")?;

    to_plaintext(cfg, updated)
}
