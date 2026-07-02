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

use openstack_keystone_config::Config;
use openstack_keystone_core::credential::CredentialProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::credential::*;

use crate::entity::credential as db_credential;
use crate::fernet::FernetKeyRepository;

/// Create a new credential row, encrypting `rec.blob` with the current
/// Primary Key.
///
/// `rec.id` and `rec.user_id` must already be resolved by the caller (the
/// core `CredentialService` computes the EC2/UUID id and defaults
/// `user_id` before calling the backend — ADR 0019 §1, §2).
pub async fn create(
    cfg: &Config,
    db: &DatabaseConnection,
    rec: CredentialCreate,
) -> Result<Credential, CredentialProviderError> {
    let id = rec
        .id
        .clone()
        .ok_or_else(|| CredentialProviderError::Driver("credential id not set".into()))?;
    let user_id = rec
        .user_id
        .clone()
        .ok_or(CredentialProviderError::MissingUserId)?;

    let repo = FernetKeyRepository::new(cfg.credential.key_repository.clone());
    let keys = repo.load(cfg.credential.insecure_allow_null_key)?;
    let encrypted_blob = keys.multi_fernet.encrypt(rec.blob.as_bytes());

    let extra = rec.extra.as_ref().map(serde_json::to_string).transpose()?;

    let model = db_credential::ActiveModel {
        id: Set(id.clone()),
        user_id: Set(user_id.clone()),
        project_id: Set(rec.project_id.clone()),
        encrypted_blob: Set(encrypted_blob),
        r#type: Set(rec.r#type.clone()),
        key_hash: Set(keys.primary_key_hash),
        extra: Set(extra),
    };
    model.insert(db).await.context("creating credential")?;

    Ok(Credential {
        id,
        user_id,
        project_id: rec.project_id,
        blob: rec.blob,
        r#type: rec.r#type,
        extra: rec.extra,
    })
}
