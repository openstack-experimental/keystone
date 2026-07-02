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

use crate::entity::{credential as db_credential, prelude::Credential as DbCredential};
use crate::fernet::FernetKeyRepository;

/// Decrypt a stored credential row into the plaintext API representation.
pub fn to_plaintext(
    cfg: &Config,
    model: db_credential::Model,
) -> Result<Credential, CredentialProviderError> {
    let repo = FernetKeyRepository::new(cfg.credential.key_repository.clone());
    let keys = repo.load(cfg.credential.insecure_allow_null_key)?;
    let plaintext = keys
        .multi_fernet
        .decrypt(&model.encrypted_blob)
        .map_err(|_| CredentialProviderError::Encryption("failed to decrypt blob".into()))?;
    let blob = String::from_utf8(plaintext)
        .map_err(|e| CredentialProviderError::Encryption(e.to_string()))?;

    let extra = model
        .extra
        .as_ref()
        .filter(|e| e.as_str() != "{}")
        .map(|e| serde_json::from_str(e))
        .transpose()?;

    Ok(Credential {
        id: model.id,
        user_id: model.user_id,
        project_id: model.project_id,
        blob,
        r#type: model.r#type,
        extra,
    })
}

/// Get a credential by its ID.
pub async fn get<I: AsRef<str>>(
    cfg: &Config,
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Credential>, CredentialProviderError> {
    let select = DbCredential::find().filter(db_credential::Column::Id.eq(id.as_ref()));

    if let Some(model) = select.one(db).await.context("fetching credential by id")? {
        return Ok(Some(to_plaintext(cfg, model)?));
    }
    Ok(None)
}

/// Get a credential by the plaintext EC2 access key
/// (`id == SHA-256(access)`).
pub async fn get_by_ec2_access(
    cfg: &Config,
    db: &DatabaseConnection,
    access: &str,
) -> Result<Option<Credential>, CredentialProviderError> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(access.as_bytes());
    let id: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    get(cfg, db, &id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    fn mock_model() -> db_credential::Model {
        db_credential::Model {
            id: "cred_id".into(),
            user_id: "user_id".into(),
            project_id: Some("project_id".into()),
            encrypted_blob: String::new(),
            r#type: "custom".into(),
            key_hash: "deadbeef".into(),
            extra: None,
        }
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results::<db_credential::Model, _, _>([vec![]])
            .into_connection();
        let cfg = Config::default();

        assert_eq!(get(&cfg, &db, "missing").await.unwrap(), None);
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "credential"."id", "credential"."user_id", "credential"."project_id", "credential"."encrypted_blob", "credential"."type", "credential"."key_hash", "credential"."extra" FROM "credential" WHERE "credential"."id" = $1 LIMIT $2"#,
                ["missing".into(), 1u64.into()]
            )]
        );
    }

    #[test]
    fn test_to_plaintext_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.credential.key_repository = dir.path().to_path_buf();
        let repo = FernetKeyRepository::new(cfg.credential.key_repository.clone());
        repo.setup().unwrap();
        let keys = repo.load(false).unwrap();

        let mut model = mock_model();
        model.encrypted_blob = keys.multi_fernet.encrypt(br#"{"access":"AKIA"}"#);

        let cred = to_plaintext(&cfg, model).unwrap();
        assert_eq!(cred.blob, r#"{"access":"AKIA"}"#);
        assert_eq!(cred.id, "cred_id");
    }
}
