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
use sea_orm::{Cursor, SelectModel};

use openstack_keystone_config::Config;
use openstack_keystone_core::credential::CredentialProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::credential::*;

use crate::credential::get::to_plaintext;
use crate::entity::{credential as db_credential, prelude::Credential as DbCredential};

/// Prepare the paginated query for listing credentials.
///
/// # Parameters
/// - `params`: The list parameters.
///
/// # Returns
/// A `Result` containing a `Cursor` for the select model.
fn get_list_query(
    params: &CredentialListParameters,
) -> Result<Cursor<SelectModel<db_credential::Model>>, CredentialProviderError> {
    let mut select = DbCredential::find();
    if let Some(user_id) = &params.user_id {
        select = select.filter(db_credential::Column::UserId.eq(user_id.as_str()));
    }
    if let Some(r#type) = &params.r#type {
        select = select.filter(db_credential::Column::Type.eq(r#type.as_str()));
    }

    let mut cursor = select.cursor_by(db_credential::Column::Id);
    if let Some(marker) = &params.pagination.marker {
        if params.pagination.page_reverse {
            cursor.before(marker);
        } else {
            cursor.after(marker);
        }
    }
    // Over-fetch by one row so the API layer can tell "there is a
    // next/previous page" exactly, instead of guessing from
    // `returned == limit` (false-positives when exactly `limit` rows
    // remain). `.last()` fetches in descending order but sea-orm returns
    // rows back in ascending order.
    if let Some(limit) = params.pagination.limit {
        if params.pagination.page_reverse {
            cursor.last(limit + 1);
        } else {
            cursor.first(limit + 1);
        }
    }
    Ok(cursor)
}

/// List credentials matching the given driver-level hints
/// (`user_id`/`type`).
pub async fn list(
    cfg: &Config,
    db: &DatabaseConnection,
    params: &CredentialListParameters,
) -> Result<Vec<Credential>, CredentialProviderError> {
    let models = get_list_query(params)?
        .all(db)
        .await
        .context("listing credentials")?;

    let mut result = Vec::with_capacity(models.len());
    for model in models {
        result.push(to_plaintext(cfg, model).await?);
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
            ..Default::default()
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::DatabaseConnection;
    use sea_orm::entity::*;

    use crate::fernet::FernetKeyRepository;
    use crate::test_support::create_credential_table;

    use super::*;

    fn test_config(key_repo: &std::path::Path) -> Config {
        let mut cfg = Config::default();
        cfg.credential.key_repository = key_repo.to_path_buf();
        cfg
    }

    async fn test_db() -> DatabaseConnection {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        create_credential_table(&db).await.unwrap();
        db
    }

    async fn insert_credential(
        cfg: &Config,
        db: &DatabaseConnection,
        id: &str,
        user_id: &str,
        r#type: &str,
        plaintext: &[u8],
    ) {
        let repo = FernetKeyRepository::new(cfg.credential.key_repository.clone());
        let keys = repo.load(false).await.unwrap();
        db_credential::ActiveModel {
            id: Set(id.to_string()),
            user_id: Set(user_id.to_string()),
            project_id: Set(None),
            encrypted_blob: Set(keys.multi_fernet.encrypt(plaintext)),
            r#type: Set(r#type.to_string()),
            key_hash: Set(keys.primary_key_hash),
            extra: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_list_returns_all_when_unfiltered() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;
        FernetKeyRepository::new(key_dir.path().to_path_buf())
            .setup()
            .await
            .unwrap();
        insert_credential(&cfg, &db, "cred-1", "user-1", "totp", b"a").await;
        insert_credential(&cfg, &db, "cred-2", "user-2", "ec2", b"b").await;

        let results = list(&cfg, &db, &CredentialListParameters::default())
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_list_filters_by_user_and_type() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;
        FernetKeyRepository::new(key_dir.path().to_path_buf())
            .setup()
            .await
            .unwrap();
        insert_credential(&cfg, &db, "cred-1", "user-1", "totp", b"a").await;
        insert_credential(&cfg, &db, "cred-2", "user-1", "ec2", b"b").await;
        insert_credential(&cfg, &db, "cred-3", "user-2", "totp", b"c").await;

        let params = CredentialListParameters {
            user_id: Some("user-1".into()),
            r#type: Some("totp".into()),
            ..Default::default()
        };
        let results = list(&cfg, &db, &params).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "cred-1");
    }

    #[tokio::test]
    async fn test_list_for_user_filters_by_owner() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;
        FernetKeyRepository::new(key_dir.path().to_path_buf())
            .setup()
            .await
            .unwrap();
        insert_credential(&cfg, &db, "cred-1", "user-1", "totp", b"a").await;
        insert_credential(&cfg, &db, "cred-2", "user-2", "totp", b"b").await;

        let results = list_for_user(&cfg, &db, "user-1", None).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "cred-1");
    }

    #[tokio::test]
    async fn test_list_pagination_over_fetches_and_uses_marker() {
        let key_dir = tempfile::tempdir().unwrap();
        let cfg = test_config(key_dir.path());
        let db = test_db().await;
        FernetKeyRepository::new(key_dir.path().to_path_buf())
            .setup()
            .await
            .unwrap();
        insert_credential(&cfg, &db, "cred-1", "user-1", "totp", b"a").await;
        insert_credential(&cfg, &db, "cred-2", "user-1", "totp", b"b").await;

        let params = CredentialListParameters {
            pagination: openstack_keystone_core_types::ListPagination {
                limit: Some(1),
                marker: Some("cred-0".into()),
                page_reverse: false,
            },
            ..Default::default()
        };
        let results = list(&cfg, &db, &params).await.unwrap();
        assert_eq!(results.len(), 2, "backend over-fetched limit+1 rows");
    }
}
