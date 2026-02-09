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
//! Create a token revocation record.

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use super::{RevocationEvent, RevocationEventCreate};
use crate::db::entity::revocation_event as db_revocation_event;
use crate::error::DbContextExt;
use crate::revoke::backend::error::RevokeDatabaseError;

/// Create token revocation record.
///
/// Invalidate the token before the regular expiration.
pub async fn create(
    db: &DatabaseConnection,
    revocation: RevocationEventCreate,
) -> Result<RevocationEvent, RevokeDatabaseError> {
    db_revocation_event::ActiveModel {
        id: NotSet,
        access_token_id: revocation
            .access_token_id
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        audit_chain_id: revocation
            .audit_chain_id
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        audit_id: revocation
            .audit_id
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        consumer_id: revocation
            .consumer_id
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        domain_id: revocation
            .domain_id
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        expires_at: revocation
            .expires_at
            .map(|val| Set(Some(val.naive_utc())))
            .unwrap_or(NotSet),
        issued_before: Set(revocation.issued_before.naive_utc()),
        project_id: revocation
            .project_id
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        revoked_at: Set(revocation.revoked_at.naive_utc()),
        role_id: revocation.role_id.clone().map(Set).unwrap_or(NotSet).into(),
        trust_id: revocation
            .trust_id
            .clone()
            .map(Set)
            .unwrap_or(NotSet)
            .into(),
        user_id: revocation.user_id.clone().map(Set).unwrap_or(NotSet).into(),
    }
    .insert(db)
    .await
    .context("creating token revocation event")?
    .try_into()
}

#[cfg(test)]
mod tests {
    use chrono::{Days, Utc};
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_mock;
    use super::*;

    #[tokio::test]
    async fn test_create() {
        let time1 = Utc::now();
        let time2 = time1.checked_add_days(Days::new(1)).unwrap();
        let time3 = time2.checked_add_days(Days::new(1)).unwrap();
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mock()]])
            .into_connection();

        let req = RevocationEventCreate {
            access_token_id: Some("access_token_id".into()),
            audit_chain_id: Some("audit_chain_id".into()),
            audit_id: Some("audit_id".into()),
            consumer_id: Some("consumer_id".into()),
            domain_id: Some("domain_id".into()),
            expires_at: Some(time1),
            issued_before: time2,
            project_id: Some("project_id".into()),
            revoked_at: time3,
            role_id: Some("role_id".into()),
            trust_id: Some("trust_id".into()),
            user_id: Some("uid".into()),
        };

        create(&db, req).await.unwrap();

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "revocation_event" ("domain_id", "project_id", "user_id", "role_id", "trust_id", "consumer_id", "access_token_id", "issued_before", "expires_at", "revoked_at", "audit_id", "audit_chain_id") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING "id", "domain_id", "project_id", "user_id", "role_id", "trust_id", "consumer_id", "access_token_id", "issued_before", "expires_at", "revoked_at", "audit_id", "audit_chain_id""#,
                [
                    "domain_id".into(),
                    "project_id".into(),
                    "uid".into(),
                    "role_id".into(),
                    "trust_id".into(),
                    "consumer_id".into(),
                    "access_token_id".into(),
                    time2.naive_utc().into(),
                    time1.naive_utc().into(),
                    time3.naive_utc().into(),
                    "audit_id".into(),
                    "audit_chain_id".into()
                ]
            ),]
        );
    }
}
