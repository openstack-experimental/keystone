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
//! Claim, read and release the registration of a configuration type.
//!
//! A registration is a lock one domain holds over a configuration type, stored
//! in `config_register` with the type as the primary key. python-keystone uses
//! it so that at most one domain drives a given mechanism at a time — the `SQL`
//! type, for instance, marks the single domain whose identity backend is
//! allowed to be the SQL one when domain specific drivers are loaded from the
//! database.
//!
//! Exclusivity is the primary key doing the work rather than a read followed by
//! a write: two nodes claiming the same type concurrently both insert, and the
//! one that loses the race is told so by the database instead of overwriting
//! the winner.

use sea_orm::entity::*;
use sea_orm::query::*;
use sea_orm::{DatabaseConnection, Set};

use openstack_keystone_core::error::{DatabaseError, DbContextExt};
use openstack_keystone_core_types::domain_config::DomainConfigProviderError;

use crate::entity::config_register;
use crate::entity::prelude::ConfigRegister as DbConfigRegister;

/// Try to register a domain for a configuration type.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain claiming the type.
/// - `driver_type`: The registration type to claim.
///
/// # Returns
/// - `Result<bool, DomainConfigProviderError>` - `true` when the domain now
///   holds the registration, `false` when somebody already does — the
///   requesting domain itself included.
pub async fn obtain(
    db: &DatabaseConnection,
    domain_id: &str,
    driver_type: &str,
) -> Result<bool, DomainConfigProviderError> {
    let row = config_register::ActiveModel {
        r#type: Set(driver_type.to_owned()),
        domain_id: Set(domain_id.to_owned()),
    };
    match DbConfigRegister::insert(row)
        .exec(db)
        .await
        .context("obtaining a domain config registration")
    {
        Ok(_) => Ok(true),
        // Losing the primary key race is the answer, not a failure: the type is
        // taken. python-keystone's `obtain_registration` swallows
        // `DBDuplicateEntry` the same way and returns `False`, which includes
        // the case of the domain already holding the registration itself.
        Err(DatabaseError::Conflict { .. }) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Read which domain holds the registration of a configuration type.
///
/// # Parameters
/// - `db`: The database connection.
/// - `driver_type`: The registration type to look up.
///
/// # Returns
/// - `Result<Option<String>, DomainConfigProviderError>` - The ID of the domain
///   holding it, or `None` when nobody does.
pub async fn read(
    db: &DatabaseConnection,
    driver_type: &str,
) -> Result<Option<String>, DomainConfigProviderError> {
    Ok(DbConfigRegister::find_by_id(driver_type)
        .one(db)
        .await
        .context("reading a domain config registration")?
        .map(|registration| registration.domain_id))
}

/// Release the registrations a domain holds.
///
/// # Parameters
/// - `db`: The database connection.
/// - `domain_id`: The ID of the domain releasing them.
/// - `driver_type`: The single type to release, or `None` for every type the
///   domain holds. `None` is the only spelling of "every type": python-keystone
///   tests its `type` argument for truth, so an empty string releases
///   everything there, whereas here it selects the registration of the empty
///   type, of which there is none.
///
/// # Returns
/// - `Result<(), DomainConfigProviderError>` - `Ok(())` if successful.
pub async fn release(
    db: &DatabaseConnection,
    domain_id: &str,
    driver_type: Option<&str>,
) -> Result<(), DomainConfigProviderError> {
    // Always filtered by domain: releasing is only ever giving up what this
    // domain holds, so a type registered to somebody else is left alone rather
    // than stolen. Holding none of it is not an error either, as
    // python-keystone's `release_registration` documents ("if it is not then do
    // nothing - no exception is raised").
    let mut query =
        DbConfigRegister::delete_many().filter(config_register::Column::DomainId.eq(domain_id));
    if let Some(driver_type) = driver_type {
        query = query.filter(config_register::Column::Type.eq(driver_type));
    }
    query
        .exec(db)
        .await
        .context("releasing a domain config registration")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, DbBackend, MockDatabase, MockExecResult, Schema, Transaction};

    use super::*;
    use crate::SqlBackend;
    use openstack_keystone_core::SqlDriver;

    /// A database with the driver's tables, for the paths whose behaviour is
    /// the database enforcing the primary key rather than a statement.
    async fn sqlite() -> DatabaseConnection {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let schema = Schema::new(DbBackend::Sqlite);
        SqlBackend::default().setup(&db, &schema).await.unwrap();
        db
    }

    #[tokio::test]
    async fn test_obtain() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![config_register::Model {
                r#type: "SQL".to_string(),
                domain_id: "did".to_string(),
            }]])
            .into_connection();

        assert!(obtain(&db, "did", "SQL").await.unwrap());

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"INSERT INTO "config_register" ("type", "domain_id") VALUES ($1, $2) RETURNING "type""#,
                ["SQL".into(), "did".into()]
            )]
        );
    }

    #[tokio::test]
    async fn test_obtain_of_a_type_another_domain_holds() {
        let db = sqlite().await;
        assert!(obtain(&db, "did", "SQL").await.unwrap());

        assert!(
            !obtain(&db, "other", "SQL")
                .await
                .expect("a taken registration is an answer, not an error"),
            "a type is registered to one domain at a time"
        );
        // The domain that got there first still holds it.
        assert_eq!(read(&db, "SQL").await.unwrap(), Some("did".to_string()));
    }

    #[tokio::test]
    async fn test_obtain_of_a_type_the_domain_already_holds() {
        // python-keystone answers `False` here too: the caller asked to become
        // the holder and nothing changed hands.
        let db = sqlite().await;
        assert!(obtain(&db, "did", "SQL").await.unwrap());

        assert!(!obtain(&db, "did", "SQL").await.unwrap());
    }

    #[tokio::test]
    async fn test_obtain_of_another_type() {
        // The registration is exclusive per type, not per domain.
        let db = sqlite().await;
        assert!(obtain(&db, "did", "SQL").await.unwrap());

        assert!(obtain(&db, "did", "LDAP").await.unwrap());
        assert_eq!(read(&db, "LDAP").await.unwrap(), Some("did".to_string()));
    }

    #[tokio::test]
    async fn test_read() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![config_register::Model {
                r#type: "SQL".to_string(),
                domain_id: "did".to_string(),
            }]])
            .into_connection();

        assert_eq!(read(&db, "SQL").await.unwrap(), Some("did".to_string()));

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "config_register"."type", "config_register"."domain_id" FROM "config_register" WHERE "config_register"."type" = $1 LIMIT $2"#,
                ["SQL".into(), 1u64.into()]
            )]
        );
    }

    #[tokio::test]
    async fn test_read_of_an_unregistered_type() {
        let db = sqlite().await;

        assert_eq!(read(&db, "SQL").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_release() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 1,
                ..Default::default()
            }])
            .into_connection();

        release(&db, "did", Some("SQL")).await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "config_register" WHERE "config_register"."domain_id" = $1 AND "config_register"."type" = $2"#,
                ["did".into(), "SQL".into()]
            )]
        );
    }

    #[tokio::test]
    async fn test_release_of_every_type_of_a_domain() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult {
                rows_affected: 2,
                ..Default::default()
            }])
            .into_connection();

        release(&db, "did", None).await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"DELETE FROM "config_register" WHERE "config_register"."domain_id" = $1"#,
                ["did".into()]
            )]
        );
    }

    #[tokio::test]
    async fn test_release_of_a_type_another_domain_holds_keeps_it() {
        let db = sqlite().await;
        assert!(obtain(&db, "did", "SQL").await.unwrap());

        release(&db, "other", Some("SQL"))
            .await
            .expect("releasing what is not held is silent");

        assert_eq!(read(&db, "SQL").await.unwrap(), Some("did".to_string()));
    }

    #[tokio::test]
    async fn test_release_of_the_empty_type_releases_nothing() {
        // Unlike python-keystone, where a falsey type means every type.
        let db = sqlite().await;
        assert!(obtain(&db, "did", "SQL").await.unwrap());

        release(&db, "did", Some("")).await.unwrap();

        assert_eq!(read(&db, "SQL").await.unwrap(), Some("did".to_string()));
    }

    #[tokio::test]
    async fn test_release_frees_the_type_for_another_domain() {
        let db = sqlite().await;
        assert!(obtain(&db, "did", "SQL").await.unwrap());

        release(&db, "did", Some("SQL")).await.unwrap();

        assert!(obtain(&db, "other", "SQL").await.unwrap());
        assert_eq!(read(&db, "SQL").await.unwrap(), Some("other".to_string()));
    }
}
