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
//! Tests running against a real (in-memory SQLite) database.
//!
//! The mocked-database tests of the sibling modules pin the generated SQL; the
//! tests here check that the SQL does what it is meant to do.
use chrono::{DateTime, Days, TimeDelta, Utc};
use sea_orm::{ActiveValue::Set, Database, DatabaseBackend, DatabaseConnection, Schema};
use sea_orm::{ConnectionTrait, EntityTrait, PaginatorTrait, Statement};
use sea_orm_migration::SchemaManager;

use openstack_keystone_core::SqlDriver;
use openstack_keystone_core_types::revoke::{
    RevocationEventListParameters, RevocationEventListParametersBuilder,
};

use crate::SqlBackend;
use crate::cleanup::delete_expired;
use crate::entity::{prelude::RevocationEvent, revocation_event};
use crate::indexes;
use crate::list::{count, exists, matching_count};

/// Whether the SQLite index exists (`has_index` is not implemented for it).
async fn index_exists(db: &DatabaseConnection, name: &str) -> bool {
    db.query_one_raw(Statement::from_string(
        DatabaseBackend::Sqlite,
        format!("SELECT name FROM sqlite_master WHERE type = 'index' AND name = '{name}'"),
    ))
    .await
    .unwrap()
    .is_some()
}

async fn setup_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    SqlBackend::default()
        .setup(&db, &Schema::new(DatabaseBackend::Sqlite))
        .await
        .unwrap();
    db
}

#[allow(clippy::too_many_arguments)]
fn event(
    audit_id: Option<&str>,
    user_id: Option<&str>,
    project_id: Option<&str>,
    domain_id: Option<&str>,
    role_id: Option<&str>,
    trust_id: Option<&str>,
    issued_before: DateTime<Utc>,
    revoked_at: DateTime<Utc>,
) -> revocation_event::ActiveModel {
    revocation_event::ActiveModel {
        audit_id: Set(audit_id.map(Into::into)),
        user_id: Set(user_id.map(Into::into)),
        project_id: Set(project_id.map(Into::into)),
        domain_id: Set(domain_id.map(Into::into)),
        role_id: Set(role_id.map(Into::into)),
        trust_id: Set(trust_id.map(Into::into)),
        issued_before: Set(issued_before.naive_utc()),
        revoked_at: Set(revoked_at.naive_utc()),
        ..Default::default()
    }
}

/// Insert every combination of "unset"/"matching"/"other" in each dimension,
/// both older and newer than the token.
async fn populate(db: &DatabaseConnection, token_issued_at: DateTime<Utc>) -> usize {
    let mut events = Vec::new();
    let times = [
        token_issued_at - TimeDelta::hours(1),
        token_issued_at + TimeDelta::hours(1),
    ];
    for issued_before in times {
        for audit in [None, Some("a1"), Some("a2")] {
            for user in [None, Some("u1"), Some("u2")] {
                for project in [None, Some("p1"), Some("p2")] {
                    for domain in [None, Some("d1"), Some("d2")] {
                        for role in [None, Some("r1"), Some("r2")] {
                            for trust in [None, Some("t1")] {
                                events.push(event(
                                    audit,
                                    user,
                                    project,
                                    domain,
                                    role,
                                    trust,
                                    issued_before,
                                    Utc::now(),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    let total = events.len();
    // SQLite limits the number of bound variables of a statement.
    for chunk in events.chunks(50) {
        RevocationEvent::insert_many(chunk.to_vec())
            .exec(db)
            .await
            .unwrap();
    }
    total
}

fn token_params(issued_at: DateTime<Utc>) -> Vec<(&'static str, RevocationEventListParameters)> {
    let builder = || RevocationEventListParametersBuilder::default();
    vec![
        ("empty", builder().build().unwrap()),
        (
            "issued_before only",
            builder().issued_before(issued_at).build().unwrap(),
        ),
        (
            "audit only",
            builder()
                .audit_id("a1")
                .issued_before(issued_at)
                .build()
                .unwrap(),
        ),
        (
            "user token",
            builder()
                .audit_id("a1")
                .issued_before(issued_at)
                .user_ids(vec!["u1".into()])
                .build()
                .unwrap(),
        ),
        (
            "project token",
            builder()
                .audit_id("a1")
                .issued_before(issued_at)
                .user_ids(vec!["u1".into()])
                .project_id("p1")
                .role_ids(vec!["r1".into(), "r2".into()])
                .build()
                .unwrap(),
        ),
        (
            "domain token",
            builder()
                .audit_id("a2")
                .issued_before(issued_at)
                .user_ids(vec!["u2".into()])
                .domain_ids(vec!["d1".into()])
                .role_ids(vec!["r1".into()])
                .build()
                .unwrap(),
        ),
        (
            "trust token",
            builder()
                .audit_id("a1")
                .issued_before(issued_at)
                .user_ids(vec!["u1".into(), "u2".into()])
                .project_id("p2")
                .trust_id("t1")
                .role_ids(vec!["r1".into()])
                .build()
                .unwrap(),
        ),
        (
            "empty lists",
            builder()
                .audit_id("a1")
                .issued_before(issued_at)
                .user_ids(Vec::<String>::new())
                .domain_ids(Vec::<String>::new())
                .role_ids(Vec::<String>::new())
                .build()
                .unwrap(),
        ),
    ]
}

/// The candidate-narrowing condition must never change which events match.
#[tokio::test]
async fn test_count_equals_plain_predicate() {
    let db = setup_db().await;
    let issued_at = Utc::now();
    let total = populate(&db, issued_at).await;
    assert_eq!(
        RevocationEvent::find().count(&db).await.unwrap(),
        u64::try_from(total).unwrap()
    );

    let mut non_trivial = 0;
    for (name, params) in token_params(issued_at) {
        let expected = matching_count(&db, &params).await.unwrap();
        let actual = count(&db, &params).await.unwrap();
        assert_eq!(expected, actual, "{name}: narrowed query differs");
        if actual > 0 {
            non_trivial += 1;
        }
    }
    assert!(non_trivial >= 4, "the matrix does not exercise the filters");
}

/// The branched existence check must agree with the plain predicate.
#[tokio::test]
async fn test_exists_equals_plain_predicate() {
    let db = setup_db().await;
    let issued_at = Utc::now();
    populate(&db, issued_at).await;

    let mut hits = 0;
    for (name, params) in token_params(issued_at) {
        let expected = matching_count(&db, &params).await.unwrap() > 0;
        let actual = exists(&db, &params).await.unwrap();
        assert_eq!(expected, actual, "{name}: existence check differs");
        if actual {
            hits += 1;
        }
    }
    assert!(hits >= 2, "the matrix does not exercise the filters");
}

#[tokio::test]
async fn test_count_user_event_matches_only_that_user() {
    let db = setup_db().await;
    let issued_at = Utc::now();
    RevocationEvent::insert(event(
        None,
        Some("u1"),
        None,
        None,
        None,
        None,
        issued_at + TimeDelta::minutes(1),
        Utc::now(),
    ))
    .exec(&db)
    .await
    .unwrap();

    let params = |user: &str| {
        RevocationEventListParametersBuilder::default()
            .audit_id("a")
            .issued_before(issued_at)
            .user_ids(vec![user.to_string()])
            .build()
            .unwrap()
    };
    assert_eq!(count(&db, &params("u1")).await.unwrap(), 1);
    assert_eq!(count(&db, &params("u2")).await.unwrap(), 0);
}

#[tokio::test]
async fn test_count_event_without_dimensions_revokes_every_token() {
    let db = setup_db().await;
    let issued_at = Utc::now();
    RevocationEvent::insert(event(
        None,
        None,
        None,
        None,
        None,
        None,
        issued_at + TimeDelta::minutes(1),
        Utc::now(),
    ))
    .exec(&db)
    .await
    .unwrap();

    let params = RevocationEventListParametersBuilder::default()
        .audit_id("anything")
        .issued_before(issued_at)
        .user_ids(vec!["anyone".into()])
        .build()
        .unwrap();
    assert_eq!(count(&db, &params).await.unwrap(), 1);
}

#[tokio::test]
async fn test_token_issued_after_event_is_not_revoked() {
    let db = setup_db().await;
    let issued_at = Utc::now();
    RevocationEvent::insert(event(
        Some("a1"),
        None,
        None,
        None,
        None,
        None,
        issued_at - TimeDelta::minutes(1),
        Utc::now(),
    ))
    .exec(&db)
    .await
    .unwrap();

    let params = RevocationEventListParametersBuilder::default()
        .audit_id("a1")
        .issued_before(issued_at)
        .build()
        .unwrap();
    assert_eq!(count(&db, &params).await.unwrap(), 0);
}

#[tokio::test]
async fn test_setup_creates_all_indexes_and_ensure_is_idempotent() {
    let db = setup_db().await;
    for (name, _) in indexes::definitions() {
        assert!(index_exists(&db, name).await, "{name} missing after setup");
    }
    // A second run, as the migration does on a database that `setup` already
    // handled, must not fail on the existing indexes.
    indexes::ensure(&SchemaManager::new(&db)).await.unwrap();
}

#[tokio::test]
async fn test_ensure_creates_only_missing_indexes() {
    let db = setup_db().await;
    // Emulate a table coming from the Python schema that lacks a new index.
    let name = "ix_revocation_event_domain_id_issued_before";
    db.execute_unprepared(&format!("DROP INDEX {name}"))
        .await
        .unwrap();
    assert!(!index_exists(&db, name).await);
    indexes::ensure(&SchemaManager::new(&db)).await.unwrap();
    assert!(index_exists(&db, name).await);
}

#[tokio::test]
async fn test_delete_expired_removes_only_old_events() {
    let db = setup_db().await;
    let now = Utc::now();
    let old = now - TimeDelta::hours(3);
    let recent = now - TimeDelta::minutes(5);

    // More than one batch of expired events plus a few that must stay.
    let mut events: Vec<_> = (0..2_500)
        .map(|i| {
            event(
                Some(&format!("old{i}")),
                None,
                None,
                None,
                None,
                None,
                old,
                old,
            )
        })
        .collect();
    events.extend((0..10).map(|i| {
        event(
            Some(&format!("new{i}")),
            None,
            None,
            None,
            None,
            None,
            recent,
            recent,
        )
    }));
    for chunk in events.chunks(50) {
        RevocationEvent::insert_many(chunk.to_vec())
            .exec(&db)
            .await
            .unwrap();
    }

    let cutoff = now - TimeDelta::hours(1);
    assert_eq!(delete_expired(&db, cutoff).await.unwrap(), 2_500);
    assert_eq!(RevocationEvent::find().count(&db).await.unwrap(), 10);
    // Nothing left to delete.
    assert_eq!(delete_expired(&db, cutoff).await.unwrap(), 0);
}

#[tokio::test]
async fn test_delete_expired_keeps_events_at_or_after_cutoff() {
    let db = setup_db().await;
    let cutoff = Utc::now().checked_sub_days(Days::new(1)).unwrap();
    RevocationEvent::insert(event(
        Some("at"),
        None,
        None,
        None,
        None,
        None,
        cutoff,
        cutoff,
    ))
    .exec(&db)
    .await
    .unwrap();
    assert_eq!(delete_expired(&db, cutoff).await.unwrap(), 0);
    assert_eq!(RevocationEvent::find().count(&db).await.unwrap(), 1);
}
