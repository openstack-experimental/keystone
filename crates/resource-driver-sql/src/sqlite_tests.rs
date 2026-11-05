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
//! The recursive query behind `project::get_project_parents` is checked here
//! against actual data; the mocked tests only see canned rows.
use sea_orm::{
    ActiveValue::Set, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, EntityTrait,
    Schema,
};

use crate::entity::project;
use crate::project::{get_project_domain_id, get_project_parent_ids, get_project_parents};

async fn setup(projects: &[(&str, Option<&str>)]) -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.execute(&Schema::new(DatabaseBackend::Sqlite).create_table_from_entity(project::Entity))
        .await
        .unwrap();
    db.execute(
        &Schema::new(DatabaseBackend::Sqlite)
            .create_table_from_entity(crate::entity::project_tag::Entity),
    )
    .await
    .unwrap();
    // The cycle and dangling-parent cases cannot exist with the constraint on.
    db.execute_unprepared("PRAGMA foreign_keys = OFF")
        .await
        .unwrap();
    for (id, parent_id) in projects {
        project::Entity::insert(project::ActiveModel {
            id: Set((*id).into()),
            name: Set(format!("name-{id}")),
            domain_id: Set("domain".into()),
            parent_id: Set(parent_id.map(Into::into)),
            is_domain: Set(parent_id.is_none()),
            enabled: Set(Some(true)),
            ..Default::default()
        })
        .exec(&db)
        .await
        .unwrap();
    }
    db
}

async fn parents(db: &DatabaseConnection, id: &str) -> Option<Vec<String>> {
    get_project_parents(db, id)
        .await
        .unwrap()
        .map(|list| list.into_iter().map(|p| p.id).collect())
}

#[tokio::test]
async fn test_parents_are_ordered_from_the_closest_to_the_root() {
    let db = setup(&[
        ("domain", None),
        ("p1", Some("domain")),
        ("p2", Some("p1")),
        ("p3", Some("p2")),
        ("p4", Some("p3")),
        ("other", Some("domain")),
    ])
    .await;

    assert_eq!(
        Some(vec![
            "p3".to_string(),
            "p2".into(),
            "p1".into(),
            "domain".into()
        ]),
        parents(&db, "p4").await
    );
    assert_eq!(
        Some(vec!["domain".to_string()]),
        parents(&db, "other").await
    );
}

#[tokio::test]
async fn test_root_has_no_parents() {
    let db = setup(&[("domain", None), ("p1", Some("domain"))]).await;

    assert_eq!(Some(Vec::new()), parents(&db, "domain").await);
}

#[tokio::test]
async fn test_missing_project_is_none() {
    let db = setup(&[("domain", None)]).await;

    assert_eq!(None, parents(&db, "nope").await);
}

#[tokio::test]
async fn test_dangling_parent_ends_the_chain() {
    // The parent row is gone: return what can be resolved, like the walk did.
    let db = setup(&[("p1", Some("missing"))]).await;

    assert_eq!(Some(Vec::new()), parents(&db, "p1").await);
}

#[tokio::test]
async fn test_cycle_terminates() {
    let db = setup(&[("a", Some("b")), ("b", Some("a"))]).await;

    assert_eq!(Some(vec!["b".to_string()]), parents(&db, "a").await);
}

async fn parent_ids(db: &DatabaseConnection, id: &str) -> Option<Vec<String>> {
    get_project_parent_ids(db, id).await.unwrap()
}

#[tokio::test]
async fn test_parent_ids_match_the_parents() {
    let db = setup(&[
        ("domain", None),
        ("p1", Some("domain")),
        ("p2", Some("p1")),
        ("p3", Some("p2")),
        ("other", Some("domain")),
    ])
    .await;

    for id in ["domain", "p1", "p2", "p3", "other", "nope"] {
        let full = parents(&db, id).await;
        assert_eq!(full, parent_ids(&db, id).await, "project {id}");
    }
    assert_eq!(
        Some(vec!["p2".to_string(), "p1".into(), "domain".into()]),
        parent_ids(&db, "p3").await
    );
}

#[tokio::test]
async fn test_parent_ids_cycle_and_dangling_parent() {
    let db = setup(&[("a", Some("b")), ("b", Some("a")), ("x", Some("missing"))]).await;

    assert_eq!(Some(vec!["b".to_string()]), parent_ids(&db, "a").await);
    assert_eq!(Some(Vec::new()), parent_ids(&db, "x").await);
}

#[tokio::test]
async fn test_project_domain_id() {
    let db = setup(&[("domain", None), ("p1", Some("domain"))]).await;
    project::Entity::update(project::ActiveModel {
        id: Set("p1".into()),
        domain_id: Set("the-domain".into()),
        ..Default::default()
    })
    .exec(&db)
    .await
    .unwrap();

    assert_eq!(
        Some("the-domain".to_string()),
        get_project_domain_id(&db, "p1").await.unwrap()
    );
    assert_eq!(None, get_project_domain_id(&db, "nope").await.unwrap());
    // The domain's own `is_domain` entry is not a project.
    assert_eq!(None, get_project_domain_id(&db, "domain").await.unwrap());
}
