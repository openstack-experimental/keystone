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
use std::collections::BTreeSet;

use sea_orm::{
    ActiveValue::Set, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, EntityTrait,
    Schema,
};

use crate::entity::{implied_role, role, role_option};
use crate::role::NULL_DOMAIN_ID;
use crate::role::list as list_roles;
use openstack_keystone_core_types::role::RoleListParameters;

async fn setup(rules: &[(&str, &str)]) -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    let schema = Schema::new(DatabaseBackend::Sqlite);
    db.execute(&schema.create_table_from_entity(role::Entity))
        .await
        .unwrap();
    db.execute(&schema.create_table_from_entity(implied_role::Entity))
        .await
        .unwrap();
    db.execute(&schema.create_table_from_entity(role_option::Entity))
        .await
        .unwrap();

    let ids: BTreeSet<&str> = rules.iter().flat_map(|(p, i)| [*p, *i]).collect();
    for id in ids {
        role::Entity::insert(role::ActiveModel {
            id: Set(id.into()),
            name: Set(format!("name-{id}")),
            domain_id: Set(NULL_DOMAIN_ID.into()),
            ..Default::default()
        })
        .exec(&db)
        .await
        .unwrap();
    }
    for (prior, implied) in rules {
        implied_role::Entity::insert(implied_role::ActiveModel {
            prior_role_id: Set((*prior).into()),
            implied_role_id: Set((*implied).into()),
        })
        .exec(&db)
        .await
        .unwrap();
    }
    db
}

async fn add_option(db: &DatabaseConnection, role_id: &str) {
    role_option::Entity::insert(role_option::ActiveModel {
        role_id: Set(role_id.into()),
        option_id: Set("IMMU".into()),
        option_value: Set(Some("true".into())),
    })
    .exec(db)
    .await
    .unwrap();
}

#[tokio::test]
async fn test_list_roles_by_ids_with_and_without_options() {
    let db = setup(&[("1", "2"), ("3", "4")]).await;
    add_option(&db, "3").await;

    let ids = Some(vec!["3".to_string(), "2".to_string()]);

    // Options requested: the role carrying one has it set.
    let with = list_roles(
        &db,
        &RoleListParameters {
            ids: ids.clone(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        vec!["2", "3"],
        with.iter().map(|r| r.id.as_str()).collect::<Vec<_>>()
    );
    assert_eq!(Some(true), with[1].options.immutable, "{:?}", with[1]);
    assert!(with[0].options == Default::default());

    // Options skipped: same roles, options left empty.
    let without = list_roles(
        &db,
        &RoleListParameters {
            ids,
            skip_options: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        vec!["2", "3"],
        without.iter().map(|r| r.id.as_str()).collect::<Vec<_>>()
    );
    assert!(without.iter().all(|r| r.options == Default::default()));
    // Everything else is identical.
    assert_eq!(with[0], without[0]);
    assert_eq!(with[1].name, without[1].name);
}

#[tokio::test]
async fn test_list_roles_ids_combine_with_other_filters() {
    let db = setup(&[("1", "2"), ("3", "4")]).await;

    let found = list_roles(
        &db,
        &RoleListParameters {
            ids: Some(vec!["1".into(), "2".into(), "3".into()]),
            name: Some("name-2".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(1, found.len());
    assert_eq!("2", found[0].id);

    // An ID that does not exist is simply absent.
    let none = list_roles(
        &db,
        &RoleListParameters {
            ids: Some(vec!["nope".into()]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(none.is_empty());

    // No filter by ID: all the roles.
    assert_eq!(
        4,
        list_roles(&db, &RoleListParameters::default())
            .await
            .unwrap()
            .len()
    );
}
