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
use std::collections::{BTreeMap, BTreeSet};

use crate::assignment::backend::error::AssignmentDatabaseError;
use crate::db::entity::prelude::ImpliedRole as DbImpliedRole;
use crate::error::DbContextExt;

/// Build a resolved tree of role inference.
fn expand_implied_role_ids(
    data: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut res: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (id, imply) in data.iter() {
        let mut implied = imply.clone();
        for im in imply.iter() {
            implied.append(&mut get_implied_role_ids(im, data));
        }
        res.insert(id.clone(), implied);
    }
    res
}

/// Recursively resolve inference tree.
fn get_implied_role_ids(
    id: &String,
    data: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut res: BTreeSet<String> = BTreeSet::new();
    if let Some(implied) = data.get(id) {
        implied.iter().for_each(|imply| {
            res.insert(imply.clone());
            res.append(&mut get_implied_role_ids(imply, data));
        })
    }
    res
}

/// List role recursively resolving imply rules.
pub async fn list_rules(
    db: &DatabaseConnection,
    resolve: bool,
) -> Result<BTreeMap<String, BTreeSet<String>>, AssignmentDatabaseError> {
    let mut implied_rules: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for imply in DbImpliedRole::find()
        .all(db)
        .await
        .context("fetching implied roles")?
    {
        implied_rules
            .entry(imply.prior_role_id)
            .and_modify(|x| {
                x.insert(imply.implied_role_id.clone());
            })
            .or_insert(BTreeSet::from([imply.implied_role_id.clone()]));
    }
    if resolve {
        Ok(expand_implied_role_ids(&implied_rules))
    } else {
        Ok(implied_rules)
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use crate::db::entity::implied_role;

    use super::*;

    #[test]
    fn test_expand_implied_role_ids() {
        let implied_data: BTreeMap<String, BTreeSet<String>> = BTreeMap::from([
            (
                "1".into(),
                BTreeSet::from(["2".to_string(), "3".to_string()]),
            ),
            ("2".into(), BTreeSet::from(["4".to_string()])),
            (
                "4".into(),
                BTreeSet::from(["7".to_string(), "8".to_string()]),
            ),
            ("5".into(), BTreeSet::from(["6".to_string()])),
        ]);
        assert_eq!(
            BTreeMap::from([
                (
                    "1".into(),
                    BTreeSet::from([
                        "2".to_string(),
                        "3".to_string(),
                        "4".to_string(),
                        "7".to_string(),
                        "8".to_string()
                    ])
                ),
                (
                    "2".into(),
                    BTreeSet::from(["4".to_string(), "7".to_string(), "8".to_string()])
                ),
                (
                    "4".into(),
                    BTreeSet::from(["7".to_string(), "8".to_string()])
                ),
                ("5".into(), BTreeSet::from(["6".to_string()])),
            ]),
            expand_implied_role_ids(&implied_data)
        );
    }

    fn get_implied_role_mock(id: String, implied_id: String) -> implied_role::Model {
        implied_role::Model {
            prior_role_id: id.clone(),
            implied_role_id: implied_id.clone(),
        }
    }

    #[tokio::test]
    async fn test_list_rules() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                get_implied_role_mock("1".into(), "2".into()),
                get_implied_role_mock("1".into(), "3".into()),
                get_implied_role_mock("2".into(), "4".into()),
                get_implied_role_mock("4".into(), "7".into()),
                get_implied_role_mock("4".into(), "8".into()),
                get_implied_role_mock("5".into(), "6".into()),
            ]])
            .append_query_results([vec![
                get_implied_role_mock("1".into(), "2".into()),
                get_implied_role_mock("1".into(), "3".into()),
                get_implied_role_mock("2".into(), "4".into()),
                get_implied_role_mock("4".into(), "7".into()),
                get_implied_role_mock("4".into(), "8".into()),
                get_implied_role_mock("5".into(), "6".into()),
            ]])
            .into_connection();
        assert_eq!(
            list_rules(&db, true).await.unwrap(),
            BTreeMap::from([
                (
                    "1".into(),
                    BTreeSet::from([
                        "2".to_string(),
                        "3".to_string(),
                        "4".to_string(),
                        "7".to_string(),
                        "8".to_string()
                    ])
                ),
                (
                    "2".into(),
                    BTreeSet::from(["4".to_string(), "7".to_string(), "8".to_string()])
                ),
                (
                    "4".into(),
                    BTreeSet::from(["7".to_string(), "8".to_string()])
                ),
                ("5".into(), BTreeSet::from(["6".to_string()])),
            ]),
        );

        assert_eq!(
            list_rules(&db, false).await.unwrap(),
            BTreeMap::from([
                (
                    "1".into(),
                    BTreeSet::from(["2".to_string(), "3".to_string(),])
                ),
                ("2".into(), BTreeSet::from(["4".to_string()])),
                (
                    "4".into(),
                    BTreeSet::from(["7".to_string(), "8".to_string()])
                ),
                ("5".into(), BTreeSet::from(["6".to_string()])),
            ]),
        );

        // Checking transaction log
        assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "implied_role"."prior_role_id", "implied_role"."implied_role_id" FROM "implied_role""#,
                    []
                ),
            ]
        );
    }
}
