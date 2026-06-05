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
use std::collections::{BTreeMap, BTreeSet};

use sea_orm::{ConnectionTrait, entity::*};
use sea_orm::{
    DatabaseConnection, FromQueryResult, JoinType, QueryFilter, QuerySelect, RelationTrait,
};

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::role::RoleProviderError;
use openstack_keystone_core_types::role::{RoleImply, RoleRef};

use crate::entity::{implied_role as db_implied_role, role as db_role};
use crate::role::NULL_DOMAIN_ID;

mod check;
mod create;
mod delete;
mod get;
mod list;

pub use check::check;
pub use create::create;
pub use delete::delete;
pub use get::get;
pub use list::{list, list_by_prior};

/// Filter variants for listing role imply rules.
pub(crate) enum ImpliedRoleFilter<'a> {
    /// Filter by prior role only.
    PriorRole(&'a str),
    /// Filter by both prior and implied role IDs.
    Exact(&'a str, &'a str),
}

/// Build a resolved tree of role inference.
///
/// # Parameters
/// - `data`: The map of implied roles.
///
/// # Returns
/// A `Result` containing the expanded map of implied roles.
fn expand_implied_role_ids(
    data: &BTreeMap<String, BTreeSet<RoleRef>>,
) -> BTreeMap<String, BTreeSet<RoleRef>> {
    let mut res: BTreeMap<String, BTreeSet<RoleRef>> = BTreeMap::new();
    for (id, imply) in data.iter() {
        let mut implied = imply.clone();
        for im in imply.iter() {
            implied.append(&mut get_implied_role_ids(&im.id, data));
        }
        res.insert(id.clone(), implied);
    }
    res
}

/// Recursively resolve inference tree.
///
/// # Parameters
/// - `id`: The role ID to resolve.
/// - `data`: The map of implied roles.
///
/// # Returns
/// A `BTreeSet` containing the implied role IDs.
fn get_implied_role_ids(
    id: &String,
    data: &BTreeMap<String, BTreeSet<RoleRef>>,
) -> BTreeSet<RoleRef> {
    let mut res: BTreeSet<RoleRef> = BTreeSet::new();
    if let Some(implied) = data.get(id) {
        implied.iter().for_each(|imply| {
            res.insert(imply.clone());
            res.append(&mut get_implied_role_ids(&imply.id, data));
        })
    }
    res
}

/// List role recursively resolving imply rules.
///
/// # Parameters
/// - `db`: The database connection.
/// - `resolve`: Whether to resolve the rules recursively.
///
/// # Returns
/// A `Result` containing the map of implied role rules, or an `Error`.
pub async fn get_inference_tree(
    db: &DatabaseConnection,
    resolve: bool,
) -> Result<BTreeMap<String, BTreeSet<RoleRef>>, RoleProviderError> {
    let mut implied_rules: BTreeMap<String, BTreeSet<RoleRef>> = BTreeMap::new();
    for imply in list_expanded(db, None).await? {
        implied_rules
            .entry(imply.prior_role.id)
            .and_modify(|x| {
                x.insert(imply.implied_role.clone());
            })
            .or_insert(BTreeSet::from([imply.implied_role.clone()]));
    }
    if resolve {
        Ok(expand_implied_role_ids(&implied_rules))
    } else {
        Ok(implied_rules)
    }
}

/// Structure to capture SQL results of the custom join.
#[derive(FromQueryResult, Debug)]
struct FlatRoleLinkRow {
    // Prior Role Fields
    prior_role_id: String,
    prior_role_name: String,
    prior_role_domain_id: String,

    // Implied Role Fields
    implied_role_id: String,
    implied_role_name: String,
    implied_role_domain_id: String,
}

/// List all role imply rules.
///
/// # Parameters
/// - `db`: The database connection.
/// - `filter`: Optional filter to apply.
///
/// # Returns
/// A `Result` containing a list of `RoleImply`, or an `Error`.
pub(crate) async fn list_expanded<C: ConnectionTrait>(
    db: &C,
    filter: Option<ImpliedRoleFilter<'_>>,
) -> Result<Vec<RoleImply>, RoleProviderError> {
    let mut query = db_implied_role::Entity::find()
        // Clear default selections so we don't fetch junk columns
        .select_only()
        // Join parent side
        .join_as(
            JoinType::InnerJoin,
            db_implied_role::Relation::PriorRole.def(),
            "prior_role",
        )
        // Join child side
        .join_as(
            JoinType::InnerJoin,
            db_implied_role::Relation::ImpliedRole.def(),
            "child_role",
        );

    // 2. Explicitly select and alias every single column to avoid collision
    // We use Expr::col to target the aliased tables safely
    use sea_orm::sea_query::Expr;

    query = query
        // Parent mapping
        .expr_as(
            Expr::col(("prior_role", db_role::Column::Id)),
            "prior_role_id",
        )
        .expr_as(
            Expr::col(("prior_role", db_role::Column::Name)),
            "prior_role_name",
        )
        .expr_as(
            Expr::col(("prior_role", db_role::Column::DomainId)),
            "prior_role_domain_id",
        )
        // Child mapping
        .expr_as(
            Expr::col(("child_role", db_role::Column::Id)),
            "implied_role_id",
        )
        .expr_as(
            Expr::col(("child_role", db_role::Column::Name)),
            "implied_role_name",
        )
        .expr_as(
            Expr::col(("child_role", db_role::Column::DomainId)),
            "implied_role_domain_id",
        );

    // Apply filters
    match filter {
        Some(ImpliedRoleFilter::PriorRole(p_id)) => {
            query = query.filter(db_implied_role::Column::PriorRoleId.eq(p_id));
        }
        Some(ImpliedRoleFilter::Exact(p_id, c_id)) => {
            query = query
                .filter(db_implied_role::Column::PriorRoleId.eq(p_id))
                .filter(db_implied_role::Column::ImpliedRoleId.eq(c_id));
        }
        None => {}
    }

    // 3. Fetch flat rows
    let flat_rows = query
        .into_model::<FlatRoleLinkRow>()
        .all(db)
        .await
        .context("listing implied roles")?;

    // 4. Map the structurally safe database rows cleanly into your RoleLink DTO
    //    array
    let rules: Vec<RoleImply> = flat_rows
        .into_iter()
        .map(|row| RoleImply {
            prior_role: openstack_keystone_core_types::role::RoleRef {
                domain_id: (row.prior_role_domain_id != NULL_DOMAIN_ID)
                    .then_some(row.prior_role_domain_id),
                id: row.prior_role_id,
                name: Some(row.prior_role_name),
            },
            implied_role: openstack_keystone_core_types::role::RoleRef {
                domain_id: (row.implied_role_domain_id != NULL_DOMAIN_ID)
                    .then_some(row.implied_role_domain_id),
                id: row.implied_role_id,
                name: Some(row.implied_role_name),
            },
        })
        .collect();

    Ok(rules)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use sea_orm::{DatabaseBackend, IntoMockRow, MockDatabase, Transaction};

    use super::*;

    #[test]
    fn test_expand_implied_role_ids() {
        fn rref(id: &str) -> RoleRef {
            RoleRef {
                id: id.into(),
                name: None,
                domain_id: None,
            }
        }

        let implied_data: BTreeMap<String, BTreeSet<RoleRef>> = BTreeMap::from([
            ("1".into(), BTreeSet::from([rref("2"), rref("3")])),
            ("2".into(), BTreeSet::from([rref("4")])),
            ("4".into(), BTreeSet::from([rref("7"), rref("8")])),
            ("5".into(), BTreeSet::from([rref("6")])),
        ]);

        assert_eq!(
            BTreeMap::from([
                (
                    "1".into(),
                    BTreeSet::from([rref("2"), rref("3"), rref("4"), rref("7"), rref("8")])
                ),
                (
                    "2".into(),
                    BTreeSet::from([rref("4"), rref("7"), rref("8")])
                ),
                ("4".into(), BTreeSet::from([rref("7"), rref("8")])),
                ("5".into(), BTreeSet::from([rref("6")])),
            ]),
            expand_implied_role_ids(&implied_data)
        );
    }

    #[tokio::test]
    async fn test_list() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                BTreeMap::from([
                    ("prior_role_id", "1".into()),
                    ("prior_role_name", "admin".into()),
                    ("prior_role_domain_id", NULL_DOMAIN_ID.into()),
                    ("implied_role_id", "2".into()),
                    ("implied_role_name", "manager".into()),
                    ("implied_role_domain_id", NULL_DOMAIN_ID.into()),
                ])
                .into_mock_row(),
                BTreeMap::from([
                    ("prior_role_id", "2".into()),
                    ("prior_role_name", "manager".into()),
                    ("prior_role_domain_id", NULL_DOMAIN_ID.into()),
                    ("implied_role_id", "3".into()),
                    ("implied_role_name", "member".into()),
                    ("implied_role_domain_id", NULL_DOMAIN_ID.into()),
                ])
                .into_mock_row(),
                BTreeMap::from([
                    ("prior_role_id", "3".into()),
                    ("prior_role_name", "member".into()),
                    ("prior_role_domain_id", NULL_DOMAIN_ID.into()),
                    ("implied_role_id", "4".into()),
                    ("implied_role_name", "reader".into()),
                    ("implied_role_domain_id", NULL_DOMAIN_ID.into()),
                ])
                .into_mock_row(),
            ]])
            .into_connection();

        let results = list_expanded(&db, None).await.unwrap();

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "prior_role"."id" AS "prior_role_id", "prior_role"."name" AS "prior_role_name", "prior_role"."domain_id" AS "prior_role_domain_id", "child_role"."id" AS "implied_role_id", "child_role"."name" AS "implied_role_name", "child_role"."domain_id" AS "implied_role_domain_id" FROM "implied_role" INNER JOIN "role" AS "prior_role" ON "implied_role"."prior_role_id" = "prior_role"."id" INNER JOIN "role" AS "child_role" ON "implied_role"."implied_role_id" = "child_role"."id""#,
                []
            )]
        );

        assert_eq!(results.len(), 3);
        assert!(results.contains(&RoleImply {
            prior_role: RoleRef {
                id: "1".into(),
                name: Some("admin".into()),
                domain_id: None,
            },
            implied_role: RoleRef {
                id: "2".into(),
                name: Some("manager".into()),
                domain_id: None,
            },
        }));
        assert!(results.contains(&RoleImply {
            prior_role: RoleRef {
                id: "2".into(),
                name: Some("manager".into()),
                domain_id: None,
            },
            implied_role: RoleRef {
                id: "3".into(),
                name: Some("member".into()),
                domain_id: None,
            },
        }));
        assert!(results.contains(&RoleImply {
            prior_role: RoleRef {
                id: "3".into(),
                name: Some("member".into()),
                domain_id: None,
            },
            implied_role: RoleRef {
                id: "4".into(),
                name: Some("reader".into()),
                domain_id: None,
            },
        }));
    }

    #[tokio::test]
    async fn test_list_empty() {
        use sea_orm::sea_query::Value;
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([Vec::<std::collections::BTreeMap<String, Value>>::new()])
            .into_connection();

        let results = list_expanded(&db, None).await.unwrap();

        assert!(results.is_empty());
    }
}
