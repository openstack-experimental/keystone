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
//! List existing token restriction.

use std::collections::HashMap;

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::token::error::TokenProviderError;
use openstack_keystone_core_types::token::{TokenRestriction, TokenRestrictionListParameters};

use crate::FromModelWithRoleAssociation;
use crate::entity::{
    prelude::{
        TokenRestriction as DbTokenRestriction,
        TokenRestrictionRoleAssociation as DbTokenRestrictionRoleAssociation,
    },
    token_restriction, token_restriction_role_association,
};

/// List existing token restrictions.
///
/// `find_with_related` issues a single query with a `LEFT JOIN` against the
/// role-association table, so a naive `.limit()` on it would cap joined rows,
/// not distinct restrictions. Instead the marker/limit is applied to a first,
/// join-free query over just the restriction ids; the joined role
/// associations are then fetched only for that page.
///
/// # Parameters
/// - `db`: The database connection.
/// - `params`: The list parameters.
///
/// # Returns
/// A `Result` containing a list of `TokenRestriction`s, or a
/// `TokenProviderError`.
pub async fn list(
    db: &DatabaseConnection,
    params: &TokenRestrictionListParameters,
) -> Result<Vec<TokenRestriction>, TokenProviderError> {
    let mut select = DbTokenRestriction::find();
    if let Some(val) = &params.domain_id {
        select = select.filter(token_restriction::Column::DomainId.eq(val));
    }
    if let Some(val) = &params.user_id {
        select = select.filter(token_restriction::Column::UserId.eq(val));
    }
    if let Some(val) = &params.project_id {
        select = select.filter(token_restriction::Column::ProjectId.eq(val));
    }

    let mut cursor = select.cursor_by(token_restriction::Column::Id);
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
    let page = cursor.all(db).await.context("listing token restrictions")?;
    if page.is_empty() {
        return Ok(Vec::new());
    }

    let order: HashMap<String, usize> = page
        .iter()
        .enumerate()
        .map(|(i, model)| (model.id.clone(), i))
        .collect();
    let ids: Vec<String> = page.into_iter().map(|model| model.id).collect();

    let db_restrictions: Vec<(
        token_restriction::Model,
        Vec<token_restriction_role_association::Model>,
    )> = DbTokenRestriction::find()
        .filter(token_restriction::Column::Id.is_in(ids))
        .find_with_related(DbTokenRestrictionRoleAssociation)
        .all(db)
        .await
        .context("listing token restriction role associations")?;

    let mut result: Vec<TokenRestriction> = db_restrictions
        .into_iter()
        .map(TokenRestriction::from_model_with_ra)
        .collect();
    result.sort_by_key(|r| order.get(&r.id).copied().unwrap_or(usize::MAX));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use crate::entity::token_restriction_role_association;

    use super::*;

    fn get_restriction_with_roles_mock<T: AsRef<str>, R: AsRef<str>>(
        tid: T,
        rid: R,
    ) -> (
        token_restriction::Model,
        token_restriction_role_association::Model,
    ) {
        (
            token_restriction::Model {
                id: tid.as_ref().to_string(),
                domain_id: "did".to_string(),
                user_id: Some("uid".to_string()),
                project_id: Some("pid".to_string()),
                allow_rescope: true,
                allow_renew: true,
            },
            token_restriction_role_association::Model {
                restriction_id: tid.as_ref().to_string(),
                role_id: rid.as_ref().to_string(),
            },
        )
    }

    #[tokio::test]
    async fn test_list() {
        // Create MockDatabase with mock query results: first the join-free
        // marker/limit query, then the `find_with_related` join for that
        // page's ids.
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![token_restriction::Model {
                id: "id".to_string(),
                domain_id: "did".to_string(),
                user_id: Some("uid".to_string()),
                project_id: Some("pid".to_string()),
                allow_rescope: true,
                allow_renew: true,
            }]])
            .append_query_results([vec![
                get_restriction_with_roles_mock("id", "rid1"),
                get_restriction_with_roles_mock("id", "rid2"),
            ]])
            .into_connection();

        assert_eq!(
            list(
                &db,
                &TokenRestrictionListParameters {
                    domain_id: Some("did".into()),
                    user_id: Some("uid".into()),
                    project_id: Some("pid".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap(),
            vec![TokenRestriction {
                id: "id".into(),
                domain_id: "did".into(),
                user_id: Some("uid".into()),
                project_id: Some("pid".into()),
                allow_rescope: true,
                allow_renew: true,
                role_ids: vec!["rid1".into(), "rid2".into()],
                roles: None,
            }]
        );

        // Checking transaction log: a join-free marker/limit query, then the
        // `find_with_related` join restricted to that page's ids.
        let txns = db.into_transaction_log();
        assert_eq!(txns.len(), 2);
        assert!(
            !txns[0].statements()[0]
                .sql
                .contains("token_restriction_role_association")
        );
        assert!(
            txns[1].statements()[0]
                .sql
                .contains("token_restriction_role_association")
        );
    }

    #[tokio::test]
    async fn test_list_pagination_over_fetches_and_uses_marker() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![
                token_restriction::Model {
                    id: "id1".to_string(),
                    domain_id: "did".to_string(),
                    user_id: None,
                    project_id: None,
                    allow_rescope: true,
                    allow_renew: true,
                },
                token_restriction::Model {
                    id: "id2".to_string(),
                    domain_id: "did".to_string(),
                    user_id: None,
                    project_id: None,
                    allow_rescope: true,
                    allow_renew: true,
                },
            ]])
            .append_query_results([vec![
                get_restriction_with_roles_mock("id1", "rid1"),
                get_restriction_with_roles_mock("id2", "rid2"),
            ]])
            .into_connection();

        let restrictions = list(
            &db,
            &TokenRestrictionListParameters {
                pagination: openstack_keystone_core_types::ListPagination {
                    limit: Some(1),
                    marker: Some("id0".into()),
                    page_reverse: false,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(restrictions.len(), 2, "backend over-fetched limit+1 rows");

        let txns = db.into_transaction_log();
        assert!(txns[0].statements()[0].sql.contains(r#""id" >"#));
        assert!(txns[0].statements()[0].sql.contains("LIMIT"));
    }
}
