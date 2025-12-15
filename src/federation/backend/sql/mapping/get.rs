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

use crate::db::entity::{
    federated_mapping as db_federated_mapping, prelude::FederatedMapping as DbFederatedMapping,
};
use crate::federation::backend::error::{FederationDatabaseError, db_err};
use crate::federation::types::*;

pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<Mapping>, FederationDatabaseError> {
    let select = DbFederatedMapping::find_by_id(id.as_ref());

    let entry: Option<db_federated_mapping::Model> = select
        .one(db)
        .await
        .map_err(|err| db_err(err, "fetching federation mapping by id"))?;
    entry.map(TryInto::try_into).transpose()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, Transaction};

    use super::super::tests::get_mapping_mock;
    use super::*;

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_mapping_mock("1")]])
            .into_connection();
        assert_eq!(
            get(&db, "1").await.unwrap().unwrap(),
            Mapping {
                id: "1".into(),
                name: "name".into(),
                domain_id: Some("did".into()),
                enabled: true,
                idp_id: "idp".into(),
                user_id_claim: "sub".into(),
                user_name_claim: "preferred_username".into(),
                domain_id_claim: Some("domain_id".into()),
                ..Default::default()
            }
        );

        assert_eq!(
            db.into_transaction_log(),
            [Transaction::from_sql_and_values(
                DatabaseBackend::Postgres,
                r#"SELECT "federated_mapping"."id", "federated_mapping"."name", "federated_mapping"."idp_id", "federated_mapping"."domain_id", CAST("federated_mapping"."type" AS "text"), "federated_mapping"."enabled", "federated_mapping"."allowed_redirect_uris", "federated_mapping"."user_id_claim", "federated_mapping"."user_name_claim", "federated_mapping"."domain_id_claim", "federated_mapping"."groups_claim", "federated_mapping"."bound_audiences", "federated_mapping"."bound_subject", "federated_mapping"."bound_claims", "federated_mapping"."oidc_scopes", "federated_mapping"."token_project_id", "federated_mapping"."token_restriction_id" FROM "federated_mapping" WHERE "federated_mapping"."id" = $1 LIMIT $2"#,
                ["1".into(), 1u64.into()]
            ),]
        );
    }
}
