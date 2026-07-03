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

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::federation::FederationProviderError;
use openstack_keystone_core_types::federation::*;

use crate::entity::{
    federated_identity_provider as db_federated_identity_provider,
    prelude::FederatedIdentityProvider as DbFederatedIdentityProvider,
};

/// Get an identity provider by its ID.
///
/// # Parameters
/// - `db`: The database connection.
/// - `id`: The ID of the identity provider.
///
/// # Returns
/// A `Result` containing an `Option` with the `IdentityProvider` if found, or
/// an `Error`.
pub async fn get<I: AsRef<str>>(
    db: &DatabaseConnection,
    id: I,
) -> Result<Option<IdentityProvider>, FederationProviderError> {
    let select = DbFederatedIdentityProvider::find_by_id(id.as_ref());

    let entry: Option<db_federated_identity_provider::Model> = select
        .one(db)
        .await
        .context("fetching identity provider by id")?;
    entry.map(TryInto::try_into).transpose()
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::super::tests::get_idp_mock;
    use super::*;

    #[tokio::test]
    async fn test_get() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![get_idp_mock("1")]])
            .into_connection();

        // `IdentityProvider` holds an `oidc_client_secret: SecretString`, which
        // is not `PartialEq`, so the returned value is asserted field by field.
        let idp = get(&db, "1").await.unwrap().unwrap();
        assert_eq!(idp.id, "1");
        assert_eq!(idp.name, "name");
        assert_eq!(idp.domain_id, Some("did".into()));
        assert!(idp.oidc_client_secret.is_none());

        // Checking transaction log: single SELECT from the right table
        let txns = db.into_transaction_log();
        assert_eq!(txns.len(), 1);
        let sql = &txns[0].statements()[0].sql;
        assert!(sql.starts_with("SELECT"));
        assert!(sql.contains("federated_identity_provider"));
        assert!(sql.contains(r#"WHERE "federated_identity_provider"."id""#));
    }
}
