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
//! # `bound_issuer` uniqueness guard
//!
//! Token exchange resolves an external token's issuer to exactly one identity
//! provider per scope (the domain, or global). The schema has no unique
//! constraint on `bound_issuer` (it is optional and shared by the `/jwt`
//! login), so the invariant is enforced here at write time: at most one
//! *enabled* identity provider per `(domain_id, bound_issuer)`. Disabled
//! identity providers are exempt so that an IdP can be rotated by creating the
//! replacement while the old one is retired.
//!
//! The check is not atomic with the following write. The lookup in
//! `FederationApi::get_identity_provider_by_issuer` therefore still fails
//! closed on ambiguity.
use sea_orm::ConnectionTrait;
use sea_orm::entity::*;
use sea_orm::query::*;

use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core::federation::FederationProviderError;

use crate::entity::{
    federated_identity_provider as db_federated_identity_provider,
    prelude::FederatedIdentityProvider as DbFederatedIdentityProvider,
};

/// Reject the write if another enabled identity provider of the same scope
/// already uses `issuer`.
///
/// # Parameters
/// - `db`: The connection or transaction to query on.
/// - `exclude_id`: The identity provider being written (`None` on create).
/// - `domain_id`: The scope of the identity provider being written.
/// - `issuer`: The `bound_issuer` the identity provider will have.
///
/// # Returns
/// `Ok(())` if the issuer is free in the scope, `Conflict` otherwise.
pub(super) async fn ensure_issuer_unique<C: ConnectionTrait>(
    db: &C,
    exclude_id: Option<&str>,
    domain_id: Option<&str>,
    issuer: &str,
) -> Result<(), FederationProviderError> {
    let mut select = DbFederatedIdentityProvider::find()
        .filter(db_federated_identity_provider::Column::Enabled.eq(true))
        .filter(db_federated_identity_provider::Column::BoundIssuer.eq(issuer));
    select = match domain_id {
        Some(d) => select.filter(db_federated_identity_provider::Column::DomainId.eq(d)),
        None => select.filter(db_federated_identity_provider::Column::DomainId.is_null()),
    };
    if let Some(id) = exclude_id {
        select = select.filter(db_federated_identity_provider::Column::Id.ne(id));
    }
    if select
        .one(db)
        .await
        .context("checking bound_issuer uniqueness")?
        .is_some()
    {
        return Err(FederationProviderError::Conflict(
            "another enabled identity provider in the same scope already uses this bound_issuer"
                .into(),
        ));
    }
    Ok(())
}
