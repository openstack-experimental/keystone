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
//! # OpenStack Keystone SQL driver for the token restriction provider
use async_trait::async_trait;

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::token::TokenProviderError;
use openstack_keystone_core::token::backend::TokenRestrictionBackend;
use openstack_keystone_core_types::token::*;

use crate::entity::{token_restriction, token_restriction_role_association};

mod create;
mod delete;
pub mod entity;
mod get;
mod list;
mod update;

#[derive(Default)]
pub struct SqlBackend {}

#[async_trait]
impl TokenRestrictionBackend for SqlBackend {
    /// Get the token restriction by the ID.
    async fn get_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<Option<TokenRestriction>, TokenProviderError> {
        get::get(&state.db, id).await
    }

    /// Create new token restriction.
    async fn create_token_restriction<'a>(
        &self,
        state: &ServiceState,
        restriction: TokenRestrictionCreate,
    ) -> Result<TokenRestriction, TokenProviderError> {
        create::create(&state.db, restriction).await
    }

    /// List token restrictions.
    async fn list_token_restrictions<'a>(
        &self,
        state: &ServiceState,
        params: &TokenRestrictionListParameters,
    ) -> Result<Vec<TokenRestriction>, TokenProviderError> {
        list::list(&state.db, params).await
    }

    /// Update token restriction by the ID.
    async fn update_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
        restriction: TokenRestrictionUpdate,
    ) -> Result<TokenRestriction, TokenProviderError> {
        update::update(&state.db, id, restriction).await
    }

    /// Delete token restriction by the ID.
    async fn delete_token_restriction<'a>(
        &self,
        state: &ServiceState,
        id: &'a str,
    ) -> Result<(), TokenProviderError> {
        delete::delete(&state.db, id).await
    }
}

impl From<token_restriction::Model> for TokenRestriction {
    fn from(value: token_restriction::Model) -> Self {
        TokenRestriction {
            id: value.id,
            domain_id: value.domain_id,
            user_id: value.user_id,
            project_id: value.project_id,
            allow_rescope: value.allow_rescope,
            allow_renew: value.allow_renew,
            role_ids: Vec::new(),
            roles: None,
        }
    }
}

pub trait FromModelWithRoleAssociation {
    fn from_model_with_ra(
        value: (
            token_restriction::Model,
            Vec<token_restriction_role_association::Model>,
        ),
    ) -> Self;
    //fn from_model_with_ra_and_role(
    //    value: (
    //        token_restriction::Model,
    //        Vec<(
    //            token_restriction_role_association::Model,
    //            Option<role::Model>,
    //        )>,
    //    ),
    //) -> Self;
}

impl FromModelWithRoleAssociation for TokenRestriction {
    fn from_model_with_ra(
        value: (
            token_restriction::Model,
            Vec<token_restriction_role_association::Model>,
        ),
    ) -> Self {
        let mut restriction: TokenRestriction = value.0.into();
        restriction.role_ids = value.1.into_iter().map(|val| val.role_id).collect();
        restriction
    }
}

#[cfg(test)]
pub mod tests {
    use crate::entity::token_restriction;

    pub fn get_restriction_mock<S: Into<String>>(id: S) -> token_restriction::Model {
        token_restriction::Model {
            id: id.into(),
            domain_id: "did".to_string(),
            user_id: Some("uid".to_string()),
            project_id: Some("pid".to_string()),
            allow_rescope: true,
            allow_renew: true,
        }
    }
}
