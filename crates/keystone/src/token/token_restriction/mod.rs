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

use crate::db::entity::{role, token_restriction, token_restriction_role_association};

use crate::token::types::TokenRestriction;

mod create;
mod delete;
mod get;
mod list;
mod update;

pub use create::create;
pub use delete::delete;
pub use get::get;
pub use list::list;
pub use update::update;

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

impl
    From<(
        token_restriction::Model,
        Vec<token_restriction_role_association::Model>,
    )> for TokenRestriction
{
    fn from(
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

impl
    From<(
        token_restriction::Model,
        Vec<(
            token_restriction_role_association::Model,
            Option<role::Model>,
        )>,
    )> for TokenRestriction
{
    fn from(
        value: (
            token_restriction::Model,
            Vec<(
                token_restriction_role_association::Model,
                Option<role::Model>,
            )>,
        ),
    ) -> Self {
        let mut restriction: TokenRestriction = value.0.into();
        let roles: Vec<crate::assignment::types::Role> = value
            .1
            .into_iter()
            .filter_map(|(_a, r)| r)
            .map(|role| crate::assignment::types::Role {
                id: role.id.clone(),
                name: role.name.clone(),
                ..Default::default()
            })
            .collect();
        restriction.role_ids = roles.iter().map(|role| role.id.clone()).collect();
        restriction.roles = Some(roles);
        restriction
    }
}

#[cfg(test)]
mod tests {
    use crate::db::entity::token_restriction;

    pub fn get_restriction_mock<S: AsRef<str>>(id: S) -> token_restriction::Model {
        token_restriction::Model {
            id: id.as_ref().to_string(),
            domain_id: "did".to_string(),
            user_id: Some("uid".to_string()),
            project_id: Some("pid".to_string()),
            allow_rescope: true,
            allow_renew: true,
        }
    }
}
