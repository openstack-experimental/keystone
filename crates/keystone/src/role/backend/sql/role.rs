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

use serde_json::Value;
use tracing::error;

mod create;
mod get;
mod list;

pub use create::create;
pub use get::get;
pub use list::list;

use crate::db::entity::role as db_role;
use crate::role::backend::error::RoleDatabaseError;
use crate::role::types::role::*;

static NULL_DOMAIN_ID: &str = "<<null>>";

impl TryFrom<db_role::Model> for Role {
    type Error = RoleDatabaseError;

    fn try_from(value: db_role::Model) -> Result<Self, Self::Error> {
        let mut builder = RoleBuilder::default();
        builder.id(value.id.clone());
        builder.name(value.name.clone());
        if value.domain_id != NULL_DOMAIN_ID {
            builder.domain_id(value.domain_id.clone());
        }
        if let Some(description) = &value.description {
            builder.description(description.clone());
        }
        if let Some(extra) = &value.extra {
            builder.extra(
                serde_json::from_str::<Value>(extra)
                    .inspect_err(|e| error!("failed to deserialize role extra: {e}"))
                    .unwrap_or_default(),
            );
        }

        Ok(builder.build()?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::db::entity::role;

    pub fn get_role_mock<I: Into<String>, N: Into<String>>(id: I, name: N) -> role::Model {
        role::Model {
            id: id.into(),
            domain_id: "foo_domain".into(),
            name: name.into(),
            ..Default::default()
        }
    }
}
