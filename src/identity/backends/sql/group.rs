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

use crate::db::entity::group;
use crate::identity::types::Group;
use serde_json::{Value, json};

mod create;
mod delete;
mod get;
mod list;

pub use create::create;
pub use delete::delete;
pub use get::get;
pub use list::list;

impl From<group::Model> for Group {
    fn from(value: group::Model) -> Self {
        Group {
            id: value.id.clone(),
            name: value.name.clone(),
            description: value.description.clone(),
            domain_id: value.domain_id.clone(),
            extra: value
                .extra
                .map(|x| serde_json::from_str::<Value>(&x).unwrap_or(json!(true))),
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    #![allow(clippy::derivable_impls)]
    use super::*;

    pub fn get_group_mock<S: AsRef<str>>(id: S) -> group::Model {
        group::Model {
            id: id.as_ref().to_string(),
            domain_id: "foo_domain".into(),
            name: "group".into(),
            description: Some("fake".into()),
            extra: Some("{\"foo\": \"bar\"}".into()),
        }
    }
}
