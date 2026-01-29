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

use crate::db::entity::nonlocal_user as db_nonlocal_user;
use crate::identity::types::UserResponseBuilder;

mod create;
mod get;

pub use create::create;
pub use get::*;

impl UserResponseBuilder {
    pub fn merge_nonlocal_user_data(&mut self, data: &db_nonlocal_user::Model) -> &mut Self {
        self.name(data.name.clone());
        self
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::db::entity::nonlocal_user as db_nonlocal_user;

    pub fn get_nonlocal_user_mock<UID: Into<String>>(user_id: UID) -> db_nonlocal_user::Model {
        db_nonlocal_user::Model {
            user_id: user_id.into(),
            domain_id: "foo_domain".into(),
            name: "foo".into(),
        }
    }
}
