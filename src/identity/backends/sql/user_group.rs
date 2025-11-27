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

mod add;
mod list;
mod remove;
mod set;

pub use add::{add_user_to_group, add_users_to_groups};
pub use list::list_user_groups;
pub use remove::{remove_user_from_group, remove_user_from_groups};
pub use set::set_user_groups;

#[cfg(test)]
pub(super) mod tests {
    use crate::db::entity::user_group_membership;

    pub fn get_user_group_mock<U: AsRef<str>, G: AsRef<str>>(
        user_id: U,
        group_id: G,
    ) -> user_group_membership::Model {
        user_group_membership::Model {
            user_id: user_id.as_ref().to_string(),
            group_id: group_id.as_ref().to_string(),
        }
    }
}
