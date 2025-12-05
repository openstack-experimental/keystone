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

pub use add::*;
pub use list::*;
pub use remove::*;
pub use set::*;

#[cfg(test)]
pub(super) mod tests {
    use chrono::{DateTime, Utc};

    use crate::db::entity::{expiring_user_group_membership, user_group_membership};

    pub(super) fn get_user_group_membership_mock<U, G>(
        user_id: U,
        group_id: G,
    ) -> user_group_membership::Model
    where
        U: AsRef<str>,
        G: AsRef<str>,
    {
        user_group_membership::Model {
            user_id: user_id.as_ref().to_string(),
            group_id: group_id.as_ref().to_string(),
        }
    }

    pub(super) fn get_expiring_user_group_membership_mock<U, G>(
        user_id: U,
        group_id: G,
        last_verified: DateTime<Utc>,
    ) -> expiring_user_group_membership::Model
    where
        U: AsRef<str>,
        G: AsRef<str>,
    {
        expiring_user_group_membership::Model {
            user_id: user_id.as_ref().to_string(),
            group_id: group_id.as_ref().to_string(),
            idp_id: "idp_id".to_string(),
            last_verified: last_verified.naive_utc(),
        }
    }
}
