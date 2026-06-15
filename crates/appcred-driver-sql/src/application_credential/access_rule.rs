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
//! # Application credential access rule database backend.

mod create;
mod delete;
mod get;
mod list;

pub use create::create;
pub use delete::delete;
pub use get::get;
pub use list::list;

#[cfg(test)]
pub(crate) mod tests {
    use crate::entity::access_rule;

    /// Build a mock `access_rule::Model` for tests.
    pub fn get_access_rule_mock<S: AsRef<str>>(
        internal_id: i32,
        external_id: S,
    ) -> access_rule::Model {
        access_rule::Model {
            id: internal_id,
            external_id: Some(external_id.as_ref().into()),
            path: Some("/v2.1/servers".into()),
            method: Some("POST".into()),
            service: Some("compute".into()),
            user_id: Some("user_id".into()),
        }
    }
}
