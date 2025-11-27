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

use super::user;
use crate::db::entity::{nonlocal_user as db_nonlocal_user, user as db_user};
use crate::identity::types::*;

pub fn get_nonlocal_user_builder(
    user: &db_user::Model,
    data: db_nonlocal_user::Model,
    opts: UserOptions,
) -> UserResponseBuilder {
    let mut user_builder: UserResponseBuilder = user::get_user_builder(user, opts);
    user_builder.name(data.name.clone());
    user_builder
}
