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

use crate::db::entity::federated_user as db_federated_user;
use crate::identity::types::*;

mod create;
mod find;

pub use create::create;
pub use find::find_by_idp_and_unique_id;

impl UserResponseBuilder {
    pub fn merge_federated_user_data<I>(&mut self, data: I) -> &mut Self
    where
        I: IntoIterator<Item = db_federated_user::Model>,
    {
        let mut feds: Vec<Federation> = Vec::new();
        if let Some(first) = data.into_iter().next() {
            if let Some(name) = first.display_name {
                self.name(name.clone());
            }

            let mut fed = FederationBuilder::default();
            fed.idp_id(first.idp_id.clone());
            fed.unique_id(first.unique_id.clone());
            let protocol = FederationProtocol {
                protocol_id: first.protocol_id.clone(),
                unique_id: first.unique_id.clone(),
            };
            fed.protocols(vec![protocol]);
            if let Ok(fed_obj) = fed.build() {
                feds.push(fed_obj);
            }
        }
        self.federated(feds);
        self
    }
}
