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

use crate::common::types::Scope;
use crate::db::entity::federated_auth_state as db_federated_auth_state;
use crate::federation::backend::error::FederationDatabaseError;
use crate::federation::types::*;

mod create;
mod delete;
mod get;

pub use create::create;
pub use delete::{delete, delete_expired};
pub use get::get;

impl TryFrom<db_federated_auth_state::Model> for AuthState {
    type Error = FederationDatabaseError;

    fn try_from(value: db_federated_auth_state::Model) -> Result<Self, Self::Error> {
        let mut builder = AuthStateBuilder::default();
        builder.state(value.state.clone());
        builder.nonce(value.nonce.clone());
        builder.idp_id(value.idp_id.clone());
        builder.mapping_id(value.mapping_id.clone());
        builder.redirect_uri(value.redirect_uri.clone());
        builder.pkce_verifier(value.pkce_verifier.clone());
        builder.expires_at(value.expires_at.and_utc());
        if let Some(scope) = value.requested_scope {
            builder.scope(serde_json::from_value::<Scope>(scope)?);
        }
        Ok(builder.build()?)
    }
}

#[cfg(test)]
mod tests {
    use crate::db::entity::federated_auth_state as db_federated_auth_state;
    use chrono::NaiveDateTime;

    pub(super) fn get_auth_state_mock<S: AsRef<str>>(state: S) -> db_federated_auth_state::Model {
        db_federated_auth_state::Model {
            idp_id: "idp".into(),
            mapping_id: "mapping".into(),
            state: state.as_ref().into(),
            nonce: "nonce".into(),
            redirect_uri: "redirect_uri".into(),
            pkce_verifier: "pkce_verifier".into(),
            expires_at: NaiveDateTime::default(),
            requested_scope: None,
        }
    }
}
