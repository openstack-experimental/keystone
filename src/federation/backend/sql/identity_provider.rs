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

use crate::db::entity::federated_identity_provider as db_federated_identity_provider;
use crate::federation::backend::error::FederationDatabaseError;
use crate::federation::types::*;

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

impl TryFrom<db_federated_identity_provider::Model> for IdentityProvider {
    type Error = FederationDatabaseError;

    fn try_from(value: db_federated_identity_provider::Model) -> Result<Self, Self::Error> {
        let mut builder = IdentityProviderBuilder::default();
        builder.id(value.id.clone());
        builder.name(value.name.clone());
        builder.enabled(value.enabled);
        if let Some(val) = &value.domain_id {
            builder.domain_id(val);
        }
        if let Some(val) = &value.oidc_discovery_url {
            builder.oidc_discovery_url(val);
        }
        if let Some(val) = &value.oidc_client_id {
            builder.oidc_client_id(val);
        }
        if let Some(val) = &value.oidc_client_secret {
            builder.oidc_client_secret(val);
        }
        if let Some(val) = &value.oidc_response_mode {
            builder.oidc_response_mode(val);
        }
        if let Some(val) = &value.oidc_response_types
            && !val.is_empty()
        {
            builder.oidc_response_types(Vec::from_iter(val.split(",").map(Into::into)));
        }
        if let Some(val) = &value.jwks_url {
            builder.jwks_url(val);
        }
        if let Some(val) = &value.jwt_validation_pubkeys
            && !val.is_empty()
        {
            builder.jwt_validation_pubkeys(Vec::from_iter(val.split(",").map(Into::into)));
        }
        if let Some(val) = &value.bound_issuer {
            builder.bound_issuer(val);
        }
        if let Some(val) = &value.provider_config {
            builder.provider_config(val.clone());
        }
        if let Some(val) = &value.default_mapping_name {
            builder.default_mapping_name(val.clone());
        }
        Ok(builder.build()?)
    }
}

#[cfg(test)]
mod tests {

    use crate::db::entity::{federated_identity_provider, federation_protocol, identity_provider};

    pub(super) fn get_idp_mock<S: AsRef<str>>(id: S) -> federated_identity_provider::Model {
        federated_identity_provider::Model {
            id: id.as_ref().into(),
            name: "name".into(),
            domain_id: Some("did".into()),
            ..Default::default()
        }
    }

    pub(super) fn get_old_idp_mock<S: AsRef<str>>(id: S) -> identity_provider::Model {
        identity_provider::Model {
            id: id.as_ref().into(),
            enabled: true,
            description: Some("name".into()),
            domain_id: "did".into(),
            authorization_ttl: None,
        }
    }

    pub(super) fn get_old_proto_mock<S: AsRef<str>>(id: S) -> federation_protocol::Model {
        federation_protocol::Model {
            id: "oidc".into(),
            idp_id: id.as_ref().into(),
            mapping_id: "<<null>>".into(),
            remote_id_attribute: None,
        }
    }

    #[test]
    fn test_from_db_model() {}
}
