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

use sea_orm::entity::*;

use crate::db::entity::kubernetes_auth as db_k8s_auth;
use crate::k8s_auth::types::*;

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

impl From<db_k8s_auth::Model> for K8sAuthConfiguration {
    fn from(value: db_k8s_auth::Model) -> Self {
        Self {
            ca_cert: value.ca_cert.into(),
            domain_id: value.domain_id.into(),
            enabled: value.enabled,
            host: value.host.into(),
            id: value.id.into(),
            name: value.name.into(),
        }
    }
}

impl From<&db_k8s_auth::Model> for K8sAuthConfiguration {
    fn from(value: &db_k8s_auth::Model) -> Self {
        Self::from(value.clone())
    }
}

impl From<K8sAuthConfigurationCreate> for db_k8s_auth::ActiveModel {
    fn from(value: K8sAuthConfigurationCreate) -> Self {
        Self {
            ca_cert: value.ca_cert.map(Set).unwrap_or(NotSet).into(),
            domain_id: Set(value.domain_id),
            enabled: Set(value.enabled),
            host: Set(value.host),
            id: value
                .id
                .map(Set)
                .unwrap_or(Set(uuid::Uuid::new_v4().simple().to_string())),
            name: value.name.map(Set).unwrap_or(NotSet).into(),
        }
    }
}

impl db_k8s_auth::Model {
    /// Build an [`kubernetes_auth::ActiveModel`] for the update operation using
    /// the [`K8sAuthConfigurationUpdate`].
    fn to_active_model_update(
        self,
        update: K8sAuthConfigurationUpdate,
    ) -> db_k8s_auth::ActiveModel {
        let mut new: db_k8s_auth::ActiveModel = self.into();
        if let Some(val) = &update.ca_cert {
            new.ca_cert = Set(Some(val.into()));
        }
        if let Some(val) = update.enabled {
            new.enabled = Set(val.into());
        }
        if let Some(val) = &update.host {
            new.host = Set(val.into());
        }
        if let Some(val) = &update.name {
            new.name = Set(Some(val.into()));
        }

        new
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use sea_orm::entity::*;

    use crate::db::entity::kubernetes_auth;
    use crate::k8s_auth::types::*;

    pub fn get_k8s_auth_config_mock<S: Into<String>>(id: S) -> kubernetes_auth::Model {
        kubernetes_auth::Model {
            ca_cert: Some("key".into()),
            domain_id: "did".into(),
            enabled: true,
            host: "host.local".into(),
            id: id.into(),
            name: Some("name".into()),
        }
    }

    #[test]
    fn test_db_to_provider_model() {
        assert_eq!(
            K8sAuthConfiguration {
                ca_cert: Some("ca".into()),
                domain_id: "did".into(),
                enabled: true,
                host: "host".into(),
                id: "id".into(),
                name: Some("name".into()),
            },
            K8sAuthConfiguration::from(kubernetes_auth::Model {
                ca_cert: Some("ca".into()),
                domain_id: "did".into(),
                enabled: true,
                host: "host".into(),
                id: "id".into(),
                name: Some("name".into()),
            })
        );
    }

    #[test]
    fn test_create_to_db_model() {
        assert_eq!(
            kubernetes_auth::ActiveModel {
                ca_cert: Set(Some("ca".into())),
                domain_id: Set("did".into()),
                enabled: Set(true),
                host: Set("host".into()),
                id: Set("id".into()),
                name: Set(Some("name".into())),
            },
            kubernetes_auth::ActiveModel::from(K8sAuthConfigurationCreate {
                ca_cert: Some("ca".into()),
                domain_id: "did".into(),
                enabled: true,
                host: "host".into(),
                id: Some("id".into()),
                name: Some("name".into()),
            })
        );
        assert!(
            !kubernetes_auth::ActiveModel::from(K8sAuthConfigurationCreate {
                ca_cert: Some("ca".into()),
                domain_id: "did".into(),
                enabled: true,
                host: "host".into(),
                id: None,
                name: Some("name".into()),
            })
            .id
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn test_model_to_active_model_update() {
        let sot = kubernetes_auth::Model {
            ca_cert: Some("ca".into()),
            domain_id: "did".into(),
            enabled: true,
            host: "host".into(),
            id: "id".into(),
            name: Some("name".into()),
        };
        let update = sot.to_active_model_update(crate::k8s_auth::K8sAuthConfigurationUpdate {
            ca_cert: Some("new_ca".into()),
            enabled: Some(true),
            host: Some("new_host".into()),
            name: Some("new_name".into()),
        });
        assert_eq!(Set(Some("new_ca".into())), update.ca_cert);
        assert_eq!(Unchanged("did".into()), update.domain_id);
        assert_eq!(Unchanged("id".into()), update.id);
        assert_eq!(Set(true), update.enabled);
        assert_eq!(Set("new_host".into()), update.host);
        assert_eq!(Set(Some("new_name".into())), update.name);
    }
}
