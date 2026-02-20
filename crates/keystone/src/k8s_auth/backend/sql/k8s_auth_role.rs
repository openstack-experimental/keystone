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

use crate::db::entity::kubernetes_auth_role;
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

impl From<kubernetes_auth_role::Model> for K8sAuthRole {
    fn from(value: kubernetes_auth_role::Model) -> Self {
        Self {
            auth_configuration_id: value.auth_configuration_id,
            bound_audience: value.bound_audience,
            bound_service_account_names: value
                .bound_service_account_names
                .split(',')
                .map(String::from)
                .collect(),
            bound_service_account_namespaces: value
                .bound_service_account_namespaces
                .split(',')
                .map(String::from)
                .collect(),
            domain_id: value.domain_id,
            enabled: value.enabled,
            id: value.id,
            name: value.name,
            token_restriction_id: value.token_restriction_id,
        }
    }
}

impl From<&kubernetes_auth_role::Model> for K8sAuthRole {
    fn from(value: &kubernetes_auth_role::Model) -> Self {
        Self::from(value.clone())
    }
}

impl From<K8sAuthRoleCreate> for kubernetes_auth_role::ActiveModel {
    fn from(value: K8sAuthRoleCreate) -> Self {
        Self {
            auth_configuration_id: Set(value.auth_configuration_id),
            bound_audience: value.bound_audience.map(Set).unwrap_or(NotSet).into(),
            bound_service_account_names: Set(value.bound_service_account_names.join(",")),
            bound_service_account_namespaces: Set(value.bound_service_account_namespaces.join(",")),
            domain_id: Set(value.domain_id),
            enabled: Set(value.enabled),
            id: value
                .id
                .map(Set)
                .unwrap_or(Set(uuid::Uuid::new_v4().simple().to_string())),
            name: Set(value.name),
            token_restriction_id: Set(value.token_restriction_id),
        }
    }
}

impl kubernetes_auth_role::Model {
    /// Build an [`kubernetes_auth_role::ActiveModel`] for the update operation
    /// using the [`K8sAuthRoleUpdate`].
    fn to_active_model_update(
        self,
        update: K8sAuthRoleUpdate,
    ) -> kubernetes_auth_role::ActiveModel {
        let mut new: kubernetes_auth_role::ActiveModel = self.into();
        if let Some(val) = &update.bound_audience {
            new.bound_audience = Set(Some(val.into()));
        }
        if let Some(val) = update.bound_service_account_names {
            new.bound_service_account_names = Set(val.join(","));
        }
        if let Some(val) = update.bound_service_account_namespaces {
            new.bound_service_account_namespaces = Set(val.join(","));
        }
        if let Some(val) = update.enabled {
            new.enabled = Set(val);
        }
        if let Some(val) = &update.name {
            new.name = Set(val.into());
        }
        if let Some(val) = &update.token_restriction_id {
            new.token_restriction_id = Set(val.into());
        }

        new
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use sea_orm::entity::*;

    use crate::db::entity::kubernetes_auth_role;
    use crate::k8s_auth::types::*;

    pub fn get_k8s_auth_role_mock<S: Into<String>>(id: S) -> kubernetes_auth_role::Model {
        kubernetes_auth_role::Model {
            auth_configuration_id: "cid".into(),
            bound_audience: Some("aud".into()),
            bound_service_account_names: "a,b".into(),
            bound_service_account_namespaces: "na,nb".into(),
            domain_id: "did".into(),
            enabled: true,
            id: id.into(),
            name: "name".into(),
            token_restriction_id: "trid".into(),
        }
    }

    #[test]
    fn test_db_to_provider_model() {
        assert_eq!(
            K8sAuthRole {
                auth_configuration_id: "cid".into(),
                bound_audience: Some("aud".into()),
                bound_service_account_names: vec!["a".into(), "b".into()],
                bound_service_account_namespaces: vec!["na".into(), "nb".into()],
                domain_id: "did".into(),
                enabled: true,
                id: "id".into(),
                name: "name".into(),
                token_restriction_id: "trid".into(),
            },
            K8sAuthRole::from(kubernetes_auth_role::Model {
                auth_configuration_id: "cid".into(),
                bound_audience: Some("aud".into()),
                bound_service_account_names: "a,b".into(),
                bound_service_account_namespaces: "na,nb".into(),
                domain_id: "did".into(),
                enabled: true,
                id: "id".into(),
                name: "name".into(),
                token_restriction_id: "trid".into(),
            })
        );
    }

    #[test]
    fn test_create_to_db_model() {
        assert_eq!(
            kubernetes_auth_role::ActiveModel {
                auth_configuration_id: Set("cid".into()),
                bound_audience: Set(Some("aud".into())),
                bound_service_account_names: Set("a,b".into()),
                bound_service_account_namespaces: Set("na,nb".into()),
                domain_id: Set("did".into()),
                enabled: Set(true),
                id: Set("id".into()),
                name: Set("name".into()),
                token_restriction_id: Set("trid".into()),
            },
            kubernetes_auth_role::ActiveModel::from(K8sAuthRoleCreate {
                auth_configuration_id: "cid".into(),
                bound_audience: Some("aud".into()),
                bound_service_account_names: vec!["a".into(), "b".into()],
                bound_service_account_namespaces: vec!["na".into(), "nb".into()],
                domain_id: "did".into(),
                enabled: true,
                id: Some("id".into()),
                name: "name".into(),
                token_restriction_id: "trid".into(),
            },)
        );
        assert!(
            !kubernetes_auth_role::ActiveModel::from(K8sAuthRoleCreate {
                auth_configuration_id: "cid".into(),
                bound_audience: Some("aud".into()),
                bound_service_account_names: vec!["a".into(), "b".into()],
                bound_service_account_namespaces: vec!["na".into(), "nb".into()],
                domain_id: "did".into(),
                enabled: true,
                id: None,
                name: "name".into(),
                token_restriction_id: "trid".into(),
            })
            .id
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn test_model_to_active_model_update() {
        let sot = kubernetes_auth_role::Model {
            auth_configuration_id: "cid".into(),
            bound_audience: Some("aud".into()),
            bound_service_account_names: "a,b".into(),
            bound_service_account_namespaces: "na,nb".into(),
            domain_id: "did".into(),
            enabled: true,
            id: "id".into(),
            name: "name".into(),
            token_restriction_id: "trid".into(),
        };
        let update = sot.to_active_model_update(crate::k8s_auth::K8sAuthRoleUpdate {
            bound_audience: Some("new_aud".into()),
            bound_service_account_names: Some(vec!["c".into()]),
            bound_service_account_namespaces: Some(vec!["nc".into()]),
            enabled: Some(true),
            name: Some("new_name".into()),
            token_restriction_id: Some("new_trid".into()),
        });
        assert_eq!(Set(Some("new_aud".into())), update.bound_audience);
        assert_eq!(Set("c".into()), update.bound_service_account_names);
        assert_eq!(Set("nc".into()), update.bound_service_account_namespaces);
        assert_eq!(Unchanged("did".into()), update.domain_id);
        assert_eq!(Unchanged("id".into()), update.id);
        assert_eq!(Set(true), update.enabled);
        assert_eq!(Set("new_name".into()), update.name);
        assert_eq!(Set("new_trid".into()), update.token_restriction_id);
    }
}
