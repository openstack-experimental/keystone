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

use openstack_keystone_core_types::role::RoleOptions;

use crate::entity::role_option;

mod list;
mod upsert;

pub use list::list_by_role_id;
pub use upsert::upsert;

impl FromIterator<role_option::Model> for RoleOptions {
    fn from_iter<I: IntoIterator<Item = role_option::Model>>(iter: I) -> Self {
        let mut role_opts: RoleOptions = RoleOptions::default();
        for opt in iter.into_iter() {
            if let ("IMMU", Some(val)) = (opt.option_id.as_str(), opt.option_value) {
                role_opts.immutable = val.parse().ok();
            }
        }
        role_opts
    }
}

pub trait RoleOptionIntoModelIterator {
    fn to_model_iter<R: Into<String>>(
        &self,
        role_id: R,
    ) -> impl IntoIterator<Item = role_option::Model>;
}

impl RoleOptionIntoModelIterator for RoleOptions {
    /// Convert role options to a model iterator.
    ///
    /// # Parameters
    /// - `role_id`: The role ID.
    ///
    /// # Returns
    /// An iterator of role option models.
    fn to_model_iter<R: Into<String>>(
        &self,
        role_id: R,
    ) -> impl IntoIterator<Item = role_option::Model> {
        let mut res: Vec<role_option::Model> = Vec::new();
        let rid = role_id.into();
        if let Some(val) = &self.immutable {
            res.push(role_option::Model {
                role_id: rid.clone(),
                option_id: "IMMU".into(),
                option_value: Some(val.to_string()),
            });
        }
        res
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::entity::role_option;

    impl Default for role_option::Model {
        fn default() -> Self {
            Self {
                role_id: "1".into(),
                option_id: "IMMU".into(),
                option_value: None,
            }
        }
    }

    #[test]
    fn test_from_rows_empty() {
        assert_eq!(
            RoleOptions::from_iter(Vec::<role_option::Model>::new()),
            RoleOptions::default()
        );
    }

    #[test]
    fn test_to_model_iter_immutable() {
        let sot = RoleOptions {
            immutable: Some(true),
        };
        let rows = vec![role_option::Model {
            role_id: "rid".into(),
            option_id: "IMMU".into(),
            option_value: Some("true".into()),
        }];
        assert_eq!(
            sot.to_model_iter("rid").into_iter().collect::<Vec<_>>(),
            rows
        );
        assert_eq!(sot, RoleOptions::from_iter(rows));
    }

    #[test]
    fn test_to_model_iter_unset() {
        let sot = RoleOptions::default();
        assert!(sot.to_model_iter("rid").into_iter().next().is_none());
    }
}
